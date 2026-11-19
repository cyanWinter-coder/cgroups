/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package cgroup2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// fsOps abstracts the file operations performed against a cgroup directory.
// It is a seam that lets the transactional update logic run against a plain
// directory in tests; production uses dirFSOps backed by the real hierarchy.
type fsOps interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	Remove(name string) error
}

// dirFSOps performs operations relative to a cgroup directory on disk.
type dirFSOps struct {
	dir string
}

// deviceInstaller is an optional fsOps capability that installs the eBPF
// device filter. dirFSOps implements it against the real hierarchy; test
// seams can implement it to inject failures without a cgroup mount.
type deviceInstaller interface {
	installDevices(devices []specs.LinuxDeviceCgroup) error
}

func (o dirFSOps) join(name string) string {
	return filepath.Join(o.dir, name)
}

func (o dirFSOps) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(o.join(name))
}

func (o dirFSOps) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(o.join(name), data, perm)
}

func (o dirFSOps) Remove(name string) error {
	return os.Remove(o.join(name))
}

func (o dirFSOps) installDevices(devices []specs.LinuxDeviceCgroup) error {
	return setDevices(o.dir, devices)
}

// RollbackFailure describes a single cgroup file whose rollback to its
// original value failed while recovering from an earlier update error.
type RollbackFailure struct {
	// Filename is the cgroup control file that could not be restored.
	Filename string
	// Err is the error encountered while restoring the file.
	Err error
	// Remaining is the value the file still holds, i.e. the state that
	// may be left behind from the partially applied update.
	Remaining string
}

func (f RollbackFailure) Error() string {
	return fmt.Sprintf("rollback of %q failed: %s (still holds %q)", f.Filename, f.Err, f.Remaining)
}

func (f RollbackFailure) Unwrap() error {
	return f.Err
}

// RollbackError is returned by Manager.Update when applying the requested
// resources failed and the subsequent rollback did not fully restore the
// previous state. The original update error is available through Unwrap (or
// errors.Is/errors.As), while Failures lists every file whose rollback failed
// together with the value that may still be applied.
type RollbackError struct {
	// Op is the operation that triggered the rollback.
	Op string
	// Original is the error that made the update fail and forced the rollback.
	Original error
	// Failures lists the control files whose rollback did not succeed.
	Failures []RollbackFailure
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf("cgroups: update of %q failed: %s; rollback incomplete: %v; residual state may remain",
		e.Op, e.Original, e.Failures)
}

// Unwrap returns the original update error so that errors.Is and errors.As
// keep matching the failure that started the rollback.
func (e *RollbackError) Unwrap() error {
	return e.Original
}

// appliedWrite records a control file that was successfully changed together
// with the snapshot needed to restore it.
type appliedWrite struct {
	filename string
	// original holds the file content captured before the update write.
	original []byte
	// existed reports whether the file was present when the snapshot was
	// taken. Files created by the update are removed on rollback.
	existed bool
}

// rollback restores the applied writes in reverse order. It returns nil when
// every file was restored, otherwise a *RollbackError carrying originalErr
// and the files that could not be restored.
func rollback(ops fsOps, applied []appliedWrite, op string, originalErr error) error {
	var failures []RollbackFailure
	for i := len(applied) - 1; i >= 0; i-- {
		w := applied[i]
		var err error
		if w.existed {
			err = ops.WriteFile(w.filename, w.original, defaultFilePerm)
		} else {
			err = ops.Remove(w.filename)
			// A file created by the update may already be gone; that is the
			// desired end state, so do not treat it as a failure.
			if os.IsNotExist(err) {
				err = nil
			}
		}
		if err != nil {
			remaining, readErr := ops.ReadFile(w.filename)
			if readErr != nil {
				remaining = []byte(fmt.Sprintf("<unreadable: %s>", readErr))
			}
			failures = append(failures, RollbackFailure{
				Filename:  w.filename,
				Err:       err,
				Remaining: string(remaining),
			})
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return &RollbackError{
		Op:       op,
		Original: originalErr,
		Failures: failures,
	}
}

// transactionWriteValues applies the given values against dir in order,
// snapshotting every affected file before it is first written. When any write
// (or snapshot) fails, the already applied writes are rolled back in reverse
// order and the caller gets back the original error, wrapped in a
// *RollbackError when the rollback itself is incomplete. On success it returns
// the applied writes, which the caller can hand to rollback if a later,
// non-transactional step (e.g. the device filter) fails.
func transactionWriteValues(ops fsOps, values []Value) ([]appliedWrite, error) {
	var applied []appliedWrite
	// Snapshots are keyed by filename so a file written more than once is
	// captured only once and restored to its pre-update value.
	snapshots := make(map[string]struct{})

	for _, v := range values {
		if _, ok := snapshots[v.filename]; !ok {
			original, err := ops.ReadFile(v.filename)
			if err != nil {
				if !os.IsNotExist(err) {
					// Snapshotting an existing file failed: nothing has been
					// written for it, but earlier writes still need undoing.
					originalErr := fmt.Errorf("failed to snapshot %q before update: %w", v.filename, err)
					if rbErr := rollback(ops, applied, "values", originalErr); rbErr != nil {
						return nil, rbErr
					}
					return nil, originalErr
				}
				// The file does not exist yet; remove it again on rollback.
				snapshots[v.filename] = struct{}{}
				applied = append(applied, appliedWrite{filename: v.filename, existed: false})
			} else {
				snapshots[v.filename] = struct{}{}
				applied = append(applied, appliedWrite{filename: v.filename, original: original, existed: true})
			}
		}

		data, err := v.bytes()
		if err != nil {
			if rbErr := rollback(ops, applied, "values", err); rbErr != nil {
				return nil, rbErr
			}
			return nil, err
		}
		if err := ops.WriteFile(v.filename, data, defaultFilePerm); err != nil {
			originalErr := fmt.Errorf("failed to write %q: %w", v.filename, err)
			if rbErr := rollback(ops, applied, "values", originalErr); rbErr != nil {
				return nil, rbErr
			}
			return nil, originalErr
		}
	}
	return applied, nil
}

// updateResources applies the resource values transactionally and then
// installs the device filter. A device filter cannot be reverted, so a failure
// at that stage rolls back every control-file write and explicitly reports
// the device state that may remain applied.
func updateResources(ops fsOps, resources *Resources) error {
	values := resources.Values()
	applied, err := transactionWriteValues(ops, values)
	if err != nil {
		return err
	}
	if len(resources.Devices) == 0 {
		return nil
	}
	installer, ok := ops.(deviceInstaller)
	if !ok {
		// The seam does not model device attachment (e.g. a plain-directory
		// test); nothing to do.
		return nil
	}
	if err := installer.installDevices(resources.Devices); err != nil {
		// The eBPF device filter is additive and cannot be detached here, so
		// roll back the control files and surface the residual device state.
		// The device residual is reported regardless of whether the
		// control-file rollback itself succeeded.
		rbe := &RollbackError{
			Op:       "devices",
			Original: err,
			Failures: []RollbackFailure{{
				Filename:  "cgroup bpf device filter",
				Err:       errors.New("device filter cannot be rolled back automatically"),
				Remaining: "the newly attached eBPF device program may remain attached",
			}},
		}
		if rbErr := rollback(ops, applied, "devices", err); rbErr != nil {
			var inner *RollbackError
			if errors.As(rbErr, &inner) {
				rbe.Failures = append(rbe.Failures, inner.Failures...)
			}
		}
		return rbe
	}
	return nil
}
