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
	"strings"
	"sync"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// pathLocks serializes operations on the same absolute cgroup path even when
// callers use separate Manager handles loaded for the same group.
var pathLocks sync.Map

func lockCgroupPath(path string) func() {
	key := filepath.Clean(path)
	if key == "." {
		key = path
	}
	v, _ := pathLocks.LoadOrStore(key, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// FSOps abstracts operations against a cgroup directory. Production uses
// dirFSOps; tests can replace Manager.ops to inject filesystem failures.
type FSOps interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	Remove(name string) error
}

// fsOps is retained as the internal name for FSOps.
type fsOps = FSOps

// deviceInstaller is an optional fsOps capability that installs the eBPF
// device filter. dirFSOps implements it against the real hierarchy.
type deviceInstaller interface {
	installDevices(devices []specs.LinuxDeviceCgroup) error
}

type dirFSOps struct {
	dir string
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

// RollbackFailure describes one control file whose rollback did not succeed.
type RollbackFailure struct {
	// Filename is the cgroup control file that could not be restored.
	Filename string
	// Err is the rollback error.
	Err error
	// Remaining is the value currently readable from Filename. It is the
	// potentially unrestored, partially applied state. If the file cannot
	// be read, Remaining describes that read error.
	Remaining string
}

func (f RollbackFailure) Error() string {
	return fmt.Sprintf("rollback of %q failed: %v (still holds %q)", f.Filename, f.Err, f.Remaining)
}

func (f RollbackFailure) Unwrap() error {
	return f.Err
}

// RollbackError is returned when an update failed and rollback did not fully
// restore the previous state. Original is the error that caused the update to
// fail. Failures contains every unsuccessful restore, not only the first one.
type RollbackError struct {
	// Op identifies the phase that triggered rollback, e.g. "values" or
	// "devices".
	Op string
	// Original is the original update error.
	Original error
	// Failures lists all control files whose restoration failed.
	Failures []RollbackFailure
}

func (e *RollbackError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "cgroups: update of %q failed: %s; rollback incomplete:", e.Op, e.Original)
	for _, failure := range e.Failures {
		b.WriteString("\n\t- ")
		b.WriteString(failure.Error())
	}
	b.WriteString("\nresidual state may remain")
	return b.String()
}

// Unwrap exposes the original update error to errors.Is and errors.As.
func (e *RollbackError) Unwrap() error {
	return e.Original
}

// Is also matches errors carried by individual rollback failures, so callers
// can query any restore sentinel without walking Failures manually.
func (e *RollbackError) Is(target error) bool {
	if target == nil {
		return false
	}
	if errors.Is(e.Original, target) {
		return true
	}
	for _, f := range e.Failures {
		if errors.Is(f.Err, target) {
			return true
		}
	}
	return false
}

// appliedWrite stores the pre-update state needed to restore one file.
type appliedWrite struct {
	filename string
	original []byte
	existed  bool
}

// rollback restores writes in reverse order. It continues after restore
// failures and returns a *RollbackError containing all of them.
func rollback(ops fsOps, applied []appliedWrite, op string, originalErr error) error {
	var failures []RollbackFailure

	for i := len(applied) - 1; i >= 0; i-- {
		w := applied[i]

		var err error
		if w.existed {
			err = ops.WriteFile(w.filename, w.original, defaultFilePerm)
		} else {
			err = ops.Remove(w.filename)
			if os.IsNotExist(err) {
				err = nil
			}
		}
		if err == nil {
			continue
		}

		remaining, readErr := ops.ReadFile(w.filename)
		value := string(remaining)
		if readErr != nil {
			value = fmt.Sprintf("<unreadable: %v>", readErr)
		}
		failures = append(failures, RollbackFailure{
			Filename:  w.filename,
			Err:       err,
			Remaining: value,
		})
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

// snapshotValues reads every distinct affected file before any write occurs.
func snapshotValues(ops fsOps, values []Value) (map[string]appliedWrite, error) {
	snapshots := make(map[string]appliedWrite, len(values))
	for _, v := range values {
		if _, ok := snapshots[v.filename]; ok {
			continue
		}

		original, err := ops.ReadFile(v.filename)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to snapshot %q before update: %w", v.filename, err)
			}
			snapshots[v.filename] = appliedWrite{filename: v.filename}
			continue
		}

		snapshots[v.filename] = appliedWrite{
			filename: v.filename,
			original: original,
			existed:  true,
		}
	}
	return snapshots, nil
}

// transactionWriteValues validates encodings, snapshots affected files, and
// writes values in order. A failure rolls back all writes attempted so far,
// including the file on which the failure occurred because os.WriteFile may
// have truncated it before returning an error.
func transactionWriteValues(ops fsOps, values []Value) ([]appliedWrite, error) {
	// Encoding errors are deterministic and do not touch the filesystem.
	for _, v := range values {
		if _, err := v.bytes(); err != nil {
			return nil, err
		}
	}

	snapshots, err := snapshotValues(ops, values)
	if err != nil {
		return nil, err
	}

	var (
		applied []appliedWrite
		begun   = make(map[string]bool, len(snapshots))
	)

	for _, v := range values {
		snapshot := snapshots[v.filename]
		if !begun[v.filename] {
			applied = append(applied, snapshot)
			begun[v.filename] = true
		}

		data, err := v.bytes()
		if err != nil {
			originalErr := fmt.Errorf("failed to encode %q: %w", v.filename, err)
			if rbErr := rollback(ops, applied, "values", originalErr); rbErr != nil {
				return nil, rbErr
			}
			return nil, originalErr
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

// UpdateResources applies resources through ops with the same transactional
// semantics as Manager.Update. It is useful for tests and alternate backends.
func UpdateResources(ops FSOps, resources *Resources) error {
	if err := resources.Validate(); err != nil {
		return err
	}
	return updateResources(ops, resources)
}

// updateResources applies all control-file values and then the device filter.
// Device filters are additive and cannot be automatically reverted; a device
// failure rolls back file values and explicitly reports the residual filter.
func updateResources(ops fsOps, resources *Resources) error {
	if resources == nil {
		return nil
	}

	applied, err := transactionWriteValues(ops, resources.Values())
	if err != nil {
		return err
	}

	if len(resources.Devices) == 0 {
		return nil
	}

	installer, ok := ops.(deviceInstaller)
	if !ok {
		// A filesystem seam may not model eBPF attachment.
		return nil
	}

	if err := installer.installDevices(resources.Devices); err != nil {
		deviceErr := &RollbackError{
			Op:       "devices",
			Original: err,
			Failures: []RollbackFailure{{
				Filename:  "cgroup bpf device filter",
				Err:       errors.New("device filter cannot be rolled back automatically"),
				Remaining: "the newly attached eBPF device program may remain attached",
			}},
		}
		if rbErr := rollback(ops, applied, "devices", err); rbErr != nil {
			var incomplete *RollbackError
			if errors.As(rbErr, &incomplete) {
				deviceErr.Failures = append(deviceErr.Failures, incomplete.Failures...)
			}
		}
		return deviceErr
	}

	return nil
}
