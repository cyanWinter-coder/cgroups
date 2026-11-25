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

package capabilities

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// CheckPathWritable verifies that path exists and is writable by the current
// process without writing to it.
func CheckPathWritable(path string) error {
	return CheckFileWritable(path, "")
}

// CheckFileWritable is CheckPathWritable with controller context used in the
// returned error.
func CheckFileWritable(path, controller string) error {
	info, err := os.Stat(path)
	if err != nil {
		reason := ReasonCapabilityCheckFailed
		if errors.Is(err, fs.ErrNotExist) {
			reason = ReasonFileMissing
		}
		return &UnwritableError{
			Controller: controller,
			File:       path,
			Path:       path,
			Reason:     reason,
			Err:        errors.Join(ErrFileNotWritable, err),
		}
	}
	if info.IsDir() {
		// Directory writability matters for creating child cgroups, but this
		// helper is used for control files. access(2) remains side-effect free.
		if err := unix.Access(path, unix.W_OK); err != nil {
			return unwritableAccessError(path, controller, path, err)
		}
		return nil
	}
	if err := unix.Access(path, unix.W_OK); err != nil {
		return unwritableAccessError(path, controller, path, err)
	}
	return nil
}

// CheckBeforeWrite performs the pre-write capability check used by the
// resource writers. Existing files must be writable. A missing file on a
// real cgroup filesystem is rejected because control files cannot be created
// by users. On other filesystems (notably unit-test temp directories), a
// missing file is allowed when its parent directory is writable, preserving
// the historical O_CREATE-based mock behavior of the writers.
func CheckBeforeWrite(path, controller string) error {
	_, statErr := os.Stat(path)
	if statErr == nil {
		// CheckFileWritable also handles directories via access(2).
		return CheckFileWritable(path, controller)
	}
	if !errors.Is(statErr, fs.ErrNotExist) {
		return &UnwritableError{Controller: controller, File: path, Path: path, Reason: ReasonCapabilityCheckFailed, Err: statErr}
	}

	parent := filepath.Dir(path)
	var st unix.Statfs_t
	if fsErr := unix.Statfs(parent, &st); fsErr == nil {
		if st.Type == unix.CGROUP2_SUPER_MAGIC || st.Type == unix.CGROUP_SUPER_MAGIC {
			return &UnwritableError{
				Controller: controller, File: filepath.Base(path), Path: path,
				Reason: ReasonFileMissing, Err: errors.Join(ErrFileNotWritable, statErr),
			}
		}
	}
	if accessErr := unix.Access(parent, unix.W_OK); accessErr != nil {
		reason := ReasonPathMissing
		if errors.Is(accessErr, fs.ErrPermission) || errors.Is(accessErr, unix.EACCES) || errors.Is(accessErr, unix.EPERM) {
			reason = ReasonAccessDenied
		}
		return &UnwritableError{
			Controller: controller, File: filepath.Base(path), Path: path,
			Reason: reason, Err: errors.Join(ErrFileNotWritable, statErr, accessErr),
		}
	}
	return nil
}

func unwritableAccessError(file, controller, path string, err error) error {
	reason := ReasonFileNotWritable
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		reason = ReasonAccessDenied
	}
	return &UnwritableError{
		Controller: controller,
		File:       file,
		Path:       path,
		Reason:     reason,
		Err:        errors.Join(ErrFileNotWritable, err),
	}
}
