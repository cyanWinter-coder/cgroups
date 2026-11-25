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
	"fmt"
	"path/filepath"
	"strings"
)

// NestedGroupPath will nest the cgroups based on the calling processes cgroup
// placing its child processes inside its own path
func NestedGroupPath(suffix string) (string, error) {
	path, err := parseCgroupFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	return joinNestedPath(path, suffix)
}

// PidGroupPath will return the correct cgroup paths for an existing process running inside a cgroup
// This is commonly used for the Load function to restore an existing container
func PidGroupPath(pid int) (string, error) {
	p := fmt.Sprintf("/proc/%d/cgroup", pid)
	return parseCgroupFile(p)
}

// joinNestedPath appends a nested suffix to a parsed cgroup path. Both
// inputs are validated so a malicious or corrupted suffix cannot escape the
// cgroup hierarchy (for example "../../etc" is rejected) instead of being
// silently normalized away by [filepath.Join].
func joinNestedPath(group, suffix string) (string, error) {
	if err := VerifyGroupPath(group); err != nil {
		return "", err
	}
	if suffix == "" {
		return group, nil
	}
	if filepath.IsAbs(suffix) {
		return "", fmt.Errorf("%w: nested suffix %q must be relative", ErrInvalidGroupPath, suffix)
	}
	// Validate the un-joined suffix: filepath.Join would clean "../" away
	// and hide the traversal, so inspect the raw segments first.
	for _, segment := range strings.Split(suffix, string(filepath.Separator)) {
		if segment == ".." || segment == "." {
			return "", ErrInvalidGroupPath
		}
	}
	joined := filepath.Join(group, suffix)
	if err := VerifyGroupPath(joined); err != nil {
		return "", err
	}
	return joined, nil
}

// VerifyGroupPath verifies the format of group path string g.
// The format is same as the third field in /proc/PID/cgroup.
// e.g. "/user.slice/user-1001.slice/session-1.scope"
//
// g must be a "clean" absolute path starts with "/", and must not contain "/sys/fs/cgroup" prefix.
//
// VerifyGroupPath doesn't verify whether g actually exists on the system.
func VerifyGroupPath(g string) error {
	if !strings.HasPrefix(g, "/") {
		return ErrInvalidGroupPath
	}
	if filepath.Clean(g) != g {
		return ErrInvalidGroupPath
	}
	if strings.HasPrefix(g, "/sys/fs/cgroup") {
		return ErrInvalidGroupPath
	}
	return nil
}
