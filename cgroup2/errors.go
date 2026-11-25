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
)

var (
	ErrInvalidFormat    = errors.New("cgroups: parsing file with invalid format failed")
	ErrInvalidGroupPath = errors.New("cgroups: invalid group path")

	// ErrControllersUnavailable is returned when one or more controllers
	// required by the requested resources are not available in the parent
	// cgroup. Match it with errors.Is and inspect the concrete
	// *ControllersUnavailableError via errors.As for the missing list.
	ErrControllersUnavailable = errors.New("cgroups: requested controllers are not available")

	// ErrControllerConflict is returned when a cgroup of the same name
	// already exists but cannot be reused with the requested resources.
	// Match it with errors.Is and inspect the concrete
	// *ControllerConflictError via errors.As for the conflicting list.
	ErrControllerConflict = errors.New("cgroups: existing cgroup does not provide the requested controllers")

	// ErrPathEscapesMount is returned when a group path resolves outside
	// the cgroup mountpoint, either through ".." elements or a symlink.
	ErrPathEscapesMount = errors.New("cgroups: group path escapes the cgroup mountpoint")
)

// ControllersUnavailableError wraps ErrControllersUnavailable and records
// which controllers were requested but are missing from the parent cgroup.
type ControllersUnavailableError struct {
	Missing []string
}

func (e *ControllersUnavailableError) Error() string {
	return ErrControllersUnavailable.Error() + ": " + joinNames(e.Missing)
}

func (e *ControllersUnavailableError) Unwrap() error {
	return ErrControllersUnavailable
}

// ControllerConflictError wraps ErrControllerConflict and records which
// requested controllers are not enabled on the existing cgroup.
type ControllerConflictError struct {
	ExistingPath string
	Missing      []string
}

func (e *ControllerConflictError) Error() string {
	return ErrControllerConflict.Error() + " for " + e.ExistingPath + ": " + joinNames(e.Missing)
}

func (e *ControllerConflictError) Unwrap() error {
	return ErrControllerConflict
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i != 0 {
			out += ", "
		}
		out += n
	}
	return out
}
