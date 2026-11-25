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

package cgroups

import "errors"

var (
	// ErrModeNotDetected is returned when the host cgroup mode cannot be
	// determined because the expected mount point cannot be inspected.
	ErrModeNotDetected = errors.New("cgroups: cgroup mode not detected")

	// ErrPathEscape is returned when a logical group path, after cleaning,
	// would resolve outside its hierarchy root, for example because it
	// contains ".." segments that traverse above the root.
	ErrPathEscape = errors.New("cgroups: path escapes the cgroup hierarchy root")

	// ErrSymlinkEscape is returned when a path component is a symbolic link
	// whose target resolves outside the hierarchy root.
	ErrSymlinkEscape = errors.New("cgroups: symbolic link escapes the cgroup hierarchy root")

	// ErrSymlinkLoop is returned when symbolic link resolution exceeds the
	// hop budget, which indicates a link cycle rather than a valid path.
	ErrSymlinkLoop = errors.New("cgroups: too many symbolic links while resolving cgroup path")

	// ErrInvalidGroup is returned when a logical group name is not a clean
	// absolute cgroup-relative path.
	ErrInvalidGroup = errors.New("cgroups: invalid logical group path")

	// ErrMountPointPrefix is returned when a logical group name embeds the
	// host mount point (for example "/sys/fs/cgroup/foo") instead of being
	// relative to the hierarchy root.
	ErrMountPointPrefix = errors.New("cgroups: group path must not include the cgroup mount point")

	// ErrStalePath is returned when a previously resolved path belongs to a
	// hierarchy that is no longer in use because the host switched between
	// cgroup v1 and v2. Callers should inspect the returned [StalePathError]
	// for the path valid on the new hierarchy.
	ErrStalePath = errors.New("cgroups: path is stale after cgroup hierarchy switch")

	// ErrControllerMountNotFound is returned when a v1 controller has no
	// mount entry in /proc/self/mountinfo and no fallback mount point is
	// known.
	ErrControllerMountNotFound = errors.New("cgroups: controller mount point not found")
)

// StalePathError reports that oldPath was resolved against a hierarchy that
// has since been replaced. NewPath is the equivalent path on the hierarchy
// currently in use; it is empty when no equivalent can be derived.
type StalePathError struct {
	// OldMode is the hierarchy mode the stale path was resolved for.
	OldMode CGMode
	// CurrentMode is the hierarchy mode detected after the switch.
	CurrentMode CGMode
	// OldPath is the path that is no longer valid.
	OldPath string
	// NewPath is the usable path on the current hierarchy, when known.
	NewPath string
}

func (e *StalePathError) Error() string {
	if e.NewPath == "" {
		return "cgroups: path " + e.OldPath + " resolved for " +
			modeName(e.OldMode) + " is stale; host now runs " + modeName(e.CurrentMode)
	}
	return "cgroups: path " + e.OldPath + " resolved for " +
		modeName(e.OldMode) + " is stale; use " + e.NewPath + " on " + modeName(e.CurrentMode)
}

// Is makes [errors.Is](err, [ErrStalePath]) succeed for every
// [StalePathError].
func (e *StalePathError) Is(target error) bool {
	return target == ErrStalePath
}

func modeName(m CGMode) string {
	switch m {
	case Legacy:
		return "cgroup v1 (legacy)"
	case Hybrid:
		return "cgroup hybrid (v1 and v2)"
	case Unified:
		return "cgroup v2 (unified)"
	default:
		return "an unavailable cgroup hierarchy"
	}
}
