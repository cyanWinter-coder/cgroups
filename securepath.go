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

import (
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinkHops bounds the number of symbolic links followed while resolving
// a single group path. A cycle (for example a link targeting itself) exhausts
// the budget instead of looping forever; the limit matches the one used by
// [filepath.EvalSymlinks].
const maxSymlinkHops = 255

// joinPath cleans and joins elem onto root without touching the filesystem.
// It returns [ErrPathEscape] when the cleaned result is not root itself or a
// descendant of root, so ".." traversal in untrusted input can never reach
// outside the hierarchy.
func joinPath(root string, elem ...string) string {
	return filepath.Clean(filepath.Join(append([]string{root}, elem...)...))
}

// isWithinRoot reports whether path equals root or is located below it. Both
// arguments must be cleaned absolute paths.
func isWithinRoot(root, path string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// SecureJoin resolves the logical, root-relative group against the hierarchy
// root on disk. It is the single chokepoint through which group names become
// real paths and enforces two boundaries:
//
//   - Lexical: the cleaned path must stay at or below root. Segments such as
//     "../" that would climb above the root are rejected with [ErrPathEscape].
//   - Symbolic: every existing component is Lstat-ed; a symlink is accepted
//     only when its resolved target stays within root. A link pointing
//     outside the hierarchy is rejected with [ErrSymlinkEscape].
//
// Components that do not exist yet (a cgroup directory the caller is about to
// create) are kept verbatim. The root itself is never required to be a
// symlink-free directory: callers pass the actual mount point.
func SecureJoin(root, group string) (string, error) {
	root = filepath.Clean(root)

	target := filepath.Clean(filepath.Join(root, group))
	if !isWithinRoot(root, target) {
		return "", ErrPathEscape
	}
	if target == root {
		return root, nil
	}

	// Walk the components that already exist. The first missing component
	// stops the check: remaining segments cannot contain a symlink on disk
	// yet, and the lexical boundary above still applies to the full target.
	//
	// Following a symlink rebuilds the work list from the link target, so
	// symlinks nested inside the target's own parent directories are
	// re-examined rather than trusted.
	current := root
	remaining := strings.Split(strings.TrimPrefix(target, root+string(filepath.Separator)), string(filepath.Separator))
	hops := 0
	for len(remaining) > 0 {
		comp := remaining[0]
		remaining = remaining[1:]
		next := filepath.Join(current, comp)
		info, err := os.Lstat(next)
		if os.IsNotExist(err) {
			// Retain the lexical result for everything below this point.
			return target, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		hops++
		if hops > maxSymlinkHops {
			return "", ErrSymlinkLoop
		}
		resolved, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(current, resolved)
		}
		resolved = filepath.Clean(resolved)
		if !isWithinRoot(root, resolved) {
			return "", ErrSymlinkEscape
		}
		// Re-walk the target from root, then continue with the components
		// that followed the link.
		current = root
		tail := remaining
		remaining = strings.Split(strings.TrimPrefix(resolved, root+string(filepath.Separator)), string(filepath.Separator))
		remaining = append(remaining, tail...)
	}
	return target, nil
}

// VerifyLogicalGroup validates a root-relative logical group path, mirroring
// the format of the third field of /proc/PID/cgroup: it must be absolute and
// clean and must not embed a host mount point prefix.
func VerifyLogicalGroup(group string) error {
	if group == "" || !filepath.IsAbs(group) {
		return ErrInvalidGroup
	}
	if filepath.Clean(group) != group {
		return ErrPathEscape
	}
	if strings.HasPrefix(group, "/sys/fs/cgroup") {
		return ErrMountPointPrefix
	}
	return nil
}
