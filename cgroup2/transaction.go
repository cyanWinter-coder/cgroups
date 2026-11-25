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

	"github.com/containerd/log"
)

// reuseMode controls what happens when the target cgroup already exists.
type reuseMode int

const (
	// reuseNone rejects an existing target with an error wrapping os.ErrExist.
	reuseNone reuseMode = iota
	// reuseCheck reuses an existing target only when it provides every
	// requested controller; otherwise a *ControllerConflictError is returned.
	reuseCheck
	// reuseLegacy preserves the historical NewManager/NewChild behavior of
	// reusing an existing target and overwriting its resource settings.
	reuseLegacy
)

// createHook is invoked immediately after a new cgroup directory is created.
// It exists solely so tests running on a plain temporary directory can mimic
// the kernel populating cgroup control files (notably cgroup.controllers) on
// directory creation; it is nil outside of tests.
var createHook func(dir string, controllers []string)

// CreateOpt configures the transactional cgroup creation functions.
type CreateOpt func(*createConfig)

type createConfig struct {
	reuseIfExists bool
}

// ReuseIfExists allows CreateGroup/CreateChild to reuse an existing cgroup
// instead of failing. Reuse is granted only when the existing cgroup provides
// every controller requested by the resources; a mismatch produces a
// *ControllerConflictError and the existing cgroup is left untouched.
func ReuseIfExists() CreateOpt {
	return func(c *createConfig) {
		c.reuseIfExists = true
	}
}

// CreateGroup creates a cgroup at the given group path under the cgroup v2
// mountpoint with transactional semantics:
//
//   - Before anything is created, the parent cgroup's cgroup.controllers file
//     is checked against the requested controllers. A missing controller
//     produces a *ControllersUnavailableError (matchable with
//     errors.Is(err, ErrControllersUnavailable)) listing every missing
//     controller, and no directory is created.
//   - If any step fails after directories have been created, all directories
//     created by this call are removed in reverse order; pre-existing
//     directories and other cgroups are never removed.
//   - An existing same-name cgroup is rejected with an error wrapping
//     os.ErrExist unless ReuseIfExists is set, in which case it is reused only
//     after a controller compatibility check.
//   - The group path is confined to the mountpoint: ".." traversal and symlink
//     components are rejected with ErrPathEscapesMount.
//
// On success the returned *Manager is a fully usable handle supporting resource
// writes, process attachment and Delete.
func CreateGroup(mountpoint, group string, resources *Resources, opts ...CreateOpt) (*Manager, error) {
	if resources == nil {
		return nil, errors.New("resources reference is nil")
	}
	if err := VerifyGroupPath(group); err != nil {
		return nil, err
	}
	cfg := createConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	path, err := secureResolve(mountpoint, filepath.Join(mountpoint, group))
	if err != nil {
		return nil, err
	}
	mode := reuseNone
	if cfg.reuseIfExists {
		mode = reuseCheck
	}
	return createCgroup(filepath.Clean(mountpoint), path, resources, mode)
}

// CreateChild is the transactional counterpart of NewChild: it creates a child
// cgroup under the manager's cgroup with the same guarantees as CreateGroup.
// The name must be relative and must not contain ".." traversal or symlink
// components.
func (c *Manager) CreateChild(name string, resources *Resources, opts ...CreateOpt) (*Manager, error) {
	if strings.HasPrefix(name, "/") {
		return nil, errors.New("name must be relative")
	}
	if name == "" {
		return nil, errors.New("name must not be empty")
	}
	cleanName := filepath.Clean(name)
	if cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("%w: %q", ErrPathEscapesMount, name)
	}
	cfg := createConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	path, err := secureResolve(c.unifiedMountpoint, filepath.Join(c.path, cleanName))
	if err != nil {
		return nil, err
	}
	mode := reuseNone
	if cfg.reuseIfExists {
		mode = reuseCheck
	}
	return createCgroup(c.unifiedMountpoint, path, resources, mode)
}

// createCgroup is the shared transactional creation routine used by the
// legacy NewManager/NewChild entry points and the strict CreateGroup/
// CreateChild entry points. The reuseMode only differs in how an existing
// target is treated; rollback, the controller pre-check and path confinement
// are identical for every caller.
func createCgroup(mountpoint, path string, resources *Resources, mode reuseMode) (_ *Manager, retErr error) {
	var want []string
	if resources != nil {
		want = resources.EnabledControllers()
	}
	parent := filepath.Dir(path)

	// Directories created by this call, in creation order. Rollback walks
	// the slice backwards so leaves are removed before their parents.
	var created []string
	defer func() {
		if retErr != nil {
			rollbackCreated(created)
		}
	}()

	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: symlink %q", ErrPathEscapesMount, path)
		}
		switch mode {
		case reuseNone:
			return nil, fmt.Errorf("cgroups: cgroup %q already exists: %w", path, os.ErrExist)
		case reuseCheck:
			if err := checkExistingCompatible(path, want); err != nil {
				return nil, err
			}
		case reuseLegacy:
			// Keep the historical overwrite behavior; nothing was created
			// by this call, so rollback stays a no-op on later failure.
		}
	case os.IsNotExist(err):
		// Fail fast on missing controllers before any directory is created,
		// so an unsatisfiable request never leaves an empty cgroup behind.
		if err := checkControllersAvailable(parent, want); err != nil {
			return nil, err
		}
		created, err = ensureParents(path)
		if err != nil {
			return nil, err
		}
		if err := os.Mkdir(path, defaultDirPerm); err != nil {
			return nil, err
		}
		created = append(created, path)
		if createHook != nil {
			createHook(path, want)
		}
	default:
		return nil, err
	}

	m := &Manager{
		unifiedMountpoint: mountpoint,
		path:              path,
	}
	if len(want) > 0 {
		if err := m.ToggleControllers(want, Enable); err != nil {
			return nil, err
		}
	}
	if err := setResources(path, resources); err != nil {
		return nil, err
	}
	return m, nil
}

// checkControllersAvailable verifies that every requested controller shows up
// in the parent cgroup's cgroup.controllers file.
func checkControllersAvailable(parentPath string, want []string) error {
	if len(want) == 0 {
		return nil
	}
	have, err := readControllers(parentPath)
	if err != nil {
		// Without a readable controllers file none of the requests can be
		// satisfied; report every requested controller as missing.
		return &ControllersUnavailableError{Missing: append([]string(nil), want...)}
	}
	if missing := subtractControllers(want, have); len(missing) > 0 {
		return &ControllersUnavailableError{Missing: missing}
	}
	return nil
}

// checkExistingCompatible verifies that an existing cgroup provides every
// controller requested for reuse.
func checkExistingCompatible(path string, want []string) error {
	if len(want) == 0 {
		return nil
	}
	have, err := readControllers(path)
	if err != nil {
		return &ControllerConflictError{ExistingPath: path, Missing: append([]string(nil), want...)}
	}
	if missing := subtractControllers(want, have); len(missing) > 0 {
		return &ControllerConflictError{ExistingPath: path, Missing: missing}
	}
	return nil
}

// readControllers parses a cgroup.controllers file.
func readControllers(dir string) (map[string]bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, controllersFile))
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool)
	for _, c := range strings.Fields(string(b)) {
		have[c] = true
	}
	return have, nil
}

// subtractControllers returns the controllers from want that are not present
// in have, preserving the request order.
func subtractControllers(want []string, have map[string]bool) []string {
	var missing []string
	for _, c := range want {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	return missing
}

// ensureParents creates any missing ancestor directories of path. The returned
// slice lists the created directories in root-to-leaf order so the caller can
// remove them in reverse on rollback. Pre-existing ancestors are never
// included.
func ensureParents(path string) ([]string, error) {
	var chain []string
	dir := filepath.Dir(path)
	for {
		fi, err := os.Lstat(dir)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%w: symlink %q", ErrPathEscapesMount, dir)
			}
			break
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		chain = append(chain, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, fmt.Errorf("cgroups: no existing ancestor for %q", path)
		}
		dir = parent
	}
	created := make([]string, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		if err := os.Mkdir(chain[i], defaultDirPerm); err != nil {
			return created, err
		}
		created = append(created, chain[i])
	}
	return created, nil
}

// rollbackCreated removes the directories created by a failed creation attempt
// in reverse order. Only real directories are removed, never symlinks, and
// removal failures are logged rather than masking the original error.
func rollbackCreated(created []string) {
	for i := len(created) - 1; i >= 0; i-- {
		fi, err := os.Lstat(created[i])
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			continue
		}
		if err := remove(created[i]); err != nil {
			log.L.WithError(err).Warnf("cgroups: failed to roll back partially created cgroup %q", created[i])
		}
	}
}

// secureResolve confines target to the cgroup mountpoint. It rejects paths that
// clean outside the mountpoint via ".." and paths whose existing components
// contain a symlink, which could otherwise redirect writes outside the
// mountpoint. The cleaned absolute target is returned on success.
func secureResolve(mountpoint, target string) (string, error) {
	base := filepath.Clean(mountpoint)
	clean := filepath.Clean(target)
	rel, err := filepath.Rel(base, clean)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrPathEscapesMount, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrPathEscapesMount, target)
	}
	if rel != "." {
		cur := base
		for _, part := range strings.Split(rel, string(os.PathSeparator)) {
			cur = filepath.Join(cur, part)
			fi, err := os.Lstat(cur)
			if err != nil {
				if os.IsNotExist(err) {
					// Remaining components do not exist either and will be
					// created as plain directories, so no symlink can hide
					// below this point.
					break
				}
				return "", err
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%w: symlink %q", ErrPathEscapesMount, cur)
			}
		}
	}
	return clean, nil
}
