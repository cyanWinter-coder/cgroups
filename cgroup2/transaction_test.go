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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockCgroup builds a cgroup2-like hierarchy under a temp directory.
// Every mock cgroup directory gets a cgroup.controllers file listing the
// available controllers and an empty, writable cgroup.subtree_control file,
// mirroring the layout ToggleControllers and the controller pre-check rely on.
func newMockCgroup(t *testing.T, available string) string {
	t.Helper()
	root := t.TempDir()
	seedMockCgroup(t, root, available)
	// Writes in tests target files that may not exist yet (the real
	// cgroup filesystem creates control files implicitly for new groups).
	oldPerm := defaultFilePerm
	defaultFilePerm = 0o600
	t.Cleanup(func() { defaultFilePerm = oldPerm })

	// Mimic the kernel populating control files for each newly created
	// cgroup directory. In real cgroupfs the kernel provides these files;
	// a plain temp directory does not.
	oldHook := createHook
	createHook = func(dir string, controllers []string) {
		seedMockCgroup(t, dir, strings.Join(controllers, " "))
	}
	t.Cleanup(func() { createHook = oldHook })
	return root
}

// seedMockCgroup creates the cgroup control files inside an existing dir.
func seedMockCgroup(t *testing.T, dir, available string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, controllersFile), []byte(available), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, subtreeControl), []byte{}, 0o600))
}

func newMockCgroupDir(t *testing.T, root, rel, available string) string {
	t.Helper()
	dir := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(dir, defaultDirPerm))
	seedMockCgroup(t, dir, available)
	return dir
}

func pidsResources() *Resources {
	return &Resources{Pids: &Pids{Max: 100}}
}

func TestCreateGroupSuccess(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids io")

	m, err := CreateGroup(root, "/test-success", pidsResources())
	require.NoError(t, err)
	require.NotNil(t, m)

	// The cgroup directory exists with its control files populated.
	assert.DirExists(t, m.path)
	checkFileContent(t, m.path, "pids.max", "100")

	// The controller was enabled on the parent subtree control file.
	checkFileContent(t, root, subtreeControl, "+pids")

	// The handle supports resource writes, process attachment points and
	// idempotent deletion.
	require.NoError(t, m.Update(&Resources{Pids: &Pids{Max: 200}}))
	checkFileContent(t, m.path, "pids.max", "200")

	require.NoError(t, m.Delete())
	assert.NoDirExists(t, m.path)
	require.NoError(t, m.Delete(), "repeated Delete must stay idempotent")
}

func TestCreateGroupMissingControllers(t *testing.T) {
	root := newMockCgroup(t, "cpu memory")

	m, err := CreateGroup(root, "/test-missing", pidsResources())
	require.Error(t, err)
	require.Nil(t, m)
	assert.True(t, errors.Is(err, ErrControllersUnavailable))

	var cue *ControllersUnavailableError
	require.True(t, errors.As(err, &cue))
	assert.Equal(t, []string{"pids"}, cue.Missing)

	// Nothing was created before the failure.
	assert.NoDirExists(t, filepath.Join(root, "test-missing"))
}

func TestCreateGroupMultipleMissingControllers(t *testing.T) {
	root := newMockCgroup(t, "cpu")

	m, err := CreateGroup(root, "/test-missing-many", &Resources{Memory: &Memory{}, Pids: &Pids{Max: 1}})
	require.Error(t, err)
	require.Nil(t, m)
	assert.True(t, errors.Is(err, ErrControllersUnavailable))

	var cue *ControllersUnavailableError
	require.True(t, errors.As(err, &cue))
	assert.ElementsMatch(t, []string{"memory", "pids"}, cue.Missing)
	assert.NoDirExists(t, filepath.Join(root, "test-missing-many"))
}

func TestCreateGroupRollbackOnToggleFailure(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	// Removing subtree_control makes ToggleControllers fail after the
	// directory has been created, exercising the rollback path.
	require.NoError(t, os.Remove(filepath.Join(root, subtreeControl)))

	_, err := CreateGroup(root, "/test-rollback", pidsResources())
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(root, "test-rollback"),
		"failed creation must not leave an empty cgroup behind")
}
func TestCreateGroupRollbackOnResourceFailure(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")

	// A read-only parent lets Mkdir succeed for the leaf but makes the
	// subsequent resource file write fail (running as a non-root user).
	if os.Geteuid() == 0 {
		t.Skip("read-only directories do not block root writes")
	}
	parent := newMockCgroupDir(t, root, "readonly", "cpu memory pids")
	require.NoError(t, os.Chmod(parent, 0o500))
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	_, err := CreateGroup(root, "/readonly/leaf", pidsResources())
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(parent, "leaf"),
		"a failed resource write must roll back the freshly created cgroup")
}

func TestCreateGroupExistingRejectedByDefault(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	target := newMockCgroupDir(t, root, "test-exists", "cpu memory pids")

	_, err := CreateGroup(root, "/test-exists", pidsResources())
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrExist))
	assert.DirExists(t, target, "existing cgroup must not be removed")
}

func TestCreateGroupReuseCompatible(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	target := newMockCgroupDir(t, root, "test-reuse", "cpu memory pids")

	m, err := CreateGroup(root, "/test-reuse", pidsResources(), ReuseIfExists())
	require.NoError(t, err)
	assert.Equal(t, target, m.path)
	checkFileContent(t, target, "pids.max", "100")
	assert.DirExists(t, target)
}

func TestCreateGroupReuseConflict(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	target := newMockCgroupDir(t, root, "test-conflict", "cpu memory")

	m, err := CreateGroup(root, "/test-conflict", pidsResources(), ReuseIfExists())
	require.Error(t, err)
	require.Nil(t, m)
	assert.True(t, errors.Is(err, ErrControllerConflict))

	var cce *ControllerConflictError
	require.True(t, errors.As(err, &cce))
	assert.Equal(t, []string{"pids"}, cce.Missing)
	assert.Equal(t, target, cce.ExistingPath)

	// The conflicting cgroup is left untouched, with no resources applied.
	assert.DirExists(t, target)
	_, statErr := os.Stat(filepath.Join(target, "pids.max"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestCreateGroupRollbackNestedParents(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	require.NoError(t, os.Remove(filepath.Join(root, subtreeControl)))

	// Two intermediate directories do not exist yet and are created by
	// ensureParents; rollback must remove both, deepest first.
	_, err := CreateGroup(root, "/a/b/c", pidsResources())
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(root, "a"))
}

func TestCreateGroupRollbackKeepsPreexistingParents(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	parent := newMockCgroupDir(t, root, "keep", "cpu memory pids")
	require.NoError(t, os.Remove(filepath.Join(root, subtreeControl)))
	require.NoError(t, os.Remove(filepath.Join(parent, subtreeControl)))

	_, err := CreateGroup(root, "/keep/child", pidsResources())
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(parent, "child"))
	assert.DirExists(t, parent, "pre-existing parent must survive rollback")
}

func TestCreateGroupRejectsDotDot(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")

	_, err := CreateGroup(root, "/../escape", pidsResources())
	assert.ErrorIs(t, err, ErrInvalidGroupPath)

	_, err = CreateGroup(root, "/foo/../../escape", pidsResources())
	assert.ErrorIs(t, err, ErrInvalidGroupPath)
}

func TestCreateGroupRejectsSymlinkEscape(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	outside := t.TempDir()
	// A symlink inside the mountpoint pointing to a directory outside it.
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linkout")))

	_, err := CreateGroup(root, "/linkout/child", pidsResources())
	assert.ErrorIs(t, err, ErrPathEscapesMount)
}

func TestCreateGroupRejectsSymlinkTarget(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linktarget")))

	_, err := CreateGroup(root, "/linktarget", pidsResources())
	assert.ErrorIs(t, err, ErrPathEscapesMount)
}

func TestNewChildStrictAndLegacy(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	parent := newMockCgroupDir(t, root, "parent", "cpu memory pids")
	pm := &Manager{unifiedMountpoint: root, path: parent}

	child, err := pm.CreateChild("child", pidsResources())
	require.NoError(t, err)
	assert.DirExists(t, child.path)

	// Strict mode rejects a same-name child.
	_, err = pm.CreateChild("child", pidsResources())
	assert.ErrorIs(t, err, os.ErrExist)

	// ReuseIfExists accepts a compatible existing child.
	reused, err := pm.CreateChild("child", pidsResources(), ReuseIfExists())
	require.NoError(t, err)
	assert.Equal(t, child.path, reused.path)

	// Legacy NewChild keeps overwriting an existing child.
	legacy, err := pm.NewChild("child", pidsResources())
	require.NoError(t, err)
	assert.Equal(t, child.path, legacy.path)

	require.NoError(t, child.Delete())
}

func TestNewChildRejectsUnsafeName(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	parent := newMockCgroupDir(t, root, "parent", "cpu memory pids")
	pm := &Manager{unifiedMountpoint: root, path: parent}

	_, err := pm.CreateChild("../sibling", pidsResources())
	assert.ErrorIs(t, err, ErrPathEscapesMount)

	_, err = pm.CreateChild("/absolute", pidsResources())
	assert.Error(t, err)
}

func TestNewChildRollbackOnFailure(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	parent := newMockCgroupDir(t, root, "parent", "cpu memory pids")
	require.NoError(t, os.Remove(filepath.Join(parent, subtreeControl)))
	pm := &Manager{unifiedMountpoint: root, path: parent}

	_, err := pm.CreateChild("orphan", pidsResources())
	require.Error(t, err)
	assert.NoDirExists(t, filepath.Join(parent, "orphan"))
}

func TestNewManagerLegacyCompatibility(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")

	// First creation succeeds.
	m1, err := NewManager(root, "/legacy", pidsResources())
	require.NoError(t, err)

	// Re-creating the same group stays idempotent (legacy overwrite) rather
	// than failing.
	m2, err := NewManager(root, "/legacy", pidsResources())
	require.NoError(t, err)
	assert.Equal(t, m1.path, m2.path)

	// Nil resources remain a hard error.
	_, err = NewManager(root, "/legacy-nil", nil)
	assert.Error(t, err)

	require.NoError(t, m2.Delete())
}

func TestDeleteIdempotentOnNeverExistingGroup(t *testing.T) {
	root := newMockCgroup(t, "cpu memory pids")
	m := &Manager{unifiedMountpoint: root, path: filepath.Join(root, "gone")}
	require.NoError(t, m.Delete())
	require.NoError(t, m.Delete())
}
