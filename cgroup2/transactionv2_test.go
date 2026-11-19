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
	"sync/atomic"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFSOps is an fsOps implementation backed by a real temporary directory
// so that rollback results can be verified by reading files back, with hooks
// to force failures at specific call numbers.
type fakeFSOps struct {
	dir string

	// writeFaults maps a 1-based WriteFile call number to the error it must
	// return (only the first matching call fails).
	writeFaults map[int]error
	// removeFaults maps a 1-based Remove call number to the error it must
	// return (only the first matching call fails).
	removeFaults map[int]error

	writes  atomic.Int64
	removes atomic.Int64

	// begin/end bracket every underlying operation; inflight is asserted to
	// never exceed 1, proving the manager serializes callers.
	begin func()
	end   func()

	// deviceErr, when non-nil, is returned by installDevices to simulate a
	// failure of the non-revertible eBPF device filter step.
	deviceErr error
}

func newFakeFSOps(t *testing.T) *fakeFSOps {
	t.Helper()
	return &fakeFSOps{
		dir:          t.TempDir(),
		writeFaults:  make(map[int]error),
		removeFaults: make(map[int]error),
	}
}

func (f *fakeFSOps) ReadFile(name string) ([]byte, error) {
	if f.begin != nil {
		f.begin()
		defer f.end()
	}
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	return b, err
}

func (f *fakeFSOps) WriteFile(name string, data []byte, perm os.FileMode) error {
	if f.begin != nil {
		f.begin()
		defer f.end()
	}
	n := int(f.writes.Add(1))
	if err, ok := f.writeFaults[n]; ok {
		delete(f.writeFaults, n)
		return err
	}
	return os.WriteFile(filepath.Join(f.dir, name), data, perm)
}

func (f *fakeFSOps) Remove(name string) error {
	if f.begin != nil {
		f.begin()
		defer f.end()
	}
	n := int(f.removes.Add(1))
	if err, ok := f.removeFaults[n]; ok {
		delete(f.removeFaults, n)
		return err
	}
	// Return the raw error (including ENOENT); the production rollback code
	// is responsible for treating a missing file as already removed.
	return os.Remove(filepath.Join(f.dir, name))
}

func (f *fakeFSOps) read(t *testing.T, name string) string {
	t.Helper()
	out, err := os.ReadFile(filepath.Join(f.dir, name))
	require.NoError(t, err)
	return string(out)
}

func (f *fakeFSOps) writeSeed(t *testing.T, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o644))
}

func (f *fakeFSOps) exists(name string) bool {
	_, err := os.Stat(filepath.Join(f.dir, name))
	return err == nil
}

// installDevices implements deviceInstaller so the device step can be driven
// and forced to fail in tests without a real cgroup hierarchy.
func (f *fakeFSOps) installDevices(devices []specs.LinuxDeviceCgroup) error {
	if f.begin != nil {
		f.begin()
		defer f.end()
	}
	return f.deviceErr
}

// newFakeManager returns a Manager whose operations target a plain directory
// through fakeFSOps, so the transactional paths are testable without a real
// cgroup hierarchy.
func newFakeManager(t *testing.T, ops *fakeFSOps) *Manager {
	t.Helper()
	return &Manager{
		unifiedMountpoint: ops.dir,
		path:              ops.dir,
		ops:               ops,
	}
}

// threeControllerResources exercises values across three controllers and
// three distinct files.
func threeControllerResources() *Resources {
	return &Resources{
		CPU: &CPU{
			Weight: toPtr(uint64(100)),
		},
		Memory: &Memory{
			Max: toPtr(int64(1024 * 1024 * 64)),
		},
		Pids: &Pids{
			Max: 1000,
		},
	}
}

// TestTransactionRollsBackOnMidFailure verifies that when a later subsystem
// write fails, the earlier successful writes are restored to their original
// values in reverse order and the original error is returned.
func TestTransactionRollsBackOnMidFailure(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	ops.writeSeed(t, "memory.max", "max")
	ops.writeSeed(t, "pids.max", "max")

	sentinel := errors.New("injected write failure")
	// cpu.weight then memory.max succeed; the third write (pids.max) fails.
	ops.writeFaults[3] = sentinel

	m := newFakeManager(t, ops)
	err := m.Update(threeControllerResources())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel, "original error must be reachable via errors.Is")

	var rbe *RollbackError
	assert.False(t, errors.As(err, &rbe), "a successful rollback must not be reported as RollbackError")

	// All earlier writes must be rolled back to their pre-update values.
	assert.Equal(t, "100", strings.TrimSpace(ops.read(t, "cpu.weight")))
	assert.Equal(t, "max", strings.TrimSpace(ops.read(t, "memory.max")))
	assert.Equal(t, "max", strings.TrimSpace(ops.read(t, "pids.max")))
}

// TestTransactionRollbackFailureReported verifies that a rollback failure is
// returned together with the original error and names the file whose value may
// still be applied.
func TestTransactionRollbackFailureReported(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	ops.writeSeed(t, "memory.max", "max")
	ops.writeSeed(t, "pids.max", "max")

	sentinel := errors.New("injected write failure")
	rollbackErr := errors.New("injected rollback failure")
	// Forward writes: cpu.weight (1), memory.max (2), pids.max fails (3).
	ops.writeFaults[3] = sentinel
	// Reverse rollback writes: pids.max is restored first (write 4), then
	// memory.max (5) fails; cpu.weight still gets restored (6).
	ops.writeFaults[5] = rollbackErr

	m := newFakeManager(t, ops)
	err := m.Update(threeControllerResources())
	require.Error(t, err)

	var rbe *RollbackError
	require.True(t, errors.As(err, &rbe), "rollback failure must be reported as *RollbackError")
	assert.ErrorIs(t, rbe, sentinel, "RollbackError must wrap the original update error")
	assert.Equal(t, "values", rbe.Op)
	require.Len(t, rbe.Failures, 1)
	assert.Equal(t, "memory.max", rbe.Failures[0].Filename)
	assert.ErrorIs(t, rbe.Failures[0], rollbackErr)
	assert.Contains(t, rbe.Error(), "residual state may remain")

	// The failed rollback leaves the new value behind, while the others were
	// restored.
	assert.Equal(t, "67108864", strings.TrimSpace(ops.read(t, "memory.max")),
		"residual value must be reported and left in place")
	assert.Equal(t, "100", strings.TrimSpace(ops.read(t, "cpu.weight")))
	assert.Equal(t, "max", strings.TrimSpace(ops.read(t, "pids.max")))
	assert.Contains(t, rbe.Failures[0].Remaining, "67108864")
}

// TestTransactionRollsBackFilesCreatedByUpdate verifies that control files
// which did not exist before the update are removed on rollback.
func TestTransactionRollsBackFilesCreatedByUpdate(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	require.False(t, ops.exists("memory.max"))
	require.False(t, ops.exists("pids.max"))

	sentinel := errors.New("injected write failure")
	// cpu.weight (1), memory.max (2) succeed; pids.max (3) fails.
	ops.writeFaults[3] = sentinel

	m := newFakeManager(t, ops)
	err := m.Update(threeControllerResources())
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)

	assert.Equal(t, "100", strings.TrimSpace(ops.read(t, "cpu.weight")))
	assert.False(t, ops.exists("memory.max"), "file created by the update must be removed on rollback")
	assert.False(t, ops.exists("pids.max"))
}

// TestTransactionRollbackRemoveFailureReported verifies that failing to remove
// a file created by the update during rollback is surfaced with the residual
// state.
func TestTransactionRollbackRemoveFailureReported(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	require.False(t, ops.exists("memory.max"))

	sentinel := errors.New("injected write failure")
	removeErr := errors.New("injected remove failure")
	// Forward: cpu.weight write (1), memory.max write (2), pids.max write
	// fails (3). pids.max therefore never exists on disk.
	ops.writeFaults[3] = sentinel
	// Reverse rollback: the first Remove is pids.max (no-op, the file was
	// never created), the second Remove is memory.max and it fails; cpu.weight
	// is then restored by the next write.
	ops.removeFaults[2] = removeErr

	m := newFakeManager(t, ops)
	err := m.Update(threeControllerResources())
	var rbe *RollbackError
	require.True(t, errors.As(err, &rbe))
	assert.ErrorIs(t, rbe, sentinel)
	require.Len(t, rbe.Failures, 1)
	assert.Equal(t, "memory.max", rbe.Failures[0].Filename)
	assert.ErrorIs(t, rbe.Failures[0], removeErr)
	assert.True(t, ops.exists("memory.max"), "the file whose removal failed must still be present")
	assert.Equal(t, "100", strings.TrimSpace(ops.read(t, "cpu.weight")))
}

// TestTransactionSnapshotFailureRollsBack verifies that a failure while
// snapshotting an existing file still rolls back everything applied so far.
func TestTransactionSnapshotFailureRollsBack(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	ops.writeSeed(t, "memory.max", "max")
	// Make pids.max unreadable so its snapshot fails: drop read permission.
	require.NoError(t, os.WriteFile(filepath.Join(ops.dir, "pids.max"), []byte("max"), 0o000))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(ops.dir, "pids.max"), 0o644) })
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions; snapshot failure cannot be simulated this way")
	}

	m := newFakeManager(t, ops)
	err := m.Update(threeControllerResources())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to snapshot")

	assert.Equal(t, "100", strings.TrimSpace(ops.read(t, "cpu.weight")))
	assert.Equal(t, "max", strings.TrimSpace(ops.read(t, "memory.max")))
}

// TestTransactionNoopAndSingleResourcePreserveBehavior verifies the unchanged
// behavior for the no-op path and the single-resource success path.
func TestTransactionNoopAndSingleResourcePreserveBehavior(t *testing.T) {
	t.Run("nil resources is a no-op", func(t *testing.T) {
		ops := newFakeFSOps(t)
		m := newFakeManager(t, ops)
		require.NoError(t, m.Update(nil))
		assert.Equal(t, int64(0), ops.writes.Load(), "no writes must happen for nil resources")
	})

	t.Run("empty resources is a no-op", func(t *testing.T) {
		ops := newFakeFSOps(t)
		m := newFakeManager(t, ops)
		require.NoError(t, m.Update(&Resources{}))
		assert.Equal(t, int64(0), ops.writes.Load())
	})

	t.Run("single resource success", func(t *testing.T) {
		ops := newFakeFSOps(t)
		ops.writeSeed(t, "pids.max", "max")
		m := newFakeManager(t, ops)
		require.NoError(t, m.Update(&Resources{Pids: &Pids{Max: 42}}))
		assert.Equal(t, "42", strings.TrimSpace(ops.read(t, "pids.max")))
	})

	t.Run("multiple values of one controller", func(t *testing.T) {
		ops := newFakeFSOps(t)
		ops.writeSeed(t, "memory.max", "max")
		ops.writeSeed(t, "memory.high", "max")
		m := newFakeManager(t, ops)
		require.NoError(t, m.Update(&Resources{
			Memory: &Memory{
				Max:  toPtr(int64(1000)),
				High: toPtr(int64(900)),
			},
		}))
		assert.Equal(t, "1000", strings.TrimSpace(ops.read(t, "memory.max")))
		assert.Equal(t, "900", strings.TrimSpace(ops.read(t, "memory.high")))
	})
}

// TestConcurrentUpdatesAreSerialized fires many Update calls at one manager
// and asserts that no two underlying file operations overlap.
func TestConcurrentUpdatesAreSerialized(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	ops.writeSeed(t, "memory.max", "max")
	ops.writeSeed(t, "pids.max", "max")

	var inflight atomic.Int32
	var overlap atomic.Bool
	ops.begin = func() {
		if inflight.Add(1) > 1 {
			overlap.Store(true)
		}
	}
	ops.end = func() {
		inflight.Add(-1)
	}

	m := newFakeManager(t, ops)
	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- m.Update(&Resources{
				CPU:    &CPU{Weight: toPtr(uint64(50 + i%5))},
				Memory: &Memory{Max: toPtr(int64(1024 * 1024 * (64 + i)))},
				Pids:   &Pids{Max: int64(100 + i)},
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.False(t, overlap.Load(), "concurrent Updates must never touch the filesystem simultaneously")
	assert.Equal(t, int32(0), inflight.Load())
}

// TestUpdateAndDeleteAreSerialized verifies that Delete cannot remove the
// cgroup directory while an Update is in flight.
func TestUpdateAndDeleteAreSerialized(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	ops.writeSeed(t, "memory.max", "max")
	ops.writeSeed(t, "pids.max", "max")

	var inflight atomic.Int32
	var overlap atomic.Bool
	ops.begin = func() {
		if inflight.Add(1) > 1 {
			overlap.Store(true)
		}
	}
	ops.end = func() {
		inflight.Add(-1)
	}

	m := newFakeManager(t, ops)

	// Hold the manager lock indirectly by starting an Update whose first
	// filesystem operation blocks, then assert Delete waits for it.
	started := make(chan struct{})
	release := make(chan struct{})
	ops.begin = func() {
		if inflight.Add(1) > 1 {
			overlap.Store(true)
		}
		closeOnce(started)
		<-release
	}
	ops.end = func() {
		inflight.Add(-1)
	}

	updateDone := make(chan error, 1)
	go func() {
		updateDone <- m.Update(&Resources{Pids: &Pids{Max: 7}})
	}()
	<-started

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- m.Delete()
	}()

	// Delete must be blocked on the manager lock while the update is held.
	// Give it a chance to (incorrectly) run past the lock.
	select {
	case err := <-deleteDone:
		t.Fatalf("Delete ran concurrently with Update: %v", err)
	default:
	}

	close(release)
	require.NoError(t, <-updateDone)
	require.NoError(t, <-deleteDone)
	assert.False(t, overlap.Load())
}

// closeOnce closes ch at most once.
func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

// TestTransactionDeviceFailureRollsBackValues verifies that when the
// non-revertible device filter step fails, all previously written control
// files are rolled back and the residual device state is explicitly reported.
func TestTransactionDeviceFailureRollsBackValues(t *testing.T) {
	ops := newFakeFSOps(t)
	ops.writeSeed(t, "cpu.weight", "100")
	ops.writeSeed(t, "memory.max", "max")
	ops.writeSeed(t, "pids.max", "max")

	deviceErr := errors.New("injected device filter failure")
	ops.deviceErr = deviceErr

	resources := threeControllerResources()
	resources.Devices = []specs.LinuxDeviceCgroup{
		{Allow: false, Type: "a", Access: "rwm"},
	}

	m := newFakeManager(t, ops)
	err := m.Update(resources)
	require.Error(t, err)

	var rbe *RollbackError
	require.True(t, errors.As(err, &rbe))
	assert.ErrorIs(t, rbe, deviceErr)
	assert.Equal(t, "devices", rbe.Op)

	// Control files must have been rolled back even though the device step
	// cannot be undone.
	assert.Equal(t, "100", strings.TrimSpace(ops.read(t, "cpu.weight")))
	assert.Equal(t, "max", strings.TrimSpace(ops.read(t, "memory.max")))
	assert.Equal(t, "max", strings.TrimSpace(ops.read(t, "pids.max")))

	// The residual, non-revertible device state must be named explicitly.
	filenames := make([]string, 0, len(rbe.Failures))
	for _, f := range rbe.Failures {
		filenames = append(filenames, f.Filename)
	}
	assert.Contains(t, filenames, "cgroup bpf device filter")
	assert.Contains(t, rbe.Error(), "residual state may remain")
}

// TestTransactionOnRealCgroup is an end-to-end check against an actual cgroup
// v2 hierarchy; it is skipped when the environment cannot create cgroups.
func TestTransactionOnRealCgroup(t *testing.T) {
	checkCgroupMode(t)

	group := fmt.Sprintf("/transaction-test-%d", os.Getpid())
	m, err := NewManager(defaultCgroup2Path, group, &Resources{})
	if err != nil {
		t.Skipf("cannot create cgroup (need privileges): %v", err)
	}
	t.Cleanup(func() { _ = m.Delete() })

	// A valid cpu.weight write followed by an invalid memory.max write
	// (memory.max must be a multiple of the page size or "max").
	bad := int64(1)
	err = m.Update(&Resources{
		CPU:    &CPU{Weight: toPtr(uint64(50))},
		Memory: &Memory{Max: &bad},
	})
	require.Error(t, err)

	out, readErr := os.ReadFile(filepath.Join(m.path, "cpu.weight"))
	require.NoError(t, readErr)
	// cpu.weight defaults to 100; the failed update must have rolled back.
	assert.Equal(t, "100", strings.TrimSpace(string(out)))
}
