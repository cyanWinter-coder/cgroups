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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type fakeMigrationGroup struct {
	mu sync.Mutex

	id        string
	pids      map[uint64]struct{}
	recursive map[uint64]struct{}
	addErr    func(pid uint64) error
	preflight error

	addCalls []uint64
	procs    func(recursive bool, current []uint64) []uint64
}

func newFakeGroup(id string, pids ...uint64) *fakeMigrationGroup {
	f := &fakeMigrationGroup{
		id:        id,
		pids:      make(map[uint64]struct{}),
		recursive: make(map[uint64]struct{}),
	}
	for _, pid := range pids {
		f.pids[pid] = struct{}{}
		f.recursive[pid] = struct{}{}
	}
	return f
}

func (f *fakeMigrationGroup) Path() string { return "/fake/" + f.id }

func (f *fakeMigrationGroup) MigrationKey() string { return f.id }

func (f *fakeMigrationGroup) AddProc(pid uint64) error {
	f.mu.Lock()
	f.addCalls = append(f.addCalls, pid)
	f.mu.Unlock()

	if f.addErr != nil {
		if err := f.addErr(pid); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pids[pid] = struct{}{}
	f.recursive[pid] = struct{}{}
	return nil
}

func (f *fakeMigrationGroup) Procs(recursive bool) ([]uint64, error) {
	f.mu.Lock()
	set := f.pids
	if recursive {
		set = f.recursive
	}
	out := make([]uint64, 0, len(set))
	for pid := range set {
		out = append(out, pid)
	}
	hook := f.procs
	f.mu.Unlock()

	out = sortedUniquePIDs(out)
	if hook != nil {
		out = hook(recursive, out)
	}
	return out, nil
}

func (f *fakeMigrationGroup) PreflightMigration() error {
	return f.preflight
}

func (f *fakeMigrationGroup) Calls() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.addCalls...)
}

func (f *fakeMigrationGroup) remove(pid uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.pids, pid)
	delete(f.recursive, pid)
}

func aliveMap(m map[uint64]bool) PIDExistenceChecker {
	return func(pid uint64) bool { return m[pid] }
}

func TestMigrateProcessesClassifiesSuccessSkippedAndFailed(t *testing.T) {
	source := newFakeGroup("source", 1, 2, 3)
	target := newFakeGroup("target", 9)

	target.addErr = func(pid uint64) error {
		switch pid {
		case 1:
			// cgroup attachment atomically removes the PID from source.
			source.remove(pid)
			return nil
		case 2:
			source.remove(pid)
			return fmt.Errorf("write cgroup.procs: %w", unix.ESRCH)
		case 3:
			return fmt.Errorf("write cgroup.procs: %w", os.ErrPermission)
		default:
			return nil
		}
	}

	result, err := Migrate(source, target,
		WithPIDExistenceChecker(aliveMap(map[uint64]bool{1: true, 2: false, 3: true})),
	)
	require.NoError(t, err)
	require.Equal(t, MigrationCounts{Total: 3, Succeeded: 1, Skipped: 1, Failed: 1}, result.Counts())
	require.Equal(t, []uint64{1}, result.Succeeded)
	require.Equal(t, []uint64{2}, result.Skipped)
	require.Equal(t, []uint64{3}, result.Failed)
	require.ErrorIs(t, result.Errors[3], os.ErrPermission)

	require.Len(t, result.Processes, 3)
	require.Equal(t, MigrationSuccess, result.Processes[0].Status)
	require.True(t, result.Processes[0].TargetAfter)
	require.False(t, result.Processes[0].SourceAfter)

	require.Equal(t, MigrationSkipped, result.Processes[1].Status)
	require.ErrorIs(t, result.Processes[1].Err, ErrProcessExited)
	require.ErrorIs(t, result.Processes[1].Err, unix.ESRCH)

	require.Equal(t, MigrationFailed, result.Processes[2].Status)
	require.True(t, result.Processes[2].SourceAfter)
	require.False(t, result.Processes[2].TargetAfter)
}

func TestMigrateProcessesContinuesAfterExitAndRecordsSnapshots(t *testing.T) {
	source := newFakeGroup("source", 10, 11)
	target := newFakeGroup("target", 20)
	target.addErr = func(pid uint64) error {
		if pid == 10 {
			source.remove(10)
			return unix.ESRCH
		}
		source.remove(11)
		return nil
	}

	result, err := Migrate(source, target, WithPIDExistenceChecker(func(uint64) bool { return false }))
	require.NoError(t, err)
	require.Equal(t, []uint64{10, 11}, result.SourceBefore)
	require.Equal(t, []uint64{20}, result.TargetBefore)
	require.Equal(t, []uint64{11}, result.Succeeded)
	require.Equal(t, []uint64{10}, result.Skipped)
	require.Empty(t, result.Failed)
}

func TestMigrateProcessesPreflightBeforeAnyAdd(t *testing.T) {
	source := newFakeGroup("source", 1, 2)
	target := newFakeGroup("target")
	target.preflight = ErrTargetFull

	result, err := Migrate(source, target)
	require.ErrorIs(t, err, ErrTargetFull)
	require.Nil(t, result)
	require.Empty(t, target.Calls())
}

func TestMigrateProcessesIdempotentForConcurrentSamePID(t *testing.T) {
	source := newFakeGroup("source", 4242)
	target := newFakeGroup("target")

	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	target.addErr = func(pid uint64) error {
		enterOnce.Do(func() { close(entered) })
		<-release
		target.mu.Lock()
		target.pids[pid] = struct{}{}
		target.recursive[pid] = struct{}{}
		target.mu.Unlock()
		source.remove(pid)
		return nil
	}

	type callResult struct {
		result *MigrationResult
		err    error
	}
	results := make(chan callResult, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := Migrate(source, target,
				WithMigrationPIDs(4242),
				WithPIDExistenceChecker(func(uint64) bool { return true }),
			)
			results <- callResult{r, err}
		}()
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first AddProc was not entered")
	}
	close(release)
	wg.Wait()
	close(results)

	for call := range results {
		require.NoError(t, call.err)
		require.Equal(t, []uint64{4242}, call.result.Succeeded)
	}
	require.Equal(t, []uint64{4242}, target.Calls(), "second concurrent call must observe the completed move")
}

func TestMigrateProcessesReportsExternalTargetArrivals(t *testing.T) {
	source := newFakeGroup("source", 1)
	target := newFakeGroup("target")
	target.addErr = func(pid uint64) error {
		source.remove(pid)
		return nil
	}

	// The final target snapshot includes both the migrated PID and a PID that
	// another operator attached after the initial target enumeration.
	target.procs = func(recursive bool, current []uint64) []uint64 {
		for _, p := range current {
			if p == 1 {
				return []uint64{1, 777}
			}
		}
		return current
	}

	result, err := Migrate(source, target)
	require.NoError(t, err)
	require.Equal(t, []uint64{1}, result.Succeeded)
	require.Equal(t, []uint64{1, 777}, result.TargetAfter)
	require.Equal(t, []uint64{1, 777}, result.TargetAppeared)
	require.Equal(t, []uint64{777}, result.TargetExternal)
}

type migrationPartialOps struct {
	mu     sync.Mutex
	files  map[string][]byte
	writes int
}

func (o *migrationPartialOps) ReadFile(name string) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	data, ok := o.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (o *migrationPartialOps) WriteFile(name string, data []byte, _ os.FileMode) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.writes++
	o.files[name] = append([]byte(nil), data...)
	return nil
}

func TestManagerPermissiveOpsSeam(t *testing.T) {
	ops := &migrationPartialOps{files: map[string][]byte{
		cgroupProcs: []byte("111\n222\n"),
	}}
	m := &Manager{path: "/unused-but-ops-seam", ops: ops}
	require.NotNil(t, m.fsOpsLocked())

	pids, err := m.Procs(false)
	require.NoError(t, err)
	require.Equal(t, []uint64{111, 222}, pids)

	require.NoError(t, m.AddProc(333))
	require.Equal(t, "333", string(ops.files[cgroupProcs]))
	require.Equal(t, 1, ops.writes)
}

func TestManagerPreflightDetectsFullAndUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not make files unwritable for root")
	}

	t.Run("full", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, cgroupProcs), nil, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "pids.max"), []byte("1\n"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "pids.current"), []byte("1\n"), 0o644))
		m := &Manager{path: dir}

		err := m.PreflightMigration()
		require.ErrorIs(t, err, ErrTargetFull)
		var full *TargetFullError
		require.ErrorAs(t, err, &full)
		require.Equal(t, uint64(1), full.Limit)
	})

	t.Run("unwritable", func(t *testing.T) {
		dir := t.TempDir()
		procs := filepath.Join(dir, cgroupProcs)
		require.NoError(t, os.WriteFile(procs, nil, 0o444))
		m := &Manager{path: dir}

		err := m.PreflightMigration()
		require.ErrorIs(t, err, ErrTargetNotWritable)
	})

	t.Run("writable without pids controller", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, cgroupProcs), nil, 0o644))
		m := &Manager{path: dir}
		require.NoError(t, m.PreflightMigration())
	})
}
