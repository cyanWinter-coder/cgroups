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
	"sync"
	"testing"
)

type uid590FakeOps struct {
	dir string
	mu  sync.Mutex
}

func (f *uid590FakeOps) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.dir, name))
}
func (f *uid590FakeOps) WriteFile(name string, data []byte, perm os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return os.WriteFile(filepath.Join(f.dir, name), data, perm)
}
func (f *uid590FakeOps) Remove(name string) error {
	return os.Remove(filepath.Join(f.dir, name))
}

func TestUID590ValidationAndRead(t *testing.T) {
	weight := uint64(10001)
	err := (&Resources{CPU: &CPU{Weight: &weight}}).Validate()
	if err == nil {
		t.Fatal("expected weight validation error")
	}

	q := int64(100)
	p := uint64(100000)
	err = (&Resources{CPU: &CPU{Max: NewCPUMax(&q, &p)}}).Validate()
	if err == nil {
		t.Fatal("expected quota validation error")
	}

	badP := uint64(999)
	err = (&Resources{CPU: &CPU{Max: NewCPUMax(nil, &badP)}}).Validate()
	if err == nil {
		t.Fatal("expected period validation error")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{path: dir, ops: &uid590FakeOps{dir: dir}}
	limits, err := m.ReadLimits()
	if err != nil {
		t.Fatal(err)
	}
	if !limits.CPU.Quota.Unlimited || limits.CPU.Quota.Set {
		t.Fatalf("cpu quota not unlimited: %+v", limits.CPU.Quota)
	}
	if !limits.CPU.Period.Set || limits.CPU.Period.Value != 100000 {
		t.Fatalf("period wrong: %+v", limits.CPU.Period)
	}
	if !limits.Memory.Max.Unlimited {
		t.Fatalf("memory max not unlimited: %+v", limits.Memory.Max)
	}
	if !limits.Memory.High.Unset() {
		t.Fatalf("missing memory.high should be unset: %+v", limits.Memory.High)
	}
}

func TestUID590SeparateManagersSerialize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte("max"), 0o644); err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := &Manager{path: dir, ops: &uid590FakeOps{dir: dir}}
			errs <- m.Update(&Resources{Pids: &Pids{Max: int64(1000 + i)}})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "pids.max"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("final pids.max=%s", b)
}

func TestUID590ValidationBeforeWrites(t *testing.T) {
	dir := t.TempDir()
	ops := &uid590FakeOps{dir: dir}
	badWeight := uint64(0)
	m := &Manager{path: dir, ops: ops}
	err := m.Update(&Resources{CPU: &CPU{Weight: &badWeight}, Memory: &Memory{Max: uid590Int64Ptr(123)}})
	if err == nil {
		t.Fatal("expected invalid update error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "memory.max")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("memory.max should not be written, stat err=%v", statErr)
	}
}

func TestUID590StructuredCPUFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000"), 0o644); err != nil {
		t.Fatal(err)
	}
	quota := int64(50000)
	period := uint64(100000)
	m := &Manager{path: dir, ops: &uid590FakeOps{dir: dir}}
	if err := m.Update(&Resources{CPU: &CPU{Quota: &quota, Period: &period}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cpu.max"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "50000 100000" {
		t.Fatalf("unexpected cpu.max: %q", string(b))
	}
}

func uid590Int64Ptr(v int64) *int64 { return &v }
