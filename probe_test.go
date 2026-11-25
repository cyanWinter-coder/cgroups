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
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeStatfs maps absolute paths to filesystem magic numbers.
type fakeStatfs struct {
	types map[string]int64
	calls int
}

func (f *fakeStatfs) statfs(path string) (int64, error) {
	f.calls++
	if t, ok := f.types[path]; ok {
		return t, nil
	}
	return 0, unix.ENOENT
}

func TestDetectModes(t *testing.T) {
	const root = "/fake/cgroup"
	cases := []struct {
		name       string
		types      map[string]int64
		wantMode   CGMode
		wantV1Root bool
		wantV2Root bool
	}{
		{
			name: "unified",
			types: map[string]int64{
				root: unix.CGROUP2_SUPER_MAGIC,
			},
			wantMode:   Unified,
			wantV2Root: true,
		},
		{
			name: "legacy",
			types: map[string]int64{
				root: unix.TMPFS_MAGIC,
			},
			wantMode:   Legacy,
			wantV1Root: true,
			wantV2Root: true, // V2Mountpoint always carries the probed location
		},
		{
			name: "hybrid",
			types: map[string]int64{
				root:              unix.TMPFS_MAGIC,
				root + "/unified": unix.CGROUP2_SUPER_MAGIC,
			},
			wantMode:   Hybrid,
			wantV1Root: true,
			wantV2Root: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeStatfs{types: tc.types}
			info, err := detect(fs.statfs, root)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			if info.Mode != tc.wantMode {
				t.Errorf("mode: got %v, want %v", info.Mode, tc.wantMode)
			}
			if tc.wantV1Root && info.V1Mountpoint != root {
				t.Errorf("v1 mountpoint: got %q, want %q", info.V1Mountpoint, root)
			}
			if !tc.wantV1Root && info.V1Mountpoint != "" {
				t.Errorf("v1 mountpoint: got %q, want empty", info.V1Mountpoint)
			}
			if tc.wantV2Root && info.V2Mountpoint != root {
				t.Errorf("v2 mountpoint: got %q, want %q", info.V2Mountpoint, root)
			}
		})
	}
}

func TestDetectStatfsError(t *testing.T) {
	fs := &fakeStatfs{types: map[string]int64{}}
	_, err := detect(fs.statfs, "/missing")
	if err == nil {
		t.Fatal("expected statfs error to propagate")
	}
	if !errors.Is(err, ErrModeNotDetected) {
		t.Fatalf("got %v, want ErrModeNotDetected", err)
	}
}

func TestProbeCache(t *testing.T) {
	resetProbeCache()
	root := t.TempDir()

	fs := &fakeStatfs{types: map[string]int64{
		root: unix.CGROUP2_SUPER_MAGIC,
	}}
	// Injected probes must not touch the shared cache.
	first, err := Probe(WithStatfs(fs.statfs), WithUnifiedMountpoint(root))
	if err != nil {
		t.Fatal(err)
	}
	if first.Mode != Unified {
		t.Fatalf("mode: got %v, want Unified", first.Mode)
	}
	if got := fs.calls; got != 1 {
		t.Fatalf("first probe expected 1 statfs call, got %d", got)
	}
	// A second injected probe re-runs detection; nothing was cached.
	if _, err := Probe(WithStatfs(fs.statfs), WithUnifiedMountpoint(root)); err != nil {
		t.Fatal(err)
	}
	if got := fs.calls; got != 2 {
		t.Fatalf("second injected probe expected 2 total calls, got %d", got)
	}

	// Shared cache stays empty after injected probes.
	probeMu.RLock()
	cached := cachedProbe
	probeMu.RUnlock()
	if cached != nil {
		t.Fatalf("injected probe polluted the shared cache: %+v", cached)
	}
}

func TestProbeForceRefresh(t *testing.T) {
	resetProbeCache()
	root := t.TempDir()
	fs := &fakeStatfs{types: map[string]int64{
		root: unix.CGROUP2_SUPER_MAGIC,
	}}

	if _, err := Probe(WithStatfs(fs.statfs), WithUnifiedMountpoint(root)); err != nil {
		t.Fatal(err)
	}
	callsBefore := fs.calls
	if _, err := Probe(
		WithStatfs(fs.statfs),
		WithUnifiedMountpoint(root),
		WithForceRefresh(),
	); err != nil {
		t.Fatal(err)
	}
	if fs.calls != callsBefore+1 {
		t.Fatalf("force refresh expected one new statfs call, got %d (was %d)", fs.calls, callsBefore)
	}
}

func TestProbeHostCacheIdempotent(t *testing.T) {
	resetProbeCache()
	// Exercise the cache path with a statfs injected through the default
	// location marker: emulate a host probe by seeding the cache directly,
	// then assert Probe returns it without invoking statfs again.
	seed := HierarchyInfo{Mode: Hybrid, V2Mountpoint: unifiedMountpoint, V1Mountpoint: unifiedMountpoint}
	probeMu.Lock()
	cachedProbe = &seed
	probeMu.Unlock()
	t.Cleanup(resetProbeCache)

	got, err := Probe() // default options must hit the cache
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != Hybrid {
		t.Fatalf("cached probe not reused: mode=%v", got.Mode)
	}

	// Even a forced default probe re-detects with the real statfs; the cache
	// is only bypassed on explicit request. Verify refresh semantics with an
	// injected, call-counting statfs instead of touching host mounts.
	calls := 0
	counting := func(string) (int64, error) {
		calls++
		return unix.CGROUP2_SUPER_MAGIC, nil
	}
	root := t.TempDir()
	if _, err := Probe(WithStatfs(counting), WithUnifiedMountpoint(root)); err != nil {
		t.Fatal(err)
	}
	if _, err := Probe(WithStatfs(counting), WithUnifiedMountpoint(root)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("injected probes must bypass the cache: got %d calls, want 2", calls)
	}
	if !errors.Is(ErrStalePath, ErrStalePath) {
		t.Fatal("sentinel mismatch")
	}
}
