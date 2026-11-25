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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeHost bundles a synthetic /proc tree with the matching statfs view of
// the cgroup mount points. Everything lives under t.TempDir() so tests never
// touch the real host hierarchies.
type fakeHost struct {
	root     string // hierarchy root (stand-in for /sys/fs/cgroup)
	procRoot string
	statfs   fakeStatfs
}

func newFakeHost(t *testing.T, mode CGMode) *fakeHost {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "sys", "fs", "cgroup")
	procRoot := filepath.Join(base, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	types := map[string]int64{}
	switch mode {
	case Unified:
		types[root] = unix.CGROUP2_SUPER_MAGIC
	case Legacy:
		types[root] = unix.TMPFS_MAGIC
	case Hybrid:
		types[root] = unix.TMPFS_MAGIC
		types[filepath.Join(root, "unified")] = unix.CGROUP2_SUPER_MAGIC
	default:
		t.Fatalf("unsupported mode %v", mode)
	}

	return &fakeHost{
		root:     root,
		procRoot: procRoot,
		statfs:   fakeStatfs{types: types},
	}
}

func (h *fakeHost) newResolver(t *testing.T) *Resolver {
	t.Helper()
	r, err := NewResolver(
		WithResolverStatfs(h.statfs.statfs),
		WithResolverMountpoint(h.root),
		WithProcRoot(h.procRoot),
	)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// writeProcCgroup creates <procRoot>/<pid>/cgroup with the given raw content.
func (h *fakeHost) writeProcCgroup(t *testing.T, pid, content string) {
	t.Helper()
	dir := filepath.Join(h.procRoot, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeMountInfo creates <procRoot>/self/mountinfo mapping each v1
// controller to "<root>/<controller>".
func (h *fakeHost) writeMountInfo(t *testing.T, controllers ...string) {
	t.Helper()
	selfDir := filepath.Join(h.procRoot, "self")
	if err := os.MkdirAll(selfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range controllers {
		// Named hierarchies are mounted at "<root>/<hierarchy>" but appear
		// as "name=<hierarchy>" in /proc/PID/cgroup and under their bare
		// hierarchy name in the mountinfo super options.
		hierarchyName := strings.TrimPrefix(c, "name=")
		mountPoint := filepath.Join(h.root, hierarchyName)
		// Fields: mount id, parent id, major:minor, root, mount point,
		// options, optional fields terminated by " - ", fs type, source,
		// super options.
		b.WriteString("36 25 0:35 / ")
		b.WriteString(mountPoint)
		b.WriteString(" rw - cgroup cgroup rw,")
		b.WriteString(hierarchyName)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(selfDir, "mountinfo"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	legacyCgroupFile = `8:net_cls:/
7:memory:/system.slice/scheduler.service
6:freezer:/
4:devices:/system.slice/scheduler.service
2:cpu,cpuacct:/system.slice/scheduler.service
1:name=systemd:/system.slice/scheduler.service
0::/
`
	unifiedCgroupFile = `0::/system.slice/scheduler.service
`
	hybridCgroupFile = `7:memory:/system.slice/scheduler.service
4:devices:/system.slice/scheduler.service
1:name=systemd:/system.slice/scheduler.service
0::/system.slice/scheduler.service
`
)

func TestResolverDetectMode(t *testing.T) {
	for _, mode := range []CGMode{Unified, Legacy, Hybrid} {
		host := newFakeHost(t, mode)
		r := host.newResolver(t)
		if got := r.Mode(); got != mode {
			t.Errorf("mode: got %v, want %v", got, mode)
		}
		if got := r.Info().V2Mountpoint; got != host.root {
			t.Errorf("v2 mountpoint: got %q, want %q", got, host.root)
		}
		if mode != Unified && r.Info().V1Mountpoint != host.root {
			t.Errorf("v1 mountpoint: got %q, want %q", r.Info().V1Mountpoint, host.root)
		}
	}
}

func TestResolveV2Unified(t *testing.T) {
	host := newFakeHost(t, Unified)
	r := host.newResolver(t)

	got, err := r.ResolveV2("/scheduler/tenant-a", "child")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(host.root, "scheduler", "tenant-a", "child")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Nested suffix attempting traversal is rejected.
	if _, err := r.ResolveV2("/scheduler", "../../../etc"); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("got %v, want ErrPathEscape", err)
	}
	// Mount-point-prefixed logical names are rejected.
	if _, err := r.ResolveV2("/sys/fs/cgroup/x", ""); !errors.Is(err, ErrMountPointPrefix) {
		t.Fatalf("got %v, want ErrMountPointPrefix", err)
	}
}

func TestResolveV2OnLegacyReturnsStaleWithNewPath(t *testing.T) {
	host := newFakeHost(t, Legacy)
	host.writeMountInfo(t, "memory", "devices", "name=systemd")
	host.writeProcCgroup(t, "self", legacyCgroupFile)
	r := host.newResolver(t)

	_, err := r.ResolveV2("/system.slice/scheduler.service", "nested")
	var stale *StalePathError
	if !errors.As(err, &stale) {
		t.Fatalf("got %T %v, want StalePathError", err, err)
	}
	if stale.CurrentMode != Legacy || stale.OldMode != Unified {
		t.Fatalf("unexpected modes: old=%v current=%v", stale.OldMode, stale.CurrentMode)
	}
	wantSuffix := filepath.Join("system.slice", "scheduler.service", "nested")
	if stale.NewPath == "" || !strings.HasSuffix(stale.NewPath, wantSuffix) {
		t.Fatalf("new path %q should end with %q", stale.NewPath, wantSuffix)
	}
	if !strings.HasPrefix(stale.NewPath, host.root) {
		t.Fatalf("new path %q must stay under hierarchy root %q", stale.NewPath, host.root)
	}
}

func TestResolveV1Legacy(t *testing.T) {
	host := newFakeHost(t, Legacy)
	host.writeMountInfo(t, "memory", "devices", "name=systemd")
	r := host.newResolver(t)

	got, err := r.ResolveV1("memory", "/system.slice/scheduler.service", "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(host.root, "memory", "system.slice", "scheduler.service", "worker-1")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Named hierarchy resolves through its dedicated mount point, which
	// uses the bare hierarchy name (no "name=" prefix) on disk.
	got, err = r.ResolveV1("name=systemd", "/system.slice/scheduler.service", "")
	if err != nil {
		t.Fatal(err)
	}
	want = filepath.Join(host.root, "systemd", "system.slice", "scheduler.service")
	if got != want {
		t.Fatalf("named hierarchy: got %q, want %q", got, want)
	}
}

func TestResolveV1OnUnifiedReturnsStale(t *testing.T) {
	host := newFakeHost(t, Unified)
	r := host.newResolver(t)

	_, err := r.ResolveV1("memory", "/tenant-a", "")
	var stale *StalePathError
	if !errors.As(err, &stale) {
		t.Fatalf("got %v, want StalePathError", err)
	}
	want := filepath.Join(host.root, "tenant-a")
	if stale.NewPath != want {
		t.Fatalf("new path: got %q, want %q", stale.NewPath, want)
	}
}

func TestResolvePidUnified(t *testing.T) {
	host := newFakeHost(t, Unified)
	host.writeProcCgroup(t, "4242", unifiedCgroupFile)
	r := host.newResolver(t)

	v1, v2, err := r.ResolvePid(4242, "child")
	if err != nil {
		t.Fatal(err)
	}
	if len(v1) != 0 {
		t.Fatalf("unified host must not return v1 paths: %v", v1)
	}
	want := filepath.Join(host.root, "system.slice", "scheduler.service", "child")
	if v2 != want {
		t.Fatalf("got %q, want %q", v2, want)
	}
}

func TestResolvePidLegacyNamedAndNested(t *testing.T) {
	host := newFakeHost(t, Legacy)
	host.writeMountInfo(t, "memory", "devices", "name=systemd")
	host.writeProcCgroup(t, "4242", legacyCgroupFile)
	r := host.newResolver(t)

	v1, v2, err := r.ResolvePid(4242, "nested")
	if err != nil {
		t.Fatal(err)
	}
	if v2 != "" {
		t.Fatalf("legacy host must not return a v2 path, got %q", v2)
	}
	want := map[string]string{
		"memory":       filepath.Join(host.root, "memory", "system.slice", "scheduler.service", "nested"),
		"devices":      filepath.Join(host.root, "devices", "system.slice", "scheduler.service", "nested"),
		"name=systemd": filepath.Join(host.root, "systemd", "system.slice", "scheduler.service", "nested"),
	}
	for k, w := range want {
		if got := v1[k]; got != w {
			t.Errorf("controller %q: got %q, want %q", k, got, w)
		}
	}

	// Invalid pid rejected explicitly.
	if _, _, err := r.ResolvePid(0, ""); err == nil {
		t.Fatal("pid 0 must be rejected")
	}
}

func TestResolvePidHybridBothHierarchies(t *testing.T) {
	host := newFakeHost(t, Hybrid)
	host.writeMountInfo(t, "memory", "devices", "name=systemd")
	host.writeProcCgroup(t, "4242", hybridCgroupFile)
	r := host.newResolver(t)

	v1, v2, err := r.ResolvePid(4242, "")
	if err != nil {
		t.Fatal(err)
	}
	if v2 != filepath.Join(host.root, "system.slice", "scheduler.service") {
		t.Fatalf("hybrid v2 path: got %q", v2)
	}
	if got := v1["memory"]; got != filepath.Join(host.root, "memory", "system.slice", "scheduler.service") {
		t.Fatalf("hybrid v1 memory path: got %q", got)
	}
}

func TestRefreshAfterHierarchySwitch(t *testing.T) {
	host := newFakeHost(t, Legacy)
	host.writeMountInfo(t, "memory")
	r := host.newResolver(t)
	if r.Mode() != Legacy {
		t.Fatalf("initial mode: %v", r.Mode())
	}

	// Simulate the host switching to a unified hierarchy during an upgrade.
	host.statfs.types = map[string]int64{
		host.root: unix.CGROUP2_SUPER_MAGIC,
	}
	info, err := r.Refresh()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode != Unified || r.Mode() != Unified {
		t.Fatalf("mode after refresh: %v", r.Mode())
	}

	// Old v1 path assumptions now fail with an explicit error carrying the
	// usable v2 replacement.
	_, err = r.ResolveV1("memory", "/system.slice/scheduler.service", "")
	var stale *StalePathError
	if !errors.As(err, &stale) {
		t.Fatalf("got %v, want StalePathError", err)
	}
	want := filepath.Join(host.root, "system.slice", "scheduler.service")
	if stale.NewPath != want {
		t.Fatalf("replacement path: got %q, want %q", stale.NewPath, want)
	}
	if !errors.Is(err, ErrStalePath) {
		t.Fatal("error must match ErrStalePath sentinel")
	}

	// The v2 API works immediately on the new hierarchy.
	got, err := r.ResolveV2("/system.slice/scheduler.service", "")
	if err != nil {
		t.Fatalf("v2 resolve after switch: %v", err)
	}
	if got != want {
		t.Fatalf("v2 path: got %q, want %q", got, want)
	}
}

func TestResolveV2OnLegacyNoReplacementWhenUnrelated(t *testing.T) {
	host := newFakeHost(t, Legacy)
	host.writeMountInfo(t, "memory")
	// The process lives at a different logical path than the request.
	host.writeProcCgroup(t, "self", legacyCgroupFile)
	r := host.newResolver(t)

	_, err := r.ResolveV2("/unrelated/tenant", "")
	var stale *StalePathError
	if !errors.As(err, &stale) {
		t.Fatalf("got %v, want StalePathError", err)
	}
	if stale.NewPath != "" {
		t.Fatalf("unrelated request must not invent a replacement, got %q", stale.NewPath)
	}
	if !errors.Is(err, ErrStalePath) {
		t.Fatal("error must match ErrStalePath sentinel")
	}
}

func TestProbeHasNoSideEffects(t *testing.T) {
	resetProbeCache()
	host := newFakeHost(t, Unified)
	first, err := NewResolver(
		WithResolverStatfs(host.statfs.statfs),
		WithResolverMountpoint(host.root),
		WithProcRoot(host.procRoot),
	)
	if err != nil {
		t.Fatal(err)
	}
	callsAfterFirst := host.statfs.calls

	// A second resolver over the same fake hierarchy re-runs only because
	// injected probes are never cached; importantly each detection performs
	// the same fixed number of read-only statfs calls and no writes.
	second, err := NewResolver(
		WithResolverStatfs(host.statfs.statfs),
		WithResolverMountpoint(host.root),
		WithProcRoot(host.procRoot),
	)
	if err != nil {
		t.Fatal(err)
	}
	if host.statfs.calls != callsAfterFirst+1 {
		t.Fatalf("each probe must issue exactly one statfs on a unified host: %d -> %d",
			callsAfterFirst, host.statfs.calls)
	}
	if first.Mode() != second.Mode() {
		t.Fatal("repeated probes must return identical results")
	}
}

func TestResolvePidSuffixEscapeRejected(t *testing.T) {
	host := newFakeHost(t, Unified)
	host.writeProcCgroup(t, "7", unifiedCgroupFile)
	r := host.newResolver(t)

	if _, _, err := r.ResolvePid(7, "../../../etc"); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("got %v, want ErrPathEscape", err)
	}
}
