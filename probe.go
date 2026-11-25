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
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// HierarchyInfo describes the cgroup hierarchies detected on the host.
//
// A fleet can contain hosts at different points of a v1 to v2 migration.
// HierarchyInfo captures what a single host is actually using at probe
// time: the [CGMode], plus the absolute mount points a logical group name
// must be joined against.
type HierarchyInfo struct {
	// Mode is the cgroups mode of the host.
	Mode CGMode

	// V2Mountpoint is the unified cgroup v2 mount point
	// ("/sys/fs/cgroup"). It is set in Unified and Hybrid modes.
	V2Mountpoint string

	// V1Mountpoint is the directory under which the per-controller v1
	// cgroup filesystems are mounted (for example "/sys/fs/cgroup"). It is
	// set in Legacy and Hybrid modes, and empty when no v1 hierarchy is
	// mounted.
	V1Mountpoint string
}

// StatfsFunc reports the filesystem type mounted at path, mirroring
// [unix.Statfs]. It is an indirection point so probe logic can be exercised
// against fake hierarchies in tests.
type StatfsFunc func(path string) (int64, error)

func defaultStatfs(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Type), nil
}

// ProbeOption configures a [Probe] call.
type ProbeOption func(*probeConfig)

type probeConfig struct {
	statfs       StatfsFunc
	v2Mountpoint string
	forceRefresh bool
	// injected is true when the statfs implementation (or mount point) was
	// overridden, in which case the result must not be cached package-wide.
	injected bool
}

// WithStatfs overrides the statfs implementation used for detection.
func WithStatfs(statfs StatfsFunc) ProbeOption {
	return func(c *probeConfig) {
		c.statfs = statfs
		c.injected = true
	}
}

// WithUnifiedMountpoint overrides the unified mountpoint used for detection
// instead of the default "/sys/fs/cgroup".
func WithUnifiedMountpoint(path string) ProbeOption {
	return func(c *probeConfig) {
		c.v2Mountpoint = path
		c.injected = true
	}
}

// WithForceRefresh forces a fresh detection instead of returning the cached
// result. Detection only performs statfs calls on a cache miss, so repeated
// probes with the default options have no side effects.
func WithForceRefresh() ProbeOption {
	return func(c *probeConfig) {
		c.forceRefresh = true
	}
}

var (
	probeMu     sync.RWMutex
	cachedProbe *HierarchyInfo
)

// Probe detects the cgroup hierarchies mounted on the host and returns the
// mode currently in use together with the real v1/v2 mount points.
//
// Results are cached: the first successful detection is reused by later
// calls, so repeated probing does not re-stat the mounts and never mutates
// host state. Pass [WithForceRefresh] to re-detect, for example after the
// host's cgroup hierarchy has been switched.
func Probe(opts ...ProbeOption) (HierarchyInfo, error) {
	cfg := probeConfig{
		statfs:       defaultStatfs,
		v2Mountpoint: unifiedMountpoint,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// Injected probes describe a caller-specific layout; they never consult
	// or populate the shared cache.
	if !cfg.forceRefresh && !cfg.injected {
		probeMu.RLock()
		info := cachedProbe
		probeMu.RUnlock()
		if info != nil {
			return *info, nil
		}
	}

	info, err := detect(cfg.statfs, cfg.v2Mountpoint)
	if err != nil {
		return HierarchyInfo{}, err
	}

	// Only a detection against the real host mounts at the standard
	// location may populate the shared package cache. Injected probes (custom
	// statfs used by tests or alternative layouts) stay local to the caller
	// so they can never poison other users of the package.
	cacheable := !cfg.forceRefresh && !cfg.injected
	if cacheable {
		probeMu.Lock()
		if cachedProbe == nil {
			cachedProbe = &info
		} else {
			info = *cachedProbe
		}
		probeMu.Unlock()
	}
	return info, nil
}

// resetProbeCache clears the cached detection result. It is used by tests
// and by hierarchy-switch handling.
func resetProbeCache() {
	probeMu.Lock()
	cachedProbe = nil
	probeMu.Unlock()
}

// detect inspects the unified mountpoint and, for legacy setups, the
// "unified" submount to distinguish Legacy from Hybrid.
func detect(statfs StatfsFunc, mountpoint string) (HierarchyInfo, error) {
	info := HierarchyInfo{V2Mountpoint: mountpoint}

	fsType, err := statfs(mountpoint)
	if err != nil {
		return HierarchyInfo{}, fmt.Errorf("%w: %s: %v", ErrModeNotDetected, mountpoint, err)
	}
	if fsType == unix.CGROUP2_SUPER_MAGIC {
		info.Mode = Unified
		return info, nil
	}
	// Any other filesystem at the cgroup root means the v1 controllers are
	// mounted there (a tmpfs holding per-controller mounts, or a single
	// cgroup fs in legacy setups).
	info.V1Mountpoint = mountpoint

	// A cgroup2 mount at "<mountpoint>/unified" alongside v1 controllers
	// means the host runs the hybrid hierarchy.
	subType, err := statfs(joinPath(mountpoint, "unified"))
	if err == nil && subType == unix.CGROUP2_SUPER_MAGIC {
		info.Mode = Hybrid
		return info, nil
	}
	info.Mode = Legacy
	return info, nil
}
