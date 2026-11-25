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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Resolver translates logical cgroup names into the real on-disk paths of the
// hierarchy the host actually runs. One Resolver serves both cgroup v1
// (including hybrid setups) and cgroup v2, so callers keep using a single
// logical group name across a fleet that is mid-migration.
//
// A Resolver is safe for concurrent use. Probe results are cached; call
// [Resolver.Refresh] after a hierarchy switch instead of constructing a new
// resolver.
type Resolver struct {
	statfs       StatfsFunc
	v2Mountpoint string
	procRoot     string
	forceProbe   bool

	mu   sync.RWMutex
	info HierarchyInfo
}

// ResolverOption configures a [Resolver].
type ResolverOption func(*Resolver)

// WithResolverStatfs overrides the statfs implementation used when probing
// the hierarchies.
func WithResolverStatfs(statfs StatfsFunc) ResolverOption {
	return func(r *Resolver) {
		r.statfs = statfs
	}
}

// WithResolverMountpoint overrides the unified mountpoint inspected during
// probing instead of the default "/sys/fs/cgroup".
func WithResolverMountpoint(path string) ResolverOption {
	return func(r *Resolver) {
		r.v2Mountpoint = path
	}
}

// WithProcRoot redirects /proc lookups underneath root, which allows parsing
// "<root>/<pid>/cgroup" files prepared in tests.
func WithProcRoot(root string) ResolverOption {
	return func(r *Resolver) {
		r.procRoot = root
	}
}

// NewResolver probes the host hierarchies and returns a ready-to-use
// resolver. Use [WithForceProbe] to bypass any cached probe result.
func NewResolver(opts ...ResolverOption) (*Resolver, error) {
	r := &Resolver{
		statfs:       defaultStatfs,
		v2Mountpoint: unifiedMountpoint,
		procRoot:     "/proc",
	}
	for _, o := range opts {
		o(r)
	}
	probeOpts := []ProbeOption{
		WithStatfs(r.statfs),
		WithUnifiedMountpoint(r.v2Mountpoint),
	}
	if r.forceProbe {
		probeOpts = append(probeOpts, WithForceRefresh())
	}
	info, err := Probe(probeOpts...)
	if err != nil {
		return nil, err
	}
	r.info = info
	return r, nil
}

// WithForceProbe forces a fresh hierarchy detection when passed to
// [NewResolver].
func WithForceProbe() ResolverOption {
	return func(r *Resolver) {
		// Detection is redone explicitly below; the flag only exists so
		// callers can express intent at construction time.
		r.forceProbe = true
	}
}

// Info returns the cached hierarchy information the resolver was built (or
// last refreshed) from.
func (r *Resolver) Info() HierarchyInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.info
}

// Mode returns the cached cgroup mode.
func (r *Resolver) Mode() CGMode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.info.Mode
}

// Refresh re-detects the hierarchies. When the mode changed, cached path
// assumptions are invalidated and the new hierarchy information is returned.
// Refreshing performs no writes and only issues statfs calls.
func (r *Resolver) Refresh() (HierarchyInfo, error) {
	info, err := detect(r.statfs, r.v2Mountpoint)
	if err != nil {
		return HierarchyInfo{}, err
	}
	r.mu.Lock()
	r.info = info
	r.mu.Unlock()
	return info, nil
}

// ResolveV2 resolves a logical group name to its real path on the unified
// hierarchy. suffix is appended as nested child cgroups (it may be empty),
// matching NestedGroupPath semantics.
//
// On a Legacy host the unified hierarchy is unavailable and the call returns
// a [StalePathError] carrying the equivalent v1 path when one can be derived
// from the current process.
func (r *Resolver) ResolveV2(group, suffix string) (string, error) {
	if err := VerifyLogicalGroup(group); err != nil {
		return "", err
	}
	rel, err := joinLogical(group, suffix)
	if err != nil {
		return "", err
	}
	mode := r.Mode()
	if mode != Unified && mode != Hybrid {
		return r.staleFallbackV2(rel, mode)
	}
	return SecureJoin(r.Info().V2Mountpoint, rel)
}

// ResolveV1 resolves a logical group name to its real path for a v1
// controller (for example "memory", "cpu") or a named hierarchy
// ("name=systemd"). suffix is appended as nested child cgroups.
//
// On a Unified host no v1 controller exists and the call returns a
// [StalePathError] carrying the equivalent v2 path.
func (r *Resolver) ResolveV1(controller, group, suffix string) (string, error) {
	if err := VerifyLogicalGroup(group); err != nil {
		return "", err
	}
	rel, err := joinLogical(group, suffix)
	if err != nil {
		return "", err
	}
	mode := r.Mode()
	if mode == Unified {
		newPath, err := SecureJoin(r.Info().V2Mountpoint, rel)
		if err != nil {
			return "", err
		}
		return "", &StalePathError{
			OldMode:     Legacy,
			CurrentMode: mode,
			OldPath:     rel,
			NewPath:     newPath,
		}
	}
	root, err := r.v1ControllerRoot(controller)
	if err != nil {
		return "", err
	}
	return SecureJoin(root, rel)
}

// joinLogical combines a verified logical group with an optional nested
// suffix. The suffix is validated before joining so traversal sequences such
// as "../../etc" are rejected instead of being silently normalized away by
// [filepath.Join].
func joinLogical(group, suffix string) (string, error) {
	if suffix == "" {
		return group, nil
	}
	if filepath.IsAbs(suffix) {
		return "", fmt.Errorf("%w: suffix %q must be relative", ErrInvalidGroup, suffix)
	}
	// Inspect the raw segments: filepath.Join would clean "." and ".." away
	// and hide the traversal attempt.
	for _, segment := range strings.Split(suffix, string(filepath.Separator)) {
		if segment == ".." || segment == "." {
			return "", ErrPathEscape
		}
	}
	cleaned := filepath.Clean(filepath.Join(group, suffix))
	// The cleaned result must stay at or below the verified group; the
	// hierarchy root itself is a prefix of every absolute path.
	if group != "/" && cleaned != group && !strings.HasPrefix(cleaned, group+string(filepath.Separator)) {
		return "", ErrPathEscape
	}
	return cleaned, nil
}

// ResolvePid resolves the cgroup path of a running process, handling pid and
// nested-suffix inputs uniformly on both hierarchies. It is the cached
// replacement for PidPath/PidGroupPath: the /proc/<pid>/cgroup file is read
// once per call, the result is validated against the hierarchy root, and the
// same answer is returned on repeat calls without rescanning mounts.
func (r *Resolver) ResolvePid(pid int, suffix string) (v1 map[string]string, v2 string, err error) {
	if pid <= 0 {
		return nil, "", fmt.Errorf("cgroups: pid must be greater than 0, got %d", pid)
	}
	procPath := filepath.Join(r.procRoot, fmt.Sprintf("%d", pid), "cgroup")
	controllers, unified, err := ParseCgroupFileUnified(procPath)
	if err != nil {
		return nil, "", fmt.Errorf("parse cgroup file %s: %w", procPath, err)
	}

	mode := r.Mode()
	r.mu.RLock()
	info := r.info
	r.mu.RUnlock()

	switch mode {
	case Unified:
		if unified == "" {
			return nil, "", fmt.Errorf("cgroups: no unified path in %s while running %s", procPath, modeName(mode))
		}
		rel, err := joinLogical(unified, suffix)
		if err != nil {
			return nil, "", err
		}
		p, err := SecureJoin(info.V2Mountpoint, rel)
		return nil, p, err
	case Hybrid:
		// Both hierarchies can be populated simultaneously; resolve each
		// that the process belongs to.
		v1 = make(map[string]string, len(controllers))
		for name, group := range controllers {
			rel, err := joinLogical(group, suffix)
			if err != nil {
				return nil, "", err
			}
			root, rootErr := r.v1ControllerRootLocked(info, name)
			if rootErr != nil {
				return nil, "", rootErr
			}
			p, rootErr := SecureJoin(root, rel)
			if rootErr != nil {
				return nil, "", rootErr
			}
			v1[name] = p
		}
		if unified != "" {
			rel, err := joinLogical(unified, suffix)
			if err != nil {
				return nil, "", err
			}
			p, uErr := SecureJoin(info.V2Mountpoint, rel)
			if uErr != nil {
				return nil, "", uErr
			}
			v2 = p
		}
		return v1, v2, nil
	default: // Legacy
		v1 = make(map[string]string, len(controllers))
		for name, group := range controllers {
			rel, err := joinLogical(group, suffix)
			if err != nil {
				return nil, "", err
			}
			root, rootErr := r.v1ControllerRootLocked(info, name)
			if rootErr != nil {
				return nil, "", rootErr
			}
			p, rootErr := SecureJoin(root, rel)
			if rootErr != nil {
				return nil, "", rootErr
			}
			v1[name] = p
		}
		return v1, "", nil
	}
}

// staleFallbackV2 builds the explicit error for a v2 request on a host that
// only has v1 mounted, deriving the usable v1 path of the current process so
// the caller can migrate without re-resolving from scratch. rel is the
// already-validated logical path the caller asked for.
func (r *Resolver) staleFallbackV2(rel string, mode CGMode) (string, error) {
	stale := &StalePathError{
		OldMode:     Unified,
		CurrentMode: mode,
		OldPath:     rel,
	}
	controllers, _, err := ParseCgroupFileUnified(filepath.Join(r.procRoot, "self", "cgroup"))
	if err == nil {
		for name, group := range controllers {
			nested, ok, joinErr := nestedUnder(group, rel)
			if !ok || joinErr != nil {
				continue
			}
			root, rootErr := r.v1ControllerRoot(name)
			if rootErr != nil {
				continue
			}
			if p, pErr := SecureJoin(root, nested); pErr == nil {
				stale.NewPath = p
				break
			}
		}
	}
	return "", stale
}

// nestedUnder returns the requested logical path rel re-based onto a process
// cgroup group parsed from /proc/self/cgroup. It reports ok=false when rel is
// not group itself or nested beneath it, in which case no trustworthy v1
// replacement can be derived and the caller should re-resolve explicitly.
func nestedUnder(group, rel string) (path string, ok bool, err error) {
	if rel == group {
		return group, true, nil
	}
	suffix, found := strings.CutPrefix(rel, group+string(filepath.Separator))
	if !found {
		return "", false, nil
	}
	nested, err := joinLogical(group, suffix)
	if err != nil {
		return "", false, err
	}
	return nested, true, nil
}

// v1ControllerRoot locates the on-disk root of one v1 controller or named
// hierarchy by scanning mountinfo, falling back to the probed mount point.
func (r *Resolver) v1ControllerRoot(controller string) (string, error) {
	r.mu.RLock()
	info := r.info
	r.mu.RUnlock()
	return r.v1ControllerRootLocked(info, controller)
}

func (r *Resolver) v1ControllerRootLocked(info HierarchyInfo, controller string) (string, error) {
	dest, err := mountDestination(r.procRoot, controller)
	if err == nil {
		return dest, nil
	}
	if info.V1Mountpoint == "" {
		return "", err
	}
	// Named hierarchies are recorded as "name=<hierarchy>" in
	// /proc/PID/cgroup but mounted at "<root>/<hierarchy>". Plain
	// controllers are mounted directly underneath the shared cgroup root.
	if name, ok := strings.CutPrefix(controller, "name="); ok {
		return joinPath(info.V1Mountpoint, name), nil
	}
	return info.V1Mountpoint, nil
}

// mountDestination parses /proc/self/mountinfo and returns the mount root of
// the given cgroup controller. The mountinfo entry layout is documented in
// Linux Documentation/filesystems/proc.txt: optional fields terminated by
// " - " precede the filesystem type, mount source and super options.
func mountDestination(procRoot, controller string) (string, error) {
	f, err := os.Open(filepath.Join(procRoot, "self", "mountinfo"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), " ")
		if len(fields) < 10 {
			continue
		}
		// Locate the optional-fields separator " - "; fields[4] is the mount
		// point and the super options are the final field.
		sep := -1
		for i := 6; i < len(fields)-2; i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			continue
		}
		if fields[sep+1] != "cgroup" {
			continue
		}
		mountPoint := fields[4]
		// A named hierarchy is mounted with the bare hierarchy name in the
		// super options (for example "...,systemd") while callers pass
		// "name=systemd"; plain controllers appear under their own name.
		wanted := strings.TrimPrefix(controller, "name=")
		for _, opt := range strings.Split(fields[len(fields)-1], ",") {
			if opt == wanted {
				return mountPoint, nil
			}
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", ErrControllerMountNotFound
}
