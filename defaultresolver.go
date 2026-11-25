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

import "sync"

var (
	defaultResolverOnce sync.Once
	defaultResolver     *Resolver
	defaultResolverErr  error
)

// DefaultResolver returns the process-wide [Resolver], constructing it on the
// first call. Construction only performs read-only statfs probes and shares
// the [Probe] cache, so repeated calls never re-detect the hierarchies and
// have no side effects.
func DefaultResolver() (*Resolver, error) {
	defaultResolverOnce.Do(func() {
		defaultResolver, defaultResolverErr = NewResolver()
	})
	return defaultResolver, defaultResolverErr
}

// ResolveV2 resolves a logical group (plus optional nested suffix) to its
// real path on the unified hierarchy using the process-wide resolver.
func ResolveV2(group, suffix string) (string, error) {
	r, err := DefaultResolver()
	if err != nil {
		return "", err
	}
	return r.ResolveV2(group, suffix)
}

// ResolveV1 resolves a logical group (plus optional nested suffix) for a v1
// controller or named hierarchy using the process-wide resolver.
func ResolveV1(controller, group, suffix string) (string, error) {
	r, err := DefaultResolver()
	if err != nil {
		return "", err
	}
	return r.ResolveV1(controller, group, suffix)
}

// ResolvePid resolves the cgroup paths of a running process, optionally
// nesting them beneath suffix, using the process-wide resolver.
func ResolvePid(pid int, suffix string) (map[string]string, string, error) {
	r, err := DefaultResolver()
	if err != nil {
		return nil, "", err
	}
	return r.ResolvePid(pid, suffix)
}
