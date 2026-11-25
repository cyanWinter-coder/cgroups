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
	"io"
	"os"
	"strings"
	"sync"

	"github.com/moby/sys/userns"
)

var (
	checkMode sync.Once
	cgMode    CGMode
)

const unifiedMountpoint = "/sys/fs/cgroup"

// CGMode is the cgroups mode of the host system
type CGMode int

const (
	// Unavailable cgroup mountpoint
	Unavailable CGMode = iota
	// Legacy cgroups v1
	Legacy
	// Hybrid with cgroups v1 and v2 controllers mounted
	Hybrid
	// Unified with only cgroups v2 mounted
	Unified
)

// Mode returns the cgroups mode running on the host.
//
// The detection shares the process-wide cache used by [Probe]: repeated
// calls perform the statfs inspection only on the first call and never
// mutate host state. Use [Probe] with [WithForceRefresh] to re-detect after
// a hierarchy switch.
func Mode() CGMode {
	checkMode.Do(func() {
		info, err := Probe()
		if err != nil {
			cgMode = Unavailable
			return
		}
		cgMode = info.Mode
	})
	return cgMode
}

// RunningInUserNS detects whether we are currently running in a user namespace.
// Copied from github.com/lxc/lxd/shared/util.go
//
// Deprecated: use [userns.RunningInUserNS].
func RunningInUserNS() bool {
	return userns.RunningInUserNS()
}

// ParseCgroupFileUnified returns legacy subsystem paths as the first value,
// and returns the unified path as the second value.
func ParseCgroupFileUnified(path string) (map[string]string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	return ParseCgroupFromReaderUnified(f)
}

// ParseCgroupFromReaderUnified returns legacy subsystem paths as the first value,
// and returns the unified path as the second value.
func ParseCgroupFromReaderUnified(r io.Reader) (map[string]string, string, error) {
	var (
		cgroups = make(map[string]string)
		unified = ""
		s       = bufio.NewScanner(r)
	)
	for s.Scan() {
		var (
			text  = s.Text()
			parts = strings.SplitN(text, ":", 3)
		)
		if len(parts) < 3 {
			return nil, unified, fmt.Errorf("invalid cgroup entry: %q", text)
		}
		for _, subs := range strings.Split(parts[1], ",") {
			if subs == "" {
				unified = parts[2]
			} else {
				cgroups[subs] = parts[2]
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, unified, err
	}
	return cgroups, unified, nil
}
