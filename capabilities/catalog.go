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

package capabilities

import "strings"

type fileSpec struct {
	name     string
	limit    string
	required bool
	glob     bool
}

type controllerSpec struct {
	canonical string
	aliases   []string
	v1Names   []string
	v2Names   []string
	v1Files   []fileSpec
	v2Files   []fileSpec
	// noFileController is true for controllers configured through interfaces
	// other than ordinary writable cgroup files (v2 devices/eBPF).
	noFileController bool
}

func (s controllerSpec) selected(wanted map[string]struct{}) bool {
	names := append([]string{s.canonical}, s.aliases...)
	names = append(names, s.v1Names...)
	names = append(names, s.v2Names...)
	for _, n := range names {
		if _, ok := wanted[n]; ok {
			return true
		}
	}
	return false
}

func catalog() []controllerSpec {
	return []controllerSpec{
		{
			canonical: "io",
			aliases:   []string{"blkio"},
			v1Names:   []string{"blkio"},
			v2Names:   []string{"io"},
			v1Files: []fileSpec{
				{name: "blkio.throttle.read_bps_device", limit: "read_bps", required: true},
				{name: "blkio.throttle.write_bps_device", limit: "write_bps", required: true},
				{name: "blkio.throttle.read_iops_device", limit: "read_iops", required: true},
				{name: "blkio.throttle.write_iops_device", limit: "write_iops", required: true},
				{name: "blkio.weight", limit: "weight"},
				{name: "blkio.bfq.weight", limit: "bfq_weight"},
			},
			v2Files: []fileSpec{
				{name: "io.max", limit: "bps/iops", required: true},
				{name: "io.weight", limit: "weight"},
				{name: "io.bfq.weight", limit: "bfq_weight"},
			},
		},
		{
			canonical: "rdma",
			v1Names:   []string{"rdma"},
			v2Names:   []string{"rdma"},
			v1Files: []fileSpec{
				{name: "rdma.max", limit: "hca_handles/hca_objects", required: true},
				{name: "rdma.current", limit: "current"},
			},
			v2Files: []fileSpec{
				{name: "rdma.max", limit: "hca_handles/hca_objects", required: true},
				{name: "rdma.current", limit: "current"},
			},
		},
		{
			canonical: "cpu",
			v1Names:   []string{"cpu"},
			v2Names:   []string{"cpu"},
			v1Files: []fileSpec{
				{name: "cpu.cfs_quota_us", limit: "quota", required: true},
				{name: "cpu.cfs_period_us", limit: "period", required: true},
				{name: "cpu.shares", limit: "shares"},
			},
			v2Files: []fileSpec{
				{name: "cpu.max", limit: "quota/period", required: true},
				{name: "cpu.weight", limit: "weight"},
			},
		},
		{
			canonical: "cpuacct",
			v1Names:   []string{"cpuacct"},
			v2Names:   nil,
			v1Files: []fileSpec{
				{name: "cpuacct.usage", limit: "usage"},
			},
		},
		{
			canonical: "cpuset",
			v1Names:   []string{"cpuset"},
			v2Names:   []string{"cpuset"},
			v1Files: []fileSpec{
				{name: "cpuset.cpus", limit: "cpus", required: true},
				{name: "cpuset.mems", limit: "mems", required: true},
			},
			v2Files: []fileSpec{
				{name: "cpuset.cpus", limit: "cpus", required: true},
				{name: "cpuset.mems", limit: "mems", required: true},
			},
		},
		{
			canonical: "memory",
			v1Names:   []string{"memory"},
			v2Names:   []string{"memory"},
			v1Files: []fileSpec{
				{name: "memory.limit_in_bytes", limit: "limit", required: true},
				{name: "memory.soft_limit_in_bytes", limit: "soft_limit"},
				{name: "memory.memsw.limit_in_bytes", limit: "swap_limit"},
			},
			v2Files: []fileSpec{
				{name: "memory.max", limit: "max", required: true},
				{name: "memory.high", limit: "high"},
				{name: "memory.low", limit: "low"},
				{name: "memory.swap.max", limit: "swap_max"},
			},
		},
		{
			canonical: "pids",
			v1Names:   []string{"pids"},
			v2Names:   []string{"pids"},
			v1Files: []fileSpec{
				{name: "pids.max", limit: "max", required: true},
			},
			v2Files: []fileSpec{
				{name: "pids.max", limit: "max", required: true},
			},
		},
		{
			canonical: "hugetlb",
			v1Names:   []string{"hugetlb"},
			v2Names:   []string{"hugetlb"},
			v1Files: []fileSpec{
				{name: "hugetlb.*.limit_in_bytes", limit: "pagesize_limit", glob: true, required: true},
			},
			v2Files: []fileSpec{
				{name: "hugetlb.*.max", limit: "pagesize_max", glob: true, required: true},
			},
		},
		{
			canonical: "freezer",
			v1Names:   []string{"freezer"},
			v2Names:   []string{"freezer"},
			v1Files: []fileSpec{
				{name: "freezer.state", limit: "state", required: true},
			},
			v2Files: []fileSpec{
				{name: "cgroup.freeze", limit: "freeze", required: true},
			},
		},
		{
			canonical: "devices",
			v1Names:   []string{"devices"},
			v2Names:   []string{"devices"},
			v1Files: []fileSpec{
				{name: "devices.allow", limit: "allow", required: true},
				{name: "devices.deny", limit: "deny", required: true},
			},
			// v2 device access is attached through eBPF rather than a
			// regular writable controller file.
			v2Files:          nil,
			noFileController: true,
		},
		{
			canonical: "net_cls",
			v1Names:   []string{"net_cls"},
			v1Files: []fileSpec{
				{name: "net_cls.classid", limit: "classid", required: true},
			},
		},
		{
			canonical: "net_prio",
			v1Names:   []string{"net_prio"},
			v1Files: []fileSpec{
				{name: "net_prio.ifpriomap", limit: "ifpriomap", required: true},
			},
		},
		{
			canonical: "perf_event",
			v1Names:   []string{"perf_event"},
			v1Files: []fileSpec{
				{name: "perf_event.context", limit: "context"},
			},
		},
	}
}

// NormalizeName maps kernel-version-specific controller names to a stable
// logical name. The empty string remains empty.
func NormalizeName(name string) string {
	switch strings.TrimSpace(name) {
	case "blkio":
		return "io"
	default:
		return name
	}
}

// CanonicalControllerName is an alias for NormalizeName.
func CanonicalControllerName(name string) string { return NormalizeName(name) }
