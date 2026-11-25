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

package cgroup1

import (
	"testing"

	"github.com/containerd/cgroups/v3/capabilities"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uid593U32Ptr(v uint32) *uint32 { return &v }

func TestUID593UpdateMissingRDMAIsExplicit(t *testing.T) {
	root := t.TempDir()
	cg := &cgroup{
		path:          StaticPath("test"),
		subsystems:    []Subsystem{NewBlkio(root)},
		allSubsystems: []Subsystem{NewBlkio(root), NewRdma(root)},
	}
	res := &specs.LinuxResources{
		Rdma: map[string]specs.LinuxRdma{
			"mlx5_0": {HcaHandles: uid593U32Ptr(1), HcaObjects: uid593U32Ptr(2)},
		},
	}

	err := cg.Update(res)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrControllerUnavailable)
	assert.ErrorIs(t, err, ErrControllerNotActive)
	assert.Contains(t, err.Error(), "rdma")

	result, err := cg.UpdateWithPolicy(res, CapabilityPolicyDegrade)
	require.NoError(t, err)
	require.Len(t, result.MissingLimits, 1)
	assert.Equal(t, "rdma", result.MissingLimits[0].Controller)
}

func TestUID593SubsystemsRemainActiveOnlyButReportIncludesMissing(t *testing.T) {
	root := t.TempDir()
	rdma := NewRdma(root)
	cg := &cgroup{
		path:          StaticPath("test"),
		subsystems:    []Subsystem{NewBlkio(root)},
		allSubsystems: []Subsystem{NewBlkio(root), rdma},
	}

	require.Len(t, cg.Subsystems(), 1)
	assert.Equal(t, Blkio, cg.Subsystems()[0].Name())

	report, err := cg.Capabilities()
	require.NoError(t, err)
	assert.Equal(t, capabilities.VersionV1, report.Version)
	rdmaReport := report.Get("rdma")
	require.NotNil(t, rdmaReport)
	assert.False(t, rdmaReport.Active)
	assert.False(t, rdmaReport.Mounted)
	assert.Equal(t, 1, rdmaReport.HierarchyVersion)
	assert.NotEmpty(t, rdmaReport.MissingReason)
	assert.Contains(t, rdmaReport.Mountpoint, "rdma")
}

func TestUID593RequestedSubsystemsMapsIONames(t *testing.T) {
	res := &specs.LinuxResources{
		BlockIO: &specs.LinuxBlockIO{
			ThrottleReadBpsDevice: []specs.LinuxThrottleDevice{
				{Rate: 1024},
			},
		},
	}
	names := requestedSubsystems(res)
	assert.Contains(t, names, Blkio)
}

func TestUID593RequestedSubsystemsMapsAllUpdaters(t *testing.T) {
	cpuSet := "0-3"
	classID := uint32(42)
	oom := true
	names := requestedSubsystems(&specs.LinuxResources{
		CPU:     &specs.LinuxCPU{Cpus: cpuSet},
		Network: &specs.LinuxNetwork{ClassID: &classID},
		BlockIO: &specs.LinuxBlockIO{WeightDevice: []specs.LinuxWeightDevice{{}}},
		Memory:  &specs.LinuxMemory{DisableOOMKiller: &oom},
	})
	assert.Contains(t, names, Cpuset)
	assert.Contains(t, names, NetCLS)
	assert.Contains(t, names, Blkio)
	assert.Contains(t, names, Memory)
}
