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
	"testing"

	"github.com/containerd/cgroups/v3/capabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeUID593Cgroup2File(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
}

func TestUID593WriteValuesPreflightsMissingFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing-cgroup")
	err := writeValues(dir, []Value{{filename: "rdma.max", value: "mlx5_0 hca_handle=1"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrControlFileNotWritable)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestUID593WriteValuesCanCreateMockFileInTempDir(t *testing.T) {
	oldPerm := defaultFilePerm
	defaultFilePerm = 0o666
	t.Cleanup(func() { defaultFilePerm = oldPerm })

	dir := t.TempDir()
	require.NoError(t, writeValues(dir, []Value{{filename: "rdma.max", value: "mlx5_0 hca_handle=1"}}))
	content, err := os.ReadFile(filepath.Join(dir, "rdma.max"))
	require.NoError(t, err)
	assert.Equal(t, "mlx5_0 hca_handle=1", string(content))
}

func TestUID593UpdateWithPolicyDegradesMissingRDMA(t *testing.T) {
	dir := t.TempDir()
	writeUID593Cgroup2File(t, filepath.Join(dir, controllersFile), "io rdma\n", 0o644)
	writeUID593Cgroup2File(t, filepath.Join(dir, "io.max"), "", 0o666)
	// Deliberately do not create rdma.max: simulates a partial controller.

	m := &Manager{path: dir, unifiedMountpoint: dir}
	res := &Resources{
		IO: &IO{Max: []Entry{{Major: 8, Minor: 0, Type: WriteBPS, Rate: 4096}}},
		RDMA: &RDMA{Limit: []RDMAEntry{{
			Device: "mlx5_0", HcaHandles: 1, HcaObjects: 1,
		}}},
	}

	strict, err := m.UpdateWithPolicy(res, CapabilityPolicyStrict)
	require.Error(t, err)
	assert.ErrorIs(t, err, capabilities.ErrDegradedPolicy)
	assert.Len(t, strict.MissingLimits, 1)
	assert.Equal(t, "rdma.max", strict.MissingLimits[0].File)

	degraded, err := m.UpdateWithPolicy(res, CapabilityPolicyDegrade)
	require.NoError(t, err)
	require.Len(t, degraded.MissingLimits, 1)
	assert.Equal(t, "rdma", degraded.MissingLimits[0].Controller)
	require.Len(t, degraded.Written, 1)
	assert.Equal(t, "io.max", degraded.Written[0].File)

	content, err := os.ReadFile(filepath.Join(dir, "io.max"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "8:0 wbps=4096")
	_, err = os.Stat(filepath.Join(dir, "rdma.max"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestUID593ManagerCapabilitiesReportMountpointAndVersion(t *testing.T) {
	dir := t.TempDir()
	writeUID593Cgroup2File(t, filepath.Join(dir, controllersFile), "io\n", 0o644)
	writeUID593Cgroup2File(t, filepath.Join(dir, "io.max"), "", 0o666)
	m := &Manager{path: dir, unifiedMountpoint: dir}

	report, err := m.Capabilities()
	require.NoError(t, err)
	assert.Equal(t, capabilities.VersionV2, report.Version)
	ctl := report.Get("io")
	require.NotNil(t, ctl)
	assert.True(t, ctl.Available)
	assert.Equal(t, 2, ctl.HierarchyVersion)
	assert.NotEmpty(t, ctl.Mountpoint)
}

func TestUID593ControllerForFile(t *testing.T) {
	assert.Equal(t, "io", ControllerForFile("io.max"))
	assert.Equal(t, "rdma", ControllerForFile("rdma.max"))
	assert.Equal(t, "cpuset", ControllerForFile("cpuset.cpus"))
	assert.Empty(t, ControllerForFile("unknown.file"))
}

func TestUID593UnwritableErrorIsSentinel(t *testing.T) {
	err := capabilities.CheckPathWritable(filepath.Join(t.TempDir(), "x"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrControlFileNotWritable))
}
