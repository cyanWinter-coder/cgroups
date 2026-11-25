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

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func writeUID593File(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
}

func TestUID593ProbeV2PartialIOAndMissingRDMA(t *testing.T) {
	dir := t.TempDir()
	writeUID593File(t, filepath.Join(dir, controllersFile), "cpu memory io\n", 0o644)
	writeUID593File(t, filepath.Join(dir, "io.max"), "8:0 rbps=1048576\n", 0o666)
	writeUID593File(t, filepath.Join(dir, "cgroup.procs"), "123\n", 0o666)

	report, err := Probe(WithRoot(dir))
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, VersionV2, report.Version)
	assert.Equal(t, 2, report.HierarchyVersion)
	assert.Equal(t, "cgroup2", report.Hierarchy)

	ioCtl := report.Get("io")
	require.NotNil(t, ioCtl)
	assert.Equal(t, "io", ioCtl.Name)
	assert.True(t, ioCtl.Mounted)
	assert.True(t, ioCtl.Available)
	assert.True(t, ioCtl.Writable)
	assert.Contains(t, ioCtl.WritableFiles, "io.max")
	assert.Equal(t, dir, ioCtl.Mountpoint)
	assert.Equal(t, dir, ioCtl.MountPoint)

	require.NoError(t, CheckWritable(report, "io", "io.max"))

	rdmaCtl := report.Get("rdma")
	require.NotNil(t, rdmaCtl)
	assert.False(t, rdmaCtl.Available)
	assert.False(t, rdmaCtl.Writable)
	assert.Equal(t, StatusMissing, rdmaCtl.Status)
	assert.Equal(t, ReasonControllerNotListed, rdmaCtl.Reason)
	assert.NotEmpty(t, rdmaCtl.MissingReason)
	assert.ErrorIs(t, CheckWritable(report, "rdma", "rdma.max"), ErrFileNotWritable)

	data, err := report.JSON()
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "v2", decoded["version"])
	assert.NotEmpty(t, decoded["controllers"])
}

func TestUID593ProbeV1BlkioAliasAndReadOnlyRDMA(t *testing.T) {
	root := t.TempDir()
	blkio := filepath.Join(root, "blkio")
	rdma := filepath.Join(root, "rdma")
	writeUID593File(t, filepath.Join(blkio, "blkio.throttle.read_bps_device"), "", 0o666)
	writeUID593File(t, filepath.Join(rdma, "rdma.max"), "", 0o444)

	denyAccess := func(path string, flags uint32) error {
		if flags == unix.W_OK && filepath.Base(path) == "rdma.max" {
			return unix.EACCES
		}
		return unix.Access(path, flags)
	}

	report, err := Probe(WithRoot(root), withAccessFunc(denyAccess))
	require.NoError(t, err)
	assert.Equal(t, VersionV1, report.Version)
	assert.Equal(t, 1, report.HierarchyVersion)

	ioCtl := report.Get("io")
	require.NotNil(t, ioCtl, "canonical io lookup should find blkio")
	assert.Equal(t, "blkio", ioCtl.Name)
	assert.Contains(t, ioCtl.Aliases, "io")
	assert.Equal(t, VersionV1, ioCtl.Version)
	assert.True(t, ioCtl.Available)
	assert.True(t, ioCtl.Degraded, "only one of four throttle files exists")
	assert.Contains(t, ioCtl.Mountpoint, "blkio")
	assert.NotEmpty(t, ioCtl.MissingFiles)

	byBlkio := report.Get("blkio")
	require.NotNil(t, byBlkio)
	assert.Equal(t, ioCtl.Name, byBlkio.Name)

	rdmaCtl := report.Get("rdma")
	require.NotNil(t, rdmaCtl)
	assert.True(t, rdmaCtl.Exists)
	assert.False(t, rdmaCtl.Writable)
	assert.True(t, rdmaCtl.ReadOnly)
	assert.Equal(t, StatusReadOnly, rdmaCtl.Status)
	assert.ErrorIs(t, CheckWritable(report, "rdma", "rdma.max"), ErrFileNotWritable)
}

func TestUID593StrictAndDegradePolicy(t *testing.T) {
	dir := t.TempDir()
	writeUID593File(t, filepath.Join(dir, controllersFile), "io\n", 0o644)
	writeUID593File(t, filepath.Join(dir, "io.max"), "", 0o666)
	report, err := Probe(WithRoot(dir))
	require.NoError(t, err)

	limits := []RequestedLimit{
		{Controller: "io", File: "io.max"},
		{Controller: "rdma", File: "rdma.max"},
	}
	strict, err := PolicyStrict.Check(report, limits)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDegradedPolicy)
	assert.Len(t, strict.MissingLimits, 1)

	degraded, err := PolicyDegrade.Check(report, limits)
	require.NoError(t, err)
	require.Len(t, degraded.MissingLimits, 1)
	assert.Equal(t, "rdma", degraded.MissingLimits[0].Controller)
	assert.True(t, degraded.Missing())
	assert.Len(t, degraded.Applied, 1)
}

func TestUID593ProbeIsReadOnlyAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	writeUID593File(t, filepath.Join(dir, controllersFile), "io rdma\n", 0o644)
	writeUID593File(t, filepath.Join(dir, "io.max"), "original\n", 0o666)
	writeUID593File(t, filepath.Join(dir, "rdma.max"), "original rdma\n", 0o666)

	first, err := Probe(WithRoot(dir))
	require.NoError(t, err)
	second, err := Probe(WithRoot(dir))
	require.NoError(t, err)
	assert.Equal(t, first, second)

	content, err := os.ReadFile(filepath.Join(dir, "io.max"))
	require.NoError(t, err)
	assert.Equal(t, "original\n", string(content))
	content, err = os.ReadFile(filepath.Join(dir, "rdma.max"))
	require.NoError(t, err)
	assert.Equal(t, "original rdma\n", string(content))
}

func TestUID593ParseMountInfoAndReportMountpoint(t *testing.T) {
	rdmaMount := t.TempDir()
	root := t.TempDir()
	mountInfo := filepath.Join(root, "mountinfo")
	line := "100 24 0:30 / " + rdmaMount + " rw,noatime - cgroup cgroup rw,nosuid,nodev,noexec,rdma\n"
	require.NoError(t, os.WriteFile(mountInfo, []byte(line), 0o644))

	report, err := Probe(WithMountInfo(mountInfo), WithControllers("rdma"))
	require.NoError(t, err)
	require.Len(t, report.Mounts, 1)
	assert.Equal(t, "cgroup", report.Mounts[0].FSType)
	assert.Contains(t, report.Mounts[0].Controllers, "rdma")

	ctl := report.Get("rdma")
	require.NotNil(t, ctl)
	assert.True(t, ctl.Mounted)
	assert.Equal(t, rdmaMount, ctl.Mountpoint)
	assert.Equal(t, rdmaMount, ctl.MountPoint)
}

func TestUID593CheckPathWritableErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "rdma.max")
	err := CheckPathWritable(missing)
	require.Error(t, err)
	var unwritable *UnwritableError
	require.True(t, errors.As(err, &unwritable))
	assert.Equal(t, ReasonFileMissing, unwritable.Reason)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
