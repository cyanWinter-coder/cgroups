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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/cgroups/v3/capabilities"
)

// Re-exported capability types and sentinel errors so callers can discover
// the API from either the root cgroups package or the versioned package.
type (
	// CapabilityReport is the machine-readable controller diagnostic report.
	CapabilityReport = capabilities.Report
	// ControllerCapability is one controller's diagnostic status.
	ControllerCapability = capabilities.Controller
	// ControllerStatus is an alias for ControllerCapability.
	ControllerStatus = capabilities.Controller
	// CapabilityPolicy controls behavior when a limit cannot be enforced.
	CapabilityPolicy = capabilities.Policy
	// MissingCapabilityLimit describes a limit skipped by degrade policy.
	MissingCapabilityLimit = capabilities.MissingLimit
	// CapabilityUpdateReport is the result of a policy-aware resource update.
	CapabilityUpdateReport = capabilities.PolicyResult
)

const (
	// CapabilityPolicyStrict blocks updates when requested files are unavailable.
	CapabilityPolicyStrict = capabilities.PolicyStrict
	// CapabilityPolicyDegrade skips unavailable limits and reports them.
	CapabilityPolicyDegrade = capabilities.PolicyDegrade
)

// NewManagerWithPolicy creates a cgroup and applies resources with an explicit
// capability policy. Under degrade policy the returned report lists limits that
// were not enforced while the manager is still returned for startup.
func NewManagerWithPolicy(mountpoint, group string, resources *Resources, policy CapabilityPolicy) (*Manager, *CapabilityUpdateReport, error) {
	if resources == nil {
		return nil, nil, errors.New("resources reference is nil")
	}
	if err := VerifyGroupPath(group); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(mountpoint, group)
	if err := os.MkdirAll(path, defaultDirPerm); err != nil {
		return nil, nil, err
	}
	m := Manager{unifiedMountpoint: mountpoint, path: path}
	if err := m.ToggleControllers(resources.EnabledControllers(), Enable); err != nil {
		os.Remove(path)
		return nil, nil, err
	}
	report, err := m.UpdateWithPolicy(resources, policy)
	if err != nil {
		os.Remove(path)
		return nil, report, err
	}
	if err := setDevices(path, resources.Devices); err != nil {
		os.Remove(path)
		return nil, report, err
	}
	return &m, report, nil
}

// NewDegradedManager is NewManagerWithPolicy with CapabilityPolicyDegrade.
func NewDegradedManager(mountpoint, group string, resources *Resources) (*Manager, *CapabilityUpdateReport, error) {
	return NewManagerWithPolicy(mountpoint, group, resources, CapabilityPolicyDegrade)
}

var (
	// ErrControllerUnavailable is returned when a required controller is absent.
	ErrControllerUnavailable = capabilities.ErrControllerUnavailable
	// ErrControlFileNotWritable is returned when a target file cannot be written.
	ErrControlFileNotWritable = capabilities.ErrFileNotWritable
	// ErrControllerNotWritable is an alias for ErrControlFileNotWritable.
	ErrControllerNotWritable = capabilities.ErrControllerNotWritable
)

// ProbeCapabilities enumerates controllers and writable control files. By
// default it inspects the host mount table; pass capabilities options to
// probe fake roots in tests.
func ProbeCapabilities(opts ...capabilities.Option) (*capabilities.Report, error) {
	return capabilities.Probe(opts...)
}

// Probe is an alias for ProbeCapabilities.
func Probe(opts ...capabilities.Option) (*capabilities.Report, error) {
	return capabilities.Probe(opts...)
}

// Diagnose is an alias for ProbeCapabilities.
func Diagnose(opts ...capabilities.Option) (*capabilities.Report, error) {
	return capabilities.Diagnose(opts...)
}

// ProbeControllerStatuses returns only per-controller status objects.
func ProbeControllerStatuses(opts ...capabilities.Option) ([]ControllerStatus, error) {
	report, err := capabilities.Probe(opts...)
	if err != nil {
		return nil, err
	}
	return report.Controllers, nil
}

// Diagnostics returns a machine-readable capability report for this manager.
func (m *Manager) Diagnostics() (*capabilities.Report, error) {
	return m.Capabilities()
}

// ProbeDirectoryCapabilities probes an explicit cgroup directory.
func ProbeDirectoryCapabilities(path string) (*capabilities.Report, error) {
	return capabilities.ProbePath(path, capabilities.VersionV2)
}

// Capabilities probes the concrete cgroup managed by m without mutating it.
func (m *Manager) Capabilities() (*capabilities.Report, error) {
	return ProbeDirectoryCapabilities(m.path)
}

// UpdateWithPolicy writes resources according to policy. Strict policy is
// equivalent to Update but returns structured capability errors. Degrade
// policy skips unavailable limits and includes them in the returned report.
func (m *Manager) UpdateWithPolicy(resources *Resources, policy capabilities.Policy) (*capabilities.PolicyResult, error) {
	if resources == nil {
		return &capabilities.PolicyResult{Policy: policy}, nil
	}
	report, err := m.Capabilities()
	if err != nil {
		return nil, err
	}
	result := &capabilities.PolicyResult{Policy: policy}
	for _, v := range resources.Values() {
		controller := ControllerForFile(v.filename)
		limit := capabilities.RequestedLimit{
			Controller: controller,
			File:       v.filename,
			Value:      fmt.Sprint(v.value),
		}
		if err := capabilities.CheckWritable(report, controller, v.filename); err != nil {
			missing := capabilities.MissingLimit{
				RequestedLimit: limit,
				Reason:         capabilities.ReasonCapabilityCheckFailed,
				Detail:         err.Error(),
			}
			var unwritable *capabilities.UnwritableError
			if errors.As(err, &unwritable) {
				missing.Reason = unwritable.Reason
			}
			result.MissingLimits = append(result.MissingLimits, missing)
			if policy != capabilities.PolicyDegrade {
				result.Skipped = result.MissingLimits
				return result, fmt.Errorf("%w: %w", capabilities.ErrDegradedPolicy, err)
			}
			continue
		}
		if err := v.write(m.path, defaultFilePerm); err != nil {
			missing := capabilities.MissingLimit{
				RequestedLimit: limit,
				Reason:         capabilities.ReasonFileNotWritable,
				Detail:         err.Error(),
			}
			result.MissingLimits = append(result.MissingLimits, missing)
			if policy != capabilities.PolicyDegrade {
				result.Skipped = result.MissingLimits
				return result, fmt.Errorf("%w: %w: %w", capabilities.ErrDegradedPolicy, ErrControlFileNotWritable, err)
			}
			continue
		}
		result.Written = append(result.Written, limit)
		result.Applied = append(result.Applied, limit)
	}
	result.Skipped = result.MissingLimits
	return result, nil
}

// ControllerForFile maps a cgroup2 control filename to its controller.
func ControllerForFile(filename string) string {
	switch {
	case strings.HasPrefix(filename, "io."):
		return "io"
	case strings.HasPrefix(filename, "rdma."):
		return "rdma"
	case strings.HasPrefix(filename, "cpuset."):
		return "cpuset"
	case strings.HasPrefix(filename, "cpu."):
		return "cpu"
	case strings.HasPrefix(filename, "memory."):
		return "memory"
	case strings.HasPrefix(filename, "pids."):
		return "pids"
	case strings.HasPrefix(filename, "hugetlb."):
		return "hugetlb"
	case filename == "cgroup.freeze":
		return "freezer"
	default:
		return ""
	}
}

func ensureValueWritable(basePath, filename string) error {
	controller := ControllerForFile(filename)
	return capabilities.CheckBeforeWrite(filepath.Join(basePath, filename), controller)
}
