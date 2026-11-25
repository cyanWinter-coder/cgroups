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
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/containerd/cgroups/v3/capabilities"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type (
	// CapabilityReport is the machine-readable cgroup v1 capability report.
	CapabilityReport = capabilities.Report
	// ControllerCapability is one cgroup v1 controller diagnostic.
	ControllerCapability = capabilities.Controller
	// SubsystemStatus is an alias for ControllerCapability.
	SubsystemStatus = capabilities.Controller
	// SubsystemInfo is an alias for SubsystemStatus.
	SubsystemInfo = capabilities.Controller
	// CapabilityPolicy controls partial-controller behavior.
	CapabilityPolicy = capabilities.Policy
	// CapabilityUpdateReport records applied and skipped resource limits.
	CapabilityUpdateReport = capabilities.PolicyResult
)

const (
	// CapabilityPolicyStrict returns an error when a requested controller is unavailable.
	CapabilityPolicyStrict = capabilities.PolicyStrict
	// CapabilityPolicyDegrade skips unavailable controllers and reports their limits.
	CapabilityPolicyDegrade = capabilities.PolicyDegrade
)

var (
	// ErrControllerUnavailable indicates a requested subsystem is not active/writable.
	ErrControllerUnavailable = capabilities.ErrControllerUnavailable
	// ErrControlFileNotWritable indicates a target control file is not writable.
	ErrControlFileNotWritable = capabilities.ErrFileNotWritable
	// ErrControllerNotWritable is an alias for ErrControlFileNotWritable.
	ErrControllerNotWritable = capabilities.ErrControllerNotWritable
)

// ProbeCapabilities enumerates cgroup v1 mounts/controllers and writable files.
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

// ProbeSubsystems returns only the per-subsystem capability statuses.
func ProbeSubsystems(opts ...capabilities.Option) ([]SubsystemStatus, error) {
	report, err := capabilities.Probe(opts...)
	if err != nil {
		return nil, err
	}
	return report.Controllers, nil
}

// EnumerateSubsystems is an alias for ProbeSubsystems.
func EnumerateSubsystems(opts ...capabilities.Option) ([]SubsystemStatus, error) {
	return ProbeSubsystems(opts...)
}

// SubsystemDiagnostics returns the subsystem statuses for a Cgroup handle.
func SubsystemDiagnostics(cg Cgroup) ([]SubsystemStatus, error) {
	report, err := DiagnosticsOf(cg)
	if err != nil {
		return nil, err
	}
	return report.Controllers, nil
}

// Diagnostics returns a machine-readable capability report for this cgroup.
func (c *cgroup) Diagnostics() (*capabilities.Report, error) {
	return c.Capabilities()
}

// DiagnosticsOf returns capability diagnostics for an arbitrary Cgroup.
func DiagnosticsOf(cg Cgroup) (*capabilities.Report, error) {
	return CapabilitiesOf(cg)
}

// CapabilityReporter is implemented by cgroup handles that expose explicit
// capability diagnostics without changing the baseline Cgroup interface.
type CapabilityReporter interface {
	Capabilities() (*capabilities.Report, error)
	Diagnostics() (*capabilities.Report, error)
}

// PolicyUpdater is implemented by handles supporting degradation policies.
type PolicyUpdater interface {
	UpdateWithPolicy(*specs.LinuxResources, capabilities.Policy) (*capabilities.PolicyResult, error)
}

// Capabilities returns a diagnostic report for this concrete cgroup. It
// includes subsystems known to the configured hierarchy even when they were
// skipped during New or Load and therefore are not returned by Subsystems.
func (c *cgroup) Capabilities() (*capabilities.Report, error) {
	return c.capabilityReport()
}

// CapabilitiesOf returns cgroup capability diagnostics when cg is the
// package's concrete Cgroup implementation.
func CapabilitiesOf(cg Cgroup) (*capabilities.Report, error) {
	if c, ok := cg.(*cgroup); ok {
		return c.Capabilities()
	}
	return nil, fmt.Errorf("%w: external Cgroup implementation does not expose capability diagnostics", ErrControllerUnavailable)
}

// LastUpdateReport returns the degradation report from the most recent Update.
func (c *cgroup) LastUpdateReport() *capabilities.PolicyResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastReport
}

// UpdateWithPolicy applies resources using the supplied degradation policy.
func (c *cgroup) UpdateWithPolicy(resources *specs.LinuxResources, policy capabilities.Policy) (*capabilities.PolicyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	result, err := c.updateWithPolicyLocked(resources, policy)
	c.lastReport = result
	return result, err
}

// UpdateWithPolicy applies resources through an arbitrary Cgroup handle. It
// returns ErrControllerUnavailable for external implementations that do not
// expose the package's capability metadata.
func UpdateWithPolicy(cg Cgroup, resources *specs.LinuxResources, policy capabilities.Policy) (*capabilities.PolicyResult, error) {
	c, ok := cg.(*cgroup)
	if !ok {
		return nil, fmt.Errorf("%w: external Cgroup implementation does not support policy updates", ErrControllerUnavailable)
	}
	return c.UpdateWithPolicy(resources, policy)
}

// DegradedUpdate applies resources with CapabilityPolicyDegrade.
func DegradedUpdate(cg Cgroup, resources *specs.LinuxResources) (*capabilities.PolicyResult, error) {
	return UpdateWithPolicy(cg, resources, CapabilityPolicyDegrade)
}

func (c *cgroup) updateWithPolicyLocked(resources *specs.LinuxResources, policy capabilities.Policy) (*capabilities.PolicyResult, error) {
	result := &capabilities.PolicyResult{Policy: policy}
	requested := requestedSubsystems(resources)

	for _, name := range requested {
		s := c.getSubsystem(name)
		if s == nil {
			all := c.getAllSubsystem(name)
			reason := capabilities.ReasonNotMounted
			if all != nil {
				reason = capabilities.ReasonControllerNotEnabled
			}
			missing := capabilities.MissingLimit{
				RequestedLimit: capabilities.RequestedLimit{Controller: string(name)},
				Reason:         reason,
				Detail:         fmt.Sprintf("cgroup v1 subsystem %q is not active", name),
			}
			result.MissingLimits = append(result.MissingLimits, missing)
			if policy != capabilities.PolicyDegrade {
				result.Skipped = result.MissingLimits
				return result, fmt.Errorf("%w: %w: cgroup v1 subsystem %q is not active", ErrControllerUnavailable, ErrControllerNotActive, name)
			}
			continue
		}

		sp, err := c.path(name)
		if err != nil {
			missing := capabilities.MissingLimit{
				RequestedLimit: capabilities.RequestedLimit{Controller: string(name)},
				Reason:         capabilities.ReasonPathMissing,
				Detail:         err.Error(),
			}
			result.MissingLimits = append(result.MissingLimits, missing)
			if policy != capabilities.PolicyDegrade {
				result.Skipped = result.MissingLimits
				if errors.Is(err, ErrControllerNotActive) {
					return result, fmt.Errorf("%w: %w", ErrControllerUnavailable, err)
				}
				return result, err
			}
			continue
		}

		if p, ok := s.(pather); ok {
			dir := p.Path(sp)
			if err := capabilities.CheckBeforeWrite(dir, string(name)); err != nil {
				missing := capabilities.MissingLimit{
					RequestedLimit: capabilities.RequestedLimit{Controller: string(name)},
					Reason:         capabilities.ReasonFileNotWritable,
					Detail:         err.Error(),
				}
				var unwritable *capabilities.UnwritableError
				if errors.As(err, &unwritable) && unwritable.Reason != "" {
					missing.Reason = unwritable.Reason
				}
				result.MissingLimits = append(result.MissingLimits, missing)
				if policy != capabilities.PolicyDegrade {
					result.Skipped = result.MissingLimits
					return result, fmt.Errorf("cgroups: subsystem %s path %s is not writable: %w", name, dir, err)
				}
				continue
			}
		}

		u, ok := s.(updater)
		if !ok {
			continue
		}
		if err := u.Update(sp, resources); err != nil {
			missing := capabilities.MissingLimit{
				RequestedLimit: capabilities.RequestedLimit{Controller: string(name)},
				Reason:         capabilities.ReasonCapabilityCheckFailed,
				Detail:         err.Error(),
			}
			result.MissingLimits = append(result.MissingLimits, missing)
			if policy != capabilities.PolicyDegrade {
				result.Skipped = result.MissingLimits
				return result, fmt.Errorf("cgroups: subsystem %s resource write failed: %w: %w", name, ErrControlFileNotWritable, err)
			}
			continue
		}
		result.Applied = append(result.Applied, capabilities.RequestedLimit{Controller: string(name)})
		result.Written = result.Applied
	}
	result.Skipped = result.MissingLimits
	return result, nil
}

func (c *cgroup) getAllSubsystem(n Name) Subsystem {
	for _, s := range c.allSubsystems {
		if s.Name() == n {
			return s
		}
	}
	return nil
}

func (c *cgroup) capabilityReport() (*capabilities.Report, error) {
	report := &capabilities.Report{
		Version:          capabilities.VersionV1,
		CgroupVersion:    capabilities.VersionV1,
		Hierarchy:        "cgroup1",
		HierarchyVersion: 1,
	}
	subsystems := c.allSubsystems
	if len(subsystems) == 0 {
		subsystems = c.subsystems
	}
	for _, s := range subsystems {
		name := s.Name()
		active := c.getSubsystem(name) != nil
		controller := capabilities.Controller{
			Name: string(name), Controller: string(name), CanonicalName: capabilities.NormalizeName(string(name)),
			Version: capabilities.VersionV1, CgroupVersion: capabilities.VersionV1,
			Hierarchy: "cgroup1", HierarchyVersion: 1,
			Mounted: active,
			Active:  active,
		}
		p, ok := s.(pather)
		if ok {
			root := p.Path("/")
			if _, err := os.Stat(root); err == nil {
				controller.Mounted = true
			}
			controller.Mountpoint = root
			controller.MountPoint = root
			controller.Mountpoints = []string{root}
			controller.MountPoints = []string{root}
			if sp, err := c.path(name); err == nil {
				dir := p.Path(sp)
				controller.Path = dir
				if r, perr := capabilities.ProbePath(dir, capabilities.VersionV1,
					capabilities.WithMountInfo(os.DevNull),
					capabilities.WithControllers(string(name)),
					capabilities.WithMountPoint(root),
					capabilities.WithDirectory(dir),
				); perr == nil {
					if rc := r.Get(string(name)); rc != nil {
						controller = *rc
						controller.Active = active
						if _, statErr := os.Stat(root); statErr != nil {
							controller.Mounted = false
						} else {
							controller.Mounted = true
						}
						controller.Mountpoint = root
						controller.MountPoint = root
						controller.Mountpoints = []string{root}
						controller.MountPoints = []string{root}
						controller.Path = dir
					}
				}
			} else {
				controller.Reason = capabilities.ReasonNotMounted
				controller.MissingReason = ErrControllerNotActive.Error()
				controller.Message = err.Error()
				controller.Err = err
			}
		}
		report.Controllers = append(report.Controllers, controller)
	}
	return report, nil
}

func isCapabilityWriteError(err error) bool {
	return errors.Is(err, ErrControlFileNotWritable) ||
		os.IsNotExist(err) ||
		os.IsPermission(err) ||
		errors.Is(err, syscall.EROFS)
}

func requestedSubsystems(r *specs.LinuxResources) []Name {
	if r == nil {
		return nil
	}
	var out []Name
	add := func(n Name) {
		for _, existing := range out {
			if existing == n {
				return
			}
		}
		out = append(out, n)
	}
	if r.BlockIO != nil && blockIOHasLimits(r.BlockIO) {
		add(Blkio)
	}
	if len(r.Rdma) > 0 {
		for _, limit := range r.Rdma {
			if limit.HcaHandles != nil || limit.HcaObjects != nil {
				add(Rdma)
				break
			}
		}
	}
	if r.CPU != nil {
		if cpuHasLimits(r.CPU) {
			add(Cpu)
		}
		if r.CPU.Cpus != "" || r.CPU.Mems != "" {
			add(Cpuset)
		}
	}
	if r.Network != nil && r.Network.ClassID != nil && *r.Network.ClassID > 0 {
		add(NetCLS)
	}
	if r.Memory != nil && memoryHasLimits(r.Memory) {
		add(Memory)
	}
	if r.Pids != nil && r.Pids.Limit != nil && *r.Pids.Limit != 0 {
		add(Pids)
	}
	if len(r.HugepageLimits) > 0 {
		add(Hugetlb)
	}
	if len(r.Devices) > 0 {
		add(Devices)
	}
	return out
}

func blockIOHasLimits(b *specs.LinuxBlockIO) bool {
	if b.Weight != nil && *b.Weight != 0 {
		return true
	}
	if b.LeafWeight != nil && *b.LeafWeight != 0 {
		return true
	}
	return len(b.WeightDevice) > 0 ||
		len(b.ThrottleReadBpsDevice) > 0 ||
		len(b.ThrottleWriteBpsDevice) > 0 ||
		len(b.ThrottleReadIOPSDevice) > 0 ||
		len(b.ThrottleWriteIOPSDevice) > 0
}

func cpuHasLimits(c *specs.LinuxCPU) bool {
	return c.Shares != nil || c.Quota != nil || c.Period != nil || c.RealtimeRuntime != nil || c.RealtimePeriod != nil
}

func memoryHasLimits(m *specs.LinuxMemory) bool {
	return m.Limit != nil || m.Reservation != nil || m.Swap != nil || m.Kernel != nil || m.KernelTCP != nil || m.Swappiness != nil || m.DisableOOMKiller != nil
}
