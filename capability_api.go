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

import "github.com/containerd/cgroups/v3/capabilities"

// CapabilityReport is a machine-readable controller capability diagnostic.
type CapabilityReport = capabilities.Report

// ControllerCapability is the availability diagnostic for one controller.
type ControllerCapability = capabilities.Controller

// ControllerStatus is an alias for ControllerCapability.
type ControllerStatus = capabilities.Controller

// SubsystemStatus is an alias for ControllerCapability.
type SubsystemStatus = capabilities.Controller

// CapabilityDiagnostic is an alias for CapabilityReport.
type CapabilityDiagnostic = capabilities.Report

// Diagnostics is an alias for the machine-readable capability report.
type Diagnostics = capabilities.Report

// CapabilityPolicy decides whether missing controllers block or degrade.
type CapabilityPolicy = capabilities.Policy

// Policy is an alias for CapabilityPolicy.
type Policy = capabilities.Policy

// RequestedLimit is an alias for the policy input type.
type RequestedLimit = capabilities.RequestedLimit

// RequestedCapabilityLimit identifies a resource file about to be written.
type RequestedCapabilityLimit = capabilities.RequestedLimit

// MissingLimit reports a limit that degradation skipped.
type MissingLimit = capabilities.MissingLimit

// MissingCapabilityLimit reports a limit that degradation skipped.
type MissingCapabilityLimit = capabilities.MissingLimit

// PolicyResult is the report returned by policy-aware writes.
type PolicyResult = capabilities.PolicyResult

// CapabilityPolicyResult is the report returned by policy-aware writes.
type CapabilityPolicyResult = capabilities.PolicyResult

// Capability probe policy and status constants.
const (
	PolicyStrict     = capabilities.PolicyStrict
	PolicyDegrade    = capabilities.PolicyDegrade
	PolicyContinue   = capabilities.PolicyContinue
	PolicyBestEffort = capabilities.PolicyBestEffort

	CapabilityPolicyStrict  = capabilities.PolicyStrict
	CapabilityPolicyDegrade = capabilities.PolicyDegrade

	ControllerAvailable = capabilities.StatusAvailable
	ControllerDegraded  = capabilities.StatusDegraded
	ControllerReadOnly  = capabilities.StatusReadOnly
	ControllerMissing   = capabilities.StatusMissing
)

// Capability sentinel errors.
var (
	ErrDegradedPolicy                  = capabilities.ErrDegradedPolicy
	ErrCapabilityControllerUnavailable = capabilities.ErrControllerUnavailable
	ErrCapabilityFileNotWritable       = capabilities.ErrFileNotWritable
	ErrCapabilityControllerNotWritable = capabilities.ErrControllerNotWritable
	ErrCapabilityDegradedPolicy        = capabilities.ErrDegradedPolicy

	ErrControllerUnavailable = capabilities.ErrControllerUnavailable
	ErrControllerNotWritable = capabilities.ErrControllerNotWritable
	ErrFileNotWritable       = capabilities.ErrFileNotWritable
)

// Probe is the canonical startup capability probe entry point.
func Probe(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Probe(opts...)
}

// ProbeCapabilities enumerates mounted cgroup controllers and writable files.
// The probe is read-only and safe to call repeatedly at startup.
func ProbeCapabilities(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Probe(opts...)
}

// DiagnoseCapabilities is an alias for ProbeCapabilities.
func DiagnoseCapabilities(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Probe(opts...)
}

// Diagnose is a short alias for DiagnoseCapabilities.
func Diagnose(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Probe(opts...)
}

// ProbeRoot probes an explicit fake/root directory.
func ProbeRoot(root string, opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.ProbeRoot(root, opts...)
}

// DetectCapabilities is an alias for ProbeCapabilities.
func DetectCapabilities(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Detect(opts...)
}

// Detect is an alias for DetectCapabilities.
func Detect(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Detect(opts...)
}

// CollectDiagnostics is an alias for ProbeCapabilities.
func CollectDiagnostics(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Probe(opts...)
}

// ProbeControllers is an alias for ProbeCapabilities.
func ProbeControllers(opts ...capabilities.Option) (*CapabilityReport, error) {
	return capabilities.Probe(opts...)
}

// EnumerateControllers returns just the per-controller status list.
func EnumerateControllers(opts ...capabilities.Option) ([]ControllerStatus, error) {
	report, err := capabilities.Probe(opts...)
	if err != nil {
		return nil, err
	}
	return report.Controllers, nil
}

// ProbeControllerStatuses is an alias for EnumerateControllers.
func ProbeControllerStatuses(opts ...capabilities.Option) ([]ControllerStatus, error) {
	return EnumerateControllers(opts...)
}

// GetCapabilities returns just the per-controller status list.
func GetCapabilities(opts ...capabilities.Option) ([]ControllerStatus, error) {
	return EnumerateControllers(opts...)
}

// CapabilityOption configures a capability probe.
type CapabilityOption = capabilities.Option

// WithCapabilityRoot prefixes proc and mount paths with root.
func WithCapabilityRoot(root string) CapabilityOption {
	return capabilities.WithRoot(root)
}

// WithRoot is an alias for WithCapabilityRoot.
func WithRoot(root string) CapabilityOption { return capabilities.WithRoot(root) }

// WithProcRoot reads /proc/self/mountinfo from an alternate proc root.
func WithProcRoot(root string) CapabilityOption {
	return capabilities.WithProcRoot(root)
}

// WithMountpoint sets an explicit cgroup mount point.
func WithMountpoint(path string) CapabilityOption {
	return capabilities.WithMountpoint(path)
}

// WithCapabilityMountInfo supplies a mountinfo file to the probe.
func WithCapabilityMountInfo(path string) CapabilityOption {
	return capabilities.WithMountInfo(path)
}

// WithMountInfo is an alias for WithCapabilityMountInfo.
func WithMountInfo(path string) CapabilityOption { return capabilities.WithMountInfo(path) }

// WithCapabilityTarget supplies the target cgroup directory to probe.
func WithCapabilityTarget(target string) CapabilityOption {
	return capabilities.WithTarget(target)
}

// WithTarget is an alias for WithCapabilityTarget.
func WithTarget(target string) CapabilityOption { return capabilities.WithTarget(target) }

// WithCapabilityControllers limits the probe to named controllers.
func WithCapabilityControllers(names ...string) CapabilityOption {
	return capabilities.WithControllers(names...)
}

// WithControllers is an alias for WithCapabilityControllers.
func WithControllers(names ...string) CapabilityOption {
	return capabilities.WithControllers(names...)
}

// CheckCapabilityWritable verifies that named file is writable for controller.
func CheckCapabilityWritable(report *CapabilityReport, controller, file string) error {
	return capabilities.CheckWritable(report, controller, file)
}

// NormalizeControllerName maps version-specific names such as blkio to io.
func NormalizeControllerName(name string) string {
	return capabilities.NormalizeName(name)
}
