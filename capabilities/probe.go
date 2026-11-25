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

// Package capabilities provides read-only cgroup controller capability
// probing and explicit degradation reporting.
//
// Probe never writes to a cgroup hierarchy. Writable files are checked with
// access(2), not by opening or writing control files, so repeated probes do
// not change system state.
package capabilities

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Version identifies a cgroup hierarchy version.
type Version string

const (
	// VersionUnknown means no supported cgroup hierarchy was detected.
	VersionUnknown Version = "unknown"
	// VersionV1 is a legacy cgroup v1 controller hierarchy.
	VersionV1 Version = "v1"
	// VersionV2 is the unified cgroup v2 hierarchy.
	VersionV2 Version = "v2"
	// VersionHybrid contains both v1 and v2 mounts.
	VersionHybrid Version = "hybrid"
)

// Status is the coarse availability state of one controller.
type Status string

const (
	StatusAvailable Status = "available"
	StatusDegraded  Status = "degraded"
	StatusReadOnly  Status = "read_only"
	StatusMissing   Status = "missing"
	StatusError     Status = "error"
)

// Stable machine-readable reason codes.
const (
	ReasonNone                  = ""
	ReasonNotMounted            = "not_mounted"
	ReasonMountPointMissing     = "mountpoint_missing"
	ReasonPathMissing           = "path_missing"
	ReasonControllerNotEnabled  = "controller_not_enabled"
	ReasonControllerNotListed   = "controller_not_listed"
	ReasonFileMissing           = "file_missing"
	ReasonFileNotWritable       = "file_not_writable"
	ReasonNoWritableFile        = "no_writable_file"
	ReasonAccessDenied          = "access_denied"
	ReasonNotADirectory         = "not_a_directory"
	ReasonMountInfoInvalid      = "mountinfo_invalid"
	ReasonCapabilityCheckFailed = "capability_check_failed"
)

// Diagnostics is an alternate name for a capability Report.
type Diagnostics = Report

// CapabilityReport is an alternate name for Report.
type CapabilityReport = Report

// Report is the machine-readable result of probing a host or a fake
// hierarchy root.
type Report struct {
	// Version is the host hierarchy mode. Individual controllers may still
	// report VersionV1 or VersionV2 in hybrid mode.
	Version Version `json:"version"`
	// CgroupVersion is an alias for Version.
	CgroupVersion Version `json:"cgroup_version"`
	// Hierarchy is "cgroup1", "cgroup2", "hybrid" or "unknown".
	Hierarchy string `json:"hierarchy"`
	// HierarchyVersion is the major hierarchy version: 1, 2 or 0 for mixed/unknown.
	HierarchyVersion int `json:"hierarchy_version"`
	// Root is the path prefix used for filesystem and proc inputs.
	Root string `json:"root,omitempty"`
	// Target is the optional cgroup directory relative to each mount point.
	Target string `json:"target,omitempty"`
	// Mounts contains all cgroup and cgroup2 mount table entries found.
	Mounts []Mount `json:"mounts"`
	// Controllers contains one entry per known or discovered controller.
	Controllers []Controller `json:"controllers"`
	// Subsystems is an alias for Controllers.
	Subsystems []Controller `json:"subsystems,omitempty"`
	// ControllerStatuses and Statuses are compatibility aliases for Controllers.
	ControllerStatuses []Controller `json:"controller_statuses,omitempty"`
	Statuses           []Controller `json:"statuses,omitempty"`
	// ByName and ControllersByName provide map-style lookup in addition to Get.
	ByName            map[string]Controller `json:"by_name,omitempty"`
	ControllersByName map[string]Controller `json:"controllers_by_name,omitempty"`
	// WritableControllers contains kernel names with at least one writable file.
	WritableControllers []string `json:"writable_controllers,omitempty"`
	// AvailableControllers contains kernel names that can accept resource writes.
	AvailableControllers []string `json:"available_controllers,omitempty"`
	// DegradedControllers contains available controllers with missing optional files.
	DegradedControllers []string `json:"degraded_controllers,omitempty"`
	// MissingControllers contains known controllers that are not usable.
	MissingControllers []string `json:"missing_controllers,omitempty"`
	// MissingLimits contains concrete required settings/files that cannot be enforced.
	MissingLimits []MissingLimit `json:"missing_limits,omitempty"`
	// UnenforcedLimits is an alias for MissingLimits.
	UnenforcedLimits []MissingLimit `json:"unenforced_limits,omitempty"`
	// OK/Ready/Healthy report whether every required probed file is writable.
	OK      bool `json:"ok"`
	Ready   bool `json:"ready"`
	Healthy bool `json:"healthy"`
	// Degraded is true when at least one controller is available but incomplete.
	Degraded bool `json:"degraded"`
}

// Mount describes one cgroup mount table entry.
type Mount struct {
	FSType      string   `json:"fstype"`
	Source      string   `json:"source,omitempty"`
	Root        string   `json:"mount_root,omitempty"`
	Mountpoint  string   `json:"mountpoint"`
	MountPoint  string   `json:"mount_point"`
	Options     []string `json:"options,omitempty"`
	Controllers []string `json:"controllers,omitempty"`
	Version     Version  `json:"version"`
}

// File describes the writability of one cgroup control file.
type File struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Controller    string `json:"controller,omitempty"`
	Limit         string `json:"limit,omitempty"`
	Required      bool   `json:"required,omitempty"`
	Exists        bool   `json:"exists"`
	Readable      bool   `json:"readable"`
	Writable      bool   `json:"writable"`
	Mode          uint32 `json:"mode,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
	MissingReason string `json:"missing_reason,omitempty"`
	Message       string `json:"message,omitempty"`
	Err           error  `json:"-"`
}

// Controller describes the availability of one cgroup controller.
type Controller struct {
	// Name is the kernel/on-disk controller name, for example blkio or io.
	Name string `json:"name"`
	// Controller is an alias for Name.
	Controller string `json:"controller"`
	// CanonicalName is the version-independent logical name ("io" for blkio/io).
	CanonicalName string   `json:"canonical_name"`
	Aliases       []string `json:"aliases,omitempty"`

	Status           Status  `json:"status"`
	State            Status  `json:"state"`
	Version          Version `json:"version"`
	CgroupVersion    Version `json:"cgroup_version"`
	Hierarchy        string  `json:"hierarchy"`
	HierarchyVersion int     `json:"hierarchy_version"`

	Mounted   bool `json:"mounted"`
	Active    bool `json:"active"`
	Listed    bool `json:"listed"`
	Exists    bool `json:"exists"`
	Available bool `json:"available"`
	Writable  bool `json:"writable"`
	Degraded  bool `json:"degraded"`
	ReadOnly  bool `json:"read_only"`

	// Mountpoint is the controller filesystem mount point.
	Mountpoint string `json:"mountpoint,omitempty"`
	// MountPoint is an alias for Mountpoint.
	MountPoint string `json:"mount_point,omitempty"`
	// Mountpoints contains every matching mount point. Combined v1 mounts
	// can expose more than one controller name at one location.
	Mountpoints []string `json:"mountpoints,omitempty"`
	MountPoints []string `json:"mount_points,omitempty"`
	// Path is the directory whose files are represented in Files.
	Path string `json:"path,omitempty"`

	Files         []File   `json:"files,omitempty"`
	WritableFiles []string `json:"writable_files,omitempty"`
	MissingFiles  []string `json:"missing_files,omitempty"`
	Limits        []string `json:"limits,omitempty"`

	Reason        string `json:"reason,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
	MissingReason string `json:"missing_reason,omitempty"`
	Message       string `json:"message,omitempty"`
	Err           error  `json:"-"`
}

// Get returns a controller by kernel name, canonical name or alias. Exact
// kernel names win over aliases so hybrid v1 blkio and v2 io stay distinct.
func (r *Report) Get(name string) *Controller {
	if r == nil {
		return nil
	}
	for i := range r.Controllers {
		c := &r.Controllers[i]
		if c.Name == name || c.Controller == name {
			return c
		}
	}
	for i := range r.Controllers {
		c := &r.Controllers[i]
		if c.CanonicalName == name {
			return c
		}
		for _, a := range c.Aliases {
			if a == name {
				return c
			}
		}
	}
	return nil
}

// Controller returns a controller by kernel name, canonical name or alias.
func (r Report) Controller(name string) (Controller, bool) {
	c := r.Get(name)
	if c == nil {
		return Controller{}, false
	}
	return *c, true
}

func (c Controller) matchesName(name string) bool {
	if c.Name == name || c.Controller == name || c.CanonicalName == name {
		return true
	}
	for _, a := range c.Aliases {
		if a == name {
			return true
		}
	}
	return false
}

// IsAvailable reports whether resource writes should currently succeed.
func (c Controller) IsAvailable() bool { return c.Available }

// IsWritable reports whether at least one controller-specific file is writable.
func (c Controller) IsWritable() bool { return c.Writable }

// IsMissing reports whether the controller is unusable.
func (c Controller) IsMissing() bool { return c.Status == StatusMissing || !c.Available }

// Missing returns true when the report contains unenforced limits.
func (r *Report) Missing() bool { return r != nil && len(r.MissingLimits) > 0 }

// JSON renders the report as indented JSON. It is intended for startup
// diagnostics and fleet-wide machine consumption.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteJSON writes indented machine-readable JSON to w.
func (r *Report) WriteJSON(w io.Writer) error {
	data, err := r.JSON()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type config struct {
	root           string
	procRoot       string
	mountInfoPath  string
	cgroupFilePath string
	mountpoint     string
	directory      string
	target         string
	names          []string
	allFiles       bool
	forcedVersion  Version
	access         func(path string, flags uint32) error
}

// Option configures a read-only capability probe.
type Option func(*config)

// WithRoot uses root as a chroot-like prefix for proc files and mount points.
// If <root>/proc/self/mountinfo exists it is parsed; otherwise root itself is
// treated as a fake cgroup hierarchy.
func WithRoot(root string) Option {
	return func(c *config) { c.root = root }
}

// WithProcRoot reads proc files from root/proc instead of the host /proc.
// Unlike WithRoot, mount points in mountinfo are not prefixed with root.
func WithProcRoot(root string) Option {
	return func(c *config) { c.procRoot = root }
}

// WithMountpoint is an alternate spelling of WithMountPoint.
func WithMountpoint(mountpoint string) Option {
	return WithMountPoint(mountpoint)
}

// WithMountInfo uses the provided mountinfo file instead of
// /proc/self/mountinfo (or <root>/proc/self/mountinfo when WithRoot is set).
func WithMountInfo(path string) Option {
	return func(c *config) { c.mountInfoPath = path }
}

// WithMountInfoPath is an alias for WithMountInfo.
func WithMountInfoPath(path string) Option { return WithMountInfo(path) }

// WithProcPath is an alias for WithProcRoot.
func WithProcPath(path string) Option { return WithProcRoot(path) }

// WithRootPath is an alias for WithRoot.
func WithRootPath(path string) Option { return WithRoot(path) }

// WithCgroupFile sets an optional /proc/<pid>/cgroup input. It is currently
// used only for diagnostics and tests.
func WithCgroupFile(path string) Option {
	return func(c *config) { c.cgroupFilePath = path }
}

// WithTarget probes files in target relative to each controller mount point.
// This is the cgroup directory that will receive resource writes.
func WithTarget(target string) Option {
	return func(c *config) { c.target = target }
}

// WithMountPoint sets an explicit controller mount point. It is useful when
// probing a constructed path without mountinfo.
func WithMountPoint(mountpoint string) Option {
	return func(c *config) { c.mountpoint = mountpoint }
}

// WithDirectory sets the exact directory whose files are checked. It is
// independent of Mountpoint, which remains available for diagnostics.
func WithDirectory(directory string) Option {
	return func(c *config) { c.directory = directory }
}

// WithControllers limits probing to the supplied controller names.
func WithControllers(names ...string) Option {
	return func(c *config) { c.names = append([]string(nil), names...) }
}

// WithoutDirectoryEnumeration disables enumeration of unexpected regular
// files in the probed directory. Known resource files are still checked.
func WithoutDirectoryEnumeration() Option {
	return func(c *config) { c.allFiles = false }
}

// AccessFunc reports whether path may be accessed with the supplied unix
// access flags (for example unix.W_OK). It is primarily an injection point for
// hermetic tests that must simulate EACCES while running as root.
type AccessFunc func(path string, flags uint32) error

// WithAccessFunc overrides the access(2) implementation used by Probe.
func WithAccessFunc(fn AccessFunc) Option {
	return func(c *config) { c.access = fn }
}

// withAccessFunc keeps the internal test helper spelling.
func withAccessFunc(fn func(path string, flags uint32) error) Option {
	return WithAccessFunc(fn)
}

// Probe enumerates cgroup mounts, controllers and writable resource files.
// It performs read-only filesystem operations and never writes to cgroupfs.
func Probe(opts ...Option) (*Report, error) {
	cfg := config{
		allFiles:      true,
		access:        unix.Access,
		forcedVersion: VersionUnknown,
	}
	for _, o := range opts {
		o(&cfg)
	}
	procPrefix := cfg.procRoot
	if procPrefix == "" {
		procPrefix = cfg.root
	}
	if cfg.mountInfoPath == "" {
		cfg.mountInfoPath = filepath.Join(procPrefix, "proc", "self", "mountinfo")
		if procPrefix == "" {
			cfg.mountInfoPath = "/proc/self/mountinfo"
		}
	}
	if cfg.cgroupFilePath == "" {
		cfg.cgroupFilePath = filepath.Join(procPrefix, "proc", "self", "cgroup")
		if procPrefix == "" {
			cfg.cgroupFilePath = "/proc/self/cgroup"
		}
	}

	rep := &Report{Root: cfg.root, Target: cfg.target}
	mounts, mountErr := parseMountInfo(cfg.mountInfoPath)
	if mountErr != nil && !errors.Is(mountErr, fs.ErrNotExist) {
		return nil, mountErr
	}
	for i := range mounts {
		mounts[i].Mountpoint = resolveUnderRoot(cfg.root, mounts[i].Mountpoint)
		mounts[i].MountPoint = mounts[i].Mountpoint
		mounts[i].Root = resolveUnderRoot(cfg.root, mounts[i].Root)
	}
	rep.Mounts = mounts
	rep.Version = detectHostVersion(mounts)
	rep.CgroupVersion = rep.Version
	rep.Hierarchy = hierarchyName(rep.Version)
	if rep.Version == VersionV1 {
		rep.HierarchyVersion = 1
	} else if rep.Version == VersionV2 {
		rep.HierarchyVersion = 2
	}

	specs := catalog()
	if len(cfg.names) > 0 {
		wanted := make(map[string]struct{}, len(cfg.names))
		for _, n := range cfg.names {
			wanted[n] = struct{}{}
		}
		filtered := specs[:0]
		for _, spec := range specs {
			if spec.selected(wanted) {
				filtered = append(filtered, spec)
			}
		}
		specs = filtered
	}

	if !hasCgroupMount(mounts) {
		mounts = inferMounts(cfg, specs, mounts)
		rep.Mounts = mounts
		if cfg.forcedVersion != VersionUnknown {
			rep.Version = cfg.forcedVersion
		} else if inferred := detectHostVersion(mounts); inferred != VersionUnknown {
			rep.Version = inferred
		}
		rep.CgroupVersion = rep.Version
		rep.Hierarchy = hierarchyName(rep.Version)
		rep.HierarchyVersion = versionNumber(rep.Version)
	}

	for _, spec := range specs {
		rep.Controllers = append(rep.Controllers, probeController(spec, cfg, mounts)...)
	}

	for i := range rep.Controllers {
		rep.Controllers[i].State = rep.Controllers[i].Status
		rep.Controllers[i].ReasonCode = rep.Controllers[i].Reason
		for j := range rep.Controllers[i].Files {
			rep.Controllers[i].Files[j].ReasonCode = rep.Controllers[i].Files[j].Reason
		}
	}
	summarize(rep)
	rep.Subsystems = rep.Controllers
	rep.ControllerStatuses = rep.Controllers
	rep.Statuses = rep.Controllers
	rep.ByName = make(map[string]Controller, len(rep.Controllers))
	rep.ControllersByName = make(map[string]Controller, len(rep.Controllers))
	for _, c := range rep.Controllers {
		for _, key := range append([]string{c.Name, c.Controller, c.CanonicalName}, c.Aliases...) {
			if key == "" {
				continue
			}
			rep.ByName[key] = c
			rep.ControllersByName[key] = c
		}
	}
	// Exact kernel names win over version-independent aliases.
	for _, c := range rep.Controllers {
		if c.Name != "" {
			rep.ByName[c.Name] = c
			rep.ControllersByName[c.Name] = c
		}
		if c.Controller != "" {
			rep.ByName[c.Controller] = c
			rep.ControllersByName[c.Controller] = c
		}
	}
	return rep, nil
}

func versionNumber(v Version) int {
	switch v {
	case VersionV1:
		return 1
	case VersionV2:
		return 2
	default:
		return 0
	}
}

// Detect is an alias for Probe.
func Detect(opts ...Option) (*Report, error) { return Probe(opts...) }

// ProbeRoot probes a chroot-like fake or real cgroup root directory.
func ProbeRoot(root string, opts ...Option) (*Report, error) {
	all := append([]Option{WithRoot(root)}, opts...)
	return Probe(all...)
}

// ProbeMountInfo probes using an explicit mountinfo file.
func ProbeMountInfo(mountInfoPath string, opts ...Option) (*Report, error) {
	all := append([]Option{WithMountInfo(mountInfoPath)}, opts...)
	return Probe(all...)
}

// Diagnose is an alias for Probe.
func Diagnose(opts ...Option) (*Report, error) { return Probe(opts...) }

// ProbePath probes a single cgroup directory. The hierarchy version is
// inferred from cgroup.controllers and known v1 subdirectories unless version
// is not VersionUnknown.
func ProbePath(path string, version Version, opts ...Option) (*Report, error) {
	allOpts := append([]Option{WithRoot(path)}, opts...)
	if version != VersionUnknown {
		allOpts = append(allOpts, withForcedVersion(version))
	}
	return Probe(allOpts...)
}

func withForcedVersion(v Version) Option {
	return func(c *config) { c.forcedVersion = v }
}

func hasCgroupMount(mounts []Mount) bool {
	for _, m := range mounts {
		if m.FSType == "cgroup" || m.FSType == "cgroup2" {
			return true
		}
	}
	return false
}

func resolveUnderRoot(root, path string) string {
	if root == "" || path == "" {
		return path
	}
	if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
		return path
	}
	return filepath.Join(root, path)
}

func hierarchyName(v Version) string {
	switch v {
	case VersionV1:
		return "cgroup1"
	case VersionV2:
		return "cgroup2"
	case VersionHybrid:
		return "hybrid"
	default:
		return "unknown"
	}
}

func detectHostVersion(mounts []Mount) Version {
	var v1, v2 bool
	for _, m := range mounts {
		switch m.FSType {
		case "cgroup2":
			v2 = true
		case "cgroup":
			v1 = true
		}
	}
	switch {
	case v1 && v2:
		return VersionHybrid
	case v2:
		return VersionV2
	case v1:
		return VersionV1
	default:
		return VersionUnknown
	}
}

func summarize(r *Report) {
	for i := range r.Controllers {
		c := &r.Controllers[i]
		if c.Writable {
			r.WritableControllers = append(r.WritableControllers, c.Name)
		}
		if c.Available {
			r.AvailableControllers = append(r.AvailableControllers, c.Name)
		}
		if c.Degraded {
			r.DegradedControllers = append(r.DegradedControllers, c.Name)
		}
		if !c.Available {
			r.MissingControllers = append(r.MissingControllers, c.Name)
		}
		for _, f := range c.Files {
			if !f.Required || f.Writable {
				continue
			}
			reason := firstNonEmpty(f.Reason, c.Reason, ReasonFileNotWritable)
			r.MissingLimits = append(r.MissingLimits, MissingLimit{
				RequestedLimit: RequestedLimit{
					Controller: c.Name,
					File:       f.Name,
					Setting:    f.Limit,
				},
				Status: c.Status,
				Reason: reason,
				Detail: firstNonEmpty(f.Message, c.Message),
			})
		}
	}
	r.UnenforcedLimits = append([]MissingLimit(nil), r.MissingLimits...)
	r.Degraded = len(r.DegradedControllers) > 0
	r.OK = len(r.MissingControllers) == 0 && len(r.MissingLimits) == 0
	r.Ready = r.OK
	r.Healthy = r.OK
	slices.Sort(r.WritableControllers)
	slices.Sort(r.AvailableControllers)
	slices.Sort(r.DegradedControllers)
	slices.Sort(r.MissingControllers)
}

// UnwritableError is returned by CheckWritable when a target control file
// cannot accept resource writes.
type UnwritableError struct {
	Controller string
	File       string
	Path       string
	Mountpoint string
	Version    Version
	Reason     string
	Err        error
}

func (e *UnwritableError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "cgroups: controller %q file %q is not writable", e.Controller, e.File)
	if e.Reason != "" {
		fmt.Fprintf(&b, ": %s", e.Reason)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	return b.String()
}

func (e *UnwritableError) Unwrap() error { return e.Err }

// Is reports whether the target error is a controller capability error.
func (e *UnwritableError) Is(target error) bool {
	_, ok := target.(*UnwritableError)
	return ok
}

// CheckWritable verifies that file in controller is present and writable in
// the supplied report. The report is expected to have been probed with the
// same target cgroup directory.
func CheckWritable(report *Report, controller, file string) error {
	if report == nil {
		return &UnwritableError{Controller: controller, File: file, Reason: ReasonCapabilityCheckFailed, Err: errors.New("nil capability report")}
	}
	c := report.Get(controller)
	if c == nil {
		return &UnwritableError{Controller: controller, File: file, Reason: ReasonNotMounted, Version: report.Version, Err: ErrControllerUnavailable}
	}
	for _, f := range c.Files {
		if f.Name != file && filepath.Base(f.Path) != file {
			continue
		}
		if f.Writable {
			return nil
		}
		err := f.Err
		if err == nil {
			err = errors.Join(ErrControllerUnavailable, ErrFileNotWritable)
		} else {
			err = errors.Join(ErrControllerUnavailable, ErrFileNotWritable, err)
		}
		return &UnwritableError{
			Controller: c.Name, File: file, Path: f.Path, Mountpoint: c.Mountpoint,
			Version: c.Version, Reason: firstNonEmpty(f.Reason, f.MissingReason, c.Reason), Err: err,
		}
	}
	return &UnwritableError{
		Controller: c.Name, File: file, Mountpoint: c.Mountpoint, Version: c.Version,
		Reason: ReasonFileMissing,
		Err:    errors.Join(ErrControllerUnavailable, ErrFileNotWritable, fmt.Errorf("%s: %w", file, fs.ErrNotExist)),
	}
}

var (
	// ErrControllerUnavailable means a controller cannot accept requested limits.
	ErrControllerUnavailable = errors.New("cgroups: controller unavailable")
	// ErrFileNotWritable means a control file is absent or not writable.
	ErrFileNotWritable = errors.New("cgroups: control file not writable")
	// ErrControllerNotWritable is an alias for ErrFileNotWritable.
	ErrControllerNotWritable = ErrFileNotWritable
	// ErrDegradedPolicy means strict policy rejected one or more missing limits.
	ErrDegradedPolicy = errors.New("cgroups: resource limit degraded")
)

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
