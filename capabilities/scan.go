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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func inferMounts(cfg config, specs []controllerSpec, existing []Mount) []Mount {
	mounts := append([]Mount(nil), existing...)
	if cfg.root == "" {
		return mounts
	}
	if cfg.forcedVersion == VersionV2 || looksLikeV2Root(cfg.root, specs) {
		if !hasMountpoint(mounts, cfg.root, "cgroup2") {
			mounts = append(mounts, Mount{
				FSType: "cgroup2", Version: VersionV2, Mountpoint: cfg.root, MountPoint: cfg.root,
			})
		}
	}
	if cfg.forcedVersion != VersionV2 {
		entries, _ := os.ReadDir(cfg.root)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			names := strings.Split(entry.Name(), ",")
			matched := false
			for _, spec := range specs {
				for _, candidate := range append(append([]string{}, spec.v1Names...), spec.aliases...) {
					for _, n := range names {
						if n == candidate {
							matched = true
						}
					}
				}
			}
			if matched {
				mp := filepath.Join(cfg.root, entry.Name())
				if !hasMountpoint(mounts, mp, "cgroup") {
					mounts = append(mounts, Mount{
						FSType: "cgroup", Version: VersionV1, Mountpoint: mp, MountPoint: mp,
						Controllers: names,
					})
				}
			}
		}

		// ProbePath can point directly at a controller directory containing
		// rdma.max/blkio.* files rather than at the common cgroup root. When
		// the directory is already recognizable as cgroup v2, identically
		// named files such as rdma.max must not create a phantom v1 mount.
		if cfg.forcedVersion == VersionV1 || !looksLikeV2Root(cfg.root, specs) {
			for _, spec := range specs {
				if directFilesExist(cfg.root, spec.v1Files) {
					name := spec.v1Names[0]
					if !hasControllerMountAt(mounts, cfg.root, name) {
						mounts = append(mounts, Mount{
							FSType: "cgroup", Version: VersionV1, Mountpoint: cfg.root, MountPoint: cfg.root,
							Controllers: []string{name},
						})
					}
				}
			}
		}
	}
	return mounts
}

func hasMountpoint(mounts []Mount, mp, fsType string) bool {
	for _, m := range mounts {
		if m.Mountpoint == mp && (fsType == "" || m.FSType == fsType) {
			return true
		}
	}
	return false
}

func hasControllerMountAt(mounts []Mount, mp, controller string) bool {
	for _, m := range mounts {
		if m.Mountpoint != mp || m.FSType != "cgroup" {
			continue
		}
		for _, c := range m.Controllers {
			if c == controller {
				return true
			}
		}
	}
	return false
}

func looksLikeV2Root(root string, specs []controllerSpec) bool {
	if _, err := os.Stat(filepath.Join(root, controllersFile)); err == nil {
		return true
	}
	for _, spec := range specs {
		if directFilesExist(root, spec.v2Files) {
			return true
		}
	}
	return false
}

func directFilesExist(dir string, specs []fileSpec) bool {
	for _, f := range specs {
		if f.glob {
			matches, _ := filepath.Glob(filepath.Join(dir, f.name))
			if len(matches) > 0 {
				return true
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, f.name)); err == nil {
			return true
		}
	}
	return false
}

const controllersFile = "cgroup.controllers"

func probeController(spec controllerSpec, cfg config, mounts []Mount) []Controller {
	var out []Controller
	if cfg.forcedVersion == VersionV2 {
		if c, ok := probeControllerVersion(spec, cfg, mounts, VersionV2); ok {
			out = append(out, c)
		}
		return out
	}
	if cfg.forcedVersion == VersionV1 {
		if c, ok := probeControllerVersion(spec, cfg, mounts, VersionV1); ok {
			out = append(out, c)
		}
		return out
	}

	// Prefer v2 when both are present for the same logical controller. In
	// hybrid mode both are returned so callers can see exactly what is mounted.
	if c, ok := probeControllerVersion(spec, cfg, mounts, VersionV2); ok {
		out = append(out, c)
	}
	if c, ok := probeControllerVersion(spec, cfg, mounts, VersionV1); ok {
		out = append(out, c)
	}
	if len(out) == 0 {
		out = append(out, missingController(spec, cfg))
	}
	return out
}

func probeControllerVersion(spec controllerSpec, cfg config, mounts []Mount, version Version) (Controller, bool) {
	names := spec.v2Names
	fsType := "cgroup2"
	fileSpecs := spec.v2Files
	if version == VersionV1 {
		names = spec.v1Names
		fsType = "cgroup"
		fileSpecs = spec.v1Files
	}
	if len(names) == 0 {
		return Controller{}, false
	}

	var matched []Mount
	for _, m := range mounts {
		if m.FSType != fsType {
			continue
		}
		if version == VersionV2 {
			matched = append(matched, m)
			continue
		}
		for _, mc := range m.Controllers {
			if slicesContains(names, mc) {
				matched = append(matched, m)
				break
			}
		}
	}
	if len(matched) == 0 && cfg.mountpoint != "" {
		m := Mount{FSType: fsType, Version: version, Mountpoint: cfg.mountpoint, MountPoint: cfg.mountpoint}
		if version == VersionV1 {
			m.Controllers = append([]string{}, names...)
		}
		matched = append(matched, m)
	}
	if len(matched) == 0 {
		return Controller{}, false
	}

	kernelName := names[0]
	c := Controller{
		Name: kernelName, Controller: kernelName, CanonicalName: spec.canonical,
		Aliases: append(append([]string{}, spec.aliases...), otherVersionNames(spec, version)...),
		Version: version, CgroupVersion: version, Hierarchy: hierarchyName(version),
		HierarchyVersion: versionNumber(version),
		Mounted:          true,
	}
	for _, m := range matched {
		c.Mountpoints = append(c.Mountpoints, m.Mountpoint)
		c.MountPoints = append(c.MountPoints, m.Mountpoint)
	}
	// Use the first mount as the primary location. Combined v1 controller
	// mounts expose the same directory through all controller names.
	c.Mountpoint = matched[0].Mountpoint
	c.MountPoint = c.Mountpoint
	c.Path = c.Mountpoint
	switch {
	case cfg.directory != "":
		c.Path = cfg.directory
	case cfg.target != "":
		c.Path = filepath.Join(c.Mountpoint, filepath.Clean("/"+cfg.target))
	}

	dirInfo, err := os.Stat(c.Path)
	switch {
	case err == nil && dirInfo.IsDir():
		c.Exists = true
	case err == nil:
		c.Exists = true
		c.Reason = ReasonNotADirectory
		c.MissingReason = ReasonNotADirectory
		c.Message = fmt.Sprintf("probe path %s is not a directory", c.Path)
		c.Err = fmt.Errorf("%w: %s", ErrControllerUnavailable, c.Message)
		return finalizeController(c, nil), true
	case errors.Is(err, fs.ErrNotExist):
		c.Exists = false
		if cfg.target != "" {
			c.Reason = ReasonPathMissing
			c.MissingReason = ReasonPathMissing
			c.Message = "target cgroup directory does not exist"
		} else {
			c.Reason = ReasonMountPointMissing
			c.MissingReason = ReasonMountPointMissing
			c.Message = "controller mount point does not exist"
		}
		c.Err = err
		return finalizeController(c, nil), true
	default:
		c.Reason = ReasonCapabilityCheckFailed
		c.MissingReason = ReasonCapabilityCheckFailed
		c.Message = err.Error()
		c.Err = err
		return finalizeController(c, nil), true
	}

	c.Listed = controllerListed(c, kernelName, cfg.access)
	files := checkKnownFiles(c, fileSpecs, cfg.access)
	if cfg.allFiles {
		files = appendActualFiles(c, spec, files, cfg.access)
	}
	c.Files = files
	return finalizeController(c, &spec), true
}

func otherVersionNames(spec controllerSpec, version Version) []string {
	if version == VersionV1 {
		return append([]string{}, spec.v2Names...)
	}
	return append([]string{}, spec.v1Names...)
}

func controllerListed(c Controller, name string, access func(string, uint32) error) bool {
	// The target's cgroup.controllers is authoritative for that cgroup. Fall
	// back to the hierarchy root when probing the root itself or when the
	// target file is absent in a fake fixture.
	for _, p := range []string{filepath.Join(c.Path, controllersFile), filepath.Join(c.Mountpoint, controllersFile)} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		listed := slicesContains(strings.Fields(string(b)), name)
		if p == filepath.Join(c.Path, controllersFile) {
			return listed
		}
		return listed
	}
	// No controllers file means this fixture/kernel interface does not make
	// enabled-state explicit. Do not turn that absence into a false negative.
	return true
}

func checkKnownFiles(c Controller, specs []fileSpec, access func(string, uint32) error) []File {
	var files []File
	byName := map[string]int{}
	for _, spec := range specs {
		if spec.glob {
			matches, _ := filepath.Glob(filepath.Join(c.Path, spec.name))
			if len(matches) == 0 {
				f := checkFile(c, spec.name, spec.limit, spec.required, access)
				files = append(files, f)
				byName[f.Name] = len(files) - 1
				continue
			}
			for _, match := range matches {
				name := filepath.Base(match)
				f := checkFile(c, name, spec.limit, spec.required, access)
				files = append(files, f)
				byName[f.Name] = len(files) - 1
			}
			continue
		}
		f := checkFile(c, spec.name, spec.limit, spec.required, access)
		files = append(files, f)
		byName[f.Name] = len(files) - 1
	}
	return files
}

func appendActualFiles(c Controller, spec controllerSpec, known []File, access func(string, uint32) error) []File {
	entries, err := os.ReadDir(c.Path)
	if err != nil {
		return known
	}
	prefixes := controllerPrefixes(c, &spec)
	seen := map[string]struct{}{}
	for _, f := range known {
		seen[f.Name] = struct{}{}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, ok := seen[name]; ok {
			continue
		}
		if !fileBelongsToController(name, prefixes) {
			continue
		}
		info, err := entry.Info()
		mode := uint32(0)
		if err == nil {
			mode = uint32(info.Mode().Perm())
		}
		f := checkFile(c, name, "", false, access)
		if err == nil {
			f.Mode = mode
		}
		known = append(known, f)
		seen[name] = struct{}{}
	}
	return known
}

func checkFile(c Controller, name, limit string, required bool, access func(string, uint32) error) File {
	path := filepath.Join(c.Path, name)
	f := File{
		Name: name, Path: path, Controller: c.Name, Limit: limit, Required: required,
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			f.Reason = ReasonFileMissing
			f.MissingReason = ReasonFileMissing
			f.Message = "control file does not exist"
		} else {
			f.Reason = ReasonCapabilityCheckFailed
			f.MissingReason = ReasonCapabilityCheckFailed
			f.Message = err.Error()
		}
		f.Err = err
		return f
	}
	f.Exists = true
	f.Mode = uint32(info.Mode().Perm())
	if access(path, unix.R_OK) == nil {
		f.Readable = true
	}
	if err := access(path, unix.W_OK); err == nil {
		f.Writable = true
	} else {
		f.Err = err
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			f.Reason = ReasonFileNotWritable
			f.MissingReason = ReasonFileNotWritable
			f.Message = "control file exists but is not writable by this process"
		} else {
			f.Reason = ReasonCapabilityCheckFailed
			f.MissingReason = ReasonCapabilityCheckFailed
			f.Message = err.Error()
		}
	}
	return f
}

func finalizeController(c Controller, spec *controllerSpec) Controller {
	controllerSpecific := false
	primaryWritable := false
	anyExisting := false
	anyWritable := false
	var missing []string
	var writable []string
	var limits []string

	prefixes := controllerPrefixes(c, spec)
	for _, f := range c.Files {
		if f.Limit != "" {
			limits = append(limits, f.Limit)
		}
		if f.Writable {
			writable = append(writable, f.Name)
		}
		if !f.Exists {
			if f.Required {
				missing = append(missing, f.Name)
			}
			continue
		}
		anyExisting = true
		if f.Writable {
			anyWritable = true
		}
		if fileBelongsToController(f.Name, prefixes) {
			controllerSpecific = true
			if f.Writable {
				if f.Required || spec == nil {
					primaryWritable = true
				}
			}
		}
		if f.Required && (!f.Exists || !f.Writable) {
			missing = append(missing, f.Name)
		}
	}
	c.WritableFiles = writable
	c.MissingFiles = uniqueSorted(missing)
	c.Limits = uniqueSorted(limits)
	c.Writable = controllerSpecific && anyWritable && hasWritableControllerFile(c.Files, prefixes)

	if spec != nil && spec.noFileController && c.Version == VersionV2 {
		c.Available = c.Mounted && c.Exists && c.Listed
	} else if spec != nil && hasRequiredSpec(spec) {
		c.Available = c.Mounted && c.Exists && c.Listed && primaryWritable
	} else {
		c.Available = c.Mounted && c.Exists && c.Listed && c.Writable
	}

	c.ReadOnly = c.Exists && controllerSpecific && !c.Writable
	c.Degraded = c.Available && len(c.MissingFiles) > 0

	switch {
	case !c.Mounted:
		c.Status = StatusMissing
		c.Reason = firstNonEmpty(c.Reason, ReasonNotMounted)
	case !c.Exists:
		c.Status = StatusMissing
		// Reason was set by caller.
	case !c.Listed:
		c.Status = StatusMissing
		c.Reason = ReasonControllerNotListed
		c.MissingReason = ReasonControllerNotEnabled
		c.Message = fmt.Sprintf("controller %q is not listed in cgroup.controllers", c.Name)
		c.Err = fmt.Errorf("%w: %s", ErrControllerUnavailable, c.Message)
	case c.Available && c.Degraded:
		c.Status = StatusDegraded
		c.Reason = "some_required_files_unavailable"
		c.MissingReason = fmt.Sprintf("missing or unwritable files: %s", strings.Join(c.MissingFiles, ", "))
		c.Message = c.MissingReason
	case c.Available:
		c.Status = StatusAvailable
		c.Reason = ""
		c.MissingReason = ""
		c.Message = ""
	case c.ReadOnly || (anyExisting && !anyWritable):
		c.Status = StatusReadOnly
		c.Reason = ReasonFileNotWritable
		c.MissingReason = ReasonNoWritableFile
		c.Message = "controller files exist but are not writable"
		c.Err = fmt.Errorf("%w: %s", ErrFileNotWritable, c.Name)
	default:
		c.Status = StatusMissing
		c.Reason = firstNonEmpty(c.Reason, ReasonNoWritableFile, ReasonFileMissing)
		c.MissingReason = c.Reason
		c.Message = firstNonEmpty(c.Message, "no writable controller resource file found")
		c.Err = firstErr(c.Err, fmt.Errorf("%w: %s", ErrControllerUnavailable, c.Name))
	}
	return c
}

func hasRequiredSpec(spec *controllerSpec) bool {
	if spec == nil {
		return false
	}
	files := spec.v2Files
	if len(spec.v1Names) > 0 && len(spec.v2Names) == 0 {
		files = spec.v1Files
	}
	for _, f := range files {
		if f.required {
			return true
		}
	}
	return false
}

func controllerPrefixes(c Controller, spec *controllerSpec) []string {
	prefixSet := map[string]struct{}{c.Name + ".": {}}
	switch c.Name {
	case "blkio":
		prefixSet["blkio."] = struct{}{}
	case "io":
		prefixSet["io."] = struct{}{}
	case "rdma":
		prefixSet["rdma."] = struct{}{}
	case "cpu", "cpuacct":
		prefixSet["cpu."] = struct{}{}
		prefixSet["cpuacct."] = struct{}{}
	case "cpuset":
		prefixSet["cpuset."] = struct{}{}
	case "memory":
		prefixSet["memory."] = struct{}{}
	case "pids":
		prefixSet["pids."] = struct{}{}
	case "hugetlb":
		prefixSet["hugetlb."] = struct{}{}
	case "freezer":
		if c.Version == VersionV2 {
			prefixSet["cgroup.freeze"] = struct{}{}
		} else {
			prefixSet["freezer."] = struct{}{}
		}
	case "devices":
		prefixSet["devices."] = struct{}{}
	case "net_cls":
		prefixSet["net_cls."] = struct{}{}
	case "net_prio":
		prefixSet["net_prio."] = struct{}{}
	case "perf_event":
		prefixSet["perf_event."] = struct{}{}
	}
	if spec != nil {
		for _, a := range spec.aliases {
			prefixSet[a+"."] = struct{}{}
		}
	}
	out := make([]string, 0, len(prefixSet))
	for p := range prefixSet {
		out = append(out, p)
	}
	return out
}

func fileBelongsToController(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) || name == p {
			return true
		}
	}
	return false
}

func hasWritableControllerFile(files []File, prefixes []string) bool {
	for _, f := range files {
		if f.Writable && fileBelongsToController(f.Name, prefixes) {
			return true
		}
	}
	return false
}

func missingController(spec controllerSpec, cfg config) Controller {
	version := cfg.forcedVersion
	name := spec.canonical
	if version == VersionV1 && len(spec.v1Names) > 0 {
		name = spec.v1Names[0]
	} else if version == VersionV2 && len(spec.v2Names) > 0 {
		name = spec.v2Names[0]
	} else if len(spec.v2Names) > 0 {
		version = VersionV2
		name = spec.v2Names[0]
	} else if len(spec.v1Names) > 0 {
		version = VersionV1
		name = spec.v1Names[0]
	} else {
		version = VersionUnknown
	}
	c := Controller{
		Name: name, Controller: name, CanonicalName: spec.canonical, Aliases: spec.aliases,
		Status: StatusMissing, Version: version, CgroupVersion: version,
		Hierarchy: hierarchyName(version), HierarchyVersion: versionNumber(version),
		Reason: ReasonNotMounted, MissingReason: ReasonNotMounted,
		Message: "no matching cgroup controller mount was found",
		Err:     fmt.Errorf("%w: %s", ErrControllerUnavailable, spec.canonical),
	}
	if cfg.root != "" {
		c.Mountpoint = cfg.root
		c.MountPoint = cfg.root
	}
	return c
}

func slicesContains[S ~[]E, E comparable](s S, v E) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
