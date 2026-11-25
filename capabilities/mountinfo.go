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
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// parseMountInfo parses a Linux mountinfo file. The format is documented in
// Documentation/filesystems/proc.rst. Parsing is intentionally tolerant of
// optional fields before the "-" separator.
func parseMountInfo(path string) ([]Mount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var mounts []Mount
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		m, err := parseMountInfoLine(line)
		if err != nil {
			return nil, err
		}
		if m != nil {
			mounts = append(mounts, *m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func parseMountInfoLine(line string) (*Mount, error) {
	fields := strings.Fields(line)
	sep := -1
	for i, f := range fields {
		if f == "-" {
			sep = i
			break
		}
	}
	// Need at least the five pre-separator fixed fields plus separator and
	// three post-separator fields.
	if sep < 5 || len(fields) < sep+4 {
		return nil, fmt.Errorf("%w: %q", ReasonError(ReasonMountInfoInvalid), line)
	}

	fstype := fields[sep+1]
	if fstype != "cgroup" && fstype != "cgroup2" {
		return nil, nil
	}
	superOptions := strings.Split(fields[sep+3], ",")
	m := &Mount{
		FSType:     fstype,
		Root:       unescapeMountField(fields[3]),
		Mountpoint: unescapeMountField(fields[4]),
		MountPoint: unescapeMountField(fields[4]),
		Source:     fields[sep+2],
		Options:    append([]string(nil), superOptions...),
	}
	if fstype == "cgroup2" {
		m.Version = VersionV2
	} else {
		m.Version = VersionV1
		// Controller names are the non-generic super-block options. The
		// generic options can overlap controller names in theory, but this
		// matches the conventional mountinfo representation used by runc and
		// containerd/cgroups.
		m.Controllers = cgroupControllersFromOptions(superOptions)
	}
	return m, nil
}

var genericMountOptions = map[string]struct{}{
	"rw": {}, "ro": {}, "relatime": {}, "norelatime": {}, "strictatime": {},
	"noatime": {}, "nodiratime": {}, "nosuid": {}, "suid": {}, "nodev": {},
	"dev": {}, "noexec": {}, "exec": {}, "sync": {}, "async": {}, "dirsync": {},
	"remount": {}, "bind": {}, "rbind": {}, "unbindable": {}, "private": {},
	"shared": {}, "slave": {}, "defaults": {}, "vers": {}, "memory_recursiveprot": {},
}

func cgroupControllersFromOptions(options []string) []string {
	var out []string
	for _, opt := range options {
		if opt == "" {
			continue
		}
		if _, ok := genericMountOptions[opt]; ok {
			continue
		}
		if strings.Contains(opt, "=") {
			if strings.HasPrefix(opt, "name=") {
				name := strings.TrimPrefix(opt, "name=")
				out = append(out, opt, name)
			}
			continue
		}
		out = append(out, opt)
	}
	return out
}

func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n, err := strconv.ParseInt(s[i+1:i+4], 8, 32)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteRune(rune(n))
		i += 3
	}
	return b.String()
}

type reasonError string

func (e reasonError) Error() string { return string(e) }

// ReasonError allows errors.Is(err, Err...) style checks for parse problems.
func ReasonError(code string) error {
	return errors.New(code)
}
