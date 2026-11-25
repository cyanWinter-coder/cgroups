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
	"strconv"
	"strings"
)

// Limit is a three-state cgroup limit.
//
// The zero value is unset: neither the caller nor the cgroup filesystem
// supplied a value. A finite value has Set=true and Value populated. The
// unlimited state is represented by Unlimited=true (the cgroupfs token
// "max"). Thus:
//
//	switch {
//	case limit.Unlimited: // "max"
//	case limit.Set:       // finite limit in limit.Value
//	default:              // unset / file absent
//	}
type Limit struct {
	// Value is the finite limit in the file's native unit. It is meaningful
	// only when Set is true and Unlimited is false.
	Value int64
	// Set reports that a finite numeric value was present.
	Set bool
	// Unlimited reports the cgroupfs "max" state.
	Unlimited bool
}

// Unset reports that no value was present.
func (l Limit) Unset() bool { return !l.Set && !l.Unlimited }

// IsUnset is an alias for Unset.
func (l Limit) IsUnset() bool { return l.Unset() }

// IsSet reports that a finite numeric value was present. It intentionally does
// not treat Unlimited as a finite set value; use Present if either state is
// considered present.
func (l Limit) IsSet() bool { return l.Finite() }

// Finite reports that a numeric value was present.
func (l Limit) Finite() bool { return l.Set && !l.Unlimited }

// IsFinite is an alias for Finite.
func (l Limit) IsFinite() bool { return l.Finite() }

// IsUnlimited reports the cgroupfs "max" state.
func (l Limit) IsUnlimited() bool { return l.Unlimited }

// Present reports that the limit was read and is either finite or unlimited.
func (l Limit) Present() bool { return l.Set || l.Unlimited }

// Int64 returns the finite value or nil for unset/unlimited states.
func (l Limit) Int64() *int64 {
	if !l.Finite() {
		return nil
	}
	v := l.Value
	return &v
}

// Uint64 returns the finite value converted to uint64. The bool is false for
// unset, unlimited, or negative values.
func (l Limit) Uint64() (uint64, bool) {
	if !l.Finite() || l.Value < 0 {
		return 0, false
	}
	return uint64(l.Value), true
}

// ParseLimit parses a scalar cgroup limit file. An empty string is unset,
// "max" is unlimited, and negative values are accepted as the historical
// unlimited sentinel. Use ParseNonNegativeLimit when validating cgroup v2
// input that must use the explicit "max" token.
func ParseLimit(s string) (Limit, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Limit{}, nil
	}
	if strings.EqualFold(s, "max") {
		return Limit{Unlimited: true}, nil
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return Limit{}, fmt.Errorf("%w: %q", ErrInvalidFormat, s)
	}
	if v < 0 {
		return Limit{Unlimited: true}, nil
	}
	return Limit{Set: true, Value: v}, nil
}

// ParseNonNegativeLimit is like ParseLimit but rejects negative numeric
// values instead of treating them as unlimited.
func ParseNonNegativeLimit(s string) (Limit, error) {
	l, err := ParseLimit(s)
	if err != nil {
		return l, err
	}
	if l.Unlimited && strings.TrimSpace(s) != "" && !strings.EqualFold(strings.TrimSpace(s), "max") {
		return Limit{}, fmt.Errorf("%w: negative limit %q is not valid in cgroup v2; use %q", ErrInvalidValue, s, "max")
	}
	return l, nil
}

// ParseLimitValue returns the conventional pointer representation of a
// three-state limit. A nil value with unlimited=false means unset; a non-nil
// value is finite; a nil value with unlimited=true means cgroupfs "max".
func ParseLimitValue(s string) (value *int64, unlimited bool, err error) {
	l, err := ParseLimit(s)
	if err != nil {
		return nil, false, err
	}
	if l.Unset() {
		return nil, false, nil
	}
	if l.Unlimited {
		return nil, true, nil
	}
	v := l.Value
	return &v, false, nil
}

// ParseOptionalInt64 is an alias for ParseLimitValue.
func ParseOptionalInt64(s string) (*int64, bool, error) { return ParseLimitValue(s) }

// ParseOptionalUint64 is the unsigned counterpart of ParseLimitValue.
func ParseOptionalUint64(s string) (*uint64, bool, error) {
	v, unlimited, err := ParseLimitValue(s)
	if err != nil || v == nil {
		return nil, unlimited, err
	}
	u := uint64(*v)
	return &u, false, nil
}

// CPUMaxLimit is the three-state parse result of cpu.max.
type CPUMaxLimit struct {
	Quota  Limit
	Period Limit
}

// ParseCPUMaxLimit parses the value representation used by cpu.max. Unlike the
// legacy extractQuotaAndPeriod helper, it does not replace "max" with
// math.MaxInt64 and can represent an absent quota or period.
func ParseCPUMaxLimit[T ~string](max T) (CPUMaxLimit, error) {
	s := strings.TrimSpace(string(max))
	if s == "" {
		return CPUMaxLimit{}, nil
	}

	fields := strings.Fields(s)
	if len(fields) < 1 || len(fields) > 2 {
		return CPUMaxLimit{}, fmt.Errorf("%w: cpu.max must contain quota [period]", ErrInvalidFormat)
	}

	var out CPUMaxLimit
	if strings.EqualFold(fields[0], "max") {
		out.Quota = Limit{Unlimited: true}
	} else {
		q, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || q < 0 {
			return CPUMaxLimit{}, fmt.Errorf("%w: invalid quota %q", ErrInvalidQuota, fields[0])
		}
		out.Quota = Limit{Set: true, Value: q}
	}

	if len(fields) == 2 {
		p, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || p < 0 {
			return CPUMaxLimit{}, fmt.Errorf("%w: invalid period %q", ErrInvalidPeriod, fields[1])
		}
		out.Period = Limit{Set: true, Value: p}
	}

	return out, nil
}

// ParseCPUMaxString parses a plain string cpu.max value.
func ParseCPUMaxString(max string) (CPUMaxLimit, error) {
	return ParseCPUMaxLimit(max)
}

// CPULimits contains readable CPU controller limits.
type CPULimits struct {
	// Max is the raw cpu.max value, retained for exact round-tripping.
	Max    CPUMax
	Weight Limit
	Quota  Limit
	Period Limit
}

// MemoryLimits contains readable memory controller limits.
type MemoryLimits struct {
	Min  Limit
	Low  Limit
	High Limit
	Max  Limit
	Swap Limit
}

// PidsLimits contains readable process-number limits.
type PidsLimits struct {
	Max Limit
}

// Limits is a snapshot of common resource limits. A missing controller file is
// represented by the zero Limit (unset), while a readable "max" value is
// represented by Limit.Unlimited.
type Limits struct {
	CPU    CPULimits
	Memory MemoryLimits
	Pids   PidsLimits
}

func readLimitFile(ops fsOps, name string) (Limit, error) {
	b, err := ops.ReadFile(name)
	if os.IsNotExist(err) {
		return Limit{}, nil
	}
	if err != nil {
		return Limit{}, err
	}
	return ParseLimit(string(b))
}

// ReadLimit reads one scalar limit file relative to the manager's cgroup.
// A missing file returns the zero Limit and no error.
func (m *Manager) ReadLimit(name string) (Limit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlockPath := lockCgroupPath(m.path)
	defer unlockPath()
	return readLimitFile(m.fsOpsLocked(), name)
}

// GetLimit is an alias for ReadLimit.
func (m *Manager) GetLimit(name string) (Limit, error) {
	return m.ReadLimit(name)
}

// ReadCPUMax reads the raw cpu.max file. A missing file returns an empty
// CPUMax, which represents unset in CPU.Values.
func (m *Manager) ReadCPUMax() (CPUMax, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlockPath := lockCgroupPath(m.path)
	defer unlockPath()

	b, err := m.fsOpsLocked().ReadFile("cpu.max")
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return CPUMax(strings.TrimSpace(string(b))), nil
}

// GetCPUMax is an alias for ReadCPUMax.
func (m *Manager) GetCPUMax() (CPUMax, error) { return m.ReadCPUMax() }

// ReadCPULimits reads only CPU limits.
func (m *Manager) ReadCPULimits() (CPULimits, error) {
	l, err := m.ReadLimits()
	if l == nil {
		return CPULimits{}, err
	}
	return l.CPU, err
}

// GetCPULimits is an alias for ReadCPULimits.
func (m *Manager) GetCPULimits() (CPULimits, error) { return m.ReadCPULimits() }

// GetCPU reads the current CPU settings in the update representation.
func (m *Manager) GetCPU() (*CPU, error) {
	r, err := m.ReadResources()
	if r == nil {
		return nil, err
	}
	return r.CPU, err
}

// ReadCPU is an alias for GetCPU.
func (m *Manager) ReadCPU() (*CPU, error) { return m.GetCPU() }

// GetMemory reads the current memory settings in the update representation.
func (m *Manager) GetMemory() (*Memory, error) {
	r, err := m.ReadResources()
	if r == nil {
		return nil, err
	}
	return r.Memory, err
}

// ReadMemory is an alias for GetMemory.
func (m *Manager) ReadMemory() (*Memory, error) { return m.GetMemory() }

// ReadMemoryLimits reads only memory limits.
func (m *Manager) ReadMemoryLimits() (MemoryLimits, error) {
	l, err := m.ReadLimits()
	if l == nil {
		return MemoryLimits{}, err
	}
	return l.Memory, err
}

// GetMemoryLimits is an alias for ReadMemoryLimits.
func (m *Manager) GetMemoryLimits() (MemoryLimits, error) { return m.ReadMemoryLimits() }

// ReadPidsLimits reads only pids limits.
func (m *Manager) ReadPidsLimits() (PidsLimits, error) {
	l, err := m.ReadLimits()
	if l == nil {
		return PidsLimits{}, err
	}
	return l.Pids, err
}

// GetPidsLimits is an alias for ReadPidsLimits.
func (m *Manager) GetPidsLimits() (PidsLimits, error) { return m.ReadPidsLimits() }

// ReadLimits reads CPU, memory and pids limits. Missing files are reported as
// unset; malformed or unreadable present files return an error.
func (m *Manager) ReadLimits() (*Limits, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlockPath := lockCgroupPath(m.path)
	defer unlockPath()
	ops := m.fsOpsLocked()

	out := &Limits{}
	var errs []error

	if w, err := readLimitFile(ops, "cpu.weight"); err != nil {
		errs = append(errs, err)
	} else {
		out.CPU.Weight = w
	}

	if b, err := ops.ReadFile("cpu.max"); err != nil {
		if !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	} else if parsed, err := ParseCPUMaxLimit(CPUMax(string(b))); err != nil {
		errs = append(errs, err)
	} else {
		out.CPU.Max = CPUMax(strings.TrimSpace(string(b)))
		out.CPU.Quota = parsed.Quota
		out.CPU.Period = parsed.Period
	}

	readInto := func(name string, dst *Limit) {
		l, err := readLimitFile(ops, name)
		if err != nil {
			errs = append(errs, err)
			return
		}
		*dst = l
	}

	readInto("memory.min", &out.Memory.Min)
	readInto("memory.low", &out.Memory.Low)
	readInto("memory.high", &out.Memory.High)
	readInto("memory.max", &out.Memory.Max)
	readInto("memory.swap.max", &out.Memory.Swap)
	readInto("pids.max", &out.Pids.Max)

	if len(errs) > 0 {
		return out, errors.Join(errs...)
	}
	return out, nil
}

// Limits is an alias for ReadLimits.
func (m *Manager) Limits() (*Limits, error) { return m.ReadLimits() }

// GetLimits is an alias for ReadLimits.
func (m *Manager) GetLimits() (*Limits, error) { return m.ReadLimits() }

// Resources converts the read limits back into the update representation.
// Unlimited memory values use the package's negative-one sentinel, which
// Memory.Values writes as "max". Missing/unset fields remain nil. CPU raw
// cpu.max contents are preserved exactly.
func (l *Limits) Resources() *Resources {
	if l == nil {
		return nil
	}
	r := &Resources{}

	if l.CPU.Weight.Finite() || l.CPU.Max != "" {
		r.CPU = &CPU{Max: l.CPU.Max}
		if w, ok := l.CPU.Weight.Uint64(); ok {
			r.CPU.Weight = &w
		}
		if q := l.CPU.Quota.Int64(); q != nil {
			r.CPU.Quota = q
		}
		if p, ok := l.CPU.Period.Uint64(); ok {
			r.CPU.Period = &p
		}
	}

	mem := &Memory{}
	hasMemory := false
	setMemory := func(dst **int64, v Limit) {
		if p := v.resourcePointer(); p != nil {
			*dst = p
			hasMemory = true
		}
	}
	setMemory(&mem.Min, l.Memory.Min)
	setMemory(&mem.Low, l.Memory.Low)
	setMemory(&mem.High, l.Memory.High)
	setMemory(&mem.Max, l.Memory.Max)
	setMemory(&mem.Swap, l.Memory.Swap)
	if hasMemory {
		r.Memory = mem
	}

	if l.Pids.Max.Set || l.Pids.Max.Unlimited {
		switch {
		case l.Pids.Max.Finite():
			r.Pids = &Pids{Max: l.Pids.Max.Value}
		case l.Pids.Max.Unlimited:
			r.Pids = &Pids{Max: -1}
		}
	}

	return r
}

// ReadResources reads limits and converts them to the Update request type.
func (m *Manager) ReadResources() (*Resources, error) {
	limits, err := m.ReadLimits()
	if err != nil {
		return nil, err
	}
	return limits.Resources(), nil
}

// GetResources is an alias for ReadResources.
func (m *Manager) GetResources() (*Resources, error) { return m.ReadResources() }

func (l Limit) resourcePointer() *int64 {
	switch {
	case l.Finite():
		v := l.Value
		return &v
	case l.Unlimited:
		v := int64(-1)
		return &v
	default:
		return nil
	}
}

// Naming aliases for callers that refer to the snapshot as resource/cgroup
// limits rather than simply "limits".
type (
	ResourceLimits = Limits
	CgroupLimits   = Limits
	ResourceLimit  = Limit
)

// ReadLimits reads limits from a plain cgroup directory path without requiring
// a previously loaded Manager.
func ReadLimits(path string) (*Limits, error) {
	return (&Manager{path: path}).ReadLimits()
}

// GetLimits is an alias for ReadLimits.
func GetLimits(path string) (*Limits, error) { return ReadLimits(path) }

// ReadResourceLimits is an alias for ReadLimits.
func (m *Manager) ReadResourceLimits() (*ResourceLimits, error) { return m.ReadLimits() }

// GetResourceLimits is an alias for ReadLimits.
func (m *Manager) GetResourceLimits() (*ResourceLimits, error) { return m.ReadLimits() }

// ResourceLimits is an alias for ReadLimits.
func (m *Manager) ResourceLimits() (*ResourceLimits, error) { return m.ReadLimits() }

// CurrentLimits is an alias for ReadLimits.
func (m *Manager) CurrentLimits() (*Limits, error) { return m.ReadLimits() }

// SnapshotLimits is an alias for ReadLimits.
func (m *Manager) SnapshotLimits() (*Limits, error) { return m.ReadLimits() }

// ReadCgroupLimits is an alias for ReadLimits.
func (m *Manager) ReadCgroupLimits() (*CgroupLimits, error) { return m.ReadLimits() }

// GetCgroupLimits is an alias for ReadLimits.
func (m *Manager) GetCgroupLimits() (*CgroupLimits, error) { return m.ReadLimits() }
