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
)

// Kernel-enforced CPU controller bounds, in microseconds where applicable.
// See Documentation/scheduler/sched-bwc.rst and Documentation/admin-guide/cgroup-v2.rst.
const (
	MinCPUWeight = 1
	MaxCPUWeight = 10000

	MinCPUQuotaUSec  = 1000
	MinCPUPeriodUSec = 1000
	MaxCPUPeriodUSec = 1000000
)

// Compatibility aliases for callers/tests that prefer the USec spelling.
const (
	MinCPUQuota  = MinCPUQuotaUSec
	MinCPUPeriod = MinCPUPeriodUSec
	MaxCPUPeriod = MaxCPUPeriodUSec
)

var (
	// ErrInvalidValue is wrapped by every pre-write validation failure.
	ErrInvalidValue = errors.New("cgroups: invalid resource value")

	ErrInvalidWeight = errors.New("invalid CPU weight")
	ErrInvalidQuota  = errors.New("invalid CPU quota")
	ErrInvalidPeriod = errors.New("invalid CPU period")

	// More explicit aliases for callers that qualify the controller.
	ErrInvalidCPUWeight = ErrInvalidWeight
	ErrInvalidCPUQuota  = ErrInvalidQuota
	ErrInvalidCPUPeriod = ErrInvalidPeriod
)

// ValidationError describes one invalid resource field.
type ValidationError struct {
	Field string
	Value any
	Err   error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("cgroups: invalid %s value %v: %v", e.Field, e.Value, e.Err)
}

// Unwrap exposes both the field-specific reason and ErrInvalidValue.
func (e *ValidationError) Unwrap() []error {
	return []error{e.Err, ErrInvalidValue}
}

func invalidValue(field string, value any, reason error) *ValidationError {
	return &ValidationError{Field: field, Value: value, Err: reason}
}

// Validate validates r. It is a short package-level alias for
// ValidateResources and (*Resources).Validate.
func Validate(r *Resources) error { return r.Validate() }

// ValidateResources validates r and is provided as a package-level counterpart
// to (*Resources).Validate.
func ValidateResources(r *Resources) error { return r.Validate() }

// ValidateCPU validates c and is provided as a package-level counterpart to
// (*CPU).Validate.
func ValidateCPU(c *CPU) error { return c.Validate() }

// ValidateResources reports whether the request is valid without touching the
// cgroup filesystem.
func (r *Resources) ValidateResources() error { return r.Validate() }

// Validate checks every resource value that can be rejected deterministically
// before writing it to the kernel. It returns all detected problems joined
// together. Nil controllers are unset and therefore valid.
func (r *Resources) Validate() error {
	if r == nil {
		return nil
	}

	var errs []error
	if r.CPU != nil {
		if err := r.CPU.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	// Memory, IO and device values retain their historical kernel-side
	// validation. The pre-write range check requested for online updates is
	// specific to CPU quota, period and weight.
	return errors.Join(errs...)
}

// Validate checks CPU weight and cpu.max quota/period ranges.
func (c *CPU) Validate() error {
	if c == nil {
		return nil
	}

	var errs []error
	if c.Weight != nil {
		w := *c.Weight
		if w < MinCPUWeight || w > MaxCPUWeight {
			errs = append(errs, invalidValue("cpu.weight", w,
				fmt.Errorf("%w: must be between %d and %d", ErrInvalidWeight, MinCPUWeight, MaxCPUWeight)))
		}
	}

	if c.Max != "" {
		limits, err := ParseCPUMaxLimit(c.Max)
		if err != nil {
			errs = append(errs, invalidValue("cpu.max", string(c.Max), err))
		} else {
			if q := limits.Quota; q.Set && !q.Unlimited && q.Value < MinCPUQuotaUSec {
				errs = append(errs, invalidValue("cpu.max.quota", q.Value,
					fmt.Errorf("%w: finite quota must be at least %d us", ErrInvalidQuota, MinCPUQuotaUSec)))
			}
			if p := limits.Period; p.Set && !p.Unlimited && (p.Value < MinCPUPeriodUSec || p.Value > MaxCPUPeriodUSec) {
				errs = append(errs, invalidValue("cpu.max.period", p.Value,
					fmt.Errorf("%w: period must be between %d and %d us", ErrInvalidPeriod, MinCPUPeriodUSec, MaxCPUPeriodUSec)))
			}
		}
	}

	if c.Quota != nil && *c.Quota < MinCPUQuotaUSec {
		errs = append(errs, invalidValue("cpu.quota", *c.Quota,
			fmt.Errorf("%w: finite quota must be at least %d us; use nil quota for %q", ErrInvalidQuota, MinCPUQuotaUSec, "max")))
	}
	if c.Period != nil && (*c.Period < MinCPUPeriodUSec || *c.Period > MaxCPUPeriodUSec) {
		errs = append(errs, invalidValue("cpu.period", *c.Period,
			fmt.Errorf("%w: period must be between %d and %d us", ErrInvalidPeriod, MinCPUPeriodUSec, MaxCPUPeriodUSec)))
	}

	return errors.Join(errs...)
}
