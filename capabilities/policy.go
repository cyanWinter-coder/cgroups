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
)

// Policy decides what happens when a requested limit cannot be enforced.
type Policy string

const (
	// PolicyStrict fails closed and blocks the caller/container start. This
	// prevents starting a workload without the requested protection.
	PolicyStrict Policy = "strict"
	// PolicyFailClosed is an alias for PolicyStrict.
	PolicyFailClosed = PolicyStrict
	// PolicyDegrade skips limits whose controller/file is unavailable and
	// records them in the returned report. Other limits continue to apply.
	PolicyDegrade Policy = "degrade"
	// PolicyContinue is an alias for PolicyDegrade.
	PolicyContinue = PolicyDegrade
	// PolicyBestEffort is an alias for PolicyDegrade.
	PolicyBestEffort = PolicyDegrade
)

// RequestedLimit identifies one resource setting that is about to be written.
type RequestedLimit struct {
	Controller string `json:"controller"`
	File       string `json:"file"`
	Setting    string `json:"setting,omitempty"`
	Value      string `json:"value,omitempty"`
}

// MissingLimit describes a limit that was not enforced.
type MissingLimit struct {
	RequestedLimit
	Status Status `json:"status,omitempty"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// SkippedLimit is an alias for MissingLimit.
type SkippedLimit = MissingLimit

// PolicyResult is the explicit degradation report returned after checking or
// applying requested limits.
type PolicyResult struct {
	Policy        Policy           `json:"policy"`
	Applied       []RequestedLimit `json:"applied,omitempty"`
	Written       []RequestedLimit `json:"written,omitempty"`
	MissingLimits []MissingLimit   `json:"missing_limits,omitempty"`
	Skipped       []MissingLimit   `json:"skipped,omitempty"`
}

// Missing returns true if one or more requested limits were not enforced.
func (r *PolicyResult) Missing() bool { return r != nil && len(r.MissingLimits) > 0 }

// Check evaluates all requested limits against report without performing
// writes. Under PolicyStrict the first unavailable limit is returned; under
// PolicyDegrade all unavailable limits are accumulated.
func (p Policy) Check(report *Report, limits []RequestedLimit) (result *PolicyResult, err error) {
	result = &PolicyResult{Policy: p}
	defer func() { result.Skipped = result.MissingLimits }()
	for _, limit := range limits {
		err := CheckWritable(report, limit.Controller, limit.File)
		if err == nil {
			result.Applied = append(result.Applied, limit)
			continue
		}
		missing := MissingLimit{RequestedLimit: limit, Reason: ReasonCapabilityCheckFailed, Detail: err.Error()}
		var unwritable *UnwritableError
		if errors.As(err, &unwritable) {
			missing.Reason = unwritable.Reason
		}
		if c := report.Get(limit.Controller); c != nil {
			missing.Status = c.Status
			if missing.Reason == "" {
				missing.Reason = firstNonEmpty(c.Reason, c.MissingReason)
			}
		}
		result.MissingLimits = append(result.MissingLimits, missing)
		if p == PolicyDegrade || p == PolicyContinue || p == PolicyBestEffort {
			continue
		}
		return result, fmt.Errorf("%w: %w", ErrDegradedPolicy, err)
	}
	result.Skipped = result.MissingLimits
	return result, nil
}

// Apply checks each limit immediately before invoking write. If the pre-write
// probe rejects a limit, write is not called. A write failure is converted to
// a missing limit under the degrade policy and returned immediately under the
// strict policy.
func (p Policy) Apply(report *Report, limits []RequestedLimit, write func(RequestedLimit) error) (result *PolicyResult, err error) {
	result = &PolicyResult{Policy: p}
	defer func() { result.Skipped = result.MissingLimits }()
	for _, limit := range limits {
		if err := CheckWritable(report, limit.Controller, limit.File); err != nil {
			missing := MissingLimit{RequestedLimit: limit, Reason: ReasonCapabilityCheckFailed, Detail: err.Error()}
			var unwritable *UnwritableError
			if errors.As(err, &unwritable) {
				missing.Reason = unwritable.Reason
			}
			result.MissingLimits = append(result.MissingLimits, missing)
			if p == PolicyDegrade || p == PolicyContinue || p == PolicyBestEffort {
				continue
			}
			return result, fmt.Errorf("%w: %w", ErrDegradedPolicy, err)
		}
		if write != nil {
			if err := write(limit); err != nil {
				missing := MissingLimit{RequestedLimit: limit, Reason: ReasonFileNotWritable, Detail: err.Error()}
				result.MissingLimits = append(result.MissingLimits, missing)
				if p == PolicyDegrade || p == PolicyContinue || p == PolicyBestEffort {
					continue
				}
				return result, fmt.Errorf("%w: %w", ErrDegradedPolicy, err)
			}
		}
		result.Written = append(result.Written, limit)
		result.Applied = append(result.Applied, limit)
	}
	result.Skipped = result.MissingLimits
	return result, nil
}

// Check is a convenience wrapper using PolicyStrict.
func Check(report *Report, limits ...RequestedLimit) error {
	_, err := PolicyStrict.Check(report, limits)
	return err
}

// Degrade checks limits using the degrade policy and returns missing limits.
func Degrade(report *Report, limits ...RequestedLimit) (*PolicyResult, error) {
	return PolicyDegrade.Check(report, limits)
}
