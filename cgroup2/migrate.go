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
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// MigrationStatus is the verified outcome for one process.
type MigrationStatus string

const (
	// MigrationSuccess means the process was found in the target group
	// during the post-migration audit.
	MigrationSuccess MigrationStatus = "success"
	// MigrationSkipped means the process exited before it could be migrated.
	MigrationSkipped MigrationStatus = "skipped"
	// MigrationFailed means the process is not in the target group and is
	// still alive, or its final ownership could not be verified.
	MigrationFailed MigrationStatus = "failed"
)

// String returns the stable machine-readable status.
func (s MigrationStatus) String() string { return string(s) }

var (
	// ErrTargetFull is returned by preflight when pids.max has already
	// reached pids.current.
	ErrTargetFull = errors.New("cgroups: target group is full")
	// ErrTargetNotWritable is returned when the target's cgroup.procs file
	// cannot be opened for writing.
	ErrTargetNotWritable = errors.New("cgroups: target group is not writable")
	// ErrProcessExited marks a process that disappeared during migration.
	ErrProcessExited = errors.New("cgroups: process exited")
	// ErrMigrationVerification marks a process whose final ownership does
	// not match the requested target.
	ErrMigrationVerification = errors.New("cgroups: process migration could not be verified")
)

// ProcessGroup is the minimal cgroup operation set required by the batched
// migration logic. *Manager implements it. Test doubles may implement it
// without touching a real cgroup filesystem.
type ProcessGroup interface {
	AddProc(pid uint64) error
	Procs(recursive bool) ([]uint64, error)
}

// MigrationPreflighter is an optional target capability checked before any
// process is moved.
type MigrationPreflighter interface {
	PreflightMigration() error
}

// PIDExistenceChecker allows callers or tests to supply an explicit liveness
// check instead of using kill(pid, 0).
type PIDExistenceChecker func(pid uint64) bool

// MigrateOption configures a batched migration.
type MigrateOption func(*migrationConfig)

type migrationConfig struct {
	ctx          context.Context
	recursive    bool
	preflight    bool
	verify       bool
	lockPID      bool
	pids         []uint64
	alive        PIDExistenceChecker
	actualCgroup func(pid uint64) string
	targetKey    string
}

// WithRecursiveMigration controls whether Procs(true) is used for snapshots
// and verification. AddProc always places a process directly in the target
// Manager's cgroup.procs file.
func WithRecursiveMigration(recursive bool) MigrateOption {
	return func(cfg *migrationConfig) { cfg.recursive = recursive }
}

// WithMigrationPreflight controls the target full/writable check. Preflight
// is enabled by default.
func WithMigrationPreflight(enabled bool) MigrateOption {
	return func(cfg *migrationConfig) { cfg.preflight = enabled }
}

// WithMigrationVerification controls the final ownership audit. Verification
// is enabled by default.
func WithMigrationVerification(enabled bool) MigrateOption {
	return func(cfg *migrationConfig) { cfg.verify = enabled }
}

// WithPIDExistenceChecker replaces the operating-system liveness probe.
func WithPIDExistenceChecker(check PIDExistenceChecker) MigrateOption {
	return func(cfg *migrationConfig) { cfg.alive = check }
}

// WithMigrationContext stops pending work when ctx is canceled.
func WithMigrationContext(ctx context.Context) MigrateOption {
	return func(cfg *migrationConfig) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

// WithMigrationPIDs replaces the source enumeration with an explicit PID list.
// Source and target snapshots are still recorded for reporting.
func WithMigrationPIDs(pids ...uint64) MigrateOption {
	return func(cfg *migrationConfig) { cfg.pids = append([]uint64(nil), pids...) }
}

func defaultMigrationConfig() migrationConfig {
	return migrationConfig{
		ctx:       context.Background(),
		recursive: true,
		preflight: true,
		verify:    true,
		lockPID:   true,
		// Generic ProcessGroup doubles are not operating-system PID
		// namespaces; runMigration enables the kill(2) probe only for real
		// *Manager values unless a caller supplies an explicit checker.
		alive:        nil,
		actualCgroup: nil,
	}
}

// ProcessResult is the audited outcome for one PID from the initial source
// set.
type ProcessResult struct {
	// PID is the process identifier from the source snapshot.
	PID uint64 `json:"pid"`
	// Status is one of success, skipped, or failed.
	Status MigrationStatus `json:"status"`

	// MoveErr is the error returned by AddProc, if any. A non-nil MoveErr can
	// still coexist with Status == success when a concurrent operator or
	// idempotent retry had already placed the PID in the target.
	MoveErr error `json:"-"`
	// Err is the final classification error. It is nil for successful
	// processes. Skipped and failed processes carry a wrapped cause.
	Err error `json:"-"`
	// Error is retained as an exported alias for callers and tests that use
	// that field name. New code should use Err.
	Error error `json:"-"`
	// Reason is the stable string form of Err.
	Reason string `json:"reason,omitempty"`

	// Attempted reports whether AddProc was called. It can be false when the
	// PID was already verified as belonging to the target.
	Attempted bool `json:"attempted"`
	// AlreadyInTarget reports that the PID was found in the target immediately
	// before its move attempt.
	AlreadyInTarget bool `json:"already_in_target"`

	SourceBefore bool `json:"source_before"`
	TargetBefore bool `json:"target_before"`
	SourceAfter  bool `json:"source_after"`
	TargetAfter  bool `json:"target_after"`

	// Exists is the final liveness result. It is nil when no check was made.
	Exists *bool `json:"exists,omitempty"`
	// ActualCgroup is /proc/PID/cgroup's v2 path when the PID is alive but
	// was not found in either the source or target snapshot.
	ActualCgroup string `json:"actual_cgroup,omitempty"`
}

// FailedProcess describes one PID that did not reach the target.
type FailedProcess struct {
	PID   uint64
	Error error
}

// MigrationCounts contains the three headline result categories.
type MigrationCounts struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

// MigrationResult is the point-in-time report returned after a batch.
//
// The Succeeded/Skipped/Failed PID slices and Errors map are safe to use for
// accounting. Processes contains the full audited records, while
// FailedProcesses contains only failed records with their causes.
type MigrationResult struct {
	// SourceBefore and TargetBefore are the initial snapshots required for
	// stable accounting.
	SourceBefore []uint64 `json:"source_before"`
	TargetBefore []uint64 `json:"target_before"`
	// SourceAfter and TargetAfter are the final audit snapshots.
	SourceAfter []uint64 `json:"source_after"`
	TargetAfter []uint64 `json:"target_after"`

	// Results is ordered by PID and contains one entry for each unique PID
	// in the initial source set (or explicit WithMigrationPIDs list).
	Results []ProcessResult `json:"results"`
	// Processes and ProcessResults are compatibility aliases for Results.
	Processes      []ProcessResult `json:"processes"`
	ProcessResults []ProcessResult `json:"process_results"`

	// Succeeded, Skipped and Failed are PID classifications.
	Succeeded  []uint64 `json:"succeeded"`
	Skipped    []uint64 `json:"skipped"`
	Failed     []uint64 `json:"failed"`
	Successful []uint64 `json:"successful"`
	Success    []uint64 `json:"success"`

	// Explicit PID-slice aliases.
	SucceededPIDs []uint64 `json:"succeeded_pids"`
	SuccessPIDs   []uint64 `json:"success_pids"`
	SkippedPIDs   []uint64 `json:"skipped_pids"`
	FailedPIDs    []uint64 `json:"failed_pids"`

	// Errors contains the final classification error for failed PIDs.
	Errors map[uint64]error `json:"errors"`
	// FailureReasons and Failures are aliases for Errors.
	FailureReasons map[uint64]error `json:"failure_reasons"`
	Failures       map[uint64]error `json:"failures"`
	// ErrorList contains the same failure errors without PID keys.
	ErrorList []error `json:"-"`

	// FailedProcesses is a convenience view combining Failed PIDs and Errors.
	FailedProcesses []FailedProcess `json:"failed_processes"`
	// FailedResults contains the full audited records for failed PIDs.
	FailedResults []ProcessResult `json:"failed_results"`

	// SourceAppeared lists PIDs present in SourceAfter but not SourceBefore.
	// These are processes that joined the source during the window and were
	// intentionally not part of this batch.
	SourceAppeared []uint64 `json:"source_appeared"`
	// TargetAppeared lists all PIDs present in TargetAfter but not
	// TargetBefore. It includes both migrated PIDs and unrelated arrivals.
	TargetAppeared []uint64 `json:"target_appeared"`
	// TargetExternal lists target arrivals that are not among the processed
	// PIDs. This keeps concurrent operators' writes out of migration totals.
	TargetExternal []uint64 `json:"target_external"`

	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Recursive   bool      `json:"recursive"`
}

// GetResults returns the audited process records.
func (r *MigrationResult) GetResults() []ProcessResult {
	if r == nil {
		return nil
	}
	return r.Results
}

// Count returns the headline counts.
func (r *MigrationResult) Count() MigrationCounts {
	if r == nil {
		return MigrationCounts{}
	}
	return MigrationCounts{
		Total:     len(r.Results),
		Succeeded: len(r.Succeeded),
		Skipped:   len(r.Skipped),
		Failed:    len(r.Failed),
	}
}

// Counts is an alias for Count.
func (r *MigrationResult) Counts() MigrationCounts { return r.Count() }

// HasFailures reports whether at least one process failed.
func (r *MigrationResult) HasFailures() bool { return r != nil && len(r.Failed) > 0 }

// Err returns an error joining all process-level failures, or nil when every
// planned process succeeded or was skipped because it exited.
func (r *MigrationResult) Err() error {
	if r == nil || len(r.FailedProcesses) == 0 {
		return nil
	}
	errs := make([]error, 0, len(r.FailedProcesses)+1)
	errs = append(errs, fmt.Errorf("%w: %d process(es)", ErrMigrationVerification, len(r.FailedProcesses)))
	for _, f := range r.FailedProcesses {
		errs = append(errs, fmt.Errorf("pid %d: %w", f.PID, f.Error))
	}
	return errors.Join(errs...)
}

// Migrate migrates all processes currently listed by source into target and
// audits the result. Existing *Manager callers can use this package-level
// function or the Manager.MigrateTo method.
func Migrate(source, target ProcessGroup, opts ...MigrateOption) (*MigrationResult, error) {
	cfg := defaultMigrationConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return runMigration(cfg, source, target)
}

// MigrateTo is the Manager method form of Migrate.
func (c *Manager) MigrateTo(target *Manager, opts ...MigrateOption) (*MigrationResult, error) {
	if c == nil {
		return nil, errors.New("cgroups: source manager is nil")
	}
	if target == nil {
		return nil, errors.New("cgroups: target manager is nil")
	}
	opts = append([]MigrateOption{withManagerIdentity(c, target)}, opts...)
	return Migrate(c, target, opts...)
}

// Migrate is an alias for MigrateTo.
func (c *Manager) Migrate(target *Manager, opts ...MigrateOption) (*MigrationResult, error) {
	return c.MigrateTo(target, opts...)
}

// Path returns the absolute cgroup directory managed by c.
func (c *Manager) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

func withManagerIdentity(source, target *Manager) MigrateOption {
	return func(cfg *migrationConfig) {
		srcPath := source.Path()
		dstPath := target.Path()
		if p, err := filepath.Abs(srcPath); err == nil {
			srcPath = p
		}
		if p, err := filepath.Abs(dstPath); err == nil {
			dstPath = p
		}
		cfg.targetKey = "cgroup2:" + dstPath
		cfg.actualCgroup = func(pid uint64) string {
			path, err := PidGroupPath(int(pid))
			if err != nil {
				return ""
			}
			return path
		}
		_ = srcPath
	}
}

func runMigration(cfg migrationConfig, source, target ProcessGroup) (*MigrationResult, error) {
	if source == nil {
		return nil, errors.New("cgroups: migration source is nil")
	}
	if target == nil {
		return nil, errors.New("cgroups: migration target is nil")
	}
	if cfg.ctx == nil {
		cfg.ctx = context.Background()
	}
	if cfg.alive == nil {
		if _, realManager := target.(*Manager); realManager {
			cfg.alive = processExists
		} else if _, realManager := source.(*Manager); realManager {
			cfg.alive = processExists
		}
	}
	if cfg.actualCgroup == nil {
		if _, realManager := target.(*Manager); realManager {
			cfg.actualCgroup = pidCgroupPath
		}
	}

	started := time.Now()
	sourceBeforeUnsorted, err := source.Procs(cfg.recursive)
	if err != nil {
		return nil, fmt.Errorf("cgroups: enumerate source processes before migration: %w", err)
	}
	targetBeforeUnsorted, err := target.Procs(cfg.recursive)
	if err != nil {
		return nil, fmt.Errorf("cgroups: enumerate target processes before migration: %w", err)
	}

	sourceBefore := sortedUniquePIDs(sourceBeforeUnsorted)
	targetBefore := sortedUniquePIDs(targetBeforeUnsorted)

	if cfg.preflight {
		if err := preflightTarget(target); err != nil {
			return nil, err
		}
	}

	pids := cfg.pids
	if len(pids) == 0 {
		pids = sourceBefore
	}
	pids = sortedUniquePIDs(pids)

	result := &MigrationResult{
		SourceBefore: sourceBefore,
		TargetBefore: targetBefore,
		Results:      make([]ProcessResult, 0, len(pids)),
		Errors:       make(map[uint64]error),
		StartedAt:    started,
		Recursive:    cfg.recursive,
	}

	beforeSourceSet := pidSet(sourceBefore)
	beforeTargetSet := pidSet(targetBefore)
	for _, pid := range pids {
		_, sourceBefore := beforeSourceSet[pid]
		_, targetBefore := beforeTargetSet[pid]
		pr := ProcessResult{
			PID:          pid,
			SourceBefore: sourceBefore,
			TargetBefore: targetBefore,
		}
		if err := cfg.ctx.Err(); err != nil {
			pr.Status = MigrationFailed
			pr.Err = err
			pr.Error = err
			result.Results = append(result.Results, pr)
			continue
		}

		moveErr := moveOnePID(cfg, target, pid, &pr)
		pr.MoveErr = moveErr
		result.Results = append(result.Results, pr)
	}

	if cfg.verify {
		auditMigration(cfg, source, target, result)
	} else {
		for i := range result.Results {
			pr := &result.Results[i]
			if pr.MoveErr == nil || pr.AlreadyInTarget {
				pr.Status = MigrationSuccess
			} else if isNoSuchProcess(pr.MoveErr) {
				pr.Status = MigrationSkipped
				pr.Err = wrapProcessExited(pr.PID, pr.MoveErr)
				pr.Error = pr.Err
			} else {
				pr.Status = MigrationFailed
				pr.Err = pr.MoveErr
				pr.Error = pr.MoveErr
			}
		}
	}

	indexMigrationResult(result)
	result.CompletedAt = time.Now()

	if err := cfg.ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func moveOnePID(cfg migrationConfig, target ProcessGroup, pid uint64, pr *ProcessResult) error {
	unlock := func() {}
	if cfg.lockPID {
		key := cfg.targetKey
		if key == "" {
			key = groupIdentity(target)
		}
		unlock = lockPIDStripe(key, pid)
		defer unlock()
	}

	// Another operator or a concurrent Migrate call may already have moved
	// the PID. Reading the direct cgroup.procs file is sufficient because
	// AddProc attaches directly to this Manager's group.
	if currentlyInTarget(target, pid) {
		pr.Attempted = false
		pr.AlreadyInTarget = true
		pr.TargetAfter = true
		return nil
	}

	pr.Attempted = true
	return target.AddProc(pid)
}

func currentlyInTarget(target ProcessGroup, pid uint64) bool {
	pids, err := target.Procs(false)
	if err != nil {
		return false
	}
	for _, p := range pids {
		if p == pid {
			return true
		}
	}
	return false
}

func preflightTarget(target ProcessGroup) error {
	checker, ok := target.(MigrationPreflighter)
	if !ok {
		// Also recognize common alternate method names on test doubles and
		// future implementations.
		switch t := target.(type) {
		case interface{ Preflight() error }:
			return t.Preflight()
		case interface{ CheckMigrationReady() error }:
			return t.CheckMigrationReady()
		case interface{ Ready() error }:
			return t.Ready()
		default:
			return nil
		}
	}
	return checker.PreflightMigration()
}

func auditMigration(cfg migrationConfig, source, target ProcessGroup, result *MigrationResult) {
	targetAfterUnsorted, errTarget := target.Procs(cfg.recursive)
	sourceAfterUnsorted, errSource := source.Procs(cfg.recursive)
	if errTarget != nil && cfg.recursive {
		// Migrated PIDs are direct members. A recursive walk can fail because
		// of a disappearing child; the direct file is still authoritative for
		// the attach operation.
		targetAfterUnsorted, errTarget = target.Procs(false)
	}
	if errSource != nil && cfg.recursive {
		sourceAfterUnsorted, errSource = source.Procs(false)
	}

	result.TargetAfter = sortedUniquePIDs(targetAfterUnsorted)
	result.SourceAfter = sortedUniquePIDs(sourceAfterUnsorted)
	targetSet := pidSet(result.TargetAfter)
	sourceSet := pidSet(result.SourceAfter)

	for i := range result.Results {
		pr := &result.Results[i]
		pid := pr.PID
		_, inTargetAfter := targetSet[pid]
		_, inSourceAfter := sourceSet[pid]
		pr.TargetAfter = inTargetAfter
		pr.SourceAfter = inSourceAfter

		switch {
		case pr.TargetAfter:
			pr.Status = MigrationSuccess
			pr.Err = nil
			pr.Error = nil
		case isNoSuchProcess(pr.MoveErr):
			pr.Status = MigrationSkipped
			pr.Err = wrapProcessExited(pid, pr.MoveErr)
			pr.Error = pr.Err
		default:
			// A final source listing is direct evidence that the process is
			// still in the source group. Prefer it over a host liveness probe
			// so fake ProcessGroup implementations and stale/zombie entries
			// are classified from cgroup ownership first.
			if inSourceAfter {
				pr.Status = MigrationFailed
				pr.Err = migrationFailureCause(pr, errTarget, errSource, pid)
				pr.Error = pr.Err
				break
			}

			exists, existenceKnown := checkExistence(cfg, pid)
			if existenceKnown {
				b := exists
				pr.Exists = &b
			}
			if existenceKnown && !exists {
				pr.Status = MigrationSkipped
				pr.Err = wrapProcessExited(pid, firstNonNil(pr.MoveErr, unix.ESRCH))
				pr.Error = pr.Err
				continue
			}

			pr.Status = MigrationFailed
			pr.Err = migrationFailureCause(pr, errTarget, errSource, pid)
			pr.Error = pr.Err

			if exists && !inSourceAfter && cfg.actualCgroup != nil {
				pr.ActualCgroup = cfg.actualCgroup(pid)
			}
		}
	}
}

func checkExistence(cfg migrationConfig, pid uint64) (exists bool, known bool) {
	if cfg.alive == nil {
		return false, false
	}
	return cfg.alive(pid), true
}

func migrationFailureCause(pr *ProcessResult, errTarget, errSource error, pid uint64) error {
	switch {
	case pr.MoveErr != nil:
		return pr.MoveErr
	case errTarget != nil:
		return fmt.Errorf("%w: re-read target: %v", ErrMigrationVerification, errTarget)
	case errSource != nil:
		return fmt.Errorf("%w: re-read source: %v", ErrMigrationVerification, errSource)
	default:
		return fmt.Errorf("%w: pid %d is not in target cgroup.procs", ErrMigrationVerification, pid)
	}
}

func pidCgroupPath(pid uint64) string {
	path, err := PidGroupPath(int(pid))
	if err != nil {
		return ""
	}
	return path
}

func indexMigrationResult(result *MigrationResult) {
	processed := make(map[uint64]struct{}, len(result.Results))
	for i := range result.Results {
		pr := &result.Results[i]
		if pr.Err != nil {
			pr.Reason = pr.Err.Error()
		} else {
			pr.Reason = ""
		}
		processed[pr.PID] = struct{}{}
		switch pr.Status {
		case MigrationSuccess:
			result.Succeeded = append(result.Succeeded, pr.PID)
		case MigrationSkipped:
			result.Skipped = append(result.Skipped, pr.PID)
		case MigrationFailed:
			result.Failed = append(result.Failed, pr.PID)
			result.Errors[pr.PID] = pr.Err
			result.FailedProcesses = append(result.FailedProcesses, FailedProcess{PID: pr.PID, Error: pr.Err})
		}
	}

	result.Succeeded = sortedUniquePIDs(result.Succeeded)
	result.Skipped = sortedUniquePIDs(result.Skipped)
	result.Failed = sortedUniquePIDs(result.Failed)

	result.Successful = append([]uint64(nil), result.Succeeded...)
	result.Success = append([]uint64(nil), result.Succeeded...)
	result.SucceededPIDs = append([]uint64(nil), result.Succeeded...)
	result.SuccessPIDs = append([]uint64(nil), result.Succeeded...)
	result.SkippedPIDs = append([]uint64(nil), result.Skipped...)
	result.FailedPIDs = append([]uint64(nil), result.Failed...)
	result.FailureReasons = result.Errors
	result.Failures = result.Errors
	result.Processes = result.Results
	result.ProcessResults = result.Results
	result.ErrorList = result.ErrorList[:0]
	result.FailedResults = result.FailedResults[:0]
	for _, pr := range result.Results {
		if pr.Status == MigrationFailed {
			if pr.Err != nil {
				result.ErrorList = append(result.ErrorList, pr.Err)
			}
			result.FailedResults = append(result.FailedResults, pr)
		}
	}

	result.SourceAppeared = difference(result.SourceAfter, result.SourceBefore)
	result.TargetAppeared = difference(result.TargetAfter, result.TargetBefore)
	for _, pid := range result.TargetAppeared {
		if _, ok := processed[pid]; !ok {
			result.TargetExternal = append(result.TargetExternal, pid)
		}
	}
	result.TargetExternal = sortedUniquePIDs(result.TargetExternal)
}

// PreflightMigration verifies that c can accept at least one new process. It
// opens cgroup.procs without writing and checks pids.max/pids.current when the
// pids controller files are present.
func (c *Manager) PreflightMigration() error {
	if c == nil {
		return errors.New("cgroups: target manager is nil")
	}
	procsPath := filepath.Join(c.path, cgroupProcs)
	f, err := os.OpenFile(procsPath, os.O_WRONLY, 0)
	if err != nil {
		return &TargetNotWritableError{Path: procsPath, Err: err}
	}
	if err := f.Close(); err != nil {
		return &TargetNotWritableError{Path: procsPath, Err: err}
	}

	full, current, limit, err := c.pidsFull()
	if err != nil {
		return err
	}
	if full {
		return &TargetFullError{Path: c.path, Current: current, Limit: limit}
	}
	return nil
}

// Preflight is a short alias for PreflightMigration.
func (c *Manager) Preflight() error { return c.PreflightMigration() }

// CheckMigrationReady is an alternate name for PreflightMigration.
func (c *Manager) CheckMigrationReady() error { return c.PreflightMigration() }

// IsFull reports whether pids.current has reached pids.max. A missing pids
// controller or pids.max == "max" is reported as not full.
func (c *Manager) IsFull() (bool, error) {
	full, _, _, err := c.pidsFull()
	return full, err
}

func (c *Manager) pidsFull() (full bool, current uint64, limit uint64, err error) {
	maxBytes, err := c.readCgroupFile("pids.max")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, 0, 0, nil
		}
		return false, 0, 0, fmt.Errorf("cgroups: read pids.max: %w", err)
	}
	maxValue := strings.TrimSpace(string(maxBytes))
	if maxValue == "max" {
		return false, 0, 0, nil
	}
	limit, err = strconv.ParseUint(maxValue, 10, 64)
	if err != nil {
		return false, 0, 0, fmt.Errorf("cgroups: parse pids.max %q: %w", maxValue, err)
	}

	currentBytes, err := c.readCgroupFile("pids.current")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// pids.max without pids.current is unexpected in a real hierarchy;
			// treat the limit as authoritative only when current is readable.
			return false, 0, limit, nil
		}
		return false, 0, limit, fmt.Errorf("cgroups: read pids.current: %w", err)
	}
	current, err = strconv.ParseUint(strings.TrimSpace(string(currentBytes)), 10, 64)
	if err != nil {
		return false, 0, limit, fmt.Errorf("cgroups: parse pids.current: %w", err)
	}
	return current >= limit, current, limit, nil
}

// TargetFullError wraps ErrTargetFull and reports the observed capacity.
type TargetFullError struct {
	Path    string
	Current uint64
	Limit   uint64
}

func (e *TargetFullError) Error() string {
	return fmt.Sprintf("%s: pids.current=%d pids.max=%d path=%q", ErrTargetFull, e.Current, e.Limit, e.Path)
}

func (e *TargetFullError) Unwrap() error { return ErrTargetFull }

// TargetNotWritableError wraps ErrTargetNotWritable and the filesystem cause.
type TargetNotWritableError struct {
	Path string
	Err  error
}

func (e *TargetNotWritableError) Error() string {
	return fmt.Sprintf("%s: %q: %v", ErrTargetNotWritable, e.Path, e.Err)
}

func (e *TargetNotWritableError) Unwrap() error {
	return errors.Join(ErrTargetNotWritable, e.Err)
}

// ProcessExitedError marks a PID that disappeared while migrating.
type ProcessExitedError struct {
	PID uint64
	Err error
}

func (e *ProcessExitedError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pid %d: %s: %v", e.PID, ErrProcessExited, e.Err)
	}
	return fmt.Sprintf("pid %d: %s", e.PID, ErrProcessExited)
}

func (e *ProcessExitedError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrProcessExited}
	}
	return []error{ErrProcessExited, e.Err}
}

func wrapProcessExited(pid uint64, err error) error {
	return &ProcessExitedError{PID: pid, Err: err}
}

func isNoSuchProcess(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrProcessDone) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such process") || strings.Contains(msg, "process already finished")
}

func processExists(pid uint64) bool {
	if pid == 0 {
		return true // PID 0 is the kernel context in some cgroup files; never migrate it.
	}
	err := unix.Kill(int(pid), 0)
	if err == nil {
		return true
	}
	return errors.Is(err, unix.EPERM)
}

var pidLockStripes [128]sync.Mutex

func lockPIDStripe(key string, pid uint64) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	var pidBytes [8]byte
	for i := 7; i >= 0; i-- {
		pidBytes[i] = byte(pid)
		pid >>= 8
	}
	_, _ = h.Write(pidBytes[:])
	mu := &pidLockStripes[h.Sum32()%uint32(len(pidLockStripes))]
	mu.Lock()
	return mu.Unlock
}

func groupIdentity(g ProcessGroup) string {
	switch v := g.(type) {
	case interface{ MigrationKey() string }:
		return v.MigrationKey()
	case interface{ Key() string }:
		return v.Key()
	case interface{ Path() string }:
		p := v.Path()
		if abs, err := filepath.Abs(p); err == nil {
			return "group:" + abs
		}
		return "group:" + p
	default:
		return fmt.Sprintf("%T:%p", g, g)
	}
}

func sortedUniquePIDs(in []uint64) []uint64 {
	if len(in) == 0 {
		return []uint64{}
	}
	out := append([]uint64(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	w := 1
	for r := 1; r < len(out); r++ {
		if out[r] != out[w-1] {
			out[w] = out[r]
			w++
		}
	}
	return out[:w]
}

func pidSet(pids []uint64) map[uint64]struct{} {
	m := make(map[uint64]struct{}, len(pids))
	for _, pid := range pids {
		m[pid] = struct{}{}
	}
	return m
}

func difference(a, b []uint64) []uint64 {
	bSet := pidSet(b)
	var out []uint64
	for _, pid := range sortedUniquePIDs(a) {
		if _, ok := bSet[pid]; !ok {
			out = append(out, pid)
		}
	}
	if out == nil {
		out = []uint64{}
	}
	return out
}

func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
