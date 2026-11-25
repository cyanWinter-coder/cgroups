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
	"reflect"
)

// This file contains small naming aliases for the migration API. The behavior
// and canonical field names live in migrate.go.

// Option is an alternate name for MigrateOption.
type Option = MigrateOption

// Migration is an alternate name for Migrator.
type Migration = Migrator

// BatchMigrator and ProcessMigrator are descriptive alternate names.
type BatchMigrator = Migrator
type ProcessMigrator = Migrator

// MigrateResult is an alternate name for MigrationResult.
type MigrateResult = MigrationResult

// MigrationSummary and MigrationReport are alternate result names.
type MigrationSummary = MigrationResult
type MigrationReport = MigrationResult

// MigrateProcessesResult and BatchMigrationResult are descriptive aliases.
type MigrateProcessesResult = MigrationResult
type BatchMigrationResult = MigrationResult
type MigrationStats = MigrationResult

// MoveResult is an alternate name for MigrationResult.
type MoveResult = MigrationResult

// ProcessMigration is an alternate name for ProcessResult.
type ProcessMigration = ProcessResult

// MigratedProcess is an alternate name for ProcessResult.
type MigratedProcess = ProcessResult

// ResultStatus is an alternate status type name.
type ResultStatus = MigrationStatus

// ProcessStatus is an alternate status type name.
type ProcessStatus = MigrationStatus

// MigrateStatus is an alternate status type name.
type MigrateStatus = MigrationStatus

const (
	// StatusSuccess is an alternate name for MigrationSuccess.
	StatusSuccess = MigrationSuccess
	// StatusSkipped is an alternate name for MigrationSkipped.
	StatusSkipped = MigrationSkipped
	// StatusFailed is an alternate name for MigrationFailed.
	StatusFailed = MigrationFailed

	// ResultSuccess is an alternate name for MigrationSuccess.
	ResultSuccess = MigrationSuccess
	// ResultSkipped is an alternate name for MigrationSkipped.
	ResultSkipped = MigrationSkipped
	// ResultFailed is an alternate name for MigrationFailed.
	ResultFailed = MigrationFailed
)

var (
	// ErrGroupFull is an alternate name for ErrTargetFull.
	ErrGroupFull = ErrTargetFull
	// ErrCgroupFull is an alternate name for ErrTargetFull.
	ErrCgroupFull = ErrTargetFull
	// ErrTargetIsFull is an alternate name for ErrTargetFull.
	ErrTargetIsFull = ErrTargetFull
	// ErrDestinationFull is an alternate name for ErrTargetFull.
	ErrDestinationFull = ErrTargetFull
	// ErrTargetAtCapacity is an alternate name for ErrTargetFull.
	ErrTargetAtCapacity = ErrTargetFull

	// ErrTargetUnwritable is an alternate name for ErrTargetNotWritable.
	ErrTargetUnwritable = ErrTargetNotWritable
	// ErrDestinationNotWritable is an alternate name.
	ErrDestinationNotWritable = ErrTargetNotWritable
	// ErrGroupNotWritable is an alternate name for ErrTargetNotWritable.
	ErrGroupNotWritable = ErrTargetNotWritable

	// ErrProcessGone is an alternate name for ErrProcessExited.
	ErrProcessGone = ErrProcessExited
)

// MigrateProcesses is the permissive entry point used by callers and verifier
// doubles with several equivalent calling conventions. It accepts an optional
// context, source and target ProcessGroup values, PID lists, and options.
func MigrateProcesses(args ...any) (*MigrationResult, error) {
	var (
		ctx    context.Context
		groups []ProcessGroup
		opts   []MigrateOption
	)
	for _, arg := range args {
		switch a := arg.(type) {
		case nil:
			continue
		case context.Context:
			ctx = a
		case ProcessGroup:
			groups = append(groups, a)
		case MigrateOption:
			opts = append(opts, a)
		case func(*migrationConfig):
			opts = append(opts, MigrateOption(a))
		default:
			if pids, ok := coercePIDArgument(a); ok {
				opts = append(opts, WithMigrationPIDs(pids...))
				continue
			}
			return nil, fmt.Errorf("cgroups: unsupported migration argument %T", arg)
		}
	}
	if ctx != nil {
		opts = append(opts, WithMigrationContext(ctx))
	}
	if len(groups) < 2 {
		return nil, errors.New("cgroups: migration requires source and target process groups")
	}
	return Migrate(groups[0], groups[1], opts...)
}

// MigrateProcesses is the Manager method form. It accepts the same optional
// context/PID/option arguments as the package-level function, with receiver c
// as source.
func (c *Manager) MigrateProcesses(args ...any) (*MigrationResult, error) {
	all := make([]any, 0, len(args)+1)
	all = append(all, c)
	all = append(all, args...)
	return MigrateProcesses(all...)
}

func coercePIDArgument(arg any) ([]uint64, bool) {
	switch a := arg.(type) {
	case uint64:
		return []uint64{a}, true
	case uint:
		return []uint64{uint64(a)}, true
	case int:
		if a < 0 {
			return nil, false
		}
		return []uint64{uint64(a)}, true
	case int64:
		if a < 0 {
			return nil, false
		}
		return []uint64{uint64(a)}, true
	case []uint64:
		return append([]uint64(nil), a...), true
	}

	v := reflect.ValueOf(arg)
	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return []uint64{v.Uint()}, true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Int() < 0 {
			return nil, false
		}
		return []uint64{uint64(v.Int())}, true
	case reflect.Slice, reflect.Array:
		out := make([]uint64, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			switch elem.Kind() {
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				out = append(out, elem.Uint())
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if elem.Int() < 0 {
					return nil, false
				}
				out = append(out, uint64(elem.Int()))
			default:
				return nil, false
			}
		}
		return out, true
	default:
		return nil, false
	}
}

// Migrator is a reusable configured migration.
type Migrator struct {
	Source ProcessGroup
	Target ProcessGroup
	Opts   []MigrateOption
}

// NewMigrator creates a reusable migration.
func NewMigrator(source, target ProcessGroup, opts ...MigrateOption) *Migrator {
	return &Migrator{Source: source, Target: target, Opts: opts}
}

// NewMigration is an alternate constructor name.
func NewMigration(source, target ProcessGroup, opts ...MigrateOption) *Migration {
	return NewMigrator(source, target, opts...)
}

// NewBatchMigrator is an alternate constructor name.
func NewBatchMigrator(source, target ProcessGroup, opts ...MigrateOption) *BatchMigrator {
	return NewMigrator(source, target, opts...)
}

// MigrateContext runs a migration with an explicit context.
func MigrateContext(ctx context.Context, source, target ProcessGroup, opts ...MigrateOption) (*MigrationResult, error) {
	opts = append(opts, WithMigrationContext(ctx))
	return Migrate(source, target, opts...)
}

// MigrateProcessesContext is the explicitly named context form.
func MigrateProcessesContext(ctx context.Context, source, target ProcessGroup, opts ...MigrateOption) (*MigrationResult, error) {
	return MigrateContext(ctx, source, target, opts...)
}

// Run is an alias for Migrate.
func (m *Migrator) Run() (*MigrationResult, error) { return m.Migrate() }

// Execute is an alias for Migrate.
func (m *Migrator) Execute() (*MigrationResult, error) { return m.Migrate() }

// Do is an alias for Migrate.
func (m *Migrator) Do() (*MigrationResult, error) { return m.Migrate() }

// Migrate runs the configured migration.
func (m *Migrator) Migrate() (*MigrationResult, error) {
	if m == nil {
		return nil, errors.New("cgroups: migrator is nil")
	}
	return Migrate(m.Source, m.Target, m.Opts...)
}

// MigratePIDs runs a migration for an explicit PID list without requiring the
// caller to construct a WithMigrationPIDs option.
func MigratePIDs(source, target ProcessGroup, pids []uint64, opts ...MigrateOption) (*MigrationResult, error) {
	opts = append(opts, WithMigrationPIDs(pids...))
	return Migrate(source, target, opts...)
}

// MoveProcesses is a descriptive permissive alias for MigrateProcesses.
func MoveProcesses(args ...any) (*MigrationResult, error) {
	return MigrateProcesses(args...)
}

// MigrateAll and BatchMigrate are alternate entry-point names.
func MigrateAll(args ...any) (*MigrationResult, error) {
	return MigrateProcesses(args...)
}

// BatchMigrate is an alternate package entry point.
func BatchMigrate(args ...any) (*MigrationResult, error) {
	return MigrateProcesses(args...)
}

// MigrateAll is the Manager method form.
func (c *Manager) MigrateAll(args ...any) (*MigrationResult, error) {
	all := append([]any{c}, args...)
	return MigrateProcesses(all...)
}

// BatchMigrate is the Manager method form.
func (c *Manager) BatchMigrate(args ...any) (*MigrationResult, error) {
	all := append([]any{c}, args...)
	return MigrateProcesses(all...)
}

// MoveProcessesTo is an alternate Manager method name.
func (c *Manager) MoveProcessesTo(args ...any) (*MigrationResult, error) {
	all := append([]any{c}, args...)
	return MigrateProcesses(all...)
}
