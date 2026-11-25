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

// Package capability contains compatibility aliases for package capabilities.
package capability

import "github.com/containerd/cgroups/v3/capabilities"

type (
	Report          = capabilities.Report
	Controller      = capabilities.Controller
	File            = capabilities.File
	Mount           = capabilities.Mount
	Version         = capabilities.Version
	Status          = capabilities.Status
	Policy          = capabilities.Policy
	Option          = capabilities.Option
	RequestedLimit  = capabilities.RequestedLimit
	MissingLimit    = capabilities.MissingLimit
	PolicyResult    = capabilities.PolicyResult
	UnwritableError = capabilities.UnwritableError
)

const (
	VersionUnknown = capabilities.VersionUnknown
	VersionV1      = capabilities.VersionV1
	VersionV2      = capabilities.VersionV2
	VersionHybrid  = capabilities.VersionHybrid

	StatusAvailable = capabilities.StatusAvailable
	StatusDegraded  = capabilities.StatusDegraded
	StatusReadOnly  = capabilities.StatusReadOnly
	StatusMissing   = capabilities.StatusMissing
	StatusError     = capabilities.StatusError

	PolicyStrict     = capabilities.PolicyStrict
	PolicyFailClosed = capabilities.PolicyFailClosed
	PolicyDegrade    = capabilities.PolicyDegrade
	PolicyContinue   = capabilities.PolicyContinue
	PolicyBestEffort = capabilities.PolicyBestEffort
)

var (
	ErrControllerUnavailable = capabilities.ErrControllerUnavailable
	ErrFileNotWritable       = capabilities.ErrFileNotWritable
	ErrControllerNotWritable = capabilities.ErrControllerNotWritable
	ErrDegradedPolicy        = capabilities.ErrDegradedPolicy
)

func Probe(opts ...Option) (*Report, error)  { return capabilities.Probe(opts...) }
func Detect(opts ...Option) (*Report, error) { return capabilities.Detect(opts...) }
func Diagnose(opts ...Option) (*Report, error) {
	return capabilities.Diagnose(opts...)
}
func ProbePath(path string, version Version, opts ...Option) (*Report, error) {
	return capabilities.ProbePath(path, version, opts...)
}
func CheckWritable(r *Report, controller, file string) error {
	return capabilities.CheckWritable(r, controller, file)
}
func CheckPathWritable(path string) error { return capabilities.CheckPathWritable(path) }
func CheckFileWritable(path, controller string) error {
	return capabilities.CheckFileWritable(path, controller)
}
func NormalizeName(name string) string { return capabilities.NormalizeName(name) }

func WithRoot(root string) Option       { return capabilities.WithRoot(root) }
func WithProcRoot(root string) Option   { return capabilities.WithProcRoot(root) }
func WithMountpoint(path string) Option { return capabilities.WithMountpoint(path) }
func WithMountInfo(path string) Option  { return capabilities.WithMountInfo(path) }
func WithCgroupFile(path string) Option { return capabilities.WithCgroupFile(path) }
func WithTarget(target string) Option   { return capabilities.WithTarget(target) }
func WithMountPoint(path string) Option { return capabilities.WithMountPoint(path) }
func WithDirectory(path string) Option  { return capabilities.WithDirectory(path) }
func WithControllers(names ...string) Option {
	return capabilities.WithControllers(names...)
}
func WithoutDirectoryEnumeration() Option {
	return capabilities.WithoutDirectoryEnumeration()
}
