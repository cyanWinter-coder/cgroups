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

// Package diagnostics provides an alternately named entry point for capability probing.
package diagnostics

import "github.com/containerd/cgroups/v3/capabilities"

type (
	Report     = capabilities.Report
	Diagnostic = capabilities.Report
	Controller = capabilities.Controller
	Mount      = capabilities.Mount
	Option     = capabilities.Option
)

func Probe(opts ...Option) (*Report, error) { return capabilities.Probe(opts...) }
func Diagnose(opts ...Option) (*Diagnostic, error) {
	return capabilities.Diagnose(opts...)
}
func New(opts ...Option) (*Report, error) { return capabilities.Probe(opts...) }

func WithRoot(path string) Option      { return capabilities.WithRoot(path) }
func WithMountInfo(path string) Option { return capabilities.WithMountInfo(path) }
func WithTarget(target string) Option  { return capabilities.WithTarget(target) }
func WithControllers(names ...string) Option {
	return capabilities.WithControllers(names...)
}
