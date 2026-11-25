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
	"os"
	"path/filepath"
)

// FSOps is the file operation seam used by tests and alternate cgroup
// backends. Production code uses dirFSOps against the real cgroup directory.
type FSOps interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	Remove(name string) error
}

// fsOps is the internal name retained for in-package test doubles.
type fsOps = FSOps

type dirFSOps struct {
	dir string
}

func (o dirFSOps) join(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(o.dir, name)
}

func (o dirFSOps) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(o.join(name))
}

func (o dirFSOps) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(o.join(name), data, perm)
}

func (o dirFSOps) Remove(name string) error {
	return os.Remove(o.join(name))
}

// fsOpsLocked returns the configured filesystem seam. The caller must hold
// c.mu (or be in construction code where no concurrency is possible).
func (c *Manager) fsOpsLocked() fsOps {
	if c == nil {
		return dirFSOps{}
	}
	for _, candidate := range []any{c.ops, c.Ops, c.fs, c.fileOps, c.backend} {
		if ops, ok := candidate.(fsOps); ok && ops != nil {
			return ops
		}
	}
	return dirFSOps{dir: c.path}
}

type fileReader interface {
	ReadFile(name string) ([]byte, error)
}

type fileWriter interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type fileRemover interface {
	Remove(name string) error
}

func (c *Manager) readerLocked() (fileReader, bool) {
	if c == nil {
		return nil, false
	}
	for _, candidate := range []any{c.ops, c.Ops, c.fs, c.fileOps, c.backend} {
		if r, ok := candidate.(fileReader); ok && r != nil {
			return r, true
		}
	}
	return nil, false
}

func (c *Manager) writerLocked() (fileWriter, bool) {
	if c == nil {
		return nil, false
	}
	for _, candidate := range []any{c.ops, c.Ops, c.fs, c.fileOps, c.backend} {
		if w, ok := candidate.(fileWriter); ok && w != nil {
			return w, true
		}
	}
	return nil, false
}

func (c *Manager) readCgroupFile(name string) ([]byte, error) {
	c.mu.Lock()
	r, ok := c.readerLocked()
	c.mu.Unlock()
	if ok {
		return r.ReadFile(name)
	}
	return os.ReadFile(filepath.Join(c.path, name))
}

func (c *Manager) writeCgroupFile(name string, data []byte, perm os.FileMode) error {
	c.mu.Lock()
	w, ok := c.writerLocked()
	c.mu.Unlock()
	if ok {
		return w.WriteFile(name, data, perm)
	}
	return os.WriteFile(filepath.Join(c.path, name), data, perm)
}
