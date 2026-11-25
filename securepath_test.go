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

package cgroups

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyLogicalGroup(t *testing.T) {
	cases := map[string]error{
		"/":                        nil,
		"/foo":                     nil,
		"/foo/bar":                 nil,
		"/user.slice/u-1000.scope": nil,
		"":                         ErrInvalidGroup,
		"foo":                      ErrInvalidGroup,
		"/foo/../bar":              ErrPathEscape,
		"/foo/./bar":               ErrPathEscape,
		"/sys/fs/cgroup/foo":       ErrMountPointPrefix,
		"/sys/fs/cgroup/unified/x": ErrMountPointPrefix,
	}
	for group, wantErr := range cases {
		err := VerifyLogicalGroup(group)
		if wantErr == nil {
			if err != nil {
				t.Errorf("VerifyLogicalPath(%q): unexpected error %v", group, err)
			}
			continue
		}
		if !errors.Is(err, wantErr) {
			t.Errorf("VerifyLogicalPath(%q): got %v, want %v", group, err, wantErr)
		}
	}
}

func TestSecureJoinLexicalBoundary(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name    string
		group   string
		wantErr error
	}{
		{"root itself", "/", nil},
		{"plain group", "/foo/bar", nil},
		{"parent escape", "/foo/../../etc", ErrPathEscape},
		{"absolute-looking segment", "/foo/../../../", ErrPathEscape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SecureJoin(root, tc.group)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !isWithinRoot(filepath.Clean(root), filepath.Clean(got)) {
				t.Fatalf("result %q escapes root %q", got, root)
			}
		})
	}
}

func TestSecureJoinMissingComponents(t *testing.T) {
	root := t.TempDir()
	// Nothing exists below root yet: the lexical result is returned, which is
	// what cgroup creation paths require.
	got, err := SecureJoin(root, "/a/b/c")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "a", "b", "c")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSecureJoinSymlinkInside(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "realdir")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink("realdir", link); err != nil {
		t.Fatal(err)
	}
	got, err := SecureJoin(root, "/link/child")
	if err != nil {
		t.Fatalf("internal symlink rejected: %v", err)
	}
	if !isWithinRoot(root, got) {
		t.Fatalf("result %q outside root", got)
	}
}

func TestSecureJoinSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "evil")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := SecureJoin(root, "/evil/secret"); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}

	// Relative link climbing out of the root is rejected as well.
	link2 := filepath.Join(root, "evil2")
	if err := os.Symlink("../../..", link2); err != nil {
		t.Fatal(err)
	}
	if _, err := SecureJoin(root, "/evil2/etc"); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}
}

func TestSecureJoinSymlinkChain(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "real", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	// a -> real, b -> a/deep: every hop stays inside the root.
	if err := os.Symlink("real", filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("a", "deep"), filepath.Join(root, "b")); err != nil {
		t.Fatal(err)
	}
	got, err := SecureJoin(root, "/b/workload")
	if err != nil {
		t.Fatalf("internal link chain rejected: %v", err)
	}
	if !isWithinRoot(root, got) {
		t.Fatalf("result %q outside root", got)
	}
}

func TestSecureJoinSymlinkLoop(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	if _, err := SecureJoin(root, "/loop/x"); !errors.Is(err, ErrSymlinkLoop) {
		t.Fatalf("got %v, want ErrSymlinkLoop", err)
	}
}

func TestSecureJoinEscapeHiddenBehindParentLink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	// A benign-looking link points inside the root, but the directory it
	// points to contains another link that escapes.
	if err := os.MkdirAll(filepath.Join(root, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("inner", filepath.Join(root, "gate")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "inner", "trap")); err != nil {
		t.Fatal(err)
	}
	if _, err := SecureJoin(root, "/gate/trap/secret"); !errors.Is(err, ErrSymlinkEscape) {
		t.Fatalf("got %v, want ErrSymlinkEscape", err)
	}
}

func TestStalePathErrorSentinel(t *testing.T) {
	err := &StalePathError{
		OldMode:     Legacy,
		CurrentMode: Unified,
		OldPath:     "/sys/fs/cgroup/memory/x",
		NewPath:     "/sys/fs/cgroup/x",
	}
	if !errors.Is(err, ErrStalePath) {
		t.Fatal("StalePathError must satisfy errors.Is(err, ErrStalePath)")
	}
	msg := err.Error()
	for _, want := range []string{"/sys/fs/cgroup/memory/x", "/sys/fs/cgroup/x", "stale"} {
		if !contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}

	noNew := &StalePathError{OldMode: Unified, CurrentMode: Legacy, OldPath: "/x"}
	if !errors.Is(noNew, ErrStalePath) || contains(noNew.Error(), "use ") {
		t.Fatalf("empty NewPath must not advertise a replacement: %v", noNew)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
