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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyGroupPath(t *testing.T) {
	valids := map[string]bool{
		"/":                          true,
		"":                           false,
		"/foo":                       true,
		"/foo/bar":                   true,
		"/sys/fs/cgroup/foo":         false,
		"/sys/fs/cgroup/unified/foo": false,
		"foo":                        false,
		"/foo/../bar":                false,
	}
	for s, valid := range valids {
		err := VerifyGroupPath(s)
		if valid {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestJoinNestedPath(t *testing.T) {
	cases := []struct {
		name    string
		group   string
		suffix  string
		want    string
		wantErr bool
	}{
		{name: "plain nesting", group: "/user.slice/session.scope", suffix: "child", want: "/user.slice/session.scope/child"},
		{name: "empty suffix", group: "/user.slice/session.scope", suffix: "", want: "/user.slice/session.scope"},
		{name: "nested suffix", group: "/a", suffix: "b/c", want: "/a/b/c"},
		{name: "traversal rejected", group: "/a", suffix: "../../etc", wantErr: true},
		{name: "dot segments rejected", group: "/a", suffix: "./b", wantErr: true},
		{name: "unclean group rejected", group: "/a/../b", suffix: "c", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := joinNestedPath(tc.group, tc.suffix)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
