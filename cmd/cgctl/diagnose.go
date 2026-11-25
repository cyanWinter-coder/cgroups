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

package main

import (
	"encoding/json"
	"os"

	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/capabilities"
	"github.com/urfave/cli"
)

var diagnoseCommand = cli.Command{
	Name:    "diagnose-controllers",
	Aliases: []string{"diagnose", "capabilities", "probe-controllers"},
	Usage:   "emit machine-readable controller mount and writable-file diagnostics",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "target",
			Usage: "cgroup directory relative to the controller mount point to probe",
		},
		cli.StringFlag{
			Name:  "mountinfo",
			Usage: "path to a mountinfo file instead of /proc/self/mountinfo",
		},
		cli.StringSliceFlag{
			Name:  "controller",
			Usage: "limit probing to a controller name (may be repeated)",
		},
		cli.BoolFlag{
			Name:  "pretty",
			Usage: "pretty-print JSON",
		},
	},
	Action: func(clix *cli.Context) error {
		var opts []capabilities.Option
		// When the operator explicitly overrides the global cgroup root,
		// probe that hermetic/fake root. Otherwise parse the host mount table.
		if clix.GlobalIsSet("mountpoint") {
			opts = append(opts, capabilities.WithRoot(clix.GlobalString("mountpoint")))
		}
		if p := clix.String("mountinfo"); p != "" {
			opts = append(opts, capabilities.WithMountInfo(p))
		}
		if target := clix.String("target"); target != "" {
			opts = append(opts, capabilities.WithTarget(target))
		}
		if controllers := clix.StringSlice("controller"); len(controllers) > 0 {
			opts = append(opts, capabilities.WithControllers(controllers...))
		}
		report, err := cgroups.ProbeCapabilities(opts...)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		if clix.Bool("pretty") {
			enc.SetIndent("", "  ")
		}
		return enc.Encode(report)
	},
}
