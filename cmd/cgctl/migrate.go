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
	"fmt"
	"os"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/urfave/cli"
)

var migrateCommand = cli.Command{
	Name:      "migrate",
	Usage:     "migrate processes from one cgroup to another and verify the result",
	ArgsUsage: "SOURCE DESTINATION",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "recursive",
			Usage: "include processes in child cgroups when enumerating and auditing",
		},
		cli.BoolFlag{
			Name:  "pretty",
			Usage: "pretty-print the JSON migration report",
		},
	},
	Action: func(clix *cli.Context) error {
		if clix.NArg() != 2 {
			return fmt.Errorf("source and destination cgroup paths are required")
		}
		mountpoint := clix.GlobalString("mountpoint")
		sourcePath := clix.Args().Get(0)
		destinationPath := clix.Args().Get(1)

		source, err := cgroup2.Load(sourcePath, cgroup2.WithMountpoint(mountpoint))
		if err != nil {
			return fmt.Errorf("load source %q: %w", sourcePath, err)
		}
		destination, err := cgroup2.Load(destinationPath, cgroup2.WithMountpoint(mountpoint))
		if err != nil {
			return fmt.Errorf("load destination %q: %w", destinationPath, err)
		}

		report, err := source.MigrateTo(destination,
			cgroup2.WithRecursiveMigration(clix.Bool("recursive")),
		)
		if report != nil {
			encoder := json.NewEncoder(os.Stdout)
			if clix.Bool("pretty") {
				encoder.SetIndent("", "  ")
			}
			if encodeErr := encoder.Encode(report); encodeErr != nil {
				return encodeErr
			}
		}
		if err != nil {
			return err
		}
		if report.HasFailures() {
			return cli.NewExitError(fmt.Sprintf("migration completed with %d failed process(es)", len(report.Failed)), 1)
		}
		return nil
	},
}
