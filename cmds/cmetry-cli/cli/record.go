// Copyright 2023 WeFuzz Research and Development B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cli

import (
	"os"

	"github.com/ant4g0nist/chronometry/pkg/core/client"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	chronometryServer string

	recordCmd = &cobra.Command{
		Use:   "record",
		Short: "Record a vulnerability report",
		Long:  `Record a vulnerability report. This command will generate a signed blob that can be posted to the Chronometry's public data store.`,
		Run: func(cmd *cobra.Command, args []string) {

			// check if report file exists
			if _, err := os.Stat(report); os.IsNotExist(err) {
				color.Red("❌The file %s does not exist.", report)
				os.Exit(1)
			}

			// check if server is reachable
			if !client.CheckServerReachable(chronometryServer) {
				color.Red("❌The server %s is not reachable.", chronometryServer)
				os.Exit(1)
			}

			// upload the report
			if err := client.UploadReport(keys_folder, chronometryServer, report); err != nil {
				color.Red("❌The report could not be uploaded.")
				os.Exit(1)
			}

		},
	}
)

func init() {
	recordCmd.Flags().StringVarP(&report, "file", "f", "", "The vulnerability report file to sign.")
	recordCmd.MarkFlagRequired("file")

	recordCmd.PersistentFlags().StringVar(&keys_folder, "input", "~/.chronometry", "The folder to search the public and private key files.")

	recordCmd.Flags().StringVarP(&chronometryServer, "server", "s", "https://chronometry.ant4g0nist.com", "The Chronometry server to use.")
}
