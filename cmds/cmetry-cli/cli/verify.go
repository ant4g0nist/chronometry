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
	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	report string

	verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify a given report",
		Long:  `Verify a report file or a report index in the Chronometry's Trillian Log.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// check if report file is provided or index is provided
			if report == "" && index == -1 {
				color.Red("❌Please provide a report file or index")
				cmd.Help()
				os.Exit(1)
			}

			// check if report file exists
			if report != "" {
				if _, err := os.Stat(report); os.IsNotExist(err) {
					color.Red("❌The file %s does not exist.", report)
					os.Exit(1)
				}
				signature.VerifyFile(report)
			} else {
				if err := client.VerifyReportByIndex(chronometryServer, int64(index)); err != nil {
					color.Red("❌Signature verification failed")
					os.Exit(254)
				}
			}

			return nil
		},
	}
)

func init() {
	// input flags
	verifyCmd.Flags().StringVarP(&report, "report", "r", "", "Report blob to verify")
	// verifyCmd.MarkFlagRequired("report")

	// index of the report
	verifyCmd.Flags().IntVarP(&index, "index", "i", -1, "Index of the report to verify")
	verifyCmd.Flags().StringVarP(&chronometryServer, "server", "s", "https://chronometry.ant4g0nist.com", "The Chronometry server to use.")

	rootCmd.AddCommand(verifyCmd)
}
