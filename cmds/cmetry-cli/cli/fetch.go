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
	"fmt"

	"github.com/ant4g0nist/chronometry/pkg/core/client"
	"github.com/spf13/cobra"
)

var (
	index    int
	recordID string

	fetchByIndexCmd = &cobra.Command{
		Use:   "index",
		Short: "Fetch a vulnerability report by index",
		Long:  `Fetch a vulnerability report by index. This command will fetch a signed blob from the Chronometry's public data store.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("fetching by index", index)
			client.FetchReportByIndex(chronometryServer, index)
		},
	}

	fetchByRecordCmd = &cobra.Command{
		Use:   "record",
		Short: "Fetch a vulnerability report by record ID",
		Long:  `Fetch a vulnerability report by record ID. This command will fetch a signed blob from the Chronometry's public data store.`,

		Run: func(cmd *cobra.Command, args []string) {
			client.FetchReportByRecord(chronometryServer, recordID)
		},
	}

	fetchCmd = &cobra.Command{
		Use:   "fetch",
		Short: "Fetch a vulnerability report",
		Long:  `Fetch a vulnerability report. This command will fetch a signed blob from the Chronometry's public data store.`,
	}
)

func init() {

	fetchByIndexCmd.Flags().IntVarP(&index, "index", "i", 0, "The index of the vulnerability report to fetch.")
	fetchByIndexCmd.MarkFlagRequired("index")

	fetchByRecordCmd.Flags().StringVarP(&recordID, "record", "r", "", "The record ID of the vulnerability report to fetch.")
	fetchByRecordCmd.MarkFlagRequired("record")

	fetchByIndexCmd.Flags().StringVarP(&chronometryServer, "server", "s", "https://chronometry.io", "The Chronometry server to use.")
	fetchByRecordCmd.Flags().StringVarP(&chronometryServer, "server", "s", "https://chronometry.io", "The Chronometry server to use.")

	fetchCmd.AddCommand(fetchByIndexCmd, fetchByRecordCmd)
	rootCmd.AddCommand(fetchCmd)
}
