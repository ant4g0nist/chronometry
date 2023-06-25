// Copyright 2023 WeFuzz Research and Development B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"fmt"
	"os"

	"github.com/ant4g0nist/chronometry/cmds"
	"github.com/ant4g0nist/chronometry/internal/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	// kubernetes sig
)

var (
	cfgFile  string
	logLevel string

	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start a Chronometry Server",
		Long:  `Starts a Chronometry server and serves the configured api`,
		Run: func(cmd *cobra.Command, args []string) {

			version := cmds.Version

			fmt.Println("Starting Chronometry server @ " + version)

			//load config
			_, err := loadConfig()
			if err != nil {
				log.Logger.Error("Failed to load the config", zap.Error(err))
				os.Exit(1)
			}

		},
	}
)

func init() {
	serveCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cmetry-server.yaml)")

	serveCmd.PersistentFlags().StringVar(&logLevel, "log_level", "dev", "logger level to use : dev/prod")

	rootCmd.AddCommand(serveCmd)

	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		log.Logger.Fatal(err.Error())
	}
}
