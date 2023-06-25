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
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ant4g0nist/chronometry/cmds"
	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/ant4g0nist/chronometry/pkg/util"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var publickeyCmd = &cobra.Command{
	Use:   "address",
	Short: "Display the address from the key",
	Long:  `Display the address from the key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmds.Banner()

		color.Green("🤸Checking Chronometry keys...")

		name := keys_name
		if keys_folder == "~/.chronometry" {
			keys_folder = filepath.Join(os.Getenv("HOME"), ".chronometry")
		}

		// check if keys_folder exists
		if _, err := os.Stat(keys_folder); os.IsNotExist(err) {
			color.Red("❌The folder %s does not exist.", keys_folder)
			os.Exit(1)
		}

		// check if keys_folder is a directory
		if info, err := os.Stat(keys_folder); err != nil || !info.IsDir() {
			color.Red("❌The folder %s is not a directory.", keys_folder)
			os.Exit(1)
		}

		// check if keys_folder is readable
		if _, err := os.Open(keys_folder); err != nil {
			color.Red("❌The folder %s is not readable.", keys_folder)
			os.Exit(1)
		}

		privateKeyPath := util.AbsPath(keys_folder, name)

		publicKey, _, err := signature.ReadPEMFromFile(privateKeyPath, passphrase)

		if err != nil {
			color.Red("❌Error in reading public key")
			os.Exit(1)
		}

		fmt.Println("🔑Your public key is: ", util.Red+base64.StdEncoding.EncodeToString(publicKey)+util.Reset)

		return nil
	},
}

func init() {

	publickeyCmd.PersistentFlags().StringVar(&keys_name, "name", "id_ed25519", "The base name for the public and private key files. The public key file will have the suffix '.pub' appended to the name.")

	publickeyCmd.PersistentFlags().StringVar(&keys_folder, "input", "~/.chronometry", "The folder to search the public and private key files.")

	publickeyCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "The passphrase to decrypt the private key.")

}
