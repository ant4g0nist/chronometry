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

var (
	targetFile string

	showAuthor          bool
	outputBlob          string
	outputSignatureFile string

	signCmd = &cobra.Command{
		Use:   "sign",
		Short: "Sign the supplied Vulnerability Report.",
		Long:  `Sign the supplied Vulnerability Report. This command will generate a signed blob that can be posted to the Chronometry's public data store.`,
		Run: func(cmd *cobra.Command, args []string) {

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

			publicKey, privateKey, err := signature.ReadPEMFromFile(privateKeyPath, passphrase)

			if err != nil {
				color.Red("❌Error in reading public key")
				os.Exit(1)
			}

			fmt.Println("🔑Loaded public key: ", util.Red+base64.StdEncoding.EncodeToString(publicKey)+util.Reset)

			signedBlob := signature.GenerateMessage(targetFile, publicKey, privateKey, showAuthor)

			// save signedBlob to file
			if outputSignatureFile != "" {
				signedBlob.SaveSignatureToFile(outputSignatureFile)
			}

			if outputBlob != "" {
				signedBlob.SaveBlobToFile(outputBlob)
			}

		},
	}
)

func init() {
	// Anonymous flag for author. This flag checks if we should hash author's name or not.
	// How can we have this as default true and then if the user specifies the flag, it will be false?
	signCmd.Flags().BoolVarP(&showAuthor, "show-author", "a", false, "Show the author's name in the report. By default, the author's name is hashed and included in the signature")

	signCmd.Flags().StringVarP(&targetFile, "reportFile", "f", "", "A vulnerability report file to calculate generate the signature for.")
	signCmd.MarkFlagRequired("targetFile")

	signCmd.PersistentFlags().StringVar(&keys_name, "name", "id_ed25519", "The base name for the public and private key files. The public key file will have the suffix '.pub' appended to the name.")
	signCmd.PersistentFlags().StringVar(&keys_folder, "input", "~/.chronometry", "The folder to search the public and private key files.")
	signCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "The passphrase to decrypt the private key.")

	signCmd.Flags().StringVarP(&outputSignatureFile, "output-signature", "o", "", "write the signature to FILE")
	signCmd.Flags().StringVarP(&outputBlob, "blob", "b", "", "write the blob to FILE")

}
