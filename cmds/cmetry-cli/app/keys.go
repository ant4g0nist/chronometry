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
package app

import (
	"os"
	"path/filepath"

	"github.com/ant4g0nist/chronometry/cmds"
	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// This file implements the key management commands.

var (
	// keysDir     string
	keys_name   string
	keys_folder string
	passphrase  string
	yes         bool
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 64
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 256
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 128
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

func init() {

	generateCmd.PersistentFlags().StringVar(&keys_name, "name", "id_ed25519", "The base name for the public and private key files. The public key file will have the suffix '.pub' appended to the name.")

	generateCmd.PersistentFlags().StringVar(&keys_folder, "output", "~/.chronometry", "The folder to save the public and private key files. If the folder does not exist, it will be created.")

	generateCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "The passphrase to encrypt the private key file while saving.")

	generateCmd.PersistentFlags().BoolVar(&yes, "yes", false, "Non-interactive mode. Do not prompt for confirmation.")

	// We read passphrase from stdin, env or pipe.
	// If passphrase is not provided, we will prompt for it.
	// If passphrase is provided, we will use it.

	keysCmd.AddCommand(generateCmd)
}

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage Chronometry's ed25519 keys",
	Long:  "Manage Chronometry's ed25519 keys for secure communications",
	Example: ` # Generate a new Chronometry key pair,

	# Save keys will be saved in ~/.chronometry/
	chronometry keys generate

	# Save keys will be saved in ~/mykeys/
	chronometry keys generate --output ~/mykeys/

	# Save keys will be saved in ~/mykeys/ with the name mykeys
	chronometry keys generate --output ~/mykeys/ --name mykeys

	# save keys and encrypt them with a passphrase
	CHRONOMETRY_PASSWORD=myPassPhrase chronometry keys generate --output ~/mykeys/ --name mykeys

	# save keys and encrypt them with a passphrase
	chronometry keys generate --output ~/mykeys/ --name mykeys --passphrase mypassphrase

	# save keys non-interactively
	chronometry keys generate --output ~/mykeys/ --name mykeys --passphrase mypassphrase --yes
	`,
}

var generateCmd = &cobra.Command{
	Use:   "generate <name>",
	Short: "Generate a new Chronometry key pair",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmds.Banner()

		color.Green("🤸Generating public/private ed25519 key pair.")

		// default file names for private and public keys: id_ed25519 & id_ed25519.pub
		// we are following the filename standards from ssh
		name := keys_name
		if keys_folder == "~/.chronometry" {
			keys_folder = filepath.Join(os.Getenv("HOME"), ".chronometry")
		}

		// Create the root directory if it doesn't exist
		if err := os.MkdirAll(keys_folder, 0700); err != nil {
			return err
		}

		// Generate a new ed25519 private key
		publicKey, privateKey, err := signature.GenerateKeyPair()
		if err != nil {
			return err
		}

		// Save Private Key as PEM File
		signature.SavePrivateKey(privateKey, keys_folder, name, passphrase, yes)
		signature.SavePublicKey(publicKey, keys_folder, name, yes)

		color.Green("🎉Chronometry keys are written to path " + keys_folder + " \n")

		return nil
	},
}
