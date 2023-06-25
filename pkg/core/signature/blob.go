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
package signature

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ant4g0nist/chronometry/pkg/core/report"
	"github.com/fatih/color"
)

/*
This function is used to generate a signed, crymessage to be posted on
the Trillian data store. It takes a target file as input
*/
func GenerateMessage(targetFile string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) SignerBlob {
	color.Green("⌛️Generating signed blob for %s", targetFile)

	// load the report
	rep, err := report.LoadReport(filepath.Clean(targetFile))
	if err != nil {
		color.Red("Failed to load report: %s LoadReport(): %s", targetFile, err)
		os.Exit(1)
	}

	// Sign the message and generate a signed blob
	signedBlob := SignMessage(rep, publicKey, privateKey)

	color.Green("✅Signed blob generated successfully")
	return signedBlob
}

/*
This function is used to load a file from the local file system.
It takes a file reference as input and returns the file contents as a byte array
*/
func LoadFile(fileRef string) ([]byte, error) {
	var raw []byte

	// check if the file exists
	if _, err := os.Stat(fileRef); os.IsNotExist(err) {
		return nil, err
	}

	// check if the file is a directory or a file
	if info, err := os.Stat(fileRef); err == nil && info.IsDir() {
		// read the directory
		return nil, fmt.Errorf("fileRef is a directory")
	} else {
		// read the file
		raw, err = os.ReadFile(filepath.Clean(fileRef))
		if err != nil {
			return nil, err
		}
	}

	return raw, nil
}
