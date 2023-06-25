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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/ant4g0nist/chronometry/pkg/util"
	"github.com/fatih/color"
)

/*
This function verifies a given Report Blob file.
*/
func Verify(fileRef string) error {

	color.Green("⌛️Verifying signature...")

	var signerBlob SignerBlob

	// read the file
	signerBlob.ReadBlobFromJSONFile(fileRef)

	signature := signerBlob.Signature
	publicKey := signerBlob.PublicKey

	fmt.Printf("publicKey: %s\n", util.Red+base64.StdEncoding.EncodeToString(publicKey)+util.Reset)
	fmt.Printf("signature: %s\n", util.Green+base64.StdEncoding.EncodeToString(signature)+util.Reset)

	// calculate hash of the entire report
	reportHash := sha256.New()
	reportHash.Write([]byte(signerBlob.Report.Version))
	reportHash.Write([]byte(signerBlob.Report.Author))
	reportHash.Write([]byte(signerBlob.Report.Title))
	reportHash.Write([]byte(signerBlob.Report.Description))
	reportHash.Write([]byte(signerBlob.Report.Platform))
	reportHash.Write([]byte(signerBlob.Report.Attributes))
	reportHash.Write([]byte(signerBlob.Report.Severity))
	reportHash.Write([]byte(signerBlob.Report.Attachments))

	// verify signature
	if !ed25519.Verify(publicKey, reportHash.Sum(nil), []byte(signature)) {
		color.Red("❌Signature verification failed")
		os.Exit(254)
	}

	color.Green("✅Signature verification successful")
	return nil
}
