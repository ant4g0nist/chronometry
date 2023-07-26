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
func VerifyFile(fileRef string) error {

	color.Green("⌛️Verifying signature...")

	var signerBlob SignerBlob

	// read the file
	signerBlob.ReadBlobFromJSONFile(fileRef)

	signature := signerBlob.Signature
	publicKey := signerBlob.PublicKey

	fmt.Printf("publicKey: %s\n", util.Red+base64.StdEncoding.EncodeToString(publicKey)+util.Reset)
	fmt.Printf("signature: %s\n", util.Green+base64.StdEncoding.EncodeToString(signature)+util.Reset)

	// calculate hash of the entire report & verify signature
	if !verifyReport(signerBlob.Report, publicKey, signature) {
		color.Red("❌Signature verification failed")
		os.Exit(254)
	}

	color.Green("✅Signature verification successful")
	return nil
}

/*
This function verifies given Report Entry.
*/
func VerifyReportWithBase64(report Report, publicKey string, signature string) bool {
	color.Green("⌛️Verifying signature...")

	// decode base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		color.Red("❌Invalid public key")
		return false
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		color.Red("❌Invalid signature")
		return false
	}

	// verify signature
	if !verifyReport(report, publicKeyBytes, signatureBytes) {
		color.Red("❌Signature verification failed")
		return false
	}

	return true
}

/*
This function verifies given Report Entry with public key as ed25519.PublicKey.
*/
func VerifyReportWithPublicKey(report Report, publicKey ed25519.PublicKey, signature []byte) bool {
	color.Green("⌛️Verifying signature...")

	// verify signature
	if !verifyReport(report, publicKey, signature) {
		color.Red("❌Signature verification failed")
		return false
	}

	return true
}

/*
This function verifies given Report.
*/
func verifyReport(report Report, publicKey []byte, signature []byte) bool {
	// calculate hash of the entire report
	authorHash := base64.URLEncoding.EncodeToString(Hash(report.Author))

	reportHash := sha256.New()
	reportHash.Write([]byte(report.Version))
	reportHash.Write([]byte(authorHash))
	reportHash.Write([]byte(report.AuthorDetailsHash))
	reportHash.Write([]byte(report.Title))
	reportHash.Write([]byte(report.Description))
	reportHash.Write([]byte(report.Platform))
	reportHash.Write([]byte(report.Attributes))
	reportHash.Write([]byte(report.Severity))
	reportHash.Write([]byte(report.Attachments))

	// verify signature
	return ed25519.Verify(publicKey, reportHash.Sum(nil), []byte(signature))
}
