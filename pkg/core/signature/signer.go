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
	"encoding/json"
	"log"
	"os"

	"github.com/ant4g0nist/chronometry/pkg/core/report"
)

/*
This is the vulnerability report structure YAML file passed as input to generate the Signature.
*/
type VulnerabilityBlob struct {
	// The version of the report file.
	Version string `json:"Version"`

	// Title of the report
	Title string `json:"Title"`

	// Description of the report
	Description string `json:"Description"`

	// Attributes of the report: list of key value pairs: e.g. "CVE": "CVE-2021-1234"
	Attributes string `json:"Attributes"`

	// Author of the report
	Author string `json:"Author"`

	// Platform of the report
	Platform string `json:"Platform"`

	// Severity of the report
	Severity string `json:"Severity"`

	// Attachments of the report
	Attachments string `json:"Attachments"`
}

// Signer creates digital signatures over a message using a specified key pair
type SignerBlob struct {
	Report    VulnerabilityBlob `json:"Report"`
	PublicKey ed25519.PublicKey `json:"PublicKey"`
	Signature []byte            `json:"Signature"`
}

func (s *SignerBlob) SaveSignatureToFile(output string) bool {
	// Save the signature to a file
	signature := s.Signature
	// write to file
	err := os.WriteFile(output, []byte(signature), 0644)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return true
}

func (s *SignerBlob) GetBytes() []byte {
	var blob []byte
	blob = append(blob, []byte(s.Report.Version)...)
	blob = append(blob, []byte(s.Report.Title)...)
	blob = append(blob, []byte(s.Report.Description)...)
	blob = append(blob, []byte(s.Report.Attributes)...)
	blob = append(blob, []byte(s.Report.Author)...)
	blob = append(blob, []byte(s.Report.Platform)...)
	blob = append(blob, []byte(s.Report.Severity)...)
	blob = append(blob, []byte(s.Report.Attachments)...)
	blob = append(blob, []byte(s.PublicKey)...)
	blob = append(blob, []byte(s.Signature)...)
	return blob
}

func (s *SignerBlob) ReadBlobFromJSONFile(input string) bool {
	// read SignerBlob from json file
	signerBlob, err := os.ReadFile(input)
	if err != nil {
		log.Fatal(err)
		return false
	}

	// unmarshal
	err = json.Unmarshal(signerBlob, &s)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return true
}

func (s *SignerBlob) PrettyPrintJSON() string {
	// Pretty print JSON
	data, _ := json.MarshalIndent(s, "", " ")
	return string(data)
}

func (s *SignerBlob) SaveBlobToFile(output string) bool {
	// Save the blob to a file
	data, _ := json.MarshalIndent(s, "", " ")

	// write to file
	err := os.WriteFile(output, data, 0644)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return true
}

// Signer creates digital signatures over a message using a specified key pair
func SignMessage(report report.VulnerabilityReport, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) SignerBlob {

	// Sign the message and generate a signed blob
	authorHash := base64.URLEncoding.EncodeToString(report.Author.Hash())
	titleHash := base64.URLEncoding.EncodeToString(Hash(report.Title))
	descriptionHash := base64.URLEncoding.EncodeToString(Hash(report.Description))
	platformHash := base64.URLEncoding.EncodeToString(Hash(string(report.Platform)))
	severityHash := base64.URLEncoding.EncodeToString(Hash(string(report.Severity)))
	versionHash := base64.URLEncoding.EncodeToString(Hash(string(report.Version)))

	attributeHash := sha256.New()
	for _, attribute := range report.Attributes {
		hash := attribute.Hash()
		attributeHash.Write(hash)
	}

	attributeHashSum := base64.URLEncoding.EncodeToString(attributeHash.Sum(nil))

	attachmentsHash := sha256.New()
	for _, attachment := range report.Attachments {
		hash := attachment.Hash()
		attachmentsHash.Write(hash)
	}

	attachmentsHashSum := base64.URLEncoding.EncodeToString(attachmentsHash.Sum(nil))

	// calculate hash of the entire report
	reportHash := sha256.New()
	reportHash.Write([]byte(versionHash))
	reportHash.Write([]byte(authorHash))
	reportHash.Write([]byte(titleHash))
	reportHash.Write([]byte(descriptionHash))
	reportHash.Write([]byte(platformHash))
	reportHash.Write([]byte(attributeHashSum))
	reportHash.Write([]byte(severityHash))
	reportHash.Write([]byte(attachmentsHashSum))

	// sign the report
	signature := ed25519.Sign(privateKey, reportHash.Sum(nil))

	// create a signed blob
	signedBlob := SignerBlob{
		Report: VulnerabilityBlob{
			Version:     versionHash,
			Author:      authorHash,
			Title:       titleHash,
			Description: descriptionHash,
			Platform:    platformHash,
			Attributes:  attributeHashSum,
			Severity:    severityHash,
			Attachments: attachmentsHashSum,
		},
		PublicKey: publicKey,
		Signature: signature,
	}

	return signedBlob
}

// Hash calculates the hash of a byte array
func Hash(data string) []byte {
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}
