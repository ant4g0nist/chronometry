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
package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/ant4g0nist/chronometry/pkg/util"
	"github.com/fatih/color"
)

type RecordEntryResponse struct {
	Data    Data `json:"data"`
	Success bool `json:"success"`
}

type Entry struct {
	ETag     string            `json:"ETag"`
	Location string            `json:"Location"`
	Payload  map[string]Record `json:"Payload"`
	Cid      string            `json:"cid"`
}

func (e *Entry) Bytes() []byte {
	b, _ := json.Marshal(e)
	return b
}

type Record struct {
	Body string `json:"body"`
	// Version        string       `json:"version"`
	// Description    string       `json:"description"`
	// Attributes     string       `json:"attributes"`
	// Author         string       `json:"author"`
	// Platform       string       `json:"platform"`
	// Service        string       `json:"service"`
	// Severity       string       `json:"severity"`
	// Attachments    string       `json:"attachments"`
	// PubKey         string       `json:"pubKey"`
	// Signature      string       `json:"signature"`
	IntegratedTime int64        `json:"integratedTime"`
	LogID          string       `json:"logID"`
	LogIndex       int64        `json:"logIndex"`
	Verification   Verification `json:"verification"`
}

type InclusionProof struct {
	Checkpoint interface{} `json:"checkpoint"`
	Hashes     []string    `json:"hashes"`
	LogIndex   int64       `json:"logIndex"`
	RootHash   string      `json:"rootHash"`
	TreeSize   int64       `json:"treeSize"`
}

type Verification struct {
	InclusionProof *InclusionProof `json:"inclusionProof"`

	SignedEntryTimestamp string `json:"signedEntryTimestamp"`
}

type Data struct {
	Entry Entry  `json:"entry"`
	Error string `json:"error"`
}

func (r *RecordEntryResponse) PrettyPrint() {
	entry := r.Data.Entry
	fmt.Println("ETag:", entry.ETag)
	fmt.Println("Location:", entry.Location)

	for key, record := range entry.Payload {
		fmt.Println("Payload:")
		fmt.Println("  Key:", key)
		fmt.Println("  IntegratedTime:", record.IntegratedTime)
		fmt.Println("  LogID:", record.LogID)
		fmt.Println("  LogIndex:", record.LogIndex)
		fmt.Println("  Verification:")
		fmt.Println("    InclusionProof:")
		fmt.Println("      Checkpoint:", record.Verification.InclusionProof.Checkpoint)
		fmt.Println("      Hashes:", record.Verification.InclusionProof.Hashes)
		fmt.Println("      LogIndex:", record.Verification.InclusionProof.LogIndex)
		fmt.Println("      RootHash:", record.Verification.InclusionProof.RootHash)
		fmt.Println("      TreeSize:", record.Verification.InclusionProof.TreeSize)
		fmt.Println("    SignedEntryTimestamp:", record.Verification.SignedEntryTimestamp)
		if entry.Cid != "" {
			fmt.Println("  IPFS Cid:", entry.Cid)
		}
	}
}

/*
Save Entry to home directory on Client with logID as filename
*/
func SaveEntry(homedir string, entry Entry) error {
	// save entry
	for _, record := range entry.Payload {
		// Chronometry home directory
		if strings.HasPrefix(homedir, "~/") {
			homedir = filepath.Join(os.Getenv("HOME"), homedir[2:])
		}

		filename := util.AbsPath(homedir, fmt.Sprintf("%d.poh", record.LogIndex))

		err := ioutil.WriteFile(filename, entry.Bytes(), 0644)
		if err != nil {
			fmt.Println("Error saving entry to", err)
			return err
		}
	}

	return nil
}

/*
Check if the server is reachable
*/
func CheckServerReachable(server string) bool {
	url := server + "/health"

	resp, err := http.Get(url)
	if err != nil {
		return false
	}

	if resp.StatusCode != http.StatusOK {
		return false
	}

	return true
}

/*
Upload a vulnerability report to the server
*/
func UploadReport(homedir string, server string, report string, saveToIPFS bool) error {
	url := server + "/record?ipfs=" + fmt.Sprintf("%t", saveToIPFS)

	// read report
	body, err := ioutil.ReadFile(report)
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))

	if err != nil {
		fmt.Println(err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {

		return err
	}
	defer res.Body.Close()

	if err := loadAndPrint(res.Body, true, homedir); err != nil {
		fmt.Println("Error uploading report to server", err)
		return err
	} else {
		fmt.Println("Report uploaded successfully")
	}

	return nil
}

/*
Fetch a vulnerability report from the server by index
*/
func FetchReportByIndex(server string, index int) error {
	url := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", server, index)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}

	if loadAndPrint(res.Body, false, "") != nil {
		fmt.Println("Error fetching report")
	} else {
		fmt.Println("Report fetched successfully")
	}

	return nil
}

/*
Verify report by index
*/
func VerifyReportByIndex(server string, index int64) error {
	url := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", server, index)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}

	var f RecordEntryResponse
	err = json.Unmarshal(body, &f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	if f.Success {
		// get report body
		for _, record := range f.Data.Entry.Payload {
			var signerBlob signature.SignerBlob
			err = json.Unmarshal([]byte(record.Body), &signerBlob)
			if err != nil {
				fmt.Println(err)
				return err
			}

			sig := signerBlob.Signature
			publicKey := signerBlob.PublicKey

			fmt.Printf("publicKey: %s\n", util.Red+base64.StdEncoding.EncodeToString(publicKey)+util.Reset)
			fmt.Printf("signature: %s\n", util.Green+base64.StdEncoding.EncodeToString(sig)+util.Reset)

			// calculate hash of the entire report & verify signature
			if !signature.VerifyReportWithPublicKey(signerBlob.Report, publicKey, sig) {
				return errors.New("Signature verification failed")
			}

			color.Green("✅Signature verification successful")
		}
	} else {
		color.Red("❌Error fetching report")
		return errors.New(f.Data.Error)
	}

	return nil
}

/*
Fetch a vulnerability report from the server by record id
*/
func FetchReportByRecord(server string, record string) error {
	url := fmt.Sprintf("%s/api/v1/log/entries?uuid=%s", server, record)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}

	if loadAndPrint(res.Body, false, "") != nil {
		fmt.Println("Error fetching report")
	} else {
		fmt.Println("Report fetched successfully")
	}

	return nil
}

func loadAndPrint(bodyReader io.ReadCloser, saveEntry bool, homedir string) error {
	body, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		fmt.Println(err)
		return err
	}

	// parse json
	var f RecordEntryResponse
	err = json.Unmarshal(body, &f)
	if err != nil {
		fmt.Println(err)
		return err
	}

	if f.Success {
		f.PrettyPrint()
		if saveEntry {
			fmt.Println("Saving entry to", homedir)
			SaveEntry(homedir, f.Data.Entry)
		}
		return nil
	} else {
		return errors.New(f.Data.Error)
	}
}
