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
package report

import (
	"crypto/sha256"
	"os"

	"github.com/fatih/color"
	"gopkg.in/yaml.v2"
)

type Platform string

const (
	// HackerOne is the HackerOne platform
	HackerOnePlatform Platform = "hackerone"

	// BugCrowd is the BugCrowd platform
	BugCrowdPlatform Platform = "bugcrowd"

	// Intigriti is the Intigriti platform
	IntigritiPlatform Platform = "intigriti"

	// YesWeHack is the YesWeHack platform
	YesWeHackPlatform Platform = "yeswehack"

	// Synack is the Synack platform
	SynackPlatform Platform = "synack"

	// OpenBugBounty is the OpenBugBounty platform
	OpenBugBountyPlatform Platform = "openbugbounty"

	// Yōkai is the Yōkai platform
	YōkaiPlatform Platform = "yokai"
)

type Author struct {
	// Name of the author
	Name string `yaml:"name"`

	// URL of the author
	URL string `yaml:"url"`

	// Email of the author
	Email string `yaml:"email"`
}

type Attribute struct {
	// Key of the attribute
	Name string `yaml:"name"`

	// Value of the attribute
	Value string `yaml:"value"`
}

func (a *Attribute) Hash() []byte {
	// sha256 hash of the attribute name and value
	hash := sha256.New()
	hash.Write([]byte(a.Name))
	hash.Write([]byte(a.Value))
	return hash.Sum(nil)
}

func (a *Author) Hash() []byte {
	hash := sha256.New()
	hash.Write([]byte(a.Name))
	hash.Write([]byte(a.Email))
	hash.Write([]byte(a.URL))
	return hash.Sum(nil)
}

type Attachment struct {
	// Name of the attachment
	Name string `yaml:"name"`

	// Path of the attachment
	Path string `yaml:"path"`
}

func (a *Attachment) Hash() []byte {
	// sha256 hash of the attachment name and path
	hash := sha256.New()
	hash.Write([]byte(a.Name))
	// read file from path and hash it
	file, err := os.ReadFile(a.Path)
	if err != nil {
		color.Red("Error reading attachment file: %s", err.Error())
		os.Exit(1)
	}
	hash.Write(file)
	return hash.Sum(nil)
}

/*
This is the vulnerability report structure YAML file passed as input to generate the Signature.
*/
type VulnerabilityReport struct {
	// The version of the report file.
	Version string `yaml:"version"`

	// Title of the report
	Title string `yaml:"title"`

	// Description of the report
	Description string `yaml:"description"`

	// Attributes of the report: list of key value pairs: e.g. "CVE": "CVE-2021-1234"
	Attributes []Attribute `yaml:"attributes"`

	// Author of the report
	Author Author `yaml:"author"`

	// Platform of the report
	Platform Platform `yaml:"platform"`

	// Severity of the report
	Severity string `yaml:"severity"`

	// Attachments of the report
	Attachments []Attachment `yaml:"attachments"`
}

func LoadReport(fileRef string) (VulnerabilityReport, error) {
	var v VulnerabilityReport

	// check if file exists
	if _, err := os.Stat(fileRef); os.IsNotExist(err) {
		return v, err
	}

	// read VulnerabilityReport yaml file
	report, err := os.ReadFile(fileRef)

	if err != nil {
		return v, err
	}

	if err := yaml.Unmarshal(report, &v); err != nil {
		return v, err
	}

	return v, nil
}
