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

import "errors"

/*
This is the vulnerability report structure YAML file passed as input to generate the Signature.
*/
type Report struct {
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

func (r *Report) Validate() error {
	/*
		Every attribute of the report must be a 32 byte base64 encoded hash.
	*/
	if len(r.Version) != 44 {
		return ErrInvalidVersion
	}

	if len(r.Title) != 44 {
		return ErrorInvalidTitle
	}

	if len(r.Description) != 44 {
		return ErrorInvalidDescription
	}

	if len(r.Attributes) != 44 {
		return ErrorInvalidAttributes
	}

	if len(r.Author) != 44 {
		return ErrorInvalidAuthor
	}

	if len(r.Platform) != 44 {
		return ErrorInvalidPlatform
	}

	if len(r.Severity) != 44 {
		return ErrorInvalidSeverity
	}

	if len(r.Attachments) != 44 {
		return ErrorInvalidAttachments
	}

	return nil
}

var (
	ErrInvalidVersion       = errors.New("invalid version")
	ErrorInvalidTitle       = errors.New("invalid title")
	ErrorInvalidDescription = errors.New("invalid description")
	ErrorInvalidAttributes  = errors.New("invalid attributes")
	ErrorInvalidAuthor      = errors.New("invalid author")
	ErrorInvalidPlatform    = errors.New("invalid platform")
	ErrorInvalidSeverity    = errors.New("invalid severity")
	ErrorInvalidAttachments = errors.New("invalid attachments")
)
