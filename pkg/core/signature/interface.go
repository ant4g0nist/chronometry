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
	"github.com/ant4g0nist/chronometry/pkg/core/report"
)

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

	// Author of the report
	AuthorDetailsHash string `json:"AuthorDetailsHash"`

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
	if len(r.Version) != 88 {
		return report.ErrInvalidVersion
	}

	if len(r.Title) != 88 {
		return report.ErrorInvalidTitle
	}

	if len(r.Description) != 88 {
		return report.ErrorInvalidDescription
	}

	if len(r.Attributes) != 88 {
		return report.ErrorInvalidAttributes
	}

	if len(r.AuthorDetailsHash) != 88 {
		return report.ErrorInvalidAuthor
	}

	if len(r.Author) > 32 {
		return report.ErrorInvalidAuthorName
	}

	if len(r.Platform) != 88 {
		return report.ErrorInvalidPlatform
	}

	if len(r.Severity) != 88 {
		return report.ErrorInvalidSeverity
	}

	if len(r.Attachments) != 88 {
		return report.ErrorInvalidAttachments
	}

	return nil
}
