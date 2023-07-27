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
package util

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// type Path string

var (
	Black   = "\u001b[90m"
	Red     = "\u001b[91m"
	Green   = "\u001b[92m"
	Yellow  = "\u001b[93m"
	Blue    = "\u001b[94m"
	Magenta = "\u001b[95m"
	Cyan    = "\u001b[96m"
	White   = "\u001b[97m"
	Reset   = "\u001b[0m"
)

func BytesToKB(n int) float64 {
	return float64(n) / (1 << 10)
}

func CalculateHash(data []byte) string {
	hash := sha512.Sum512(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// OWASP recommends at least 128 bits of entropy for tokens: https://www.owasp.org/index.php/Insufficient_Session-ID_Length
// 32 bytes => 256 bits
// 64 bytes => 512 bits
var tokenByteLength = 64

// generate random verification code
func GenerateVerificationCode() (string, error) {
	b := make([]byte, tokenByteLength)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// url-safe no padding
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// absPath returns the absolute path for a given relative or absolute path.
func AbsPath(dir string, path string) string {
	// could be relative or absolute

	if filepath.IsAbs(string(path)) {
		// filepath.Join cleans the path so we should clean the absolute paths as well for consistency.
		return filepath.Clean(string(path))
	} else if strings.HasPrefix(path, "~/") {
		dirname, _ := os.UserHomeDir()

		return filepath.Join(dirname, path[2:])
	}

	return filepath.Join(dir, string(path))
}
