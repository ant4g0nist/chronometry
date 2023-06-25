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
package config

import (
	"crypto/ed25519"
	"os"
	"path/filepath"

	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/ant4g0nist/chronometry/pkg/util"

	"gopkg.in/yaml.v2"
)

// Current Config Version
const Version = 1

// Chronometry config
type CMConfig struct {
	// The version of the configuration file.
	Version      int          `yaml:"version"`
	ServerConfig ServerConfig `yaml:"server"`

	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func loadConfig(basePath string,
	configData []byte,
	readFile func(string) ([]byte, error),
) (*CMConfig, error) {

	var c CMConfig

	var err error
	if err = yaml.Unmarshal(configData, &c); err != nil {
		return nil, err
	}

	if err = c.check(); err != nil {
		return nil, err
	}

	path := c.ServerConfig.PrivateKeyPath
	privateKeyPath := util.AbsPath(basePath, path)

	publicKey, privateKey, err := signature.ReadPEMFromFile(string(privateKeyPath), c.ServerConfig.Passphrase)

	c.PublicKey = publicKey
	c.PrivateKey = privateKey

	return &c, err
}

func LoadConfig(configPath string) (*CMConfig, error) {
	configData, err := os.ReadFile(configPath)

	if err != nil {
		return nil, err
	}

	basePath, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}

	// Pass the current working directory and os.ReadFile so that they can
	// be mocked in the tests
	return loadConfig(basePath, configData, os.ReadFile)
}
