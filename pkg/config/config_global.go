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

// A Path on the filesystem.
type Path string

// Postgres Config
type DatabaseOptions struct {
	// The username for postgres server
	Username string `yaml: "username"`
	Password string `yaml: "password"`

	DBName string `yaml:"dbname"`

	// Postgres server host
	Server string `yaml:"server"`
	// Postgress server port
	Port string `yaml:"port"`
	//ssl mode
	SSLmode string `yaml:"sslmode"`

	//timezone
	TimeZone string `yaml:"timezone"`

	// Maximum open connections to the DB (0 = use default, negative means unlimited)
	MaxOpenConnections int `yaml:"max_open_conns"`

	// Maximum idle connections to the DB (0 = use default, negative means unlimited)
	MaxIdleConnections int `yaml:"max_idle_conns"`

	// maximum amount of time (in seconds) a connection may be reused (<= 0 means unlimited)
	ConnMaxLifetimeSeconds int `yaml:"conn_max_lifetime"`
}

// Global config
type ServerConfig struct {

	// Home Server bind address
	HTTPBind string `yaml:"http_bind"`

	// Home Server HTTPS Bind address
	HTTPSBind string `yaml:"https_bind"`

	// Zap Logger configuration
	Logger LoggerOpts `yaml:"logger"`

	// Global pool of database connections
	DatabaseOptions DatabaseOptions `yaml:"database,omitempty"`

	// Path to the private key which will be used to sign requests and events.
	PrivateKeyPath string `yaml:"private_key"`
	Passphrase     string `yaml:"passphrase"`

	Trillian Trillian `yaml:"trillian"`
}

// Google Trillian Server config
type Trillian struct {
	Address string `yaml:"address"`
	Port    int64  `yaml:"port"`
}
