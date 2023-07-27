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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"strings"

	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ant4g0nist/chronometry/pkg/util"
	"github.com/fatih/color"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// Generate a new Ed25519 key pair
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	// Generate a new Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

// Save Public Key as PEM File
func SavePublicKey(publicKey ed25519.PublicKey, keys_folder string, name string, yes bool) {
	fmt.Println("🔑Your public key is: ", util.Red+base64.StdEncoding.EncodeToString(publicKey)+util.Reset)

	// Encode the public key as a PEM block
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		color.Red("❌Error in encoding public key")
		fmt.Println(err)
		os.Exit(1)
	}

	pubKeyPEM := pem.Block{
		Type:  "CHRONOMETRY PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	// Write the public key to a file
	pubKeyPath := filepath.Join(keys_folder, name+".pub")

	if err := os.WriteFile(pubKeyPath, pem.EncodeToMemory(&pubKeyPEM), 0644); err != nil {
		color.Red("❌Error in writing public key to file")
		fmt.Println(err)
		os.Exit(1)
	}
}

// Save Private Key as PEM File
func SavePrivateKey(privateKey ed25519.PrivateKey, keys_folder string, name string, passphrase string, yes bool) {
	// Implementation is similar to SSH key saving with passphrase
	// Save Private Key as PEM File
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		color.Red("❌Error in encoding private key")
		fmt.Println(err)
		os.Exit(1)
	}

	privKeyPEM := &pem.Block{
		Type:  "CHRONOMETRY PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	if passphrase == "" && !yes {
		passphrase, err = GetPasswordFromStdIn()
		fmt.Println()
		if err != nil {
			color.Red("❌Error in reading passphrase from stdin")
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Encrypt PEM File with passphrase like SSH keys
	// Note: we cannot use x509.EncryptPEMBlock because it is deprecated
	if passphrase != "" {
		privKeyPEM, err = EncryptPEMBlock(privKeyBytes, []byte(passphrase))
		if err != nil {
			color.Red("❌Error in encrypting PEM block")
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Write the private key to a file
	privKeyPath := filepath.Join(keys_folder, name)

	if err := WritePEMToFile(name, privKeyPath, privKeyPEM, yes); err != nil {
		color.Red("❌Error in writing private key to file")
		color.Yellow(err.Error())
		os.Exit(1)
	}
}

// Write Pem to file
func WritePEMToFile(name string, path string, pemBlock *pem.Block, yes bool) error {
	_, err := os.Stat(path)
	if err == nil && !yes {
		// Key already exists, prompt the user before overwriting
		c := color.New(color.FgWhite).Add(color.Bold)
		c.Print("❓CHRONOMETRY keys with the name " + name + " already exist in " + path + " directory. Do you want to overwrite it? [y/N]: ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "yes" {
			return errors.New("❌key generation cancelled")
		}
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return err
	}

	return nil
}

// GetPasswordFromStdIn gathers the password from stdin
func GetPasswordFromStdIn() (string, error) {
	pass, err := ReadPassword()
	if err != nil {
		return "", err
	}
	return string(pass), nil
}

// ReadPassword reads a password from stdin
func ReadPassword() ([]byte, error) {
	// Handle environment password.
	if pw, ok := os.LookupEnv("CHRONOMETRY_PASSWORD"); ok {
		return []byte(pw), nil
	}

	fmt.Print("🗝️ Enter passphrase (empty for no passphrase): ")

	// Handle terminal passwords.
	if term.IsTerminal(0) {
		return term.ReadPassword(0)
	}

	// Handle piped in passwords.
	return io.ReadAll(os.Stdin)
}

// Encrypts a PEM block using AES-256 encryption with the provided passphrase.
func EncryptPEMBlock(data []byte, passphrase []byte) (*pem.Block, error) {
	// Derive a 32-byte AES key from the passphrase using PBKDF2
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key(passphrase, salt, 4096, 32, sha512.New)

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := make([]byte, len(data))

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, data)

	// Create the PEM block
	pemBlock := &pem.Block{
		Type: "CHRONOMETRY PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"IV":        base64.StdEncoding.EncodeToString(iv),
			"Salt":      base64.StdEncoding.EncodeToString(salt),
		},
		Bytes: ciphertext,
	}

	return pemBlock, nil
}

// Decrypts a PEM block using AES-256 encryption with the provided passphrase.
func DecryptPEMBlock(pblock *pem.Block, passphrase []byte) ([]byte, error) {
	iv, _ := base64.StdEncoding.DecodeString(pblock.Headers["IV"])
	salt, _ := base64.StdEncoding.DecodeString(pblock.Headers["Salt"])
	ciphertext := pblock.Bytes

	// Derive the encryption key from the passphrase and salt using PBKDF2
	key := pbkdf2.Key(passphrase, salt, 4096, 32, sha512.New)

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error in creating new cipher block")
		return nil, err
	}

	// Create a stream for decrypting the data
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt the ciphertext
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// IsEncryptedPEMBlock checks if the PEM block is encrypted
func IsEncryptedPEMBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

// Read private key from PEM file and return ed25519 key pair
func ReadPEMFromFile(path string, passphrase string) (ed25519.PublicKey, ed25519.PrivateKey, error) {

	// Read the private key from a file
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	// Parse the PEM-encoded private key
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic("Failed to decode PEM block containing private key")
	}

	decryptedBlock := block.Bytes

	// Private key file might be encrypted with passphrase
	if IsEncryptedPEMBlock(block) {

		// Get password from stdin
		if passphrase == "" {
			fmt.Println("🔐Private key is encrypted. Please enter passphrase to decrypt it.")

			passphrase, err = GetPasswordFromStdIn()
			fmt.Println()
			if err != nil {
				color.Red("❌Error in reading passphrase from stdin")
				fmt.Println(err)
				os.Exit(1)
			}
		}

		// Decrypt PEM block
		decryptedBlock, err = DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			color.Red("❌Error in decrypting PEM block")
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Parse the ECDSA private key
	key, err := x509.ParsePKCS8PrivateKey(decryptedBlock)
	if err != nil {
		return nil, nil, err
	}

	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("not an ed25519 private key")
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	return publicKey, privateKey, nil
}
