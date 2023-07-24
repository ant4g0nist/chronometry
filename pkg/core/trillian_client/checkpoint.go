// Copyright 2023 WeFuzz Research and Development B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trillian_client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ant4g0nist/chronometry/pkg/config"
	"github.com/google/trillian/types"
	"golang.org/x/mod/sumdb/note"
)

type SignedNote struct {
	// Textual representation of a note to sign.
	Note string
	// Signatures are one or more signature lines covering the payload
	Signatures []note.Signature
}

// String returns the String representation of the SignedNote
func (s SignedNote) String() string {
	var b strings.Builder
	b.WriteString(s.Note)
	b.WriteRune('\n')
	for _, sig := range s.Signatures {
		var hbuf [4]byte
		binary.BigEndian.PutUint32(hbuf[:], sig.Hash)
		sigBytes, _ := base64.StdEncoding.DecodeString(sig.Base64)
		b64 := base64.StdEncoding.EncodeToString(append(hbuf[:], sigBytes...))
		fmt.Fprintf(&b, "%c %s %s\n", '\u2014', sig.Name, b64)
	}

	return b.String()
}

// MarshalText returns the common format representation of this SignedNote.
func (s SignedNote) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

type Checkpoint struct {
	// Origin is the unique identifier/version string
	Origin string
	// Size is the number of entries in the log at this checkpoint.
	Size uint64
	// Hash is the hash which commits to the contents of the entire log.
	Hash []byte
	// OtherContent is any additional data to be included in the signed payload; each element is assumed to be one line
	OtherContent []string
}

type SignedCheckpoint struct {
	Checkpoint
	SignedNote
}

// String returns the String representation of the Checkpoint
func (c Checkpoint) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Hash))
	for _, line := range c.OtherContent {
		fmt.Fprintf(&b, "%s\n", line)
	}
	return b.String()
}

// MarshalText returns the common format representation of this Checkpoint.
func (c Checkpoint) MarshalCheckpoint() ([]byte, error) {
	return []byte(c.String()), nil
}

// UnmarshalText parses the common formatted checkpoint data and stores the result
// in the Checkpoint.
//
// The supplied data is expected to begin with the following 3 lines of text,
// each followed by a newline:
// <ecosystem/version string>
// <decimal representation of log size>
// <base64 representation of root hash>
// <optional non-empty line of other content>...
// <optional non-empty line of other content>...
//
// This will discard any content found after the checkpoint (including signatures)
func (c *Checkpoint) UnmarshalCheckpoint(data []byte) error {
	l := bytes.Split(data, []byte("\n"))
	if len(l) < 4 {
		return errors.New("invalid checkpoint - too few newlines")
	}
	origin := string(l[0])
	if len(origin) == 0 {
		return errors.New("invalid checkpoint - empty ecosystem")
	}
	size, err := strconv.ParseUint(string(l[1]), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid checkpoint - size invalid: %w", err)
	}
	h, err := base64.StdEncoding.DecodeString(string(l[2]))
	if err != nil {
		return fmt.Errorf("invalid checkpoint - invalid hash: %w", err)
	}
	*c = Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   h,
	}
	if len(l) >= 3 {
		for _, line := range l[3:] {
			if len(line) == 0 {
				break
			}
			c.OtherContent = append(c.OtherContent, string(line))
		}
	}
	return nil
}

func (r *SignedCheckpoint) UnmarshalText(data []byte) error {
	s := SignedNote{}
	if err := s.UnmarshalText([]byte(data)); err != nil {
		return fmt.Errorf("unmarshalling signed note: %w", err)
	}
	c := Checkpoint{}
	if err := c.UnmarshalCheckpoint([]byte(s.Note)); err != nil {
		return fmt.Errorf("unmarshalling checkpoint: %w", err)
	}
	*r = SignedCheckpoint{Checkpoint: c, SignedNote: s}
	return nil
}

func (r *SignedCheckpoint) SetTimestamp(timestamp uint64) {
	var ts uint64
	for i, val := range r.OtherContent {
		if n, _ := fmt.Fscanf(strings.NewReader(val), "Timestamp: %d", &ts); n == 1 {
			r.OtherContent = append(r.OtherContent[:i], r.OtherContent[i+1:]...)
		}
	}
	r.OtherContent = append(r.OtherContent, fmt.Sprintf("Timestamp: %d", timestamp))
	r.SignedNote = SignedNote{Note: string(r.Checkpoint.String())}
}

func (r *SignedCheckpoint) GetTimestamp() uint64 {
	var ts uint64
	for _, val := range r.OtherContent {
		if n, _ := fmt.Fscanf(strings.NewReader(val), "Timestamp: %d", &ts); n == 1 {
			break
		}
	}
	return ts
}

/*
Create and sign checkpoint
*/
func CreateAndSignCheckpoint(cfg *config.CMConfig, ctx context.Context, hostname string, treeID int64, root *types.LogRootV1) ([]byte, error) {
	sth, err := CreateSignedCheckpoint(Checkpoint{
		Origin: fmt.Sprintf("%s - %d", hostname, treeID),
		Size:   root.TreeSize,
		Hash:   root.RootHash,
	})

	if err != nil {
		return nil, fmt.Errorf("error creating checkpoint: %v", err)
	}

	sth.SetTimestamp(uint64(time.Now().UnixNano()))
	if _, err := sth.Sign(hostname, Signer{
		Signer:    cfg.PrivateKey,
		PublicKey: cfg.PublicKey,
	}); err != nil {
		return nil, fmt.Errorf("error signing checkpoint: %v", err)
	}

	scBytes, err := sth.SignedNote.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("error marshalling checkpoint: %v", err)
	}

	fmt.Println("scBytes: ", string(scBytes))

	return scBytes, nil
}

/*
Create signed checkpoint
*/
func CreateSignedCheckpoint(c Checkpoint) (*SignedCheckpoint, error) {
	text, err := c.MarshalCheckpoint()
	if err != nil {
		return nil, err
	}
	return &SignedCheckpoint{
		Checkpoint: c,
		SignedNote: SignedNote{Note: string(text)},
	}, nil
}

type Signer struct {
	// Signer is the signer to use for signing checkpoints
	Signer ed25519.PrivateKey

	// PublicKey is the public key of the signer
	PublicKey ed25519.PublicKey
}

// Sign adds a signature to a SignedCheckpoint object
// The signature is added to the signature array as well as being directly returned to the caller
func (s *SignedNote) Sign(identity string, signer Signer) (*note.Signature, error) {
	sig := ed25519.Sign(signer.Signer, []byte(s.Note))

	pk := signer.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}

	pkSha := sha256.Sum256(pubKeyBytes)

	signature := note.Signature{
		Name:   identity,
		Hash:   binary.BigEndian.Uint32(pkSha[:]),
		Base64: base64.StdEncoding.EncodeToString(sig),
	}

	s.Signatures = append(s.Signatures, signature)
	return &signature, nil
}

// UnmarshalText parses the common formatted signed note data and stores the result
// in the SignedNote. THIS DOES NOT VERIFY SIGNATURES INSIDE THE CONTENT!
//
// The supplied data is expected to contain a single Note, followed by a single
// line with no comment, followed by one or more lines with the following format:
//
// \u2014 name signature
//
//   - name is the string associated with the signer
//   - signature is a base64 encoded string; the first 4 bytes of the decoded value is a
//     hint to the public key; it is a big-endian encoded uint32 representing the first
//     4 bytes of the SHA256 hash of the public key
func (s *SignedNote) UnmarshalText(data []byte) error {
	sigSplit := []byte("\n\n")
	// Must end with signature block preceded by blank line.
	split := bytes.LastIndex(data, sigSplit)
	if split < 0 {
		return errors.New("malformed note")
	}
	text, data := data[:split+1], data[split+2:]
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("malformed note")
	}

	sn := SignedNote{
		Note: string(text),
	}

	b := bufio.NewScanner(bytes.NewReader(data))
	for b.Scan() {
		var name, signature string
		if _, err := fmt.Fscanf(strings.NewReader(b.Text()), "\u2014 %s %s\n", &name, &signature); err != nil {
			return fmt.Errorf("parsing signature: %w", err)
		}

		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return fmt.Errorf("decoding signature: %w", err)
		}
		if len(sigBytes) < 5 {
			return errors.New("signature is too small")
		}

		sig := note.Signature{
			Name:   name,
			Hash:   binary.BigEndian.Uint32(sigBytes[0:4]),
			Base64: base64.StdEncoding.EncodeToString(sigBytes[4:]),
		}
		sn.Signatures = append(sn.Signatures, sig)

	}
	if len(sn.Signatures) == 0 {
		return errors.New("no signatures found in input")
	}

	// copy sc to s
	*s = sn
	return nil
}
