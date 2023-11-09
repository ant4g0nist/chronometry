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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ant4g0nist/chronometry/internal/log"
	"github.com/ant4g0nist/chronometry/pkg/config"
	cclient "github.com/ant4g0nist/chronometry/pkg/core/client"
	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/swag"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	ttypes "github.com/google/trillian/types"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/mediocregopher/radix/v4"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	tlog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/durationpb"
)

func CreateAndInitTree(ctx context.Context, adminClient trillian.TrillianAdminClient, logClient trillian.TrillianLogClient) (*trillian.Tree, error) {
	t, err := adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeType:        trillian.TreeType_LOG,
			TreeState:       trillian.TreeState_ACTIVE,
			MaxRootDuration: durationpb.New(time.Hour),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create tree: %w", err)
	}

	if err := client.InitLog(ctx, t, logClient); err != nil {
		return nil, fmt.Errorf("init log: %w", err)
	}

	return t, nil
}

/*
Create Entries
*/
func CreateEntry(redis radix.Client, ctx context.Context, api *API, cfg *config.CMConfig, report signature.Report, signedReport signature.SignerBlob, saveToIPFS bool) (cclient.Entry, error) {
	fmt.Println("Create Sign Entry", signedReport)

	var logEntry cclient.Entry

	// json to bytes
	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Println("Error in marshalling json to bytes", err)
		return logEntry, err
	}

	canonicalized, err := jsoncanonicalizer.Transform(reportBytes)
	if err != nil {
		return logEntry, fmt.Errorf("canonicalizing error: %v", err)
	}

	// json to bytes
	signedReportBytes, err := json.Marshal(signedReport)
	if err != nil {
		fmt.Println("Error in marshalling json to bytes", err)
		return logEntry, err
	}

	tc := NewTrillianClient(ctx, *api)

	resp := tc.addLeaf(signedReportBytes, canonicalized)
	if resp.Err != nil {
		fmt.Println("Error in adding leaf", resp.Err)
		return logEntry, err
	}

	// this represents the results of inserting the proposed leaf into the log; status is nil in success path
	insertionStatus := resp.GetAddResult.QueuedLeaf.Status
	if insertionStatus != nil {
		switch insertionStatus.Code {
		case int32(code.Code_OK):
		case int32(code.Code_ALREADY_EXISTS), int32(code.Code_FAILED_PRECONDITION):
			existingUUID := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(reportBytes))
			err := fmt.Errorf("error in adding leaf: Leaf %s already exists", existingUUID)
			return logEntry, err
		default:
			err := fmt.Errorf("error in adding leaf: %s", insertionStatus.String())
			// err := fmt.Errorf("grpc error: %v", insertionStatus.String())
			fmt.Println("Error in adding leaf", err)
			return logEntry, err
		}
	}

	queuedLeaf := resp.GetAddResult.QueuedLeaf.Leaf
	fmt.Println("Queued Leaf", queuedLeaf)
	uuid := hex.EncodeToString(queuedLeaf.GetMerkleLeafHash())
	activeTree := fmt.Sprintf("%x", tc.LogID)

	fmt.Println("UUID", uuid)
	fmt.Println("Active Tree", activeTree)

	entryIDstruct, err := sharding.CreateEntryIDFromParts(activeTree, uuid)
	if err != nil {
		err := fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", activeTree, uuid, err)
		fmt.Println("Error in adding leaf", err)
	}

	fmt.Println("EntryID", entryIDstruct)
	entryID := entryIDstruct.ReturnEntryIDString()

	// The log index should be the virtual log index across all shards
	virtualIndex := sharding.VirtualLogIndex(queuedLeaf.LeafIndex, api.LogRanges.ActiveTreeID(), api.LogRanges)
	fmt.Println("Virtual Index", api.LogRanges.ActiveTreeID(), api.LogID)
	logEntryAnon := models.LogEntryAnon{
		LogID:          swag.String(api.PubkeyHash),
		LogIndex:       swag.Int64(virtualIndex),
		Body:           queuedLeaf.GetLeafValue(),
		IntegratedTime: swag.Int64(queuedLeaf.IntegrateTimestamp.AsTime().Unix()),
	}

	fmt.Println("Log Entry Anon", logEntryAnon)
	fmt.Println("Entry ID", entryID)

	go func() {
		var keys []string
		keys = append(keys, string(signedReport.PublicKey))
		keys = append(keys, string(signedReport.Signature))
		keys = append(keys, fmt.Sprintf("%d", virtualIndex))

		for _, key := range keys {
			if err := redis.Do(ctx, radix.Cmd(nil, "LPUSH", key, entryID)); err != nil {
				log.Logger.Error("adding keys to index: %v", zap.Error(err))
			}
		}
	}()

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(resp.GetLeafAndProofResult.SignedLogRoot.LogRoot); err != nil {
		log.Logger.Error("Error unmarshalling log root", zap.Error(err))
	}

	hashes := []string{}
	for _, hash := range resp.GetLeafAndProofResult.Proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	scBytes, err := CreateAndSignCheckpoint(cfg, ctx, cfg.ServerConfig.Hostname, tc.LogID, root)
	if err != nil {
		log.Logger.Error("Error in creating and signing checkpoint", zap.Error(err))
		return logEntry, err
	}

	inclusionProof := cclient.InclusionProof{
		TreeSize:   int64(root.TreeSize),
		RootHash:   hex.EncodeToString(root.RootHash),
		LogIndex:   queuedLeaf.LeafIndex,
		Hashes:     hashes,
		Checkpoint: string(scBytes),
	}

	// base64 encode the signature
	signature := base64.StdEncoding.EncodeToString(signedReport.Signature)

	verification := cclient.Verification{
		InclusionProof:       &inclusionProof,
		SignedEntryTimestamp: signature,
	}

	payload := make(map[string]cclient.Record)

	payload[entryID] = cclient.Record{
		Body:           string(queuedLeaf.GetLeafValue()),
		IntegratedTime: queuedLeaf.IntegrateTimestamp.AsTime().Unix(),
		LogID:          activeTree,
		LogIndex:       virtualIndex,
		Verification:   verification,
	}

	logEntry = cclient.Entry{
		Payload:  payload,
		ETag:     uuid,
		Location: cfg.ServerConfig.Hostname + "?uuid=" + entryID,
	}

	// replicate on IPFS
	if saveToIPFS {
		sh := shell.NewShell("localhost:5001")
		cid, err := sh.Add(bytes.NewReader(logEntry.Bytes()))

		if err != nil {
			log.Logger.Error("Error in adding to IPFS", zap.Error(err))
			return logEntry, err
		}

		logEntry.Cid = cid
	}

	return logEntry, nil
}

/*
Get latest checkpoint
*/
func GetLatestCheckpoint(tc TrillianClient, tl trillian.TrillianLogClient, treeID int64, ctx context.Context) (*tlog.Checkpoint, error) {
	req := trillian.GetLatestSignedLogRootRequest{LogId: treeID}
	resp, err := tl.GetLatestSignedLogRoot(ctx, &req)
	if err != nil {
		fmt.Println("Error in getting latest signed log root", err)
		return nil, fmt.Errorf("failed to get latest signed log root: %w", err)
	}

	root := resp.GetSignedLogRoot()
	var logRoot ttypes.LogRootV1
	if err := logRoot.UnmarshalBinary(root.LogRoot); err != nil {
		fmt.Println("Error in unmarshalling log root", err)
		return nil, err
	}

	fmt.Println("Log Root", logRoot)

	return &tlog.Checkpoint{
		Origin: "Chronometry",
		Hash:   logRoot.RootHash,
		Size:   logRoot.TreeSize,
	}, nil
}

/*
Get trillian log entry by record id
*/
func GetEntryByRecord(ctx context.Context, api *API, cfg *config.CMConfig, entryID string) (cclient.Entry, error) {
	var logEntry cclient.Entry
	uuid, err := sharding.GetUUIDFromIDString(entryID)
	if err != nil {
		return logEntry, sharding.ErrPlainUUID
	}

	// Get the tree ID and check that shard for the entry
	tid, err := sharding.TreeID(entryID)
	if err == nil {
		return retrieveUUIDFromTree(ctx, api, cfg, uuid, tid)
	}

	// If we got a UUID instead of an EntryID, search all shards
	if errors.Is(err, sharding.ErrPlainUUID) {
		trees := []sharding.LogRange{{TreeID: api.LogRanges.ActiveTreeID()}}
		trees = append(trees, api.LogRanges.GetInactive()...)

		for _, t := range trees {
			logEntry, err := retrieveUUIDFromTree(ctx, api, cfg, uuid, t.TreeID)
			if err != nil {
				continue
			}
			return logEntry, nil
		}
		return logEntry, ErrNotFound
	}

	return logEntry, err
}

/*
Get entry by index
*/
func GetEntryByIndex(ctx context.Context, api *API, cfg *config.CMConfig, logIndex int64) (cclient.Entry, error) {
	var logEntry cclient.Entry

	logEntry, err := retrieveLogEntryByIndex(ctx, api, cfg, logIndex)
	if err != nil {
		return logEntry, err
	}

	return logEntry, nil
}

/*
Retrieve UUID from tree
*/
func retrieveUUIDFromTree(ctx context.Context, api *API, cfg *config.CMConfig, uuid string, tid int64) (cclient.Entry, error) {
	var logEntry cclient.Entry
	hashValue, err := hex.DecodeString(uuid)
	if err != nil {
		return logEntry, fmt.Errorf("error decoding uuid %v: %w", uuid, err)
	}

	tc := NewTrillianClientFromTreeID(ctx, tid, api)
	log.Logger.Debug("Attempting to retrieve UUID %v from TreeID %v", zap.Any("uuid", uuid), zap.Int64("treeID", tid))

	resp := tc.getLeafAndProofByHash(hashValue)
	switch resp.Status {
	case codes.OK:
		result := resp.GetLeafAndProofResult
		leaf := result.Leaf
		if leaf == nil {
			return logEntry, ErrNotFound
		}

		logEntry, err := logEntryFromLeaf(ctx, cfg, tc, leaf, result.SignedLogRoot, result.Proof, tid, api.LogRanges)
		if err != nil {
			return logEntry, errors.New("could not create log entry from leaf")
		}
		return logEntry, nil

	case codes.NotFound:
		return logEntry, ErrNotFound
	default:
		log.Logger.Error("Unexpected response code while attempting to retrieve UUID", zap.Any("uuid", uuid), zap.Int64("treeID", tid), zap.Any("status", resp.Status))
		return logEntry, errors.New("unexpected error")
	}
}

func retrieveLogEntryByIndex(ctx context.Context, api *API, cfg *config.CMConfig, logIndex int64) (cclient.Entry, error) {
	var logEntry cclient.Entry

	// _, resolvedIndex := api.LogRanges.ResolveVirtualIndex(int(logIndex))
	// fmt.Println("Resolved Index", resolvedIndex)

	tid := api.LogID
	tc := NewTrillianClientFromTreeID(ctx, api.LogID, api)
	log.Logger.Debug("Retrieving resolved index", zap.Int64("resolvedIndex", logIndex), zap.Int64("treeID", tid))

	resp := tc.getLeafAndProofByIndex(logIndex)
	switch resp.Status {
	case codes.OK:
	case codes.NotFound, codes.OutOfRange, codes.InvalidArgument:
		return logEntry, ErrNotFound
	default:
		return logEntry, fmt.Errorf("grpc err: %w: %s", resp.Err, trillianCommunicationError)
	}

	result := resp.GetLeafAndProofResult
	leaf := result.Leaf
	if leaf == nil {
		return logEntry, ErrNotFound
	}

	return logEntryFromLeaf(ctx, cfg, tc, leaf, result.SignedLogRoot, result.Proof, tid, api.LogRanges)
}

// logEntryFromLeaf creates a signed LogEntry struct from trillian structs
func logEntryFromLeaf(ctx context.Context, cfg *config.CMConfig, tc TrillianClient, leaf *trillian.LogLeaf, signedRoot *trillian.SignedLogRoot, proof *trillian.Proof, treeID int64, logRanges sharding.LogRanges) (cclient.Entry, error) {
	var logEntry cclient.Entry

	root := &ttypes.LogRootV1{}
	if err := root.UnmarshalBinary(signedRoot.LogRoot); err != nil {
		log.Logger.Error("Error unmarshalling log root", zap.Error(err))
	}

	hashes := []string{}
	for _, hash := range proof.Hashes {
		hashes = append(hashes, hex.EncodeToString(hash))
	}

	virtualIndex := sharding.VirtualLogIndex(leaf.GetLeafIndex(), treeID, logRanges)

	logEntryAnon := cclient.Record{
		Body:           string(leaf.LeafValue),
		IntegratedTime: leaf.IntegrateTimestamp.AsTime().Unix(),
		LogID:          string(cfg.PublicKey),
		LogIndex:       virtualIndex,
	}

	// // base64 encode the signature
	signature, err := signEntry(ctx, cfg.PrivateKey, logEntryAnon)
	if err != nil {
		log.Logger.Error("Error in signing entry", zap.Error(err))
		return logEntry, fmt.Errorf("signing entry error: %w", err)
	}

	scBytes, err := CreateAndSignCheckpoint(cfg, ctx, cfg.ServerConfig.Hostname, tc.LogID, root)
	if err != nil {
		log.Logger.Error("Error in creating and signing checkpoint", zap.Error(err))
		return logEntry, err
	}

	inclusionProof := cclient.InclusionProof{
		TreeSize:   int64(root.TreeSize),
		RootHash:   hex.EncodeToString(root.RootHash),
		LogIndex:   leaf.LeafIndex,
		Hashes:     hashes,
		Checkpoint: string(scBytes),
	}

	uuid := hex.EncodeToString(leaf.MerkleLeafHash)
	tid := fmt.Sprintf("%x", treeID)
	entryIDstruct, err := sharding.CreateEntryIDFromParts(tid, uuid)
	if err != nil {
		return logEntry, fmt.Errorf("error creating EntryID from active treeID %v and uuid %v: %w", treeID, uuid, err)
	}
	entryID := entryIDstruct.ReturnEntryIDString()

	payload := make(map[string]cclient.Record)
	payload[entryID] = cclient.Record{
		Body:           string(leaf.LeafValue),
		IntegratedTime: leaf.IntegrateTimestamp.AsTime().Unix(),
		LogID:          tid,
		LogIndex:       virtualIndex,
		Verification: cclient.Verification{
			InclusionProof:       &inclusionProof,
			SignedEntryTimestamp: base64.StdEncoding.EncodeToString(signature),
		},
	}

	logEntry = cclient.Entry{
		Payload:  payload,
		ETag:     uuid,
		Location: cfg.ServerConfig.Hostname + "/entry" + entryID,
	}

	return logEntry, nil
}

/*
Sign entry
*/
func signEntry(ctx context.Context, privateKey ed25519.PrivateKey, logEntryAnon cclient.Record) ([]byte, error) {
	logEntryBytes, err := json.Marshal(logEntryAnon)
	if err != nil {
		return nil, fmt.Errorf("marshalling log entry error: %w", err)
	}

	canonicalized, err := jsoncanonicalizer.Transform(logEntryBytes)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing error: %w", err)
	}

	signature := ed25519.Sign(privateKey, canonicalized)

	return signature, nil
}
