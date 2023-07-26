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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/types"
	"github.com/mediocregopher/radix/v4"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Trillian ERRORS
var ErrNotFound = errors.New("grpc returned 0 leaves with success code")
var trillianCommunicationError = "unexpected error communicating with transparency log"

type API struct {
	LogClient  trillian.TrillianLogClient
	LogID      int64
	LogRanges  sharding.LogRanges
	Pubkey     string // PEM encoded public key
	PubkeyHash string // SHA256 hash of DER-encoded public key
	App        *fiber.App
	Redis      radix.Client
}

type TrillianClient struct {
	Client  trillian.TrillianLogClient
	LogID   int64
	Context context.Context
}

func NewTrillianClient(ctx context.Context, api API) TrillianClient {
	return TrillianClient{
		Client: api.LogClient,
		// ranges:  api.logRanges,
		LogID:   api.LogID,
		Context: ctx,
	}
}

func NewTrillianClientFromTreeID(ctx context.Context, treeID int64, api *API) TrillianClient {
	return TrillianClient{
		Client:  api.LogClient,
		LogID:   treeID,
		Context: ctx,
	}
}

type Response struct {
	Status                    codes.Code                                `json:"status"`
	Err                       error                                     `json:"err"`
	GetAddResult              *trillian.QueueLeafResponse               `json:"getAddResult"`
	GetProofResult            *trillian.GetInclusionProofByHashResponse `json:"getProofResult"`
	GetLeafAndProofResult     *trillian.GetEntryAndProofResponse        `json:"getLeafAndProofResult"`
	GetLatestResult           *trillian.GetLatestSignedLogRootResponse  `json:"getLatestResult"`
	GetConsistencyProofResult *trillian.GetConsistencyProofResponse     `json:"getConsistencyProofResult"`
}

func unmarshalLogRoot(logRoot []byte) (types.LogRootV1, error) {
	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRoot); err != nil {
		return types.LogRootV1{}, err
	}
	return root, nil
}

func (t *TrillianClient) root() (types.LogRootV1, error) {
	rqst := &trillian.GetLatestSignedLogRootRequest{
		LogId: t.LogID,
	}
	resp, err := t.Client.GetLatestSignedLogRoot(t.Context, rqst)
	if err != nil {
		return types.LogRootV1{}, err
	}
	return unmarshalLogRoot(resp.SignedLogRoot.LogRoot)
}

func (t *TrillianClient) addLeaf(byteValue []byte, extraData []byte) *Response {
	leaf := &trillian.LogLeaf{
		LeafValue: byteValue,
		ExtraData: extraData,
	}
	rqst := &trillian.QueueLeafRequest{
		LogId: t.LogID,
		Leaf:  leaf,
	}
	resp, err := t.Client.QueueLeaf(t.Context, rqst)

	// check for error
	if err != nil || (resp.QueuedLeaf.Status != nil && resp.QueuedLeaf.Status.Code != int32(codes.OK)) {
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}

	root, err := t.root()
	if err != nil {
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}
	v := client.NewLogVerifier(rfc6962.DefaultHasher)
	logClient := client.New(t.LogID, t.Client, v, root)

	waitForInclusion := func(ctx context.Context, leafHash []byte) *Response {
		if logClient.MinMergeDelay > 0 {
			select {
			case <-ctx.Done():
				return &Response{
					Status: codes.DeadlineExceeded,
					Err:    ctx.Err(),
				}
			case <-time.After(logClient.MinMergeDelay):
			}
		}
		for {
			root = *logClient.GetRoot()
			if root.TreeSize >= 1 {
				proofResp := t.getProofByHash(resp.QueuedLeaf.Leaf.MerkleLeafHash)
				// if this call succeeds or returns an error other than "not found", return
				if proofResp.Err == nil || (proofResp.Err != nil && status.Code(proofResp.Err) != codes.NotFound) {
					return proofResp
				}
				// otherwise wait for a root update before trying again
			}

			if _, err := logClient.WaitForRootUpdate(ctx); err != nil {
				return &Response{
					Status: codes.Unknown,
					Err:    err,
				}
			}
		}
	}

	proofResp := waitForInclusion(t.Context, resp.QueuedLeaf.Leaf.MerkleLeafHash)
	if proofResp.Err != nil {
		return &Response{
			Status:       status.Code(proofResp.Err),
			Err:          proofResp.Err,
			GetAddResult: resp,
		}
	}

	proofs := proofResp.GetProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(resp.QueuedLeaf.Leaf.MerkleLeafHash), len(proofs))
		return &Response{
			Status:       status.Code(err),
			Err:          err,
			GetAddResult: resp,
		}
	}

	leafIndex := proofs[0].LeafIndex
	leafResp := t.getLeafAndProofByIndex(leafIndex)
	if leafResp.Err != nil {
		return &Response{
			Status:       status.Code(leafResp.Err),
			Err:          leafResp.Err,
			GetAddResult: resp,
		}
	}

	// overwrite queued leaf that doesn't have index set
	resp.QueuedLeaf.Leaf = leafResp.GetLeafAndProofResult.Leaf

	return &Response{
		Status:       status.Code(err),
		Err:          err,
		GetAddResult: resp,
		// include getLeafAndProofResult for inclusion proof
		GetLeafAndProofResult: leafResp.GetLeafAndProofResult,
	}
}

func (t *TrillianClient) getLeafAndProofByIndex(index int64) *Response {
	ctx, cancel := context.WithTimeout(t.Context, 20*time.Second)
	defer cancel()

	rootResp := t.getLatest(0)
	if rootResp.Err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}

	root, err := unmarshalLogRoot(rootResp.GetLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}

	resp, err := t.Client.GetEntryAndProof(ctx,
		&trillian.GetEntryAndProofRequest{
			LogId:     t.LogID,
			LeafIndex: index,
			TreeSize:  int64(root.TreeSize),
		})

	if resp != nil && resp.Proof != nil {
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(index), root.TreeSize, resp.GetLeaf().MerkleLeafHash, resp.Proof.Hashes, root.RootHash); err != nil {
			return &Response{
				Status: status.Code(err),
				Err:    err,
			}
		}
		return &Response{
			Status: status.Code(err),
			Err:    err,
			GetLeafAndProofResult: &trillian.GetEntryAndProofResponse{
				Proof:         resp.Proof,
				Leaf:          resp.Leaf,
				SignedLogRoot: rootResp.GetLatestResult.SignedLogRoot,
			},
		}
	}

	return &Response{
		Status: status.Code(err),
		Err:    err,
	}
}

func (t *TrillianClient) getLeafAndProofByHash(hash []byte) *Response {
	// get inclusion proof for hash, extract index, then fetch leaf using index
	proofResp := t.getProofByHash(hash)
	if proofResp.Err != nil {
		return &Response{
			Status: status.Code(proofResp.Err),
			Err:    proofResp.Err,
		}
	}

	proofs := proofResp.GetProofResult.Proof
	if len(proofs) != 1 {
		err := fmt.Errorf("expected 1 proof from getProofByHash for %v, found %v", hex.EncodeToString(hash), len(proofs))
		return &Response{
			Status: status.Code(err),
			Err:    err,
		}
	}

	return t.getLeafAndProofByIndex(proofs[0].LeafIndex)
}

func (t *TrillianClient) getProofByHash(hashValue []byte) *Response {
	ctx, cancel := context.WithTimeout(t.Context, 20*time.Second)
	defer cancel()

	rootResp := t.getLatest(0)
	if rootResp.Err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}
	root, err := unmarshalLogRoot(rootResp.GetLatestResult.SignedLogRoot.LogRoot)
	if err != nil {
		return &Response{
			Status: status.Code(rootResp.Err),
			Err:    rootResp.Err,
		}
	}

	// issue 1308: if the tree is empty, there's no way we can return a proof
	if root.TreeSize == 0 {
		return &Response{
			Status: codes.NotFound,
			Err:    status.Error(codes.NotFound, "tree is empty"),
		}
	}

	resp, err := t.Client.GetInclusionProofByHash(ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    t.LogID,
			LeafHash: hashValue,
			TreeSize: int64(root.TreeSize),
		})

	if resp != nil {
		v := client.NewLogVerifier(rfc6962.DefaultHasher)
		for _, proof := range resp.Proof {
			if err := v.VerifyInclusionByHash(&root, hashValue, proof); err != nil {
				return &Response{
					Status: status.Code(err),
					Err:    err,
				}
			}
		}
		// Return an inclusion proof response with the requested
		return &Response{
			Status: status.Code(err),
			Err:    err,
			GetProofResult: &trillian.GetInclusionProofByHashResponse{
				Proof:         resp.Proof,
				SignedLogRoot: rootResp.GetLatestResult.SignedLogRoot,
			},
		}
	}

	return &Response{
		Status: status.Code(err),
		Err:    err,
	}
}

func (t *TrillianClient) getLatest(leafSizeInt int64) *Response {

	ctx, cancel := context.WithTimeout(t.Context, 20*time.Second)
	defer cancel()

	resp, err := t.Client.GetLatestSignedLogRoot(ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId:         t.LogID,
			FirstTreeSize: leafSizeInt,
		})

	return &Response{
		Status:          status.Code(err),
		Err:             err,
		GetLatestResult: resp,
	}
}

func (t *TrillianClient) getConsistencyProof(firstSize, lastSize int64) *Response {

	ctx, cancel := context.WithTimeout(t.Context, 20*time.Second)
	defer cancel()

	resp, err := t.Client.GetConsistencyProof(ctx,
		&trillian.GetConsistencyProofRequest{
			LogId:          t.LogID,
			FirstTreeSize:  firstSize,
			SecondTreeSize: lastSize,
		})

	return &Response{
		Status:                    status.Code(err),
		Err:                       err,
		GetConsistencyProofResult: resp,
	}
}
