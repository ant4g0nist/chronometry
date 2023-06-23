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

package core

import (
	"context"
	"fmt"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
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

	// log.Logger.Info()
	return t, nil
}
