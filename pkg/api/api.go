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
package api

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ant4g0nist/chronometry/internal/log"
	"github.com/ant4g0nist/chronometry/pkg/config"
	"github.com/ant4g0nist/chronometry/pkg/core"
	"github.com/gofiber/fiber/v2"
	"github.com/google/trillian"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gorm.io/gorm"
)

type API struct {
	logClient  trillian.TrillianLogClient
	logID      int64
	pubkey     string // PEM encoded public key
	pubkeyHash string // SHA256 hash of DER-encoded public key
	app        *fiber.App
}

func dial(ctx context.Context, rpcServer string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Set up and test connection to rpc server
	creds := insecure.NewCredentials()
	conn, err := grpc.DialContext(ctx, rpcServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Logger.Fatal("Failed to connect to RPC server:", zap.Error(err))
	}
	return conn, nil
}

func StartServer(cfg *config.CMConfig, db *gorm.DB) {
	log.Logger.Info("Starting Server")

	logRPCServer := fmt.Sprintf("%s:%d",
		cfg.ServerConfig.Trillian.Address,
		cfg.ServerConfig.Trillian.Port)

	ctx := context.Background()
	tConn, err := dial(ctx, logRPCServer)

	logAdminClient := trillian.NewTrillianAdminClient(tConn)
	logClient := trillian.NewTrillianLogClient(tConn)

	fmt.Println(logAdminClient, logClient, err)
	log.Logger.Info("Attempting to create a new tree")

	t, err := core.CreateAndInitTree(ctx, logAdminClient, logClient)
	if err != nil {
		//	return nil, fmt.Errorf("create and init tree: %w", err)
		log.Logger.Error("Create and init tree", zap.Error(err))
		os.Exit(1)
	}

	tid := t.TreeId

	log.Logger.Info(fmt.Sprintf("Starting Chronometry server with active tree %v", tid))
}
