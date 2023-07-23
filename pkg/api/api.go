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
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/ant4g0nist/chronometry/internal/log"
	"github.com/ant4g0nist/chronometry/pkg/api/entries"
	"github.com/ant4g0nist/chronometry/pkg/config"
	"github.com/ant4g0nist/chronometry/pkg/core/trillian_client"
	"github.com/gofiber/fiber/v2"
	"github.com/google/trillian"
	"github.com/mediocregopher/radix/v4"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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

func StartServer(cfg *config.CMConfig) {
	log.Logger.Info("Starting Server")

	logRPCServer := fmt.Sprintf("%s:%d",
		cfg.ServerConfig.Trillian.Address,
		cfg.ServerConfig.Trillian.Port)

	ctx := context.Background()
	tConn, err := dial(ctx, logRPCServer)
	if err != nil {
		log.Logger.Fatal("Failed to connect to RPC server:", zap.Error(err))
		os.Exit(1)
	}

	logAdminClient := trillian.NewTrillianAdminClient(tConn)
	logClient := trillian.NewTrillianLogClient(tConn)

	fmt.Println("logAdminClient", logAdminClient, logClient, err)
	log.Logger.Info("Attempting to create a new tree")

	shardingConfig := viper.GetString("trillian_log_server.sharding_config")
	ranges, err := sharding.NewLogRanges(ctx, logClient, shardingConfig, cfg.ServerConfig.Trillian.TreeID)
	if err != nil {
		log.Logger.Error("unable get sharding details from sharding config: %w", zap.Error(err))
		os.Exit(1)
	}

	tid := int64(cfg.ServerConfig.Trillian.TreeID)

	if tid == 0 {
		t, err := trillian_client.CreateAndInitTree(ctx, logAdminClient, logClient)
		if err != nil {
			//	return nil, fmt.Errorf("create and init tree: %w", err)
			log.Logger.Error("Create and init tree", zap.Error(err))
			os.Exit(1)
		}

		tid = t.TreeId
		cfg.ServerConfig.Trillian.TreeID = uint(tid)
	}

	ranges.SetActive(tid)

	// Connect to Redis
	rad := radix.PoolConfig{}
	redisClient, err := rad.New(context.Background(), "tcp", fmt.Sprintf("%s:%d", cfg.ServerConfig.Redis.Address, cfg.ServerConfig.Redis.Port))
	if err != nil {
		log.Logger.Fatal("Failed to connect to Redis server:", zap.Error(err))
	}

	log.Logger.Info(fmt.Sprintf("Starting Chronometry server with active tree %v", tid))

	// Start the server
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Server", "Chronometry")
		return c.Next()
	})

	// Cross-Origin Resource Sharing
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "*")
		c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
		return c.Next()
	})

	// setup API
	api := trillian_client.API{
		LogClient:  logClient,
		LogID:      tid,
		LogRanges:  ranges,
		Pubkey:     string(cfg.PublicKey),
		PubkeyHash: hex.EncodeToString(cfg.PublicKey[:]),
		App:        app,
		Redis:      redisClient,
	}

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("api", &api)
		c.Locals("cfg", cfg)
		return c.Next()
	})

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World 👋!")
	})

	// health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	app.Post("/record", entries.CreateEntry)
	app.Get("/record/:recordID", entries.GetEntryByRecord)
	app.Get("/api/v1/log/entries/", entries.GetEntryByIndex)

	if err := app.Listen(cfg.ServerConfig.HTTPBind); err != nil {
		log.Logger.Error("Error starting server", zap.Error(err))
		os.Exit(1)
	}
}
