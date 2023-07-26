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
package entries

import (
	"fmt"

	"github.com/ant4g0nist/chronometry/pkg/config"
	"github.com/ant4g0nist/chronometry/pkg/core/signature"
	"github.com/ant4g0nist/chronometry/pkg/core/trillian_client"
	"github.com/gofiber/fiber/v2"
)

/*
Create a new Trillian Log Entry:
3 steps:
- Verify the signature
- Sign the report sent by the user
- Create the entry in Trillian Log
- Return the signed blob to the user
*/
func CreateEntry(ctx *fiber.Ctx) error {
	cfg := ctx.Locals("cfg").(*config.CMConfig)
	api := ctx.Locals("api").(*trillian_client.API)

	saveToIPFS := ctx.Query("ipfs") == "true"
	fmt.Println("saveToIPFS", saveToIPFS, ctx.Query("saveToIPFS")) //no

	var createEntryRequest ICreateEntryRequest
	if err := ctx.BodyParser(&createEntryRequest); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	// validate the request
	if err := createEntryRequest.Validate(); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"data": fiber.Map{
				"error": err.Error(),
			},
		})
	}

	// verify signature
	if !signature.VerifyReportWithBase64(createEntryRequest.Report, createEntryRequest.PublicKey, createEntryRequest.UserSignature) {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"data": fiber.Map{
				"error": "Signature verification failed",
			},
		})
	}

	signedBlob := signature.SignBlob(createEntryRequest.Report, cfg.PublicKey, cfg.PrivateKey)

	// Create the entry
	entry, err := trillian_client.CreateEntry(api.Redis, ctx.Context(), api, cfg, createEntryRequest.Report, signedBlob, saveToIPFS)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"data": fiber.Map{
				"error": err.Error(),
			},
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"data": fiber.Map{
			"entry": entry,
		},
	})
}
