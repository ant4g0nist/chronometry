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
	"strconv"

	"github.com/ant4g0nist/chronometry/pkg/config"
	cclient "github.com/ant4g0nist/chronometry/pkg/core/client"
	"github.com/ant4g0nist/chronometry/pkg/core/trillian_client"
	"github.com/gofiber/fiber/v2"
)

/*
Get a Trillian Log Entry
*/
func GetEntryByRecord(ctx *fiber.Ctx) error {
	api := ctx.Locals("api").(*trillian_client.API)
	cfg := ctx.Locals("cfg").(*config.CMConfig)

	recordID := ctx.Params("recordID")

	entry, err := trillian_client.GetEntryByRecord(ctx.Context(), api, cfg, recordID)

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

/*
Get a Trillian Log Entry
*/
func GetEntryByIndex(ctx *fiber.Ctx) error {
	api := ctx.Locals("api").(*trillian_client.API)
	cfg := ctx.Locals("cfg").(*config.CMConfig)

	uuid := ctx.Query("uuid")
	indexStr := ctx.Query("logIndex")

	if uuid == "" && indexStr == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"data": fiber.Map{
				"error": "uuid and logIndex are required",
			},
		})
	}

	var err error
	var entry cclient.Entry

	if indexStr != "" {
		index, err := strconv.ParseInt(indexStr, 10, 64)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"success": false,
				"data": fiber.Map{
					"error": err.Error(),
				},
			})
		}

		entry, err = trillian_client.GetEntryByIndex(ctx.Context(), api, cfg, index)

		if err != nil {
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"data": fiber.Map{
					"error": err.Error(),
				},
			})
		}
	} else if uuid != "" {
		entry, err = trillian_client.GetEntryByRecord(ctx.Context(), api, cfg, uuid)

		if err != nil {
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"data": fiber.Map{
					"error": err.Error(),
				},
			})
		}
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"data": fiber.Map{
			"entry": entry,
		},
	})
}
