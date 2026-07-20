/*
 * Copyright (c) 2025 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	"fmt"

	"github.com/go-openapi/runtime/middleware"
	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations/tracing"
)

// ConfigGetTraceParsers handles GET /config/trace/parsers
// Lists all available trace parsers registered in the system
func ConfigGetTraceParsers(params tracing.GetTraceParsersParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] GET /config/trace/parsers\n")

	// Get parser list via API hooks
	parserMetas, err := ApiHooks.NetTraceParserListGet()
	if err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to get parser list: %v\n", err)
		return tracing.NewGetTraceParsersInternalServerError().WithPayload(&models.Error{
			Code:    500,
			Message: fmt.Sprintf("Failed to get parser list: %v", err),
		})
	}

	// Convert to swagger models
	var parsers []*models.TraceParserInfo
	for _, meta := range parserMetas {
		nameStr := meta.Name
		versionStr := meta.Version
		protocolStr := meta.Protocol
		info := &models.TraceParserInfo{
			Name:           &nameStr,
			Version:        &versionStr,
			Protocol:       &protocolStr,
			SupportedPaths: meta.SupportedPaths,
		}
		parsers = append(parsers, info)
	}

	tk.LogIt(tk.LogInfo, "[API] Retrieved %d trace parser(s)\n", len(parsers))

	return tracing.NewGetTraceParsersOK().WithPayload(&tracing.GetTraceParsersOKBody{
		Parsers: parsers,
	})
}

// ConfigGetCatalogParser handles GET /config/trace/catalog/{id}/parser
// Returns the parser currently assigned to a catalog
func ConfigGetCatalogParser(params tracing.GetCatalogParserParams, principal interface{}) middleware.Responder {
	catalogID := uint16(params.CatalogID)
	tk.LogIt(tk.LogDebug, "[API] GET /config/trace/catalog/%d/parser\n", catalogID)

	// Get parser name for catalog
	parserName, err := ApiHooks.NetTraceCatalogParserGet(catalogID)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[API] No parser assigned to catalog[%d]: %v\n", catalogID, err)
		return tracing.NewGetCatalogParserNotFound().WithPayload(&models.Error{
			Code:    404,
			Message: fmt.Sprintf("No parser assigned to catalog %d", catalogID),
		})
	}

	// Get catalog info
	catalogName, parserType, err := ApiHooks.NetTraceCatalogInfoGet(catalogID)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[API] Failed to get catalog info for ID %d: %v\n", catalogID, err)
		catalogName = ""
		parserType = ""
	}

	catalogIDInt := int64(catalogID)
	result := &models.CatalogParserMapping{
		CatalogID:   &catalogIDInt,
		CatalogName: catalogName,
		ParserName:  parserName,
		ParserType:  parserType,
	}

	tk.LogIt(tk.LogInfo, "[API] Catalog[%d] (%s) -> parser '%s'\n", catalogID, catalogName, parserName)
	return tracing.NewGetCatalogParserOK().WithPayload(result)
}

// ConfigUpdateCatalogParser handles PUT /config/trace/catalog/{id}/parser
// Updates the parser assignment for a catalog at runtime
func ConfigUpdateCatalogParser(params tracing.UpdateCatalogParserParams, principal interface{}) middleware.Responder {
	catalogID := uint16(params.CatalogID)
	parserName := *params.Attr.ParserName
	tk.LogIt(tk.LogDebug, "[API] PUT /config/trace/catalog/%d/parser (parser=%s)\n", catalogID, parserName)

	// Update catalog -> parser mapping via API hooks
	if err := ApiHooks.NetTraceCatalogParserUpdate(catalogID, parserName); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to update parser for catalog[%d]: %v\n", catalogID, err)

		// Check if it's a validation error (parser not found)
		if err.Error() == fmt.Sprintf("parser '%s' not found", parserName) {
			return tracing.NewUpdateCatalogParserBadRequest().WithPayload(&models.Error{
				Code:    400,
				Message: err.Error(),
			})
		}

		return tracing.NewUpdateCatalogParserInternalServerError().WithPayload(&models.Error{
			Code:    500,
			Message: fmt.Sprintf("Failed to sync parser: %v", err),
		})
	}

	tk.LogIt(tk.LogInfo, "[API] Updated catalog[%d] -> parser '%s'\n", catalogID, parserName)
	// Return success - PostSuccess model should just confirm operation
	return tracing.NewUpdateCatalogParserOK()
}

// ConfigDeleteCatalogParser handles DELETE /config/trace/catalog/{id}/parser
// Removes parser assignment for a catalog (falls back to path-based or default)
func ConfigDeleteCatalogParser(params tracing.DeleteCatalogParserParams, principal interface{}) middleware.Responder {
	catalogID := uint16(params.CatalogID)
	tk.LogIt(tk.LogDebug, "[API] DELETE /config/trace/catalog/%d/parser\n", catalogID)

	// Remove catalog -> parser mapping via API hooks
	if err := ApiHooks.NetTraceCatalogParserDelete(catalogID); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to delete parser mapping for catalog[%d]: %v\n", catalogID, err)
		return tracing.NewDeleteCatalogParserInternalServerError().WithPayload(&models.Error{
			Code:    500,
			Message: fmt.Sprintf("Failed to delete parser mapping: %v", err),
		})
	}

	tk.LogIt(tk.LogInfo, "[API] Removed parser mapping for catalog[%d] (will use path-based or default parser)\n", catalogID)
	return tracing.NewDeleteCatalogParserNoContent()
}
