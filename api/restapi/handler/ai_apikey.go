/*
 * Copyright (c) 2022-2025 NetLOX Inc
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
 *
 * AI Gateway - API key lifecycle REST API handlers
 */
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/api/models"
	aiops "github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	cmn "github.com/loxilb-io/loxilb/common"
)

// keyStoreFailure gives a key-store condition the status and the wording it
// must be answered with, or nil when err is about something else.
//
// The two conditions are told apart on the wire because they ask the operator
// for different things. "Unconfigured" means no store was ever named, and the
// fix is a --aikey-db-host; "unavailable" means one was named and cannot be
// reached, and the fix is at the store. Both are 503: the routes are
// registered either way, so neither is a 501, and neither is a fault in the
// gateway, so neither is a 500.
func keyStoreFailure(err error) *ErrorResponse {
	switch {
	case errors.Is(err, cmn.ErrKeyStoreUnconfigured):
		return errorResponseWithCode(http.StatusServiceUnavailable, "ai_key_store_unconfigured")
	case errors.Is(err, cmn.ErrDBUnavailable):
		return errorResponseWithCode(http.StatusServiceUnavailable, "ai_key_store_unavailable")
	}
	return nil
}

// writeKeyStoreFailure is keyStoreFailure for the raw-handler arm, which does
// not go through the generated responder chain.
func writeKeyStoreFailure(w http.ResponseWriter, err error) bool {
	resp := keyStoreFailure(err)
	if resp == nil {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(int(resp.Payload.Code))
	json.NewEncoder(w).Encode(map[string]string{"error": resp.Payload.Message}) //nolint:errcheck
	return true
}

// ConfigPostAIApikey - POST /config/ai/apikey
// Creates a new API key for a tenant. Returns the raw key exactly once.
func ConfigPostAIApikey(params aiops.PostConfigAiApikeyParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIApikey %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	req := params.Body
	if req == nil || req.TenantID == nil || strings.TrimSpace(*req.TenantID) == "" {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("tenant_id is required")}
	}

	entry := cmn.ApiKeyEntry{
		TenantID: *req.TenantID,
		Name:     req.Name,
		// Caller-supplied key material, when present. The store validates its
		// length and charset and keeps only the hash; this handler must not log
		// it, and the response below does not echo it.
		ApiKey:        req.APIKey,
		AllowedModels: req.AllowedModels,
		RateLimitRPS:  int(req.RateLimitRps),
		BurstSize:     int(req.BurstSize),
		TokensPerMin:  int(req.TokensPerMin),
		Enabled:       true, // default to enabled
	}
	// Allow caller to explicitly disable the key at creation time
	if req.Enabled != nil {
		entry.Enabled = *req.Enabled
	}
	// Guard against both Go zero time (0001-01-01) and strfmt's Unix-epoch sentinel
	// (1970-01-01T00:00:00Z) returned by ParseDateTime(""). Only treat a future
	// timestamp as a real expiry.
	expiresAt := time.Time(req.ExpiresAt)
	if !expiresAt.IsZero() && !expiresAt.Equal(time.Unix(0, 0).UTC()) {
		entry.ExpiresAt = &expiresAt
	}

	rawKey, keyID, err := ApiHooks.NetAPIKeyCreate(entry)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIApikey] Failed to create API key for tenant %s: %v\n", *req.TenantID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// raw key must never be logged. It is also empty when the caller supplied
	// the key material: echoing a value the caller already holds would put it
	// into response logs and API traces for no benefit.
	return aiops.NewPostConfigAiApikeyCreated().WithPayload(&models.APIKeyCreateResponse{
		RawKey: &rawKey,
		KeyID:  keyID,
	})
}

// ConfigGetAIApikeys - GET /config/ai/apikey
// Lists API keys. Filters by tenant_id when provided; returns all keys when omitted.
func ConfigGetAIApikeys(params aiops.GetConfigAiApikeyParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIApikey %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tenantID := ""
	if params.TenantID != nil {
		tenantID = *params.TenantID
	}

	keys, err := ApiHooks.NetAPIKeyList(tenantID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIApikey] Failed to list API keys (tenant=%q): %v\n", tenantID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	result := make([]*models.APIKeySummary, 0, len(keys))
	for _, k := range keys {
		summary := apiKeySummaryToModel(k)
		result = append(result, summary)
	}

	return aiops.NewGetConfigAiApikeyOK().WithPayload(result)
}

// ConfigGetAIApikeyByID - GET /config/ai/apikey/{key_id}
// Returns metadata for a single API key.
func ConfigGetAIApikeyByID(params aiops.GetConfigAiApikeyKeyIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIApikey %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	key, err := ApiHooks.NetAPIKeyGet(params.KeyID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIApikey] Failed to get API key %s: %v\n", params.KeyID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return aiops.NewGetConfigAiApikeyKeyIDOK().WithPayload(apiKeySummaryToModel(*key))
}

// ConfigDeleteAIApikey - DELETE /config/ai/apikey/{key_id}
// Permanently deletes an API key (hard delete); cache eviction completes before
// the response is sent, and a subsequent GET returns 404. To disable a key
// reversibly while keeping it visible, PATCH enabled=false instead.
func ConfigDeleteAIApikey(params aiops.DeleteConfigAiApikeyKeyIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIApikey %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if err := ApiHooks.NetAPIKeyDelete(params.KeyID); err != nil {
		tk.LogIt(tk.LogError, "[AIApikey] Failed to delete API key %s: %v\n", params.KeyID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return aiops.NewDeleteConfigAiApikeyKeyIDNoContent()
}

// ConfigPatchAIApikey - PATCH /config/ai/apikey/{key_id}
// Updates allowed_models and/or enabled for an existing API key.
// This is a raw HTTP handler (not swagger-generated) wired via setupGlobalMiddleware.
func ConfigPatchAIApikey(w http.ResponseWriter, r *http.Request, keyID string) {
	tk.LogIt(tk.LogTrace, "api: AIApikey PATCH API called by IP: %s, keyID: %s\n",
		r.RemoteAddr, keyID)

	if strings.TrimSpace(keyID) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "key_id is required"})
		return
	}

	var body struct {
		AllowedModels []string `json:"allowed_models"`
		Enabled       *bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if err := ApiHooks.NetAPIKeyPatch(keyID, body.AllowedModels, body.Enabled); err != nil {
		tk.LogIt(tk.LogError, "[AIApikey] Failed to patch API key %s: %v\n", keyID, err)
		if writeKeyStoreFailure(w, err) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ConfigPostAITenantRateLimit - POST /config/ai/tenant/ratelimit
// Upserts the per-tenant rate limit configuration.
func ConfigPostAITenantRateLimit(params aiops.PostConfigAiTenantRatelimitParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AITenantRateLimit %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	body := params.Body
	if body == nil || body.TenantID == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("tenant_id is required")}
	}

	modelLimits := make([]cmn.TenantModelRateLimit, 0, len(body.ModelLimits))
	for _, ml := range body.ModelLimits {
		if ml == nil || ml.Model == "" {
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("model_limits entries require a model name")}
		}
		modelLimits = append(modelLimits, cmn.TenantModelRateLimit{
			Model:        ml.Model,
			TokensPerMin: int(ml.TokensPerMin),
		})
	}

	if err := ApiHooks.NetTenantRateLimitSet(*body.TenantID, int(body.Rps), int(body.TokensPerMin), int(body.BurstPct), modelLimits); err != nil {
		tk.LogIt(tk.LogError, "[AITenantRateLimit] Failed to set rate limit for tenant %s: %v\n", *body.TenantID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return aiops.NewPostConfigAiTenantRatelimitNoContent()
}

// ConfigGetAITenantRateLimit - GET /config/ai/tenant/ratelimit/{tenant_id}
// Returns the current rate limit configuration for a tenant.
func ConfigGetAITenantRateLimit(params aiops.GetConfigAiTenantRatelimitTenantIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AITenantRateLimit %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	entry, err := ApiHooks.NetTenantRateLimitGet(params.TenantID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AITenantRateLimit] Failed to get rate limit for tenant %s: %v\n", params.TenantID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tenantID := entry.TenantID
	result := &models.TenantRateLimitEntry{
		TenantID:     &tenantID,
		Rps:          int64(entry.RPS),
		TokensPerMin: int64(entry.TokensPerMin),
		BurstPct:     int64(entry.BurstPct),
		UpdatedAt:    strfmt.DateTime(entry.UpdatedAt),
	}
	for _, ml := range entry.ModelLimits {
		result.ModelLimits = append(result.ModelLimits, &models.TenantModelRateLimit{
			Model:        ml.Model,
			TokensPerMin: int64(ml.TokensPerMin),
		})
	}

	return aiops.NewGetConfigAiTenantRatelimitTenantIDOK().WithPayload(result)
}

// apiKeySummaryToModel converts a cmn.ApiKeySummary to the API model.
func apiKeySummaryToModel(k cmn.ApiKeySummary) *models.APIKeySummary {
	summary := &models.APIKeySummary{
		KeyID:         k.KeyID,
		TenantID:      k.TenantID,
		Name:          k.Name,
		AllowedModels: k.AllowedModels,
		RateLimitRps:  int64(k.RateLimitRPS),
		BurstSize:     int64(k.BurstSize),
		TokensPerMin:  int64(k.TokensPerMin),
		CreatedAt:     strfmt.DateTime(k.CreatedAt),
		Enabled:       k.Enabled,
	}
	if k.ExpiresAt != nil {
		summary.ExpiresAt = strfmt.DateTime(*k.ExpiresAt)
	}
	return summary
}
