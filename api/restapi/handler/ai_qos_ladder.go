/*
 * Copyright (c) 2026 LoxiLB Authors
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
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/api/models"
	aiops "github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	cmn "github.com/loxilb-io/loxilb/common"
)

// QoS ladder configuration surface: explicit per-user limits (level 1) and
// the configurable defaults (level 3). Same store-failure and validation
// conventions as the tenant handlers in ai_apikey.go.

// notFoundErr reports whether a service error is the "no such row" answer,
// which the routes map to 404 rather than a generic 500.
func notFoundErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

// ConfigPostAIUserRateLimit - POST /config/ai/user/ratelimit
// Upserts one user's explicit rate-limit entry (model limits replace as a set).
func ConfigPostAIUserRateLimit(params aiops.PostConfigAiUserRatelimitParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIUserRateLimit %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	body := params.Body
	if body == nil || body.TenantID == nil || body.UserID == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("tenant_id and user_id are required")}
	}
	entry := cmn.UserRateLimitEntry{
		TenantID:     *body.TenantID,
		UserID:       *body.UserID,
		RPS:          int(body.Rps),
		BurstSize:    int(body.BurstSize),
		TokensPerMin: int(body.TokensPerMin),
	}
	for _, ml := range body.ModelLimits {
		if ml == nil || ml.Model == "" {
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("model_limits entries require a model name")}
		}
		entry.ModelLimits = append(entry.ModelLimits, cmn.UserModelRateLimit{
			Model:        ml.Model,
			TokensPerMin: int(ml.TokensPerMin),
		})
	}

	if err := ApiHooks.NetUserRateLimitSet(entry); err != nil {
		tk.LogIt(tk.LogError, "[AIUserRateLimit] Failed to set rate limit for %s/%s: %v\n",
			entry.TenantID, entry.UserID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		// Validation refusals arrive as typed cmn.ValidationError values;
		// ResultErrorResponseError classifies them 400 by structure, so no
		// wording-dependent branch is needed here.
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return aiops.NewPostConfigAiUserRatelimitNoContent()
}

// userRateLimitEntryToModel converts a cmn entry to the API model.
func userRateLimitEntryToModel(e cmn.UserRateLimitEntry) *models.UserRateLimitEntry {
	tenantID, userID := e.TenantID, e.UserID
	m := &models.UserRateLimitEntry{
		TenantID:     &tenantID,
		UserID:       &userID,
		Rps:          int64(e.RPS),
		BurstSize:    int64(e.BurstSize),
		TokensPerMin: int64(e.TokensPerMin),
		UpdatedAt:    strfmt.DateTime(e.UpdatedAt),
	}
	for _, ml := range e.ModelLimits {
		m.ModelLimits = append(m.ModelLimits, &models.UserModelRateLimit{
			Model:        ml.Model,
			TokensPerMin: int64(ml.TokensPerMin),
		})
	}
	return m
}

// ConfigListAIUserRateLimits - GET /config/ai/user/ratelimit/{tenant_id}
func ConfigListAIUserRateLimits(params aiops.GetConfigAiUserRatelimitTenantIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIUserRateLimit %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	entries, err := ApiHooks.NetUserRateLimitList(params.TenantID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIUserRateLimit] Failed to list rate limits for tenant %s: %v\n", params.TenantID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	result := make([]*models.UserRateLimitEntry, 0, len(entries))
	for _, e := range entries {
		result = append(result, userRateLimitEntryToModel(e))
	}
	return aiops.NewGetConfigAiUserRatelimitTenantIDOK().WithPayload(result)
}

// ConfigGetAIUserRateLimit - GET /config/ai/user/ratelimit/{tenant_id}/{user_id}
func ConfigGetAIUserRateLimit(params aiops.GetConfigAiUserRatelimitTenantIDUserIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIUserRateLimit %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	entry, err := ApiHooks.NetUserRateLimitGet(params.TenantID, params.UserID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIUserRateLimit] Failed to get rate limit for %s/%s: %v\n",
			params.TenantID, params.UserID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		if notFoundErr(err) {
			return aiops.NewGetConfigAiUserRatelimitTenantIDUserIDNotFound().WithPayload(ResultErrorResponseError(err))
		}
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return aiops.NewGetConfigAiUserRatelimitTenantIDUserIDOK().WithPayload(userRateLimitEntryToModel(*entry))
}

// ConfigDeleteAIUserRateLimit - DELETE /config/ai/user/ratelimit/{tenant_id}/{user_id}
func ConfigDeleteAIUserRateLimit(params aiops.DeleteConfigAiUserRatelimitTenantIDUserIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIUserRateLimit %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if err := ApiHooks.NetUserRateLimitDelete(params.TenantID, params.UserID); err != nil {
		tk.LogIt(tk.LogError, "[AIUserRateLimit] Failed to delete rate limit for %s/%s: %v\n",
			params.TenantID, params.UserID, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		if notFoundErr(err) {
			return aiops.NewDeleteConfigAiUserRatelimitTenantIDUserIDNotFound().WithPayload(ResultErrorResponseError(err))
		}
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return aiops.NewDeleteConfigAiUserRatelimitTenantIDUserIDNoContent()
}

// ConfigPostAIRateLimitDefaults - POST /config/ai/ratelimit/defaults
func ConfigPostAIRateLimitDefaults(params aiops.PostConfigAiRatelimitDefaultsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIRateLimitDefaults %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	body := params.Body
	if body == nil || body.Scope == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("scope is required")}
	}
	entry := cmn.RateLimitDefaultsEntry{
		Scope:            *body.Scope,
		RuleIdent:        body.RuleIdent,
		DefaultUserRPS:   int(body.DefaultUserRps),
		DefaultUserTPM:   int(body.DefaultUserTpm),
		DefaultTenantRPS: int(body.DefaultTenantRps),
		DefaultTenantTPM: int(body.DefaultTenantTpm),
		VipSharedRPS:     int(body.VipSharedRps),
		VipSharedTPM:     int(body.VipSharedTpm),
	}
	if err := ApiHooks.NetRateLimitDefaultsSet(entry); err != nil {
		tk.LogIt(tk.LogError, "[AIRateLimitDefaults] Failed to set defaults (%s/%s): %v\n",
			entry.Scope, entry.RuleIdent, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return aiops.NewPostConfigAiRatelimitDefaultsNoContent()
}

// defaultsRuleIdent resolves the optional rule_ident query parameter.
func defaultsRuleIdent(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ConfigGetAIRateLimitDefaults - GET /config/ai/ratelimit/defaults/{scope}
func ConfigGetAIRateLimitDefaults(params aiops.GetConfigAiRatelimitDefaultsScopeParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIRateLimitDefaults %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	entry, err := ApiHooks.NetRateLimitDefaultsGet(params.Scope, defaultsRuleIdent(params.RuleIdent))
	if err != nil {
		tk.LogIt(tk.LogError, "[AIRateLimitDefaults] Failed to get defaults (%s): %v\n", params.Scope, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		if notFoundErr(err) {
			return aiops.NewGetConfigAiRatelimitDefaultsScopeNotFound().WithPayload(ResultErrorResponseError(err))
		}
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	scope := entry.Scope
	result := &models.RateLimitDefaultsEntry{
		Scope:            &scope,
		RuleIdent:        entry.RuleIdent,
		DefaultUserRps:   int64(entry.DefaultUserRPS),
		DefaultUserTpm:   int64(entry.DefaultUserTPM),
		DefaultTenantRps: int64(entry.DefaultTenantRPS),
		DefaultTenantTpm: int64(entry.DefaultTenantTPM),
		VipSharedRps:     int64(entry.VipSharedRPS),
		VipSharedTpm:     int64(entry.VipSharedTPM),
		UpdatedAt:        strfmt.DateTime(entry.UpdatedAt),
	}
	return aiops.NewGetConfigAiRatelimitDefaultsScopeOK().WithPayload(result)
}

// ConfigDeleteAIRateLimitDefaults - DELETE /config/ai/ratelimit/defaults/{scope}
func ConfigDeleteAIRateLimitDefaults(params aiops.DeleteConfigAiRatelimitDefaultsScopeParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIRateLimitDefaults %s API called by IP: %s. url: %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if err := ApiHooks.NetRateLimitDefaultsDelete(params.Scope, defaultsRuleIdent(params.RuleIdent)); err != nil {
		tk.LogIt(tk.LogError, "[AIRateLimitDefaults] Failed to delete defaults (%s): %v\n", params.Scope, err)
		if resp := keyStoreFailure(err); resp != nil {
			return resp
		}
		if notFoundErr(err) {
			return aiops.NewDeleteConfigAiRatelimitDefaultsScopeNotFound().WithPayload(ResultErrorResponseError(err))
		}
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return aiops.NewDeleteConfigAiRatelimitDefaultsScopeNoContent()
}
