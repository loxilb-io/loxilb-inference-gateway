/*
 * Copyright (c) 2026 NetLOX Inc
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
	"errors"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/api/models"
	aiops "github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	cmn "github.com/loxilb-io/loxilb/common"
)

// aiModelProfileEntryModel projects the discovery read model onto the wire
// schema. The required fields are schema-required (generated as pointers);
// the optional groups stay value typed and omit when empty. Artifact locator
// paths and any other host-filesystem detail never appear here — the read
// model does not carry them, by design (pkg/loxinet/ai_kv_profile_discovery.go).
func aiModelProfileEntryModel(m *cmn.AiModelProfileMod) *models.AiModelProfileEntry {
	e := &models.AiModelProfileEntry{
		ProfileID:             swag.String(m.ProfileID),
		Gen:                   swag.Uint64(m.Gen),
		BaseModel:             swag.String(m.BaseModel),
		AliasPolicy:           swag.String(m.AliasPolicy),
		AllowedAliases:        m.AllowedAliases,
		SupportedApis:         m.SupportedApis,
		SupportedFeatures:     m.SupportedFeatures,
		ExcludedFeatures:      m.ExcludedFeatures,
		TokenizerRevision:     m.TokenizerRevision,
		TokenizerSha256:       swag.String(m.TokenizerSha256),
		TemplateSha256:        m.TemplateSha256,
		TemplateContentFormat: m.TemplateContentFormat,
		RendererEngine:        m.RendererEngine,
		RendererVersion:       m.RendererVersion,
		OracleEngine:          m.OracleEngine,
		OracleVersion:         m.OracleVersion,
	}
	// supportedApis is declared required: it must serialize as a JSON array
	// even if a hook ever hands back a nil slice ([] = "declares nothing",
	// never null/absent = "unknown").
	if e.SupportedApis == nil {
		e.SupportedApis = []string{}
	}
	return e
}

// ConfigGetAIModelProfiles - GET the published model-profile registry
// generation as the discovery envelope. Read-only; generation 0 with an empty
// profiles array is the documented no-registry-published (legacy-mode)
// answer, not an error. Discovery is a cache, never an admission authority —
// rule POST admission re-validates against the generation current at POST
// time.
func ConfigGetAIModelProfiles(params aiops.GetConfigAiModelProfilesParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AI model-profile %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	reg, err := ApiHooks.NetAiModelProfileList()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		// Explicit status mapping, never the shared message-text classifier:
		// this read-only operation declares its full response surface in
		// swagger; anything the hook reports is a server fault.
		return errorResponseWithCode(http.StatusInternalServerError, err.Error())
	}

	profiles := make([]*models.AiModelProfileEntry, 0, len(reg.Profiles))
	for i := range reg.Profiles {
		profiles = append(profiles, aiModelProfileEntryModel(&reg.Profiles[i]))
	}
	return aiops.NewGetConfigAiModelProfilesOK().WithPayload(&models.AiModelProfileRegistry{
		RegistryGeneration: swag.Uint64(reg.RegistryGeneration),
		SetDigest:          reg.SetDigest,
		Profiles:           profiles,
	})
}

// ConfigGetAIModelProfileByID - GET one published profile by id (identical
// schema to a list entry, so a client can refresh one profile cheaply). The
// typed not-found — id absent from the published generation, or no generation
// published — is the operation's declared 404; everything else the hook
// reports is a server fault.
func ConfigGetAIModelProfileByID(params aiops.GetConfigAiModelProfilesProfileIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AI model-profile %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	m, err := ApiHooks.NetAiModelProfileGet(params.ProfileID)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		if errors.Is(err, cmn.ErrAiModelProfileNotFound) {
			return aiops.NewGetConfigAiModelProfilesProfileIDNotFound()
		}
		return errorResponseWithCode(http.StatusInternalServerError, err.Error())
	}
	return aiops.NewGetConfigAiModelProfilesProfileIDOK().WithPayload(aiModelProfileEntryModel(&m))
}
