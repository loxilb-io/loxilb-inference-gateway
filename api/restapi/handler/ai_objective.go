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
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

// Objectives are rows of the AI key store, as keys and tenant limits are:
// a store that is not configured or does not answer is a 503 that says
// which, and nothing is kept on this node to answer from.

func objectiveStoreError(err error) middleware.Responder {
	tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
	if resp := keyStoreFailure(err); resp != nil {
		return resp
	}
	if notFoundErr(err) {
		return errorResponseWithCode(404, err.Error())
	}
	return &ErrorResponse{Payload: ResultErrorResponseError(err)}
}

// ConfigPostAIObjective creates or replaces an objective.
func ConfigPostAIObjective(params ai.PostConfigAiObjectiveParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIObjective %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	attr := params.Attr
	if attr == nil || attr.Name == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("name is required")}
	}
	entry := cmn.AIObjectiveEntry{Name: *attr.Name, Services: attr.Services, Priority: attr.Priority}
	if _, err := ApiHooks.NetAIObjectiveAdd(params.HTTPRequest.Context(), &entry); err != nil {
		return objectiveStoreError(err)
	}
	return &ResultResponse{Result: "Success"}
}

// ConfigGetAIObjectiveAll lists the objectives as the store holds them, or,
// while it does not answer, as this gateway applies them.
func ConfigGetAIObjectiveAll(params ai.GetConfigAiObjectiveAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIObjective %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	res, err := ApiHooks.NetAIObjectiveGet(params.HTTPRequest.Context())
	if err != nil {
		return objectiveStoreError(err)
	}
	result := make([]*models.AIObjectiveEntry, 0, len(res.Objectives))
	for i := range res.Objectives {
		o := res.Objectives[i]
		name := o.Name
		result = append(result, &models.AIObjectiveEntry{
			Name:      &name,
			Services:  o.Services,
			Priority:  o.Priority,
			UpdatedAt: strfmt.DateTime(o.UpdatedAt),
		})
	}
	body := &ai.GetConfigAiObjectiveAllOKBody{ObjectiveAttr: result,
		Source: res.Source, SourceTimestamp: strfmt.DateTime(res.SourceTimestamp),
		StoreReachable: res.StoreReachable}
	if !res.StoreLastRead.IsZero() {
		at := strfmt.DateTime(res.StoreLastRead)
		body.StoreLastRead = &at
	}
	return ai.NewGetConfigAiObjectiveAllOK().WithPayload(body)
}

// ConfigDeleteAIObjective deletes an objective by name.
func ConfigDeleteAIObjective(params ai.DeleteConfigAiObjectiveNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: AIObjective %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	if _, err := ApiHooks.NetAIObjectiveDel(params.HTTPRequest.Context(), params.Name); err != nil {
		return objectiveStoreError(err)
	}
	return &ResultResponse{Result: "Success"}
}
