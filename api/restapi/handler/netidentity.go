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
)

// netIdentityModFromEntry maps the API model onto the config mod. Nothing is
// defaulted or checked here: the net layer validates the binding and stores
// it in its canonical form, which is what a GET then reports.
func netIdentityModFromEntry(attr *models.NetIdentityEntry) cmn.NetIdentityMod {
	pm := cmn.NetIdentityMod{
		Services:        attr.Services,
		AllowedModels:   attr.AllowedModels,
		Enforce:         attr.Enforce,
		Credential:      attr.Credential,
		ForwardIdentity: attr.ForwardIdentity,
		PriorityClass:   attr.PriorityClass,
		FailMode:        attr.FailMode,
	}
	if attr.Name != nil {
		pm.Name = *attr.Name
	}
	if attr.Tenant != nil {
		pm.Tenant = *attr.Tenant
	}
	if attr.Match != nil {
		pm.Match.CIDR = attr.Match.Cidr
		pm.Match.IngressIf = attr.Match.IngressIf
		pm.Match.Vlan = int(attr.Match.Vlan)
		pm.Match.Vni = int(attr.Match.Vni)
		pm.Match.IPsecTunnel = attr.Match.IpsecTunnel
	}
	return pm
}

func netIdentityEntryFromMod(pm *cmn.NetIdentityMod) *models.NetIdentityEntry {
	name := pm.Name
	tenant := pm.Tenant
	return &models.NetIdentityEntry{
		Name: &name,
		Match: &models.NetIdentityEntryMatch{
			Cidr:        pm.Match.CIDR,
			IngressIf:   pm.Match.IngressIf,
			Vlan:        int64(pm.Match.Vlan),
			Vni:         int64(pm.Match.Vni),
			IpsecTunnel: pm.Match.IPsecTunnel,
		},
		Services:        pm.Services,
		Tenant:          &tenant,
		AllowedModels:   pm.AllowedModels,
		Enforce:         pm.Enforce,
		Credential:      pm.Credential,
		ForwardIdentity: pm.ForwardIdentity,
		PriorityClass:   pm.PriorityClass,
		FailMode:        pm.FailMode,
	}
}

// netIdentityWarner is the part of the net layer that knows what is worth
// saying about a binding that was just stored.
type netIdentityWarner interface {
	NetAINetIdentityWarning(*cmn.NetIdentityMod) string
}

// ConfigPostNetIdentity creates or replaces a network-identity binding.
func ConfigPostNetIdentity(params ai.PostConfigAiNetidentityParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: NetIdentity %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	pm := netIdentityModFromEntry(params.Attr)
	if _, err := ApiHooks.NetAINetIdentityAdd(&pm); err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	// The binding is in. What is worth saying about it goes into the same
	// reply and refuses nothing.
	if w, ok := ApiHooks.(netIdentityWarner); ok {
		if msg := w.NetAINetIdentityWarning(&pm); msg != "" {
			return &ResultResponse{Result: "Success; warning: " + msg}
		}
	}
	return &ResultResponse{Result: "Success"}
}

// ConfigGetNetIdentityAll lists the network-identity bindings.
func ConfigGetNetIdentityAll(params ai.GetConfigAiNetidentityAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: NetIdentity %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	res, err := ApiHooks.NetAINetIdentityGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	result := make([]*models.NetIdentityEntry, 0, len(res))
	for i := range res {
		result = append(result, netIdentityEntryFromMod(&res[i]))
	}
	return ai.NewGetConfigAiNetidentityAllOK().
		WithPayload(&ai.GetConfigAiNetidentityAllOKBody{NetIdentityAttr: result})
}

// ConfigDeleteNetIdentity deletes a network-identity binding by name.
func ConfigDeleteNetIdentity(params ai.DeleteConfigAiNetidentityNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: NetIdentity %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	if _, err := ApiHooks.NetAINetIdentityDel(params.Name); err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return &ResultResponse{Result: "Success"}
}
