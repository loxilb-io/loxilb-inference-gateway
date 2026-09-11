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
	tk "github.com/loxilb-io/loxilib"

	"github.com/go-openapi/runtime/middleware"
)

// jwtAuthProfileModFromEntry maps the API model onto the config mod.
// Defaults are NOT applied here: the verifier package owns them, and the
// stored configuration keeps reporting exactly what the operator sent.
func jwtAuthProfileModFromEntry(attr *models.JWTAuthProfileEntry) cmn.JWTAuthProfileMod {
	pm := cmn.JWTAuthProfileMod{
		JWKSURL:                  attr.JwksURL,
		Audiences:                attr.Audiences,
		Algs:                     attr.Algs,
		LeewaySec:                int(attr.LeewaySec),
		RefreshSec:               int(attr.RefreshSec),
		TenantClaim:              attr.TenantClaim,
		UserClaim:                attr.UserClaim,
		ModelsClaim:              attr.ModelsClaim,
		RolesClaim:               attr.RolesClaim,
		ModelRolePrefix:          attr.ModelRolePrefix,
		UsernameClaim:            attr.UsernameClaim,
		ModelAuthz:               attr.ModelAuthz,
		DefaultTenant:            attr.DefaultTenant,
		ForwardIdentity:          attr.ForwardIdentity,
		AuthorizationPassthrough: attr.AuthorizationPassthrough,
	}
	if attr.Name != nil {
		pm.Name = *attr.Name
	}
	if attr.Issuer != nil {
		pm.Issuer = *attr.Issuer
	}
	return pm
}

func jwtAuthProfileEntryFromMod(pm *cmn.JWTAuthProfileMod) *models.JWTAuthProfileEntry {
	name := pm.Name
	issuer := pm.Issuer
	return &models.JWTAuthProfileEntry{
		Name:                     &name,
		Issuer:                   &issuer,
		JwksURL:                  pm.JWKSURL,
		Audiences:                pm.Audiences,
		Algs:                     pm.Algs,
		LeewaySec:                int64(pm.LeewaySec),
		RefreshSec:               int64(pm.RefreshSec),
		TenantClaim:              pm.TenantClaim,
		UserClaim:                pm.UserClaim,
		ModelsClaim:              pm.ModelsClaim,
		RolesClaim:               pm.RolesClaim,
		ModelRolePrefix:          pm.ModelRolePrefix,
		UsernameClaim:            pm.UsernameClaim,
		ModelAuthz:               pm.ModelAuthz,
		DefaultTenant:            pm.DefaultTenant,
		ForwardIdentity:          pm.ForwardIdentity,
		AuthorizationPassthrough: pm.AuthorizationPassthrough,
	}
}

// ConfigPostJWTAuthProfile creates or replaces a JWT auth profile.
func ConfigPostJWTAuthProfile(params ai.PostConfigAiJwtauthprofileParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: JWTAuthProfile %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	pm := jwtAuthProfileModFromEntry(params.Attr)
	if _, err := ApiHooks.NetJWTAuthProfileAdd(&pm); err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return &ResultResponse{Result: "Success"}
}

// ConfigGetJWTAuthProfileAll lists the configured JWT auth profiles.
func ConfigGetJWTAuthProfileAll(params ai.GetConfigAiJwtauthprofileAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: JWTAuthProfile %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	res, err := ApiHooks.NetJWTAuthProfileGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	result := make([]*models.JWTAuthProfileEntry, 0, len(res))
	for i := range res {
		result = append(result, jwtAuthProfileEntryFromMod(&res[i]))
	}
	return ai.NewGetConfigAiJwtauthprofileAllOK().
		WithPayload(&ai.GetConfigAiJwtauthprofileAllOKBody{JwtAuthProfileAttr: result})
}

// ConfigDeleteJWTAuthProfile deletes a JWT auth profile by name.
func ConfigDeleteJWTAuthProfile(params ai.DeleteConfigAiJwtauthprofileNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: JWTAuthProfile %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)

	if _, err := ApiHooks.NetJWTAuthProfileDel(params.Name); err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return &ResultResponse{Result: "Success"}
}
