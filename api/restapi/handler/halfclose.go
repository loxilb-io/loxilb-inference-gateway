/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// The process-wide half-close hold settings and the release of every held
// client (/config/halfclose). A service's half_close_mode decides whether it
// holds at all; these decide whether new holds may be taken anywhere, and for
// how long a hold may go without an answer byte.

// halfCloseInForce returns the settings in force: as set, else the defaults.
func halfCloseInForce() (cmn.HalfCloseConfig, error) {
	cfg, err := ApiHooks.NetHalfCloseGet()
	if err != nil {
		return cmn.HalfCloseConfig{}, err
	}
	if cfg == nil {
		return cmn.DefaultHalfCloseConfig(), nil
	}
	return *cfg, nil
}

// ConfigGetHalfClose - GET /config/halfclose
func ConfigGetHalfClose(params operations.GetConfigHalfcloseParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: half-close %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	cfg, err := halfCloseInForce()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return operations.NewGetConfigHalfcloseOK().WithPayload(halfClosePayload(cfg))
}

// halfCloseKeys are the fields POST /config/halfclose takes.
var halfCloseKeys = map[string]bool{"allow": true, "capSeconds": true, "defaultMode": true}

// halfCloseBodyCheck reads a raw body for what the generated model cannot
// tell apart: the fields the settings do not have, and a defaultMode sent as
// null. A partial body treats an absent field as "keep", so without this a
// misspelt one - {"alow":false} - would succeed and change nothing, and a
// null default would pass for an omitted one.
func halfCloseBodyCheck(raw []byte) (unknown []string, nullDefault bool, err error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false, err
	}
	for k := range m {
		if !halfCloseKeys[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	if v, ok := m["defaultMode"]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		nullDefault = true
	}
	return unknown, nullDefault, nil
}

// halfClosePayload is the answer of GET and POST: the settings in force.
func halfClosePayload(cfg cmn.HalfCloseConfig) *models.HalfCloseConfig {
	cfg = cfg.Normalized()
	allow := cfg.Allow
	capSec := int32(cfg.CapSeconds)
	defaultMode := cfg.DefaultMode
	return &models.HalfCloseConfig{Allow: &allow, CapSeconds: &capSec, DefaultMode: &defaultMode}
}

// ConfigPostHalfClose - POST /config/halfclose. A field omitted keeps the
// value in force, so blocking new holds in an incident needs no other value
// and turning the default mode to hold touches neither the switch nor the
// bound;
// a field the settings do not have is refused, and the answer is the settings
// in force once applied, so the caller sees what it got.
func ConfigPostHalfClose(params operations.PostConfigHalfcloseParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: half-close %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	raw, captured := rawBodyCapture(params.HTTPRequest.Context())
	if !captured {
		// Without the raw body a misspelt field cannot be told from an
		// omitted one: refuse rather than skip the check.
		return errorResponseWithCode(http.StatusInternalServerError,
			"half-close settings: the request body was not captured, so its fields cannot be checked")
	}
	unknown, nullDefault, err := halfCloseBodyCheck(raw)
	if err != nil {
		return errorResponseWithCode(http.StatusBadRequest, "malformed half-close settings body")
	}
	if len(unknown) > 0 {
		return errorResponseWithCode(http.StatusBadRequest,
			fmt.Sprintf("unknown field(s) %v: the settings are allow, capSeconds and defaultMode", unknown))
	}
	if nullDefault {
		return errorResponseWithCode(http.StatusBadRequest,
			"defaultMode must be off or hold: null is not a value here (omit it to keep the one in force)")
	}
	attr := params.Attr
	if attr == nil || (attr.Allow == nil && attr.CapSeconds == nil && attr.DefaultMode == nil) {
		return errorResponseWithCode(http.StatusBadRequest,
			"give at least one of allow, capSeconds and defaultMode")
	}
	if attr.DefaultMode != nil {
		if err := cmn.HalfCloseDefaultModeCheck(*attr.DefaultMode); err != nil {
			return errorResponseWithCode(http.StatusBadRequest, err.Error())
		}
	}
	u := cmn.HalfCloseUpdate{Allow: attr.Allow, DefaultMode: attr.DefaultMode}
	if attr.CapSeconds != nil {
		if *attr.CapSeconds < 0 {
			return errorResponseWithCode(http.StatusBadRequest, "capSeconds must not be negative")
		}
		capSec := uint32(*attr.CapSeconds)
		u.CapSeconds = &capSec
	}
	applied, err := ApiHooks.NetHalfCloseUpdate(&u)
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return operations.NewPostConfigHalfcloseOK().WithPayload(halfClosePayload(applied))
}

// ConfigPostHalfCloseRelease - POST /config/halfclose/release
func ConfigPostHalfCloseRelease(params operations.PostConfigHalfcloseReleaseParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: half-close %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	if _, err := ApiHooks.NetHalfCloseRelease(); err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseError(err)}
	}
	return &ResultResponse{Result: "Success"}
}
