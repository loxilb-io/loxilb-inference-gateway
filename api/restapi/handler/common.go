/*
 * Copyright (c) 2022 NetLOX Inc
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
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"

	"github.com/go-openapi/runtime"
	tk "github.com/loxilb-io/loxilib"
)

var ApiHooks cmn.NetHookInterface

type CustomResponder func(http.ResponseWriter, runtime.Producer)

type ResultResponse struct {
	Result string `json:"result"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Payload *models.Error
}

func (result *ResultResponse) WriteResponse(w http.ResponseWriter, producer runtime.Producer) {
	producer.Produce(w, result)
}

func (c CustomResponder) WriteResponse(w http.ResponseWriter, p runtime.Producer) {
	c(w, p)
}

func (e *ErrorResponse) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(int(e.Payload.Code))
	producer.Produce(rw, e.Payload)
}

// errorResponseWithCode returns a responder carrying an explicit HTTP status,
// for the cases where the status is a decision rather than something inferred
// from an error message.
func errorResponseWithCode(code int, msg string) *ErrorResponse {
	return &ErrorResponse{Payload: &models.Error{
		Code:    int32(code),
		Message: msg,
		Result:  msg,
		Fields:  []string{},
	}}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func ResultErrorResponseErrorMessage(msg string) *models.Error {
	m := strings.ToLower(msg)

	// 404 Not Found
	if containsAny(m,
		"not-exists", " not exists", "not found", "no such", "not such",
		"no neigh found", "no-nh error", "no ulcl", "ephost-notfound",
		"host-notfound", "no-zone error", "no loxi-eni found", "no-master",
		"no bfd session", "my discriminator not found", "no-portimap", "no-portomap", "no-port error",
		"no such fdb", "no such route", "no such port", "no such mirror",
		"no such allowed src prefix", "no such policer", "not found interface",
		"no such ifa", "no such addrs", "vlan not created", "vlan not yet created",
		"phy port not created", "no-realport", "no realport", "no-user error", "no-rule error", "file not found",
	) {
		return &models.Error{Code: 404, Message: "Resource not found", Result: msg}
	}

	// 503 Service Unavailable — the store was never reached
	//
	// Placed ahead of the classes below because it is about whether the
	// request was answered at all, not about what the answer was. Without it
	// "user database unavailable" matched no class and fell through to 500, so
	// an outage of the management store was reported to the caller as a fault
	// in the gateway, and a retry-after-a-moment condition was rendered as one
	// that will not improve.
	if containsAny(m, "database unavailable", "store unavailable", "key_store_unconfigured") {
		return &models.Error{
			Code:    503,
			Message: "Credential store unavailable",
			Result:  "Credential store unavailable",
		}
	}

	// 401 Auth or Token
	if containsAny(m,
		"invalid token", "token is expired", "token not fou",
		"invalid refresh token", "invalid token format", "authentication failed",
		"user not found",
	) {
		return &models.Error{Code: 401, Message: "Invalid authentication credentials", Result: msg}
	}

	// 409 Conflict
	if containsAny(m,
		"lbrule-exist error", "lbrule-exists error", "fwrule-exists", "sess-exists",
		"mirr-exists", "pol-exists", "prop-exists", "zone exists", "existing zone",
		"already created", " existing ", " exists",
		"vlan has ports configured", "port exists", "vlan tag port exists",
		"vlan untag port exists", "same fdb", "rt exists", "nh exists",
		"username already exists", "lb rule-referred", "cant modify",
		"ep-host add failed as cluster node", "vlan bridge already added",
	) {
		return &models.Error{
			Code:    409,
			Message: "Resource conflict: Resource already exists OR dependency not found",
			Result:  msg,
		}
	}

	// 400 Bad Request
	if containsAny(m,
		"invalid role",
		"malformed", "parse error", "invalid parameters", "invalid ",
		"mask format is wrong", "not ipv4 address", "proto error", "malformed-proto",
		"malformed service proto", "unknown work type", "unknown log level", "unknown ep-host-state",
		"host-args unknown probe", "unknown probe port", "vxlan can not be tagged",
		"range", "overflow", "fwmark", "rule-mark error", "rule-snat error",
		"rule-allowed-src error", "service-args error", "non-udp-n3-args error",
		"secondaryip-args", "serv-port-args range", "endpoints-range",
		"source address malformed", "address malformed", "remoteip address malformed",
		"ip address parse error", "myip address parse error",
		"malformed-service", "malformed-secip", "malformed-lbep", "malformed-rule",
		"invalid gws", "zone number err", "zone is not set", "vlan zone err",
		"invalid vlanid", "fdb attr error", "fdb v6 dst unsupported",
		"host-args error", "hostarm-args error",
		"password must ", "password must not ", "password must be at least",
		"Cors URL cannot be empty", "wildcard '*' is not allowed",
		"Failed to add Cors", "Failed to delete Cors", "filename is required", "file is empty",
		"no configuration file provided", "invalid json format",
		"is required",
		// Create-time rule-validation rejections. These are addressed to the
		// operator who wrote the rule — the reason ("pd-bootstrap-port
		// requires pd_disagg_mode=true and kv-engine-type sglang") IS the
		// API's answer, so it must ride in the body. Before the fall-through
		// below stopped disclosing internal text, these reached callers only
		// by falling through it; without their own class here, closing that
		// disclosure silently rewrote every validator's answer into a 500
		// with a correlation ref.
		" requires ", " must be ", "unsupported for", "supports kvexactmode",
	) {
		return &models.Error{Code: 400, Message: "Malformed arguments for API call", Result: msg}
	}

	// 403 Forbidden
	if containsAny(m,
		"capacity", " hwm", "ulhwm", "dlhwm", "nh-hwm", "rule-hwm",
		"need-realdev", "loxilb bgp mode is disabled", "running in bgp only mode",
	) {
		return &models.Error{Code: 403, Message: "Capacity insufficient", Result: msg}
	}

	// 503 Service Unavailable
	if containsAny(m,
		"not-ready", "timeout", "unexpected http response", "maintenance", "no-master",
		"netrpc call timeout", "database unavailable",
	) {
		return &models.Error{Code: 503, Message: "Maintenance mode", Result: msg}
	}

	// 500 Internal Server Error (default).
	//
	// The branches above name a condition the API models — "no such route",
	// "resource already exists" — and their Result carries loxilb's own
	// vocabulary for it, which is API detail a caller is meant to see. This
	// branch is the opposite: it is reached by errors nothing classified, so
	// the text is whatever some internal layer happened to say. It handed out
	// the database driver's wording for a failing query's scan arity, the
	// stored timestamp format together with the Go layout the code expected,
	// and it did so on /auth/login, which is unauthenticated.
	//
	// Both Message and Result are serialised into the response body, so
	// substituting only one of them would move the disclosure rather than
	// remove it. The detail goes to the log, and the caller gets a reference
	// that lets an operator find that log line — which is the part of
	// debuggability worth keeping.
	ref := errorRef()
	tk.LogIt(tk.LogError, "api: internal error ref=%s: %s\n", ref, msg)
	return &models.Error{
		Code:    500,
		Message: "Internal service error",
		Result:  "Internal service error (ref " + ref + ")",
	}
}

// errorRef returns a short correlation token tying a 500 response to the log
// line that holds what actually went wrong.
func errorRef() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}
