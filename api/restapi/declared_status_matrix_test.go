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
package restapi

// declared_status_matrix_test.go — spec-level pins on declared response
// codes, guarding the contract the handlers can actually keep. The shared
// success responder (ResultResponse, api/restapi/handler/common.go) never
// calls WriteHeader, so every handler returning it answers 200 with a
// {"result":...} body; an operation served by it that declares 204 instead
// of 200 promises a no-body response the runtime will never produce, and a
// generated client treats the real 200 as an undeclared status. Only
// handlers that return a generated *NoContent responder really emit 204.
// These tests pin the declared-204 set to exactly the operations whose
// handlers do, so the mismatch cannot reappear silently.
//
// A third category exists: an operation marked x-raw-middleware is never
// served by a generated responder at all — setupGlobalMiddleware intercepts
// the path first and the raw handler writes the status itself. The shared
// responder's 200 argument therefore does not apply to it, and declaring 200
// to satisfy this test would put a status in the specification that the
// server never sends. Those operations are listed separately below and are
// only accepted while the specification still marks them raw-served, so the
// exemption cannot be claimed for a generated operation by editing a map.

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// declared204Operations is the exact set of operations allowed to declare
// 204. The mutating entries return a generated *NoContent responder on
// success and really answer 204; the three GET entries are vestigial
// declarations (their handlers only ever emit 200) kept for client
// compatibility. Adding a 204 anywhere else must be a conscious decision
// made together with a responder that actually writes that status.
var declared204Operations = map[string]bool{
	// mutating operations whose handlers return a generated *NoContent responder
	"DELETE /config/ai/apikey/{key_id}":                      true,
	"DELETE /config/cert/{certId}":                           true,
	"DELETE /config/l7policy/id/{id}":                        true,
	"DELETE /config/trace/catalog/{catalog_id}/parser":       true,
	"POST /config/ai/tenant/ratelimit":                       true,
	"POST /config/ai/user/ratelimit":                         true,
	"DELETE /config/ai/user/ratelimit/{tenant_id}/{user_id}": true,
	"POST /config/ai/ratelimit/defaults":                     true,
	"DELETE /config/ai/ratelimit/defaults/{scope}":           true,
	"POST /config/ipsec/tunnels":                             true,
	"POST /config/ipsec/tunnels/{name}/action":               true,
	"POST /config/l7policy":                                  true,
	"PUT /config/ipsec/tunnels/{name}":                       true,
	"PUT /config/securityrate/reset":                         true,
	// reads with a vestigial 204 alongside the 200 they actually emit
	"GET /config/params":        true,
	"GET /config/bgp/neigh/all": true,
	"GET /config/bgp/policy/definedsets/{defineset_type}/{type_name}": true,
}

// declared204RawServed lists operations whose 204 is written by a raw
// handler rather than a generated responder. Each entry must still be marked
// x-raw-middleware in the specification; the test checks that, so this map
// cannot be used to exempt a generated operation.
//
// PATCH /config/ai/apikey/{key_id} is served by ConfigPatchAIApikey
// (api/restapi/handler/ai_apikey.go), which ends in an explicit
// w.WriteHeader(http.StatusNoContent).
var declared204RawServed = map[string]bool{
	"PATCH /config/ai/apikey/{key_id}": true,
}

// rawMiddlewareOperations returns the operations the specification marks as
// served by raw middleware. Walked separately from forEachOperation so the
// shared iterator keeps its signature.
func rawMiddlewareOperations(t *testing.T, raw json.RawMessage) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for path, ops := range specPaths(t, raw) {
		for _, verb := range []string{"get", "post", "put", "delete", "patch"} {
			op, ok := ops[verb]
			if !ok {
				continue
			}
			var meta struct {
				Raw bool `json:"x-raw-middleware"`
			}
			if err := json.Unmarshal(op, &meta); err != nil {
				continue
			}
			if meta.Raw {
				out[strings.ToUpper(verb)+" "+path] = true
			}
		}
	}
	return out
}

func specPaths(t *testing.T, raw json.RawMessage) map[string]map[string]json.RawMessage {
	t.Helper()
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("spec has no paths")
	}
	return spec.Paths
}

func opResponses(t *testing.T, op json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var body struct {
		Responses map[string]json.RawMessage `json:"responses"`
	}
	if err := json.Unmarshal(op, &body); err != nil {
		t.Fatalf("unmarshal operation: %v", err)
	}
	return body.Responses
}

func forEachOperation(t *testing.T, raw json.RawMessage, fn func(verb, path string, responses map[string]json.RawMessage)) {
	t.Helper()
	verbs := []string{"get", "post", "put", "delete", "patch"}
	paths := specPaths(t, raw)
	sortedPaths := make([]string, 0, len(paths))
	for p := range paths {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)
	for _, p := range sortedPaths {
		for _, v := range verbs {
			op, ok := paths[p][v]
			if !ok {
				continue
			}
			fn(strings.ToUpper(v), p, opResponses(t, op))
		}
	}
}

func specVariants() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"SwaggerJSON":     SwaggerJSON,
		"FlatSwaggerJSON": FlatSwaggerJSON,
	}
}

// TestDeclared204SetIsPinned pins the exact set of operations that declare
// 204: everything else served by the shared success responder must declare
// the 200 it really answers.
func TestDeclared204SetIsPinned(t *testing.T) {
	for name, raw := range specVariants() {
		t.Run(name, func(t *testing.T) {
			seen := map[string]bool{}
			forEachOperation(t, raw, func(verb, path string, responses map[string]json.RawMessage) {
				if _, has204 := responses["204"]; has204 {
					seen[verb+" "+path] = true
				}
			})
			rawServed := rawMiddlewareOperations(t, raw)
			for op := range seen {
				if declared204Operations[op] {
					continue
				}
				if declared204RawServed[op] {
					// The exemption is only real while the specification
					// still says the generated router does not serve it.
					if !rawServed[op] {
						t.Errorf("%s is pinned as raw-served but the spec no longer marks it x-raw-middleware — "+
							"it is now a generated operation, and its 204 must come from a NoContent responder", op)
					}
					continue
				}
				t.Errorf("unexpected 204 declaration on %s — the shared success responder answers 200 with a body; declare 200, or return a generated NoContent responder and extend the pin", op)
			}
			for op := range declared204Operations {
				if !seen[op] {
					t.Errorf("pinned 204 declaration missing from spec: %s", op)
				}
			}
			for op := range declared204RawServed {
				if !seen[op] {
					t.Errorf("pinned raw-served 204 declaration missing from spec: %s", op)
				}
			}
		})
	}
}

// TestMutatingOperationsDeclareSomeSuccess asserts every mutating operation
// declares at least one 2xx.
func TestMutatingOperationsDeclareSomeSuccess(t *testing.T) {
	for name, raw := range specVariants() {
		t.Run(name, func(t *testing.T) {
			forEachOperation(t, raw, func(verb, path string, responses map[string]json.RawMessage) {
				if verb == "GET" {
					return
				}
				for code := range responses {
					if strings.HasPrefix(code, "2") {
						return
					}
				}
				t.Errorf("%s %s declares no 2xx success at all", verb, path)
			})
		})
	}
}
