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

// loadbalancer_kvexactstatus_test.go — unit tests for the kvexactstatus read
// endpoint's error surface. The operation declares exactly 200/401/404/500 in
// api/swagger.yml; its handler error path must never let the shared
// message-text classifier (common.go ResultErrorResponseErrorMessage) map a
// read-path lookup failure onto a status code the operation does not declare
// (e.g. the conflict class keyed on substrings like " exists").
//
// These tests run on the remote gate: the handler package compiles only
// against the go-swagger-regenerated operations/models types; darwin cannot
// compile this package (Linux cgo / regen-dependent), the same deferral as
// every handler test in this package.

package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	openapierrors "github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/authz"
)

// stubKvExactStatusHook is the standard one-method stub for the wide hook
// interface: it overrides ONLY NetKvExactStatusGet by embedding the (nil)
// interface — calling any other method would panic, but the kvexactstatus
// handler touches only NetKvExactStatusGet.
type stubKvExactStatusHook struct {
	cmn.NetHookInterface
	mods []cmn.KvExactStatusMod
	err  error
}

func (s *stubKvExactStatusHook) NetKvExactStatusGet(vip string, port uint16, proto string, modelName string) ([]cmn.KvExactStatusMod, error) {
	return s.mods, s.err
}

// newKvExactStatusParams builds params with a non-nil HTTPRequest (the handler
// logs params.HTTPRequest.Method/URL) for the given composite key.
func newKvExactStatusParams(ip string, port float64, proto string) operations.GetConfigLoadbalancerKvExactStatusParams {
	req, _ := http.NewRequest("GET",
		"/config/loadbalancer/externalipaddress/"+ip+"/port/8080/protocol/"+proto+"/kvexactstatus", nil)
	return operations.GetConfigLoadbalancerKvExactStatusParams{
		HTTPRequest: req,
		IPAddress:   ip,
		Port:        port,
		Proto:       proto,
	}
}

// kvExactStatusRespCode renders a responder and returns the HTTP status it
// actually writes on the wire.
func kvExactStatusRespCode(t *testing.T, ip string, port float64, proto string) int {
	t.Helper()
	resp := ConfigGetLoadbalancerKvExactStatus(newKvExactStatusParams(ip, port, proto), nil)
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	return rec.Code
}

// kvExactStatusDeclared is the operation's declared response surface — keep
// in lockstep with the kvexactstatus responses section of api/swagger.yml.
var kvExactStatusDeclared = map[int]bool{
	200: true, 401: true, 403: true, 404: true, 422: true, 500: true, 503: true,
}

// TestKvExactStatusEmitsOnlyDeclaredStatuses: the error-path status matrix.
// Every hook error must map onto a status the operation declares, through the
// handler's explicit mapping — never the shared message-text classifier,
// whose conflict class (substring " exists") once leaked an undeclared 409
// from this read-only GET.
func TestKvExactStatusEmitsOnlyDeclaredStatuses(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	cases := []struct {
		name string
		err  error
		want int
	}{
		// Collides with the classifier's conflict class via " exists" —
		// a server-side read fault, so 500, never 409.
		{"conflict-worded lookup failure", errors.New("kv-exact shard exists in a degraded generation"), http.StatusInternalServerError},
		// Neutral wording, same answer.
		{"plain lookup failure", errors.New("kv-exact status snapshot walk failed"), http.StatusInternalServerError},
		// A key that can never hold a rule is the coalesced 404, not a fault.
		{"unservable key", fmt.Errorf("%w: unsupported protocol %q", cmn.ErrKvExactKeyUnservable, "gre"), http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ApiHooks = &stubKvExactStatusHook{err: c.err}
			code := kvExactStatusRespCode(t, "10.10.10.1", 8080, "tcp")
			if !kvExactStatusDeclared[code] {
				t.Fatalf("undeclared status %d escaped the kvexactstatus error path for error %q", code, c.err)
			}
			if code != c.want {
				t.Fatalf("error %q answered %d, want %d", c.err, code, c.want)
			}
		})
	}
}

// TestKvExactStatusEmptyIs404: zero entries from the hook must coalesce to the
// declared 404, never an empty 200 body (the no-empty-200 guarantee).
func TestKvExactStatusEmptyIs404(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	ApiHooks = &stubKvExactStatusHook{mods: nil}
	if code := kvExactStatusRespCode(t, "10.10.10.1", 8080, "tcp"); code != http.StatusNotFound {
		t.Fatalf("empty status set answered %d, want 404", code)
	}
}

const kvExactStatusPath = "/netlox/v1/config/loadbalancer/externalipaddress/20.20.20.1/port/8080/protocol/tcp/kvexactstatus"

// TestKvExactStatusAuthForbiddenReachable: a management principal whose role
// is neither admin nor viewer is refused by the authorizer with a permission
// error, and the auth chain serves permission errors as 403 (authStatus; the
// generated chain renders the same plain error as 403). The status is
// therefore reachable on this operation regardless of what its swagger
// response section declares.
func TestKvExactStatusAuthForbiddenReachable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, kvExactStatusPath, nil)
	err := authorizePrincipal(req, "bob|reviewer|refresh-token")
	if err == nil {
		t.Fatal("role-denied principal was authorized for kvexactstatus")
	}
	if !errors.Is(err, authz.ErrPermissionDenied) {
		t.Fatalf("expected a permission denial, got %v", err)
	}
	if got := authStatus(err); got != http.StatusForbidden {
		t.Fatalf("permission denial served as %d, want 403", got)
	}
}

// TestKvExactStatusAuthStoreDownIs503: an unreachable credential store must
// surface as 503 (the credential was never examined), not as a credential
// rejection — and 503 is therefore reachable on every authenticated
// operation, kvexactstatus included.
func TestKvExactStatusAuthStoreDownIs503(t *testing.T) {
	err := authFailure(fmt.Errorf("token lookup: %w", cmn.ErrDBUnavailable))
	var coded openapierrors.Error
	if !errors.As(err, &coded) {
		t.Fatalf("store-down auth failure carries no status: %v", err)
	}
	if coded.Code() != http.StatusServiceUnavailable {
		t.Fatalf("store-down auth failure served as %d, want 503", coded.Code())
	}
}
