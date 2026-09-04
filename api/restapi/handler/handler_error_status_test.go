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

// handler_error_status_test.go — error paths must answer with the classified
// error status, never with a 200 whose result field carries the error text.
// A 200-with-error-text response reads as success to any client that keys on
// the status code, which is every generated client.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

type stubIPsecHook struct {
	cmn.NetHookInterface
	err error
}

func (s *stubIPsecHook) NetIPsecTunnelAdd(tm *cmn.IPsecTunnelMod) (int, error) {
	return 0, s.err
}

func (s *stubIPsecHook) NetIPsecTunnelDel(name string) (int, error) {
	return 0, s.err
}

func (s *stubIPsecHook) NetIPsecTunnelAction(name, action string) (int, error) {
	return 0, s.err
}

// renderStatus writes a responder the way the generated server does and
// returns the wire status.
func renderStatus(t *testing.T, resp middleware.Responder) int {
	t.Helper()
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	return rec.Code
}

func strPtr(s string) *string { return &s }

// TestIPsecErrorPathsAnswerClassifiedStatus drives each single-hook ipsec
// handler through a failing hook and asserts the wire status is the
// classified error code for that failure, not 200.
func TestIPsecErrorPathsAnswerClassifiedStatus(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	req, _ := http.NewRequest("POST", "/config/ipsec/tunnels", nil)

	cases := []struct {
		name string
		err  error
		call func() middleware.Responder
		want int
	}{
		{
			name: "create of an existing tunnel is a conflict",
			err:  errors.New("tunnel t1 already exists"),
			call: func() middleware.Responder {
				return ConfigPostIPsecTunnels(operations.PostConfigIpsecTunnelsParams{
					HTTPRequest: req,
					Attr:        &models.IPsecTunnelMod{Name: strPtr("t1")},
				}, nil)
			},
			want: http.StatusConflict,
		},
		{
			name: "delete of an unknown tunnel is not found",
			err:  errors.New("tunnel t1 not found"),
			call: func() middleware.Responder {
				return ConfigDeleteIPsecTunnelsName(operations.DeleteConfigIpsecTunnelsNameParams{
					HTTPRequest: req,
					Name:        "t1",
				}, nil)
			},
			want: http.StatusNotFound,
		},
		{
			name: "unknown action verb is a bad request",
			err:  errors.New("action must be 'initiate', 'terminate', or 'restart', got 'bounce'"),
			call: func() middleware.Responder {
				return ConfigPostIPsecTunnelsNameAction(operations.PostConfigIpsecTunnelsNameActionParams{
					HTTPRequest: req,
					Name:        "t1",
					Attr:        &models.IPsecTunnelActionMod{Action: strPtr("bounce")},
				}, nil)
			},
			want: http.StatusBadRequest,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ApiHooks = &stubIPsecHook{err: c.err}
			got := renderStatus(t, c.call())
			if got != c.want {
				t.Fatalf("wire status = %d, want %d", got, c.want)
			}
		})
	}
}

// TestIPsecTunnelDeleteSuccessStaysOK pins the success path: the fix must
// change only what errors answer.
func TestIPsecTunnelDeleteSuccessStaysOK(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	ApiHooks = &stubIPsecHook{err: nil}

	req, _ := http.NewRequest("DELETE", "/config/ipsec/tunnels/t1", nil)
	got := renderStatus(t, ConfigDeleteIPsecTunnelsName(operations.DeleteConfigIpsecTunnelsNameParams{
		HTTPRequest: req,
		Name:        "t1",
	}, nil))
	if got != http.StatusOK {
		t.Fatalf("success wire status = %d, want %d", got, http.StatusOK)
	}
}

// TestNoErrorTextRidesTheSuccessResponder pins the source pattern itself:
// no handler may wrap err.Error() in the shared success responder, where it
// would ship as a 200.
func TestNoErrorTextRidesTheSuccessResponder(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "ResultResponse{Result: err.Error()}") {
			t.Errorf("%s wraps err.Error() in the success responder — errors must go through ErrorResponse with a classified status", e.Name())
		}
	}
}
