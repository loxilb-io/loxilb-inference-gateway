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

// policy_floor_status_test.go — a policer-create refusal that names its
// reason (the MinPolRate floor) must reach the caller as a 400 carrying that
// reason. Before the handler stopped flattening the error to a string, the
// typed refusal fell through the message classifier and answered as a 500
// whose body was a correlation reference.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

type stubPolicyHook struct {
	cmn.NetHookInterface
	err error
}

func (s *stubPolicyHook) NetPolicerAdd(pm *cmn.PolMod) (int, error) {
	return 0, s.err
}

func renderPolicyPost(t *testing.T, err error) (int, models.Error) {
	t.Helper()
	prev := ApiHooks
	ApiHooks = &stubPolicyHook{err: err}
	defer func() { ApiHooks = prev }()

	req, _ := http.NewRequest("POST", "/config/policy", nil)
	ident := "pol-low"
	rate := int64(7)
	resp := ConfigPostPolicy(operations.PostConfigPolicyParams{
		HTTPRequest: req,
		Attr: &models.PolicyEntry{
			PolicyIdent: &ident,
			PolicyInfo:  &models.PolicyEntryPolicyInfo{CommittedInfoRate: rate, PeakInfoRate: rate},
		},
	}, nil)

	rec := httptest.NewRecorder()
	resp.(middleware.Responder).WriteResponse(rec, runtime.JSONProducer())
	var body models.Error
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not a models.Error: %v (%q)", err, rec.Body.String())
	}
	return rec.Code, body
}

// The typed floor refusal PolAdd now returns must answer 400 with the floor
// in the body and the refused field named.
func TestPolicyPostFloorRefusalAnswers400WithReason(t *testing.T) {
	refusal := cmn.NewValidationError("committedInfoRate",
		"cir 7 Mbps is below the minimum policer rate 8 Mbps")
	code, body := renderPolicyPost(t, refusal)
	if code != 400 {
		t.Fatalf("floor refusal answered %d, want 400", code)
	}
	if !strings.Contains(body.Result, "minimum policer rate 8") {
		t.Fatalf("body result %q does not name the 8 Mbps floor", body.Result)
	}
	if len(body.Fields) != 1 || body.Fields[0] != "committedInfoRate" {
		t.Fatalf("body fields %v do not name committedInfoRate", body.Fields)
	}
}

// The pre-fix wire answer, pinned: an untyped internal error whose text
// matches no message class must still answer 500 without disclosing the
// text — proving it is the typed refusal, not a new message pattern, that
// moved the floor rejection to 400.
func TestPolicyPostUntypedInternalErrorStillAnswers500(t *testing.T) {
	code, body := renderPolicyPost(t, errors.New("pol-info error"))
	if code != 500 {
		t.Fatalf("untyped internal error answered %d, want 500", code)
	}
	if strings.Contains(body.Result, "pol-info") {
		t.Fatalf("500 body %q discloses internal error text", body.Result)
	}
}
