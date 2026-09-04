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

// ai_model_profile_test.go — unit tests for the model-profile discovery
// operations' response surface: the documented empty state (200/gen 0/[]),
// serialization shape (ordering preserved, required fields present, optional
// arrays absent-not-null), the typed 404, the declared-status error matrix,
// and the authorization legs (viewer 200 / non-management 401 / role-denied
// 403 / store-down 503).
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
	"strings"
	"testing"

	openapierrors "github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	aiops "github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/authz"
)

// stubAiModelProfileHook is the standard one-method-family stub for the wide
// hook interface: it overrides ONLY the discovery reads by embedding the
// (nil) interface — calling any other method would panic, but the discovery
// handlers touch only these two hooks.
type stubAiModelProfileHook struct {
	cmn.NetHookInterface
	reg     cmn.AiModelProfileRegistryMod
	mod     cmn.AiModelProfileMod
	listErr error
	getErr  error
}

func (s *stubAiModelProfileHook) NetAiModelProfileList() (cmn.AiModelProfileRegistryMod, error) {
	return s.reg, s.listErr
}

func (s *stubAiModelProfileHook) NetAiModelProfileGet(profileID string) (cmn.AiModelProfileMod, error) {
	return s.mod, s.getErr
}

func aiModelProfileTestEntry(id string, gen uint64) cmn.AiModelProfileMod {
	return cmn.AiModelProfileMod{
		ProfileID:       id,
		Gen:             gen,
		BaseModel:       "acme/" + id,
		AliasPolicy:     "base_model_only",
		SupportedApis:   []string{"completions"},
		TokenizerSha256: "digest-" + id,
	}
}

// renderAiModelProfileList runs the list handler and returns the wire status
// and body bytes.
func renderAiModelProfileList(t *testing.T) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "/config/ai/model-profiles", nil)
	resp := ConfigGetAIModelProfiles(aiops.GetConfigAiModelProfilesParams{HTTPRequest: req}, nil)
	return renderResponder(t, resp)
}

// renderAiModelProfileDetail runs the detail handler for id and returns the
// wire status and body bytes.
func renderAiModelProfileDetail(t *testing.T, id string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "/config/ai/model-profiles/"+id, nil)
	resp := ConfigGetAIModelProfileByID(aiops.GetConfigAiModelProfilesProfileIDParams{HTTPRequest: req, ProfileID: id}, nil)
	return renderResponder(t, resp)
}

func renderResponder(t *testing.T, resp middleware.Responder) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	return rec.Code, rec.Body.String()
}

// TestAiModelProfilesEmptyRegistryIs200: the no-registry-published state is
// the documented legacy-mode 200 — generation 0 and "profiles":[] on the
// wire, never a 404 and never null.
func TestAiModelProfilesEmptyRegistryIs200(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	ApiHooks = &stubAiModelProfileHook{reg: cmn.AiModelProfileRegistryMod{Profiles: []cmn.AiModelProfileMod{}}}

	code, body := renderAiModelProfileList(t)
	if code != http.StatusOK {
		t.Fatalf("empty registry answered %d, want 200", code)
	}
	if !strings.Contains(body, `"registryGeneration":0`) {
		t.Fatalf("empty registry body lacks generation 0: %s", body)
	}
	if !strings.Contains(body, `"profiles":[]`) {
		t.Fatalf("empty registry did not serialize profiles as []: %s", body)
	}
	if strings.Contains(body, `"setDigest"`) {
		t.Fatalf("generation 0 must not carry a set digest: %s", body)
	}
}

// TestAiModelProfilesListSerialization: hook ordering is preserved on the
// wire, every required field is present on every entry, and nil optional
// arrays are ABSENT — never null.
func TestAiModelProfilesListSerialization(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	reg := cmn.AiModelProfileRegistryMod{
		RegistryGeneration: 4,
		SetDigest:          "sd-4",
		Profiles: []cmn.AiModelProfileMod{
			aiModelProfileTestEntry("p-alpha", 4),
			aiModelProfileTestEntry("p-mike", 4),
			aiModelProfileTestEntry("p-zulu", 4),
		},
	}
	reg.Profiles[0].AliasPolicy = "list"
	reg.Profiles[0].AllowedAliases = []string{"alias-1"}
	reg.Profiles[0].TemplateSha256 = "tpl-digest"
	ApiHooks = &stubAiModelProfileHook{reg: reg}

	code, body := renderAiModelProfileList(t)
	if code != http.StatusOK {
		t.Fatalf("list answered %d, want 200", code)
	}
	ia, im, iz := strings.Index(body, "p-alpha"), strings.Index(body, "p-mike"), strings.Index(body, "p-zulu")
	if ia < 0 || im < 0 || iz < 0 || !(ia < im && im < iz) {
		t.Fatalf("profileId ordering not preserved on the wire (%d/%d/%d): %s", ia, im, iz, body)
	}
	for _, want := range []string{`"registryGeneration":4`, `"setDigest":"sd-4"`, `"tokenizerSha256":"digest-p-zulu"`, `"allowedAliases":["alias-1"]`, `"templateSha256":"tpl-digest"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("list body lacks %s: %s", want, body)
		}
	}
	// p-mike/p-zulu declare no aliases and no features: those keys must be
	// absent from their entries, not serialized as null.
	if strings.Contains(body, "null") {
		t.Fatalf("optional empty field serialized as null: %s", body)
	}
	if got := strings.Count(body, `"allowedAliases"`); got != 1 {
		t.Fatalf("allowedAliases appears %d times, want 1 (absent when empty): %s", got, body)
	}
}

// TestAiModelProfileDetailSurface: 200 with the entry schema for a known id,
// the typed not-found as 404, anything else as 500.
func TestAiModelProfileDetailSurface(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	ApiHooks = &stubAiModelProfileHook{mod: aiModelProfileTestEntry("p-solo", 2)}
	code, body := renderAiModelProfileDetail(t, "p-solo")
	if code != http.StatusOK || !strings.Contains(body, `"profileId":"p-solo"`) {
		t.Fatalf("detail answered %d / %s, want 200 with the entry", code, body)
	}

	ApiHooks = &stubAiModelProfileHook{getErr: fmt.Errorf("lookup: %w", cmn.ErrAiModelProfileNotFound)}
	if code, _ := renderAiModelProfileDetail(t, "p-ghost"); code != http.StatusNotFound {
		t.Fatalf("typed not-found answered %d, want 404", code)
	}

	ApiHooks = &stubAiModelProfileHook{getErr: errors.New("registry snapshot walk failed")}
	if code, _ := renderAiModelProfileDetail(t, "p-any"); code != http.StatusInternalServerError {
		t.Fatalf("hook fault answered %d, want 500", code)
	}
}

// aiModelProfilesDeclared/aiModelProfileDetailDeclared are the operations'
// declared response surfaces — keep in lockstep with the model-profiles
// responses sections of api/swagger.yml.
var (
	aiModelProfilesDeclared      = map[int]bool{200: true, 401: true, 403: true, 500: true, 503: true}
	aiModelProfileDetailDeclared = map[int]bool{200: true, 401: true, 403: true, 404: true, 500: true, 503: true}
)

// TestAiModelProfilesEmitOnlyDeclaredStatuses: every hook error must map
// onto a status the operation declares through the handler's explicit
// mapping — never the shared message-text classifier, whose conflict class
// (substring " exists") once leaked an undeclared 409 from a read-only GET.
func TestAiModelProfilesEmitOnlyDeclaredStatuses(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, hookErr := range []error{
		errors.New("registry generation exists in a degraded state"), // classifier conflict-class wording
		errors.New("plain discovery fault"),
	} {
		ApiHooks = &stubAiModelProfileHook{listErr: hookErr, getErr: hookErr}
		code, _ := renderAiModelProfileList(t)
		if !aiModelProfilesDeclared[code] {
			t.Fatalf("undeclared status %d escaped the list error path for %q", code, hookErr)
		}
		if code != http.StatusInternalServerError {
			t.Fatalf("list error %q answered %d, want 500", hookErr, code)
		}
		code, _ = renderAiModelProfileDetail(t, "p-x")
		if !aiModelProfileDetailDeclared[code] {
			t.Fatalf("undeclared status %d escaped the detail error path for %q", code, hookErr)
		}
		if code != http.StatusInternalServerError {
			t.Fatalf("detail error %q answered %d, want 500", hookErr, code)
		}
	}
}

const aiModelProfilesPath = "/netlox/v1/config/ai/model-profiles"

// TestAiModelProfilesAuthLegs: the discovery operations ride the same
// authorization decision as every management GET — viewer authorized,
// non-management principal 401, role outside the closed set 403.
func TestAiModelProfilesAuthLegs(t *testing.T) {
	for _, path := range []string{aiModelProfilesPath, aiModelProfilesPath + "/p-one"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)

		if err := authorizePrincipal(req, "alice|viewer|refresh-token"); err != nil {
			t.Fatalf("viewer refused a discovery GET on %s: %v", path, err)
		}

		err := authorizePrincipal(req, nil)
		var coded openapierrors.Error
		if err == nil || !errors.As(err, &coded) || coded.Code() != http.StatusUnauthorized {
			t.Fatalf("non-management principal on %s: got %v, want a 401", path, err)
		}

		err = authorizePrincipal(req, "bob|reviewer|refresh-token")
		if err == nil || !errors.Is(err, authz.ErrPermissionDenied) {
			t.Fatalf("role-denied principal on %s: got %v, want permission denial", path, err)
		}
		if got := authStatus(err); got != http.StatusForbidden {
			t.Fatalf("permission denial on %s served as %d, want 403", path, got)
		}
	}
}

// TestAiModelProfilesAuthStoreDownIs503: an unreachable credential store
// surfaces as 503 (the credential was never examined) on every authenticated
// operation, the discovery reads included.
func TestAiModelProfilesAuthStoreDownIs503(t *testing.T) {
	err := authFailure(fmt.Errorf("token lookup: %w", cmn.ErrDBUnavailable))
	var coded openapierrors.Error
	if !errors.As(err, &coded) {
		t.Fatalf("store-down auth failure carries no status: %v", err)
	}
	if coded.Code() != http.StatusServiceUnavailable {
		t.Fatalf("store-down auth failure served as %d, want 503", coded.Code())
	}
}
