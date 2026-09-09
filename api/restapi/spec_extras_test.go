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

// spec_extras_test.go — pins on the hand-maintained specification.
//
// api/swagger-extras.yml describes routes served by raw handlers, so no code
// generation ever reconciles it against them, and `swagger diff` compares it
// only against the UI's vendored copy — never against the handler source. It
// is the least-defended surface in the repo, which is why these two facts are
// pinned here rather than left to review.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"gopkg.in/yaml.v3"
)

const extrasSpecPath = "../swagger-extras.yml"

// TestApiKeyCreateResponseKeyIDIsRequired asserts the generated model keeps
// key_id unconditional. The create handler always sets it
// (api/restapi/handler/ai_apikey.go), so a client must never have to null-check
// a field the server never omits — and go-swagger only drops omitempty when the
// specification marks the property required.
func TestApiKeyCreateResponseKeyIDIsRequired(t *testing.T) {
	raw := "id-under-test"
	body, err := json.Marshal(&models.APIKeyCreateResponse{KeyID: &raw})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got["key_id"]; !ok {
		t.Errorf("key_id absent from %s — it must serialize unconditionally; "+
			"mark it required in ApiKeyCreateResponse and regenerate", body)
	}

	// The required marking is what removes omitempty, so it must also be
	// enforced on the way in.
	if err := (&models.APIKeyCreateResponse{RawKey: &raw}).Validate(nil); err == nil {
		t.Error("a response with no key_id validated — key_id is not required")
	}
}

// TestExtrasApikeyPatchUnavailableIsSimpleError asserts the extras spec
// declares the 503 envelope the raw arm really writes. writeKeyStoreFailure
// (api/restapi/handler/ai_apikey.go) emits {"error": ...} — SimpleError — not
// the code/message/result/fields shape of RawError.
func TestExtrasApikeyPatchUnavailableIsSimpleError(t *testing.T) {
	raw, err := os.ReadFile(extrasSpecPath)
	if err != nil {
		t.Fatalf("read %s: %v", extrasSpecPath, err)
	}
	spec := map[string]any{}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", extrasSpecPath, err)
	}
	ref := digString(t, spec,
		"paths", "/config/ai/apikey/{key_id}", "patch", "responses", "503", "schema", "$ref")
	if want := "#/definitions/SimpleError"; ref != want {
		t.Errorf("PATCH /config/ai/apikey/{key_id} declares its 503 as %q, want %q — "+
			"the raw arm writes {\"error\": ...}", ref, want)
	}
}

// digString walks a decoded YAML tree and returns the string at the end of the
// key path, failing the test with the path that broke rather than panicking.
func digString(t *testing.T, tree map[string]any, keys ...string) string {
	t.Helper()
	var cur any = tree
	for i, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: not a mapping at %q", keys[:i], k)
		}
		cur, ok = m[k]
		if !ok {
			t.Fatalf("%v: key %q not found", keys[:i], k)
		}
	}
	s, ok := cur.(string)
	if !ok {
		t.Fatalf("%v: value is %T, not a string", keys, cur)
	}
	return s
}
