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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
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

// TestExtrasApikeyPatchDocumentsEveryPatchableField reconciles the PATCH body
// schema against the handler's own body struct, which nothing else does.
//
// This is the gate that was missing. The handler gained three patchable
// rate-limit fields and the specification never mentioned them, so a client
// reading the contract could not discover that a key's limits are changeable
// at all — and separately, a body naming no patchable field changed from 204
// to 400 while the specification went on declaring that such bodies "are
// currently accepted". Both drifts were invisible: code generation does not
// reach this file, and `swagger diff` compares it only against the UI's
// vendored copy, which drifts with it.
//
// Comparing the json tags to the declared properties makes the next such
// change fail here instead of shipping a contract that describes a different
// server.
func TestExtrasApikeyPatchDocumentsEveryPatchableField(t *testing.T) {
	const handlerPath = "handler/ai_apikey.go"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, handlerPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", handlerPath, err)
	}

	// The body struct is declared inside ConfigPatchAIApikey and is the only
	// struct type in it; taking the first is therefore unambiguous, and the
	// count assertion below catches it if that ever stops being true.
	var fields []string
	var structs int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ConfigPatchAIApikey" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			structs++
			if structs > 1 {
				return false
			}
			for _, f := range st.Fields.List {
				if f.Tag == nil {
					continue
				}
				tag := reflect.StructTag(strings.Trim(f.Tag.Value, "`"))
				name, _, _ := strings.Cut(tag.Get("json"), ",")
				if name != "" && name != "-" {
					fields = append(fields, name)
				}
			}
			return false
		})
	}
	if structs != 1 {
		t.Fatalf("expected exactly one struct type in ConfigPatchAIApikey, found %d — "+
			"this test reads the first one and can no longer tell which is the body", structs)
	}
	if len(fields) == 0 {
		t.Fatalf("no json-tagged fields found in ConfigPatchAIApikey's body struct")
	}

	raw, err := os.ReadFile(extrasSpecPath)
	if err != nil {
		t.Fatalf("read %s: %v", extrasSpecPath, err)
	}
	spec := map[string]any{}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse %s: %v", extrasSpecPath, err)
	}
	declared := patchBodyProperties(t, spec)

	for _, f := range fields {
		if _, ok := declared[f]; !ok {
			t.Errorf("the handler accepts %q but PATCH /config/ai/apikey/{key_id} does not declare it — "+
				"add it to the body schema in api/swagger-extras.yml", f)
		}
	}
	for d := range declared {
		if !slices.Contains(fields, d) {
			t.Errorf("the specification declares %q but the handler does not read it — "+
				"a client would send a field that is silently ignored", d)
		}
	}

	// The nonempty-patch rule is the other half of the same contract: the
	// handler refuses a body naming none of the fields above, and the 400 has
	// to say so. Matched on the concept, not on wording, so the text can be
	// improved without breaking the gate.
	handlerSrc, err := os.ReadFile(handlerPath)
	if err != nil {
		t.Fatalf("read %s: %v", handlerPath, err)
	}
	guarded := strings.Contains(string(handlerSrc), "no patchable field supplied")
	desc := digString(t, spec,
		"paths", "/config/ai/apikey/{key_id}", "patch", "responses", "400", "description")
	documented := strings.Contains(desc, "patchable")
	if guarded != documented {
		t.Errorf("the nonempty-patch rule is in the handler=%v but documented in the 400 response=%v — "+
			"these must move together; a body naming no patchable field answered 204 in earlier "+
			"builds and the status change is client-visible", guarded, documented)
	}
}

// patchBodyProperties returns the declared property names of the PATCH body
// schema, failing with the path that broke rather than panicking.
func patchBodyProperties(t *testing.T, spec map[string]any) map[string]any {
	t.Helper()
	path, ok := spec["paths"].(map[string]any)["/config/ai/apikey/{key_id}"].(map[string]any)
	if !ok {
		t.Fatal("PATCH /config/ai/apikey/{key_id} is absent from the extras specification")
	}
	params, ok := path["patch"].(map[string]any)["parameters"].([]any)
	if !ok {
		t.Fatal("the patch operation declares no parameters")
	}
	for _, p := range params {
		pm, ok := p.(map[string]any)
		if !ok || pm["in"] != "body" {
			continue
		}
		schema, ok := pm["schema"].(map[string]any)
		if !ok {
			t.Fatal("the body parameter declares no schema")
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatal("the body schema declares no properties")
		}
		return props
	}
	t.Fatal("the patch operation declares no body parameter")
	return nil
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
