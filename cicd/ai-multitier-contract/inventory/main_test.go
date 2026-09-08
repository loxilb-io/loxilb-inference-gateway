package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestInventoryMatchesSwagger(t *testing.T) {
	raw, err := build("../../..")
	if err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	fields := map[string]field{}
	for _, f := range got.Fields {
		fields[f.ID] = f
	}
	prefix := "swagger.yml#/definitions/LoadbalanceEntry/"
	for _, name := range []string{"pd_session_ttl_sec", "pd_cache_threshold", "pd_balance_abs_threshold", "kvWarmupSec", "kvDpRankCount", "chwbl_enable_cache_salt"} {
		if _, ok := fields[prefix+"serviceArguments/"+name]; !ok {
			t.Errorf("missing argument %s", name)
		}
	}
	if !fields[prefix+"endpoints/items/endpointIP"].Required {
		t.Fatal("endpoint required flag was lost")
	}
	f := fields[prefix+"serviceArguments/pd_session_ttl_sec"]
	if value, exists := f.Contract["default"]; !exists || value != float64(0) {
		t.Fatalf("explicit default zero lost: %#v", f)
	}
	description, _ := f.Contract["description"].(string)
	for _, required := range []string{"Omitted or 0", "300 seconds", "elapsed idle time exceeds", "independently of", "Zero does not disable expiry"} {
		if !strings.Contains(description, required) {
			t.Errorf("TTL contract missing %q", required)
		}
	}
	if len(got.Sources) != 2 {
		t.Fatal("both Swagger source identities are required")
	}

	for name, want := range map[string]float64{
		"host": 255, "path_prefix": 255, "session_header_name": 127, "model_name": 127,
	} {
		f := fields[prefix+"serviceArguments/"+name]
		if value, exists := f.Contract["x-loxilb-max-utf8-bytes"]; !exists || value != want {
			t.Errorf("%s encoded-byte limit lost: %#v", name, f)
		}
	}
}

func TestEndpointHashKeyRelationshipMetadata(t *testing.T) {
	raw, err := os.ReadFile("../../../api/swagger.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	relations := object(doc["x-loxilb-contract-relations"])
	rules, ok := relations["rules"].([]any)
	if !ok {
		t.Fatal("relationship rules are missing")
	}
	for _, value := range rules {
		rule := object(value)
		if rule["id"] != "LB-ENDPOINT-HASH-KEY-BYTES" {
			continue
		}
		if rule["kind"] != "conditional-join-byte-bound" || rule["unit"] != "utf8-bytes" || rule["maximum"] != 511 {
			t.Fatalf("endpoint hash-key relationship changed: %#v", rule)
		}
		if rule["enforcement"] != "server-static" {
			t.Fatalf("endpoint hash-key enforcement status changed: %#v", rule)
		}
		return
	}
	t.Fatal("LB-ENDPOINT-HASH-KEY-BYTES relationship is missing")
}

func TestInventoryFailsClosedOnUnsupportedSchema(t *testing.T) {
	for name, schema := range map[string]map[string]any{
		"missing":               nil,
		"external reference":    {"$ref": "external.yml#/x"},
		"unresolved reference":  {"$ref": "#/definitions/missing"},
		"unhandled composition": {"allOf": []any{}},
	} {
		t.Run(name, func(t *testing.T) {
			var out []field
			if err := walk(map[string]any{}, schema, "test", false, map[string]bool{}, &out); err == nil {
				t.Fatal("unsupported input must not silently drop arguments")
			}
		})
	}
}

func TestInventoryReferenceCycle(t *testing.T) {
	schema := map[string]any{"$ref": "#/definitions/self"}
	doc := map[string]any{"definitions": map[string]any{"self": schema}}
	var out []field
	if err := walk(doc, schema, "test", false, map[string]bool{}, &out); err == nil {
		t.Fatal("cycle must fail")
	}
}
