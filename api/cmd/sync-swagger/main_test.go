package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-openapi/loads"
)

const generatedFixture = "package restapi\nimport \"encoding/json\"\nvar SwaggerJSON, FlatSwaggerJSON json.RawMessage\nfunc init() {\nSwaggerJSON = json.RawMessage([]byte(`{}`))\nFlatSwaggerJSON = json.RawMessage([]byte(`{\"sentinel\":true}`))\n}\n"
const specFixture = "swagger: '2.0'\ninfo:\n  title: Test\n  version: '1'\npaths:\n  /x:\n    get:\n      responses:\n        200:\n          description: ok\ndefinitions:\n  X:\n    type: number\n    minimum: 0\n    maximum: 0\n    default: 0\nx-policy:\n  enabled: false\n  empty: ''\n  missing: null\n  values: [0, false]\n"

func TestPreservesZeroFalseNullAndNumericStatus(t *testing.T) {
	raw, err := sourceJSON([]byte(specFixture))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	x := got["definitions"].(map[string]any)["X"].(map[string]any)
	for _, key := range []string{"minimum", "maximum", "default"} {
		if value, ok := x[key]; !ok || value != float64(0) {
			t.Fatalf("%s lost: %#v", key, x)
		}
	}
	policy := got["x-policy"].(map[string]any)
	if policy["enabled"] != false || policy["empty"] != "" {
		t.Fatal(policy)
	}
	if value, exists := policy["missing"]; !exists || value != nil {
		t.Fatal(policy)
	}
	if !bytes.Contains(raw, []byte(`"200"`)) {
		t.Fatal("numeric response key lost")
	}
}

func TestSynchronizePreservesFlatAndIsIdempotent(t *testing.T) {
	out, err := synchronize([]byte(specFixture), []byte(generatedFixture))
	if err != nil {
		t.Fatal(err)
	}
	const boundary = "\nFlatSwaggerJSON ="
	if strings.SplitN(string(out), boundary, 2)[1] != strings.SplitN(generatedFixture, boundary, 2)[1] {
		t.Fatal("flattened document changed")
	}
	again, err := synchronize([]byte(specFixture), out)
	if err != nil || !bytes.Equal(out, again) {
		t.Fatalf("not idempotent: %v", err)
	}
}

func TestDescriptionBackticksUnicodeAndQuotes(t *testing.T) {
	spec := []byte("swagger: '2.0'\ninfo:\n  description: 'Use `zero`, Unicode λ, and \"quotes\".'\n")
	out, err := synchronize(spec, []byte(generatedFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("` + \"`\" + `zero")) || !bytes.Contains(out, []byte("λ")) {
		t.Fatal("description encoding lost")
	}
}

func TestMalformedInputsFailClosed(t *testing.T) {
	for name, input := range map[string]string{
		"duplicate":     "swagger: '2.0'\nx: 1\nx: 2\n",
		"collision":     "swagger: '2.0'\nx:\n  200: a\n  '200': b\n",
		"multiple-docs": "swagger: '2.0'\n---\nswagger: '2.0'\n",
		"null":          "null\n", "wrong-version": "swagger: '3.0'\n", "syntax": "[",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sourceJSON([]byte(input)); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	for name, input := range map[string]string{
		"missing": "package restapi\n", "syntax": "package",
		"duplicate":      strings.Replace(generatedFixture, "\nFlatSwaggerJSON =", "\nSwaggerJSON = nil\nFlatSwaggerJSON =", 1),
		"missing-flat":   strings.Replace(generatedFixture, "FlatSwaggerJSON =", "OtherJSON =", 1),
		"duplicate-flat": strings.Replace(generatedFixture, "\nFlatSwaggerJSON =", "\nFlatSwaggerJSON = nil\nFlatSwaggerJSON =", 1),
	} {
		t.Run(name+"-go", func(t *testing.T) {
			if _, err := synchronize([]byte(specFixture), []byte(input)); err == nil {
				t.Fatal("accepted malformed generated file")
			}
		})
	}
}

func TestAtomicWritePreservesModeAndRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	spec, target, link := filepath.Join(dir, "spec.yml"), filepath.Join(dir, "embedded.go"), filepath.Join(dir, "link.go")
	if err := os.WriteFile(spec, []byte(specFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(generatedFixture), 0640); err != nil {
		t.Fatal(err)
	}
	// Do not let the caller's umask change this permission-preservation fixture.
	if err := os.Chmod(target, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := run(spec, link, false); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := run(spec, dir, false); err == nil {
		t.Fatal("accepted directory")
	}
	before, _ := os.ReadFile(target)
	if string(before) != generatedFixture {
		t.Fatal("rejected write changed target")
	}
	if err := run(spec, target, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("mode changed: %v", err)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".embedded-spec-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files leaked: %v %v", leftovers, err)
	}
}

func TestCheckDetectsDriftWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	spec, target := filepath.Join(dir, "swagger.yml"), filepath.Join(dir, "embedded.go")
	if err := os.WriteFile(spec, []byte(specFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(generatedFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(spec, target, true); err == nil {
		t.Fatal("drift must fail")
	}
	before, _ := os.ReadFile(target)
	if string(before) != generatedFixture {
		t.Fatal("check mutated target")
	}
	if err := run(spec, target, false); err != nil {
		t.Fatal(err)
	}
	if err := run(spec, target, true); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryEmbeddedContract(t *testing.T) {
	if err := run("../../swagger.yml", "../../restapi/embedded_spec.go", true); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeLoaderRetainsZeroMinimum(t *testing.T) {
	raw, err := sourceJSON([]byte(specFixture))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := loads.Embedded(raw, raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, schema := range map[string]*float64{
		"original":  doc.OrigSpec().Definitions["X"].Minimum,
		"flattened": doc.Spec().Definitions["X"].Minimum,
	} {
		if schema == nil || *schema != 0 {
			t.Fatalf("%s lost zero minimum", name)
		}
	}
}
