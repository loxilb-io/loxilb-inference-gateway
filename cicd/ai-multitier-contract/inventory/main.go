// Command inventory inventories the Swagger rule contract without inferring coverage.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type field struct {
	ID       string         `json:"id"`
	Required bool           `json:"required"`
	Contract map[string]any `json:"contract"`
}

type inventory struct {
	Version int               `json:"schemaVersion"`
	Scope   string            `json:"scope"`
	Sources map[string]string `json:"sourceSha256"`
	Fields  []field           `json:"fields"`
}

func object(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func walk(doc, schema map[string]any, id string, required bool, stack map[string]bool, out *[]field) error {
	if ref, ok := schema["$ref"].(string); ok {
		const prefix = "#/definitions/"
		if !strings.HasPrefix(ref, prefix) || stack[ref] {
			return fmt.Errorf("unsupported or cyclic reference %q at %s", ref, id)
		}
		target := object(object(doc["definitions"])[strings.TrimPrefix(ref, prefix)])
		if target == nil {
			return fmt.Errorf("unresolved reference %q", ref)
		}
		stack[ref] = true
		err := walk(doc, target, id, required, stack, out)
		delete(stack, ref)
		return err
	}
	if schema == nil {
		return fmt.Errorf("missing schema at %s", id)
	}
	if _, ok := schema["allOf"]; ok {
		return fmt.Errorf("allOf needs explicit inventory support at %s", id)
	}
	contract := map[string]any{}
	for key, value := range schema {
		if key != "properties" && key != "items" && key != "required" {
			contract[key] = value
		}
	}
	*out = append(*out, field{ID: id, Required: required, Contract: contract})
	requiredNames := map[string]bool{}
	if names, ok := schema["required"].([]any); ok {
		for _, name := range names {
			requiredNames[fmt.Sprint(name)] = true
		}
	}
	for name, value := range object(schema["properties"]) {
		if err := walk(doc, object(value), id+"/"+name, requiredNames[name], stack, out); err != nil {
			return err
		}
	}
	if item, ok := schema["items"]; ok {
		return walk(doc, object(item), id+"/items", false, stack, out)
	}
	return nil
}

func build(root string) ([]byte, error) {
	result := inventory{Version: 1, Scope: "LoadbalanceEntry fields and AI KV inventory query parameters; not a test-coverage claim", Sources: map[string]string{}}
	for _, name := range []string{"swagger.yml", "swagger-extras.yml"} {
		raw, err := os.ReadFile(filepath.Join(root, "api", name))
		if err != nil {
			return nil, err
		}
		result.Sources[name] = fmt.Sprintf("%x", sha256.Sum256(raw))
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if name == "swagger.yml" {
			err = walk(doc, object(object(doc["definitions"])["LoadbalanceEntry"]), name+"#/definitions/LoadbalanceEntry", false, map[string]bool{}, &result.Fields)
			if err != nil {
				return nil, err
			}
		} else {
			path := "/config/ai/kv/inventory"
			operation := object(object(object(doc["paths"])[path])["get"])
			parameters, ok := operation["parameters"].([]any)
			if !ok || len(parameters) == 0 {
				return nil, fmt.Errorf("missing KV inventory query parameters")
			}
			for _, value := range parameters {
				parameter := object(value)
				nameValue, ok := parameter["name"].(string)
				if !ok {
					return nil, fmt.Errorf("unnamed KV inventory parameter")
				}
				required, _ := parameter["required"].(bool)
				if err := walk(doc, parameter, name+"#/paths"+path+"/get/parameters/"+nameValue, required, map[string]bool{}, &result.Fields); err != nil {
					return nil, err
				}
			}
		}
	}
	sort.Slice(result.Fields, func(i, j int) bool { return result.Fields[i].ID < result.Fields[j].ID })
	for i := 1; i < len(result.Fields); i++ {
		if result.Fields[i-1].ID == result.Fields[i].ID {
			return nil, fmt.Errorf("duplicate inventory field %s", result.Fields[i].ID)
		}
	}
	data, err := json.MarshalIndent(result, "", "  ")
	return append(data, '\n'), err
}

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.String("check", "", "compare with an existing inventory; fail on drift")
	output := flag.String("output", "", "write generated inventory (default stdout)")
	flag.Parse()
	data, err := build(*root)
	if err == nil && *check != "" {
		var prior []byte
		prior, err = os.ReadFile(*check)
		if err == nil && !bytes.Equal(prior, data) {
			err = fmt.Errorf("inventory drift: review new/changed fields and coverage before regenerating %s", *check)
		}
	} else if err == nil && *output != "" {
		err = os.WriteFile(*output, data, 0644)
	} else if err == nil {
		_, err = os.Stdout.Write(data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
