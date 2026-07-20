/*
 * Copyright (c) 2025 LoxiLB Authors
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

import (
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/restapi/operations/metadata"

	tk "github.com/loxilb-io/loxilib"
)

var EmbeddedSwagger []byte
var EmbeddedSwaggerExtras []byte

// Define SwaggerDoc struct
type SwaggerDoc struct {
	Paths       map[string]map[string]Operation `yaml:"paths"`
	Definitions map[string]interface{}          `yaml:"definitions"`
}

// Define Operation struct
type Operation struct {
	Parameters []Parameter `yaml:"parameters"`
}

// Define Parameter struct
type Parameter struct {
	Name     string                 `yaml:"name"`
	In       string                 `yaml:"in"`
	Required bool                   `yaml:"required"`
	Type     string                 `yaml:"type"`
	Schema   map[string]interface{} `yaml:"schema"`
}

// normalizeValue recursively converts yaml.v2's map[interface{}]interface{}
// (including maps nested inside slices) to map[string]interface{}.
func normalizeValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{})
		for k, val := range t {
			if key, ok := k.(string); ok {
				out[key] = normalizeValue(val)
			}
		}
		return out
	case []interface{}:
		for i, e := range t {
			t[i] = normalizeValue(e)
		}
		return t
	}
	return v
}

// LoadSwaggerDoc is used to load a Swagger document from a file.
func LoadSwaggerDoc(data []byte) (*SwaggerDoc, error) {

	var doc SwaggerDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	// Convert map[interface{}]interface{} to map[string]interface{}
	for key, def := range doc.Definitions {
		doc.Definitions[key] = normalizeValue(def)
	}
	// Inline body schemas (schema without $ref) carry the same
	// map[interface{}]interface{} nesting and must be normalized too.
	for _, methods := range doc.Paths {
		for _, op := range methods {
			for i := range op.Parameters {
				for k, v := range op.Parameters[i].Schema {
					op.Parameters[i].Schema[k] = normalizeValue(v)
				}
			}
		}
	}

	return &doc, nil
}

// AutoGenerateMetaData is used to automatically generate metadata as a json format from a Swagger document.
// Additional swagger fragments (e.g. swagger-extras.yml for hand-wired endpoints) may be passed as
// extraBytes; their paths and definitions are merged in, with the primary document taking precedence.
func AutoGenerateMetaData(swaggerBytes []byte, extraBytes ...[]byte) (map[string]interface{}, error) {
	doc, err := LoadSwaggerDoc(swaggerBytes)
	if err != nil {
		return nil, err
	}

	for _, extra := range extraBytes {
		if len(extra) == 0 {
			continue
		}
		extraDoc, err := LoadSwaggerDoc(extra)
		if err != nil {
			return nil, err
		}
		mergeSwaggerDoc(doc, extraDoc)
	}

	meta := extractMetaData(doc)
	return meta, nil
}

// mergeSwaggerDoc merges the paths and definitions of extra into doc.
// Entries already present in doc win over the extra document's.
func mergeSwaggerDoc(doc *SwaggerDoc, extra *SwaggerDoc) {
	if doc.Paths == nil {
		doc.Paths = make(map[string]map[string]Operation)
	}
	for path, methods := range extra.Paths {
		if _, ok := doc.Paths[path]; !ok {
			doc.Paths[path] = methods
			continue
		}
		for method, op := range methods {
			if _, ok := doc.Paths[path][method]; !ok {
				doc.Paths[path][method] = op
			}
		}
	}
	if doc.Definitions == nil {
		doc.Definitions = make(map[string]interface{})
	}
	for name, def := range extra.Definitions {
		if _, ok := doc.Definitions[name]; !ok {
			doc.Definitions[name] = def
		}
	}
}

// ConfigGetMetadata is used to get metadata from the Swagger document.
func ConfigGetMetadata(params metadata.GetMetaParams) middleware.Responder {
	tk.LogIt(tk.LogTrace, "[API] Metadata %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	jsonMeta, err := AutoGenerateMetaData(EmbeddedSwagger, EmbeddedSwaggerExtras)
	if err != nil {
		tk.LogIt(tk.LogError, "Fail create metadata: %v\n", err)
	}
	return metadata.NewGetMetaOK().WithPayload(jsonMeta)
}

// bodyMethodRank orders the body-carrying methods; when a path serves more
// than one, the entry from the higher-ranked method wins deterministically.
var bodyMethodRank = map[string]int{"post": 3, "put": 2, "patch": 1}

// extractMetaData is used to extract metadata from a Swagger document.
// Post, Put or Patch methods are processed.
func extractMetaData(doc *SwaggerDoc) map[string]interface{} {
	meta := make(map[string]interface{})
	methodRank := make(map[string]int)
	for path, methods := range doc.Paths {
		for method, op := range methods {
			rank := bodyMethodRank[strings.ToLower(method)]
			if rank > 0 && rank > methodRank[path] {
				methodRank[path] = rank
				fields := make(map[string]interface{})
				for _, param := range op.Parameters {
					if param.Type != "" {
						if param.Name == "attr" || param.Name == "user" {
							continue
						} else {
							fields[param.Name] = map[string]interface{}{
								"type":     param.Type,
								"required": param.Required,
							}
						}
						continue
					}
					if param.Schema != nil {
						var schema map[string]interface{}
						if ref, ok := param.Schema["$ref"].(string); ok {
							key := strings.TrimPrefix(ref, "#/definitions/")
							if defRaw, found := doc.Definitions[key]; found {
								if defMap, ok := defRaw.(map[string]interface{}); ok {
									schema = defMap
								}
							}
						} else {
							schema = param.Schema
						}
						if schema != nil {
							metaEntry := processSchema(schema, doc.Definitions, param.Required)
							if param.Name == "attr" || param.Name == "user" {
								if merged, ok := metaEntry.(map[string]interface{}); ok {
									for k, v := range merged {
										fields[k] = v
									}
								}
							} else {
								fields[param.Name] = metaEntry
							}
							continue
						}
						fields[param.Name] = map[string]interface{}{
							"type":     "object",
							"required": param.Required,
						}
						continue
					}
					fields[param.Name] = map[string]interface{}{
						"type":     "unknown",
						"required": param.Required,
					}
				}
				meta[path] = map[string]interface{}{
					"method": strings.ToUpper(method),
					"fields": fields,
				}
			}
		}
	}
	return meta
}

// processSchema is used to process the schema.
func processSchema(schema map[string]interface{}, defs map[string]interface{}, required bool) interface{} {
	if ref, ok := schema["$ref"].(string); ok {
		key := strings.TrimPrefix(ref, "#/definitions/")
		if defRaw, found := defs[key]; found {
			if defMap, ok := defRaw.(map[string]interface{}); ok {
				schema = defMap
			}
		}
	}

	typ, _ := schema["type"].(string)
	formatVal, _ := schema["format"].(string)
	desc, _ := schema["description"].(string)

	switch typ {
	case "object":
		if propsRaw, ok := schema["properties"]; ok {
			props, ok := propsRaw.(map[string]interface{})
			if !ok {
				break
			}
			out := make(map[string]interface{})
			reqSet := map[string]bool{}
			if reqArr, ok := schema["required"].([]interface{}); ok {
				for _, r := range reqArr {
					if rStr, ok := r.(string); ok {
						reqSet[rStr] = true
					}
				}
			}
			if attrRaw, exists := props["attr"]; exists {
				if attrSchema, ok := attrRaw.(map[string]interface{}); ok {
					merged := processSchema(attrSchema, defs, reqSet["attr"])
					if mergedMap, ok := merged.(map[string]interface{}); ok {
						for k, v := range mergedMap {
							out[k] = v
						}
					}
				}
			}
			for propName, propRaw := range props {
				if propName == "attr" {
					continue
				}
				if propSchema, ok := propRaw.(map[string]interface{}); ok {
					out[propName] = processSchema(propSchema, defs, reqSet[propName])
				}
			}
			if formatVal != "" {
				out["format"] = formatVal
			}
			if desc != "" {
				out["description"] = desc
			}
			if enumVal, ok := schema["enum"]; ok {
				out["enum"] = enumVal
			}
			return out
		}
		defOut := map[string]interface{}{
			"type":     typ,
			"required": required,
		}
		if formatVal != "" {
			defOut["format"] = formatVal
		}
		if desc != "" {
			defOut["description"] = desc
		}
		if enumVal, ok := schema["enum"]; ok {
			defOut["enum"] = enumVal
		}
		return defOut
	case "array":
		var itemResult interface{}
		if itemsRaw, ok := schema["items"]; ok {
			if itemsMap, ok := itemsRaw.(map[string]interface{}); ok {
				if t, ok := itemsMap["type"].(string); !ok || t == "" {
					if _, exists := itemsMap["properties"]; exists {
						itemsMap["type"] = "object"
					} else {
						itemsMap["type"] = "unknown"
					}
				}
				itemResult = processSchema(itemsMap, defs, false)
			} else {
				itemResult = map[string]interface{}{"type": "unknown"}
			}
		} else {
			itemResult = map[string]interface{}{"type": "unknown"}
		}
		arrOut := map[string]interface{}{
			"type":     "array",
			"required": required,
			"items":    itemResult,
		}
		if formatVal != "" {
			arrOut["format"] = formatVal
		}
		if desc != "" {
			arrOut["description"] = desc
		}
		if enumVal, ok := schema["enum"]; ok {
			arrOut["enum"] = enumVal
		}
		return arrOut
	default:
		defCaseOut := map[string]interface{}{
			"type":     typ,
			"required": required,
		}
		if formatVal != "" {
			defCaseOut["format"] = formatVal
		}
		if desc != "" {
			defCaseOut["description"] = desc
		}
		if enumVal, ok := schema["enum"]; ok {
			defCaseOut["enum"] = enumVal
		}
		return defCaseOut
	}
	// fallback
	return map[string]interface{}{
		"type":     "unknown",
		"required": required,
	}
}
