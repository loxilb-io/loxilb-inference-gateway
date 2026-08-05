/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestToolSchemasHaveNoBooleanPropertySubschemas guards a client-compat
// regression: an `any`/`interface{}` output field reflects to an empty schema,
// which google/jsonschema-go marshals as the boolean `true`. That is valid
// JSON Schema, but Claude Code / Claude Desktop validate tool schemas with Zod,
// which requires every property subschema to be an object and rejects the whole
// tools/list on a boolean ("tools fetch failed"). The fix is a `jsonschema:"…"`
// tag on each such field so it marshals as an object; this test fails if a new
// `any` property field is ever added without one.
func TestToolSchemasHaveNoBooleanPropertySubschemas(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	// Enable the monitoring backends so promql/alerts tools register too and
	// their output schemas (e.g. promqlOut.Data) are covered.
	cfg.PrometheusURL = "http://127.0.0.1:9090"
	cfg.AlertmanagerURL = "http://127.0.0.1:9093"
	b := newTestBridge(t, cfg)

	role, err := guard.ParseRole("admin")
	if err != nil {
		t.Fatal(err)
	}
	srv := b.BuildServer(role)

	ctx := context.Background()
	ct, st := sdk.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "schema-test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	res, err := cs.ListTools(ctx, &sdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(res.Tools) == 0 {
		t.Fatal("no tools registered")
	}

	for _, tool := range res.Tools {
		assertNoBoolPropertySubschema(t, tool.Name, "inputSchema", tool.InputSchema)
		assertNoBoolPropertySubschema(t, tool.Name, "outputSchema", tool.OutputSchema)
	}
}

// assertNoBoolPropertySubschema flags any value directly under a `properties`
// map that is a JSON boolean — the exact shape Claude Code's validator rejects.
// A boolean under `items`/`additionalProperties` is standard JSON Schema and is
// intentionally NOT flagged.
func assertNoBoolPropertySubschema(t *testing.T, tool, which string, schema any) {
	t.Helper()
	if schema == nil {
		return
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("%s %s: marshal: %v", tool, which, err)
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("%s %s: unmarshal: %v", tool, which, err)
	}

	var walk func(node any, underProperties bool, path string)
	walk = func(node any, underProperties bool, path string) {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if underProperties {
					if bv, ok := v.(bool); ok {
						t.Errorf("%s %s: property %q is the boolean subschema %v — "+
							"give the Go field a `jsonschema:\"…\"` tag so it marshals as an object",
							tool, which, path+"."+k, bv)
					}
				}
				walk(v, k == "properties", path+"."+k)
			}
		case []any:
			for i, v := range n {
				walk(v, false, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(root, false, which)
}
