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

package tools

import (
	"context"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

// RegisterFleet adds the multi-target fan-out tools: targets_list and
// fleet_overview.
func RegisterFleet(s *sdk.Server, role guard.Role, pol *guard.Policy, deps *Deps) {
	if deps.ResolveAll == nil {
		return
	}
	if pol.Permits(role, guard.ToolMeta{Name: "targets_list", Domain: domainAnalysis}) {
		sdk.AddTool(s, &sdk.Tool{
			Name: "targets_list",
			Description: "List the loxilb targets this bridge is configured for " +
				"(name, URL, which one is the default). Fan-out tools operate on all of them.",
			Annotations: roAnnotations("List configured targets"),
		}, deps.targetsList())
	}
	if pol.Permits(role, guard.ToolMeta{Name: "fleet_overview", Domain: domainAnalysis}) {
		sdk.AddTool(s, &sdk.Tool{
			Name: "fleet_overview",
			Description: "Run the health_overview probe against EVERY configured target " +
				"concurrently and return per-target results. Unreachable targets degrade " +
				"into their own error sections instead of failing the call.",
			Annotations: roAnnotations("Fleet health overview"),
		}, deps.fleetOverview())
	}
}

// ---- targets_list ----

type targetsListIn struct{}

type targetInfo struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Default bool   `json:"default,omitempty"`
}

type targetsListOut struct {
	Count   int          `json:"count"`
	Targets []targetInfo `json:"targets"`
}

func (d *Deps) targetsList() sdk.ToolHandlerFor[targetsListIn, targetsListOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, _ targetsListIn) (*sdk.CallToolResult, targetsListOut, error) {
		def, _ := d.Resolve("")
		out := targetsListOut{}
		for _, c := range d.ResolveAll() {
			out.Targets = append(out.Targets, targetInfo{
				Name:    clean(c.Name()),
				URL:     clean(c.Base()),
				Default: def != nil && c.Name() == def.Name(),
			})
		}
		out.Count = len(out.Targets)
		d.audit("targets_list", "", true, "")
		return nil, out, nil
	}
}

// ---- fleet_overview ----

type fleetIn struct{}

type fleetOut struct {
	TargetCount int         `json:"target_count"`
	Reachable   int         `json:"reachable"`
	Targets     []healthOut `json:"targets"`
}

func (d *Deps) fleetOverview() sdk.ToolHandlerFor[fleetIn, fleetOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, _ fleetIn) (*sdk.CallToolResult, fleetOut, error) {
		clients := d.ResolveAll()
		results := make([]healthOut, len(clients))
		var wg sync.WaitGroup
		wg.Add(len(clients))
		for i, c := range clients {
			go func() {
				defer wg.Done()
				results[i] = d.healthProbe(ctx, c)
			}()
		}
		wg.Wait()

		out := fleetOut{TargetCount: len(results), Targets: results}
		for _, r := range results {
			if r.Reachable {
				out.Reachable++
			}
		}
		d.audit("fleet_overview", "all", true, "")
		return nil, out, nil
	}
}
