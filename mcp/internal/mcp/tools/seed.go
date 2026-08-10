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

// Package tools implements the loxilb-mcp tool set. ships the five
// seed tools: version_get, health_overview, lb_list,
// ct_list, metrics_snapshot. Later phases add the full domain files.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/client"
	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

// Deps is what tool handlers need from the bridge.
type Deps struct {
	// Resolve maps a target name ("" = default) to its REST client.
	Resolve func(name string) (*client.Client, error)
	// Targets lists configured target names (for tool descriptions).
	Targets []string
	// Audit receives tool_call events (may be nil).
	Audit *guard.Auditor
	// Prom is the optional external Prometheus backend (nil disables
	// promql_* tools).
	Prom *client.PromClient
	// Alertmanager is the optional Alertmanager backend (nil disables
	// alerts_active).
	Alertmanager *client.AlertmanagerClient
	// AlertRules is the parsed alert-rule catalog (empty disables
	// alerts_catalog and the docs/alerts resource).
	AlertRules []AlertRule
	// Confirm gates destructive tools behind the preview→confirm-token flow.
	// nil (--no-confirm) executes destructive tools directly (CI use).
	Confirm *guard.Confirmer
	// AllowImport enables config_import (off by default even for admins).
	AllowImport bool
	// SecretsDir receives files holding secret material that must not enter
	// model context (ai_apikey_create raw keys, threat T5). Empty disables
	// the file sink; ai_apikey_create then requires reveal=true.
	SecretsDir string
	// Autopilot reports whether a destructive tool may execute without the
	// confirm-token step (§3.7 closed-loop hooks). nil = no autopilot tools.
	Autopilot func(tool string) bool
	// ResolveAll returns every configured target client, sorted by name
	// (multi-target fan-out).
	ResolveAll func() []*client.Client
}

const (
	domainMgmt       = "mgmt"
	domainAnalysis   = "analysis"
	domainMonitoring = "monitoring"
	domainAI         = "ai"
)

func boolPtr(b bool) *bool { return &b }

// roAnnotations marks a tool read-only and closed-world per MCP spec hints.
func roAnnotations(title string) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		DestructiveHint: boolPtr(false),
		OpenWorldHint:   boolPtr(false),
	}
}

// mutAnnotations marks a mutating, non-destructive tool.
func mutAnnotations(title string, idempotent bool) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(false),
		IdempotentHint:  idempotent,
		OpenWorldHint:   boolPtr(false),
	}
}

// destAnnotations marks a destructive tool (confirm-token gated).
func destAnnotations(title string) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(true),
		OpenWorldHint:   boolPtr(false),
	}
}

// clean sanitizes remote-originated strings before they reach model context:
// control characters stripped, length capped.
func clean(s string) string {
	const maxLen = 256
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxLen {
			break
		}
	}
	return b.String()
}

func targetDesc(targets []string) string {
	return "Target loxilb instance name (omit for default). Configured: " +
		strings.Join(targets, ", ")
}

// RegisterSeed adds every seed tool permitted by the policy for the role.
func RegisterSeed(s *sdk.Server, role guard.Role, pol *guard.Policy, deps *Deps) {
	tdesc := targetDesc(deps.Targets)

	if pol.Permits(role, guard.ToolMeta{Name: "version_get", Domain: domainAnalysis}) {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "version_get",
			Description: "Get the loxilb software version and build info of a target instance.",
			Annotations: roAnnotations("Get loxilb version"),
		}, deps.versionGet(tdesc))
	}
	if pol.Permits(role, guard.ToolMeta{Name: "lb_list", Domain: domainMgmt}) {
		sdk.AddTool(s, &sdk.Tool{
			Name: "lb_list",
			Description: "List load-balancer rules (service VIP:port/protocol, mode, endpoint count " +
				"and states). Supports substring filtering and limiting; reports total_count when truncated.",
			Annotations: roAnnotations("List load-balancer rules"),
		}, deps.lbList(tdesc))
	}
	if pol.Permits(role, guard.ToolMeta{Name: "ct_list", Domain: domainAnalysis}) {
		sdk.AddTool(s, &sdk.Tool{
			Name: "ct_list",
			Description: "Summarize live connection-tracking entries: aggregate counts by state and " +
				"protocol plus a bounded sample of matching entries. Never dumps the full table.",
			Annotations: roAnnotations("Summarize conntrack table"),
		}, deps.ctList(tdesc))
	}
	if pol.Permits(role, guard.ToolMeta{Name: "metrics_snapshot", Domain: domainMonitoring}) {
		sdk.AddTool(s, &sdk.Tool{
			Name: "metrics_snapshot",
			Description: "Scrape the loxilb Prometheus endpoint and return parsed metric families. " +
				"Use 'families' globs (e.g. loxilb_ai_*, loxilb_l4_error_events_total) to narrow output.",
			Annotations: roAnnotations("Snapshot Prometheus metrics"),
		}, deps.metricsSnapshot(tdesc))
	}
	if pol.Permits(role, guard.ToolMeta{Name: "health_overview", Domain: domainAnalysis}) {
		sdk.AddTool(s, &sdk.Tool{
			Name: "health_overview",
			Description: "Start-here health check of a loxilb instance: reachability, version, " +
				"LB rule count, conntrack totals by state, and metric family count. " +
				"Sections degrade independently with per-section errors.",
			Annotations: roAnnotations("loxilb health overview"),
		}, deps.healthOverview(tdesc))
	}
}

func (d *Deps) audit(tool, target string, ok bool, errStr string) {
	d.Audit.Log(guard.Event{
		Kind: guard.EventToolCall, Tool: tool, Target: target, OK: ok, Err: errStr,
	})
}

// auditMut records a mutating call including its (redacted) arguments.
func (d *Deps) auditMut(tool, target string, args any, ok bool, errStr string) {
	var argMap map[string]any
	if raw, err := json.Marshal(args); err == nil {
		_ = json.Unmarshal(raw, &argMap)
	}
	d.Audit.Log(guard.Event{
		Kind: guard.EventToolCall, Tool: tool, Target: target,
		Args: guard.Redact(argMap), OK: ok, Err: errStr,
	})
}

// ---- version_get ----

type versionIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
}

type versionOut struct {
	Target    string `json:"target"`
	Version   string `json:"version"`
	BuildInfo string `json:"build_info,omitempty"`
}

func (d *Deps) versionGet(string) sdk.ToolHandlerFor[versionIn, versionOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in versionIn) (*sdk.CallToolResult, versionOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, versionOut{}, err
		}
		v, err := c.Version(ctx)
		if err != nil {
			return nil, versionOut{}, err
		}
		return nil, versionOut{
			Target:    c.Name(),
			Version:   clean(v.Version),
			BuildInfo: clean(v.BuildInfo),
		}, nil
	}
}

// ---- lb_list ----

type lbListIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Filter string `json:"filter,omitempty" jsonschema:"case-insensitive substring matched against service name and external IP"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum rules to return (default 50, max 500)"`
}

type lbRule struct {
	Name          string `json:"name,omitempty"`
	ExternalIP    string `json:"external_ip"`
	Port          any    `json:"port" jsonschema:"service port (number, or string for a port range)"`
	Protocol      string `json:"protocol"`
	Mode          any    `json:"mode,omitempty" jsonschema:"load-balancer mode as returned by loxilb (number or string)"`
	EndpointCount int    `json:"endpoint_count"`
	Endpoints     []any  `json:"endpoints,omitempty"`
}

type lbListOut struct {
	Target     string   `json:"target"`
	TotalCount int      `json:"total_count"`
	Returned   int      `json:"returned"`
	Rules      []lbRule `json:"rules"`
}

func (d *Deps) lbList(string) sdk.ToolHandlerFor[lbListIn, lbListOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in lbListIn) (*sdk.CallToolResult, lbListOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, lbListOut{}, err
		}
		raw, err := c.LBRules(ctx)
		if err != nil {
			d.audit("lb_list", c.Name(), false, err.Error())
			return nil, lbListOut{}, err
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 50
		}
		if limit > 500 {
			limit = 500
		}
		filter := strings.ToLower(in.Filter)

		var matched []lbRule
		for _, entry := range raw {
			svc, _ := entry["serviceArguments"].(map[string]any)
			if svc == nil {
				continue
			}
			name, _ := svc["name"].(string)
			extIP, _ := svc["externalIP"].(string)
			proto, _ := svc["protocol"].(string)
			if filter != "" &&
				!strings.Contains(strings.ToLower(name), filter) &&
				!strings.Contains(strings.ToLower(extIP), filter) {
				continue
			}
			eps, _ := entry["endpoints"].([]any)
			rule := lbRule{
				Name:          clean(name),
				ExternalIP:    clean(extIP),
				Port:          svc["port"],
				Protocol:      clean(proto),
				Mode:          svc["mode"],
				EndpointCount: len(eps),
			}
			for _, epRaw := range eps {
				ep, _ := epRaw.(map[string]any)
				if ep == nil {
					continue
				}
				ip, _ := ep["endpointIP"].(string)
				state, _ := ep["state"].(string)
				rule.Endpoints = append(rule.Endpoints, map[string]any{
					"ip":     clean(ip),
					"state":  clean(state),
					"weight": ep["weight"],
				})
			}
			matched = append(matched, rule)
		}
		out := lbListOut{Target: c.Name(), TotalCount: len(matched)}
		if len(matched) > limit {
			matched = matched[:limit]
		}
		out.Rules = matched
		out.Returned = len(matched)
		d.audit("lb_list", c.Name(), true, "")
		return nil, out, nil
	}
}

// ---- ct_list ----

type ctListIn struct {
	Target   string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Protocol string `json:"protocol,omitempty" jsonschema:"filter by protocol (tcp|udp|sctp|icmp)"`
	State    string `json:"state,omitempty" jsonschema:"filter by conntrack state substring (e.g. est, closed, sync)"`
	Service  string `json:"service,omitempty" jsonschema:"filter by service name substring"`
	Limit    int    `json:"limit,omitempty" jsonschema:"maximum sample entries to return (default 50, max 500)"`
}

type ctEntry struct {
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	AgeMs   uint64 `json:"age_ms,omitempty"`
}

type ctListOut struct {
	Target     string         `json:"target"`
	TotalCount int            `json:"total_count"`
	Matched    int            `json:"matched"`
	ByState    map[string]int `json:"by_state"`
	ByProto    map[string]int `json:"by_proto"`
	Returned   int            `json:"returned"`
	Entries    []ctEntry      `json:"entries"`
}

func (d *Deps) ctList(string) sdk.ToolHandlerFor[ctListIn, ctListOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in ctListIn) (*sdk.CallToolResult, ctListOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, ctListOut{}, err
		}
		cts, err := c.Conntracks(ctx)
		if err != nil {
			d.audit("ct_list", c.Name(), false, err.Error())
			return nil, ctListOut{}, err
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 50
		}
		if limit > 500 {
			limit = 500
		}
		out := ctListOut{
			Target:     c.Name(),
			TotalCount: len(cts),
			ByState:    map[string]int{},
			ByProto:    map[string]int{},
		}
		proto := strings.ToLower(in.Protocol)
		state := strings.ToLower(in.State)
		service := strings.ToLower(in.Service)
		for _, ct := range cts {
			if proto != "" && !strings.EqualFold(ct.Protocol, proto) {
				continue
			}
			if state != "" && !strings.Contains(strings.ToLower(ct.State), state) {
				continue
			}
			if service != "" && !strings.Contains(strings.ToLower(ct.ServName), service) {
				continue
			}
			out.Matched++
			out.ByState[clean(strings.ToLower(ct.State))]++
			out.ByProto[clean(strings.ToLower(ct.Protocol))]++
			if len(out.Entries) < limit {
				out.Entries = append(out.Entries, ctEntry{
					Src:     clean(fmt.Sprintf("%s:%d", ct.SourceIP, ct.SourcePort)),
					Dst:     clean(fmt.Sprintf("%s:%d", ct.DestinationIP, ct.DestinationPort)),
					Proto:   clean(ct.Protocol),
					State:   clean(ct.State),
					Service: clean(ct.ServName),
					Packets: ct.Packets,
					Bytes:   ct.Bytes,
					AgeMs:   ct.AgeMs,
				})
			}
		}
		out.Returned = len(out.Entries)
		d.audit("ct_list", c.Name(), true, "")
		return nil, out, nil
	}
}

// ---- metrics_snapshot ----

type metricsIn struct {
	Target     string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Families   []string `json:"families,omitempty" jsonschema:"glob patterns of metric family names to include (e.g. loxilb_ai_*); empty means all"`
	MaxSamples int      `json:"max_samples,omitempty" jsonschema:"cap on samples per family (default 200)"`
}

type metricsOut struct {
	Target      string          `json:"target"`
	FamilyCount int             `json:"family_count"`
	Families    []client.Family `json:"families"`
}

func (d *Deps) metricsSnapshot(string) sdk.ToolHandlerFor[metricsIn, metricsOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in metricsIn) (*sdk.CallToolResult, metricsOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, metricsOut{}, err
		}
		text, err := c.MetricsText(ctx)
		if err != nil {
			d.audit("metrics_snapshot", c.Name(), false, err.Error())
			return nil, metricsOut{}, err
		}
		fams, err := client.ParseFamilies(text, in.Families, in.MaxSamples)
		if err != nil {
			return nil, metricsOut{}, err
		}
		d.audit("metrics_snapshot", c.Name(), true, "")
		return nil, metricsOut{Target: c.Name(), FamilyCount: len(fams), Families: fams}, nil
	}
}

// ---- health_overview ----

type healthIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
}

type healthOut struct {
	Target         string            `json:"target"`
	Reachable      bool              `json:"reachable"`
	Version        string            `json:"version,omitempty"`
	LBRuleCount    int               `json:"lb_rule_count"`
	ConntrackTotal int               `json:"conntrack_total"`
	CtByState      map[string]int    `json:"ct_by_state,omitempty"`
	MetricFamilies int               `json:"metric_families"`
	Errors         map[string]string `json:"errors,omitempty"`
}

func (d *Deps) healthOverview(string) sdk.ToolHandlerFor[healthIn, healthOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in healthIn) (*sdk.CallToolResult, healthOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, healthOut{}, err
		}
		out := d.healthProbe(ctx, c)
		// If every section failed, surface a real error so the model sees
		// IsError instead of an all-zero overview.
		if !out.Reachable && out.Errors != nil && len(out.Errors) >= 4 {
			keys := make([]string, 0, len(out.Errors))
			for k := range out.Errors {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			d.audit("health_overview", c.Name(), false, out.Errors[keys[0]])
			return nil, healthOut{}, fmt.Errorf("target %s unreachable: %s", c.Name(), out.Errors[keys[0]])
		}
		d.audit("health_overview", c.Name(), true, "")
		return nil, out, nil
	}
}

// healthProbe gathers the health sections of one target concurrently; failing
// sections degrade into Errors entries.
func (d *Deps) healthProbe(ctx context.Context, c *client.Client) healthOut {
	out := healthOut{Target: c.Name(), Errors: map[string]string{}}
	{
		var mu sync.Mutex
		var wg sync.WaitGroup
		fail := func(section string, err error) {
			mu.Lock()
			out.Errors[section] = clean(err.Error())
			mu.Unlock()
		}

		wg.Add(4)
		go func() {
			defer wg.Done()
			if v, err := c.Version(ctx); err != nil {
				fail("version", err)
			} else {
				mu.Lock()
				out.Version = clean(v.Version)
				out.Reachable = true
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			if rules, err := c.LBRules(ctx); err != nil {
				fail("loadbalancer", err)
			} else {
				mu.Lock()
				out.LBRuleCount = len(rules)
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			if cts, err := c.Conntracks(ctx); err != nil {
				fail("conntrack", err)
			} else {
				byState := map[string]int{}
				for _, ct := range cts {
					byState[clean(strings.ToLower(ct.State))]++
				}
				mu.Lock()
				out.ConntrackTotal = len(cts)
				out.CtByState = byState
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			if text, err := c.MetricsText(ctx); err != nil {
				fail("metrics", err)
			} else if fams, err := client.ParseFamilies(text, nil, 1); err != nil {
				fail("metrics", err)
			} else {
				mu.Lock()
				out.MetricFamilies = len(fams)
				mu.Unlock()
			}
		}()
		wg.Wait()
	}
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	return out
}
