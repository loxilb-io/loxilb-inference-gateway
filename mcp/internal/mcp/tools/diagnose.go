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
	"fmt"
	"net/url"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/client"
	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

// RegisterDiagnose adds the composite diagnostics / RCA tools
// . Each orchestrates several read endpoints and
// returns a correlated evidence bundle plus machine-readable
// suggested_actions[] (§3.7): the tool gathers, the model concludes, a human
// approves any mutation via the confirm-token flow.
func RegisterDiagnose(s *sdk.Server, role guard.Role, pol *guard.Policy, deps *Deps) {
	reg := func(name string, add func()) {
		if pol.Permits(role, guard.ToolMeta{Name: name, Domain: domainAnalysis}) {
			add()
		}
	}

	reg("diagnose_l4_errors", func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "diagnose_l4_errors",
			Description: "Correlated evidence bundle for L4 error triage (LoxilbL4ErrorBurst): " +
				"loxilb_l4_error_events_total by reason/proto, conntrack state aggregates, endpoint probe " +
				"states, and recent ERROR logs. Returns suggested_actions[] for follow-up.",
			Annotations: roAnnotations("Diagnose L4 errors"),
		}, deps.diagnoseL4Errors())
	})
	reg("diagnose_ai_latency", func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "diagnose_ai_latency",
			Description: "Correlated evidence bundle for AI latency triage (LoxilbHighTTFB): request-duration/TTFB/TTFT " +
				"histogram quantiles, KV-cache parameter hit counters, session-affinity hits, endpoint probe states, " +
				"and GPU-aware routing status. Returns suggested_actions[] for follow-up.",
			Annotations: roAnnotations("Diagnose AI latency"),
		}, deps.diagnoseAILatency())
	})
	reg("diagnose_endpoint", func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "diagnose_endpoint",
			Description: "Deep-dive one backend endpoint by IP/host: probe entries, LB rules referencing it, " +
				"conntrack flows toward it by state, and its share of L4 errors. Returns suggested_actions[].",
			Annotations: roAnnotations("Diagnose one endpoint"),
		}, deps.diagnoseEndpoint())
	})
	reg("capacity_report", func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "capacity_report",
			Description: "Capacity posture of a loxilb instance: conntrack usage vs capacity, LB rule and endpoint " +
				"counts, security rate-limit settings, and host CPU/memory/disk. Returns suggested_actions[].",
			Annotations: roAnnotations("Capacity report"),
		}, deps.capacityReport())
	})
}

// suggestedAction is the §3.7 machine-readable follow-up proposal: an agent
// may propose it, a human approves, the (already guarded) tool executes.
type suggestedAction struct {
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args,omitempty"`
	Rationale string         `json:"rationale"`
	Risk      string         `json:"risk"` // none (read-only) | low | medium | high
	// Autopilot marks the tool as on this bridge's autopilot list: an agent
	// may execute it without the confirm-token round trip (§3.7).
	Autopilot bool `json:"autopilot,omitempty"`
}

// evidence sections degrade independently: a failing source becomes an entry
// in errors instead of failing the whole diagnosis.
type diagnoseOut struct {
	Target           string            `json:"target"`
	Evidence         map[string]any    `json:"evidence"`
	SuggestedActions []suggestedAction `json:"suggested_actions"`
	Caveats          []string          `json:"caveats,omitempty"`
	Errors           map[string]string `json:"errors,omitempty"`
}

func newDiagnoseOut(target string) diagnoseOut {
	return diagnoseOut{
		Target:   target,
		Evidence: map[string]any{},
		Errors:   map[string]string{},
	}
}

func (o *diagnoseOut) fail(section string, err error) {
	o.Errors[section] = clean(err.Error())
}

func (o *diagnoseOut) finish() {
	if len(o.Errors) == 0 {
		o.Errors = nil
	}
	if o.SuggestedActions == nil {
		o.SuggestedActions = []suggestedAction{}
	}
}

// finishDiagnose finalizes a diagnosis and stamps each suggested action with
// this bridge's autopilot status so an agent knows which follow-ups it may
// execute without a confirm token (§3.7).
func (d *Deps) finishDiagnose(o *diagnoseOut) {
	o.finish()
	if d.Autopilot == nil {
		return
	}
	for i := range o.SuggestedActions {
		o.SuggestedActions[i].Autopilot = d.Autopilot(o.SuggestedActions[i].Tool)
	}
}

// hostMatches compares an endpoint hostName (possibly CIDR-suffixed, e.g.
// "10.0.0.1/32") against a user-supplied host.
func hostMatches(hostName, want string) bool {
	hostName, _, _ = strings.Cut(hostName, "/")
	return strings.EqualFold(strings.TrimSpace(hostName), strings.TrimSpace(want))
}

// epState is a compact endpoint probe summary used across diagnose tools.
type epState struct {
	Host  string `json:"host"`
	State string `json:"state,omitempty"`
	Extra any    `json:"detail,omitempty" jsonschema:"additional endpoint detail (arbitrary JSON)"`
}

// fetchEndpointStates GETs /config/endpoint/all and aggregates probe states.
func fetchEndpointStates(ctx context.Context, c *client.Client) (byState map[string]int, unhealthy []epState, err error) {
	var env struct {
		Attr []map[string]any `json:"Attr"`
	}
	if err := c.Get(ctx, "/config/endpoint/all", &env); err != nil {
		return nil, nil, err
	}
	byState = map[string]int{}
	for _, ep := range env.Attr {
		host, _ := ep["hostName"].(string)
		state, _ := ep["currState"].(string)
		if state == "" {
			if s2, ok := ep["state"].(string); ok {
				state = s2
			}
		}
		key := strings.ToLower(state)
		if key == "" {
			key = "unknown"
		}
		byState[clean(key)]++
		// "ok"/"green"/"active" family = healthy; anything else is suspect.
		switch key {
		case "ok", "green", "active", "up":
		default:
			if len(unhealthy) < maxListItems {
				unhealthy = append(unhealthy, epState{Host: clean(host), State: clean(state)})
			}
		}
	}
	return byState, unhealthy, nil
}

// ---- diagnose_l4_errors ----

func (d *Deps) diagnoseL4Errors() sdk.ToolHandlerFor[targetIn, diagnoseOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in targetIn) (*sdk.CallToolResult, diagnoseOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, diagnoseOut{}, err
		}
		out := newDiagnoseOut(c.Name())

		// 1. L4 error counters by reason/proto (always-on, unsampled).
		var errTotal float64
		errByReason := map[string]float64{}
		if text, err := c.MetricsText(ctx); err != nil {
			out.fail("l4_error_metrics", err)
		} else if fams, perr := client.ParseFamilies(text, []string{"loxilb_l4_error_events_total"}, 2000); perr != nil {
			out.fail("l4_error_metrics", perr)
		} else {
			var rows []map[string]any
			for _, f := range fams {
				for _, s := range f.Samples {
					errTotal += s.Value
					errByReason[clean(s.Labels["reason"])] += s.Value
					rows = append(rows, map[string]any{
						"proto": clean(s.Labels["proto"]), "reason": clean(s.Labels["reason"]),
						"count": s.Value,
					})
				}
			}
			out.Evidence["l4_error_events_total"] = errTotal
			out.Evidence["l4_errors_by_series"] = rows
			out.Evidence["l4_errors_by_reason"] = errByReason
		}

		// 2. Conntrack state aggregates (closed/sync-heavy tables point at
		// connection churn or half-open floods).
		if cts, err := c.Conntracks(ctx); err != nil {
			out.fail("conntrack", err)
		} else {
			byState := map[string]int{}
			byProto := map[string]int{}
			for _, ct := range cts {
				byState[clean(strings.ToLower(ct.State))]++
				byProto[clean(strings.ToLower(ct.Protocol))]++
			}
			out.Evidence["conntrack_total"] = len(cts)
			out.Evidence["conntrack_by_state"] = byState
			out.Evidence["conntrack_by_proto"] = byProto
		}

		// 3. Endpoint probe states.
		var unhealthy []epState
		if byState, unh, err := fetchEndpointStates(ctx, c); err != nil {
			out.fail("endpoints", err)
		} else {
			unhealthy = unh
			out.Evidence["endpoints_by_state"] = byState
			if len(unh) > 0 {
				out.Evidence["unhealthy_endpoints"] = unh
			}
		}

		// 4. Recent ERROR logs (untrusted data, T6).
		if lines := d.fetchErrorLogs(ctx, c, 50); lines != nil {
			out.Evidence["recent_error_logs_untrusted_data"] = lines
		}

		// Suggested follow-ups.
		for _, ep := range unhealthy {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "diagnose_endpoint",
				Args:      map[string]any{"host": ep.Host, "target": in.Target},
				Rationale: fmt.Sprintf("endpoint %s probe state is %q — inspect its rules, flows and error share", ep.Host, ep.State),
				Risk:      "none",
			})
			if len(out.SuggestedActions) >= 5 {
				break
			}
		}
		if d.Prom != nil {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool: "promql_range",
				Args: map[string]any{
					"query": `sum by (reason) (rate(loxilb_l4_error_events_total{reason!="rst_client"}[5m]))`,
					"step":  "60s",
				},
				Rationale: "counters above are cumulative; the burst window and dominant reason need a rate over time",
				Risk:      "none",
			})
		}
		if errByReason["reset"] > 0 || errByReason["rst_server"] > 0 {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "logs_tail",
				Args:      map[string]any{"keyword": "reset", "target": in.Target},
				Rationale: "server-side resets dominate — backend logs usually name the failing service",
				Risk:      "none",
			})
		}
		out.Caveats = []string{
			"l4 error counters are cumulative since start; only deltas indicate an active burst",
			"reason=rst_client is excluded from the LoxilbL4ErrorBurst alert expression (client-initiated)",
		}
		d.finishDiagnose(&out)
		d.audit("diagnose_l4_errors", c.Name(), true, "")
		return nil, out, nil
	}
}

// fetchErrorLogs best-effort tails ERROR-level logs; nil when unavailable.
func (d *Deps) fetchErrorLogs(ctx context.Context, c *client.Client, n int) []string {
	q := url.Values{"lines": {strconv.Itoa(n)}, "level": {"ERROR"}}
	var env struct {
		Logs []string `json:"logs"`
	}
	if err := c.GetQ(ctx, "/logs", q, &env); err != nil {
		return nil
	}
	var out []string
	for i, line := range env.Logs {
		if i >= n {
			break
		}
		out = append(out, cleanLong(line))
	}
	return out
}

// ---- diagnose_ai_latency ----

func (d *Deps) diagnoseAILatency() sdk.ToolHandlerFor[targetIn, diagnoseOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in targetIn) (*sdk.CallToolResult, diagnoseOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, diagnoseOut{}, err
		}
		out := newDiagnoseOut(c.Name())

		// 1. Latency histograms + KV/session counters from one scrape.
		var kvFound, kvMissing float64
		if text, err := c.MetricsText(ctx); err != nil {
			out.fail("metrics", err)
		} else if fams, perr := client.ParseFamilies(text, []string{
			"loxilb_ai_request_duration_seconds", "loxilb_proxy_http_ttfb_seconds",
			"loxilb_ai_pd_*", "loxilb_ai_active_streams", "loxilb_ai_normal_session_hits_total",
		}, 2000); perr != nil {
			out.fail("metrics", perr)
		} else {
			byName := map[string]client.Family{}
			for _, f := range fams {
				byName[f.Name] = f
			}
			if s := summarizeHistogram(byName["loxilb_ai_request_duration_seconds"]); s != nil {
				out.Evidence["ai_request_duration"] = s
			}
			if s := summarizeHistogram(byName["loxilb_proxy_http_ttfb_seconds"]); s != nil {
				out.Evidence["proxy_ttfb"] = s
			}
			if s := summarizeHistogram(byName["loxilb_ai_pd_prefill_duration_seconds"]); s != nil {
				out.Evidence["pd_prefill_duration"] = s
			}
			if s := summarizeHistogram(byName["loxilb_ai_pd_decode_ttft_seconds"]); s != nil {
				out.Evidence["pd_decode_ttft"] = s
			}
			kvFound = sumFamily(byName["loxilb_ai_pd_kv_params_found_total"])
			kvMissing = sumFamily(byName["loxilb_ai_pd_kv_params_missing_total"])
			out.Evidence["kv_params_found"] = kvFound
			out.Evidence["kv_params_missing"] = kvMissing
			out.Evidence["pd_session_hits"] = sumFamily(byName["loxilb_ai_pd_session_hits_total"])
			out.Evidence["normal_session_hits"] = sumFamily(byName["loxilb_ai_normal_session_hits_total"])
			out.Evidence["active_streams"] = sumFamily(byName["loxilb_ai_active_streams"])
		}

		// 2. Endpoint probe states (a drained/failed vLLM backend concentrates
		// load on the rest).
		var unhealthy []epState
		if byState, unh, err := fetchEndpointStates(ctx, c); err != nil {
			out.fail("endpoints", err)
		} else {
			unhealthy = unh
			out.Evidence["endpoints_by_state"] = byState
			if len(unh) > 0 {
				out.Evidence["unhealthy_endpoints"] = unh
			}
		}

		// 3. GPU-aware routing status (best-effort; feature may be disabled).
		var gpuRaw any
		if err := c.Get(ctx, "/config/gpu/status", &gpuRaw); err != nil {
			out.fail("gpu_status", err)
		} else {
			out.Evidence["gpu_status"] = sanitizeAny(gpuRaw, 0)
		}

		// Suggested follow-ups.
		if kvFound+kvMissing > 0 && kvMissing > kvFound {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "ai_kv_inventory_get",
				Args:      map[string]any{"target": in.Target},
				Rationale: "KV-cache params are missing more often than found — inspect the block inventory of the busiest endpoint (service_id/ep_idx from lb_list)",
				Risk:      "none",
			})
		}
		for _, ep := range unhealthy {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "diagnose_endpoint",
				Args:      map[string]any{"host": ep.Host, "target": in.Target},
				Rationale: fmt.Sprintf("endpoint %s is %q — remaining backends absorb its load, inflating TTFB", ep.Host, ep.State),
				Risk:      "none",
			})
			if len(out.SuggestedActions) >= 5 {
				break
			}
		}
		if d.Prom != nil {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool: "promql_range",
				Args: map[string]any{
					"query": `histogram_quantile(0.95, sum by (le) (rate(loxilb_proxy_http_ttfb_seconds_bucket[5m])))`,
					"step":  "60s",
				},
				Rationale: "quantiles above are lifetime aggregates; the alert fires on the 5m-rate p95 — confirm when it crossed 2s",
				Risk:      "none",
			})
		}
		out.Caveats = []string{
			"histogram quantiles are estimated from cumulative lifetime buckets, not a recent window",
			trafficReportCaveat,
		}
		d.finishDiagnose(&out)
		d.audit("diagnose_ai_latency", c.Name(), true, "")
		return nil, out, nil
	}
}

// ---- diagnose_endpoint ----

type diagnoseEndpointIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Host   string `json:"host" jsonschema:"endpoint IP or hostname to diagnose (as shown in endpoint_list / lb_list)"`
}

func (d *Deps) diagnoseEndpoint() sdk.ToolHandlerFor[diagnoseEndpointIn, diagnoseOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in diagnoseEndpointIn) (*sdk.CallToolResult, diagnoseOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, diagnoseOut{}, err
		}
		if strings.TrimSpace(in.Host) == "" {
			return nil, diagnoseOut{}, fmt.Errorf("host is required")
		}
		out := newDiagnoseOut(c.Name())
		host := strings.ToLower(strings.TrimSpace(in.Host))

		// 1. Probe entries for this host.
		var probeStates []map[string]any
		var env struct {
			Attr []map[string]any `json:"Attr"`
		}
		if err := c.Get(ctx, "/config/endpoint/all", &env); err != nil {
			out.fail("endpoint_probes", err)
		} else {
			for _, ep := range env.Attr {
				h, _ := ep["hostName"].(string)
				if !hostMatches(h, in.Host) {
					continue
				}
				probeStates = append(probeStates, sanitizeAny(ep, 0).(map[string]any))
				if len(probeStates) >= maxListItems {
					break
				}
			}
			out.Evidence["probe_entries"] = probeStates
		}

		// 2. LB rules referencing the endpoint.
		var referencing []map[string]any
		if rules, err := c.LBRules(ctx); err != nil {
			out.fail("lb_rules", err)
		} else {
			for _, r := range rules {
				eps, _ := r["endpoints"].([]any)
				for _, epRaw := range eps {
					ep, _ := epRaw.(map[string]any)
					if ep == nil {
						continue
					}
					ip, _ := ep["endpointIP"].(string)
					if !strings.EqualFold(ip, in.Host) {
						continue
					}
					svc, _ := r["serviceArguments"].(map[string]any)
					name, _ := svc["name"].(string)
					extIP, _ := svc["externalIP"].(string)
					referencing = append(referencing, map[string]any{
						"service": clean(name), "external_ip": clean(extIP),
						"port": svc["port"], "protocol": svc["protocol"],
						"endpoint_state": ep["state"], "weight": ep["weight"],
					})
					break
				}
				if len(referencing) >= maxListItems {
					break
				}
			}
			out.Evidence["lb_rules_referencing"] = referencing
			out.Evidence["lb_rules_referencing_count"] = len(referencing)
		}

		// 3. Conntrack flows toward the endpoint.
		if cts, err := c.Conntracks(ctx); err != nil {
			out.fail("conntrack", err)
		} else {
			byState := map[string]int{}
			var toward int
			for _, ct := range cts {
				if !strings.Contains(strings.ToLower(ct.DestinationIP), host) {
					continue
				}
				toward++
				byState[clean(strings.ToLower(ct.State))]++
			}
			out.Evidence["flows_toward_endpoint"] = toward
			out.Evidence["flows_by_state"] = byState
		}

		// Suggested follow-ups: drain is offered only when probes look bad.
		var badProbe bool
		for _, p := range probeStates {
			st, _ := p["currState"].(string)
			switch strings.ToLower(st) {
			case "ok", "green", "active", "up", "":
			default:
				badProbe = true
			}
		}
		if badProbe {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "endpoint_host_state_set",
				Args:      map[string]any{"host_name": in.Host, "state": "red", "target": in.Target},
				Rationale: "probes are failing — draining the endpoint stops new connections while it is investigated (reversible with state green)",
				Risk:      "medium",
			})
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "logs_tail",
				Args:      map[string]any{"keyword": in.Host, "target": in.Target},
				Rationale: "probe transitions for the endpoint are logged with the failure cause",
				Risk:      "none",
			})
		}
		d.finishDiagnose(&out)
		d.audit("diagnose_endpoint", c.Name(), true, "")
		return nil, out, nil
	}
}

// ---- capacity_report ----

func (d *Deps) capacityReport() sdk.ToolHandlerFor[targetIn, diagnoseOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in targetIn) (*sdk.CallToolResult, diagnoseOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, diagnoseOut{}, err
		}
		out := newDiagnoseOut(c.Name())

		// 1. Conntrack usage vs capacity + rule/endpoint gauges.
		var ctUsedPct float64 = -1
		if text, err := c.MetricsText(ctx); err != nil {
			out.fail("metrics", err)
		} else if fams, perr := client.ParseFamilies(text, []string{
			"loxilb_active_conntrack_entries", "loxilb_conntrack_max_entries",
			"loxilb_lb_rules", "loxilb_healthy_endpoints", "loxilb_unhealthy_endpoints",
			"loxilb_system_*_utilization_percent",
		}, 200); perr != nil {
			out.fail("metrics", perr)
		} else {
			gauges := map[string]float64{}
			for _, f := range fams {
				gauges[f.Name] = sumFamily(f)
			}
			out.Evidence["gauges"] = gauges
			if maxEnt := gauges["loxilb_conntrack_max_entries"]; maxEnt > 0 {
				ctUsedPct = 100 * gauges["loxilb_active_conntrack_entries"] / maxEnt
				out.Evidence["conntrack_used_percent"] = ctUsedPct
			}
		}

		// 2. Security rate-limit settings (observed thresholds vs capacity).
		var secRaw any
		if err := c.Get(ctx, "/config/securityrate/all", &secRaw); err != nil {
			out.fail("securityrate", err)
		} else {
			out.Evidence["security_rate_config"] = sanitizeAny(secRaw, 0)
		}

		// 3. Host resources.
		var devRaw any
		if err := c.Get(ctx, "/status/device", &devRaw); err != nil {
			out.fail("host_status", err)
		} else {
			out.Evidence["host_device_status"] = sanitizeAny(devRaw, 0)
		}

		// 4. Per-service traffic distribution (legacy JSON store; best-effort).
		var distRaw any
		if err := c.Get(ctx, "/metrics/servicedisttraffic", &distRaw); err != nil {
			out.fail("service_traffic_distribution", err)
		} else {
			out.Evidence["service_traffic_distribution"] = sanitizeAny(distRaw, 0)
		}

		// Suggested follow-ups.
		if ctUsedPct >= 80 {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "ct_list",
				Args:      map[string]any{"target": in.Target},
				Rationale: fmt.Sprintf("conntrack table at %.0f%% of capacity — check which states/services dominate before it saturates", ctUsedPct),
				Risk:      "none",
			})
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool:      "secrate_set",
				Args:      map[string]any{"conn_rate_enabled": true, "target": in.Target},
				Rationale: "if the growth is abusive, enabling/tightening the new-connection rate limit protects the table (set rate_per_sec to a value observed from ct churn)",
				Risk:      "medium",
			})
		}
		if d.Prom != nil {
			out.SuggestedActions = append(out.SuggestedActions, suggestedAction{
				Tool: "promql_range",
				Args: map[string]any{
					"query": `loxilb_active_conntrack_entries / loxilb_conntrack_max_entries`,
					"step":  "300s",
				},
				Rationale: "capacity trend over time shows whether usage is growing toward the 0.8/0.95 alert thresholds",
				Risk:      "none",
			})
		}
		d.finishDiagnose(&out)
		d.audit("capacity_report", c.Name(), true, "")
		return nil, out, nil
	}
}
