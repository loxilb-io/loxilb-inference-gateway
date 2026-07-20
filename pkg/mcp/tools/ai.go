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
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb/pkg/mcp/client"
	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
)

// f12Caveat is surfaced in every ai_traffic_report result (known caveat F12,
// docs/MCP-DESIGN.md §6): the request counter only sees SSE-terminated
// streams.
const f12Caveat = "F12: loxilb_ai_requests_total counts only SSE-terminated streams; " +
	"plain-JSON error responses are invisible in it. Rate-limit denials are only in " +
	"loxilb_ai_rate_limit_hits_total. Cross-check with loxilb_proxy_http_responses_total."

// RegisterAI adds the Phase-3 AI-gateway operation tools
// (docs/MCP-DESIGN.md §3.4). Read tools are viewer+, non-destructive
// mutations operator+, ai_apikey_delete admin-only behind the confirm-token
// flow. Raw API-key material never enters model context by default (T5):
// ai_apikey_create writes the key to SecretsDir unless reveal=true.
func RegisterAI(s *sdk.Server, role guard.Role, pol *guard.Policy, deps *Deps) {
	reg := func(meta guard.ToolMeta, add func()) {
		meta.Domain = domainAI
		if pol.Permits(role, meta) {
			add()
		}
	}
	ro := func(name string) guard.ToolMeta { return guard.ToolMeta{Name: name} }
	mut := func(name string) guard.ToolMeta { return guard.ToolMeta{Name: name, Mutating: true} }
	dest := func(name string) guard.ToolMeta {
		return guard.ToolMeta{Name: name, Mutating: true, Destructive: true}
	}

	// ---- read tools ----

	reg(ro("ai_apikey_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "ai_apikey_list",
			Description: "List AI-gateway API keys, optionally filtered by tenant (GET /config/ai/apikey). Returns key metadata only, never key material.",
			Annotations: roAnnotations("List AI API keys"),
		}, deps.aiApikeyList())
	})
	reg(ro("ai_apikey_get"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "ai_apikey_get",
			Description: "Get one AI-gateway API key summary by key_id (GET /config/ai/apikey/{key_id}). Metadata only, never key material.",
			Annotations: roAnnotations("Get AI API key"),
		}, deps.aiApikeyGet())
	})
	reg(ro("ai_ratelimit_get"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "ai_ratelimit_get",
			Description: "Get the per-tenant AI rate-limit configuration (GET /config/ai/tenant/ratelimit/{tenant_id}): requests/s and LLM tokens/min quotas.",
			Annotations: roAnnotations("Get tenant AI rate limit"),
		}, deps.aiRatelimitGet())
	})
	reg(ro("ai_kv_inventory_get"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "ai_kv_inventory_get",
			Description: "Dump the KV-cache block hash inventory tracked for one endpoint of an AI service " +
				"(GET /config/ai/kv/inventory?service_id&ep_idx). Returns total block count and a bounded hash sample.",
			Annotations: roAnnotations("Get KV-cache inventory"),
		}, deps.aiKvInventoryGet())
	})
	reg(ro("gpu_status"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "gpu_status",
			Description: "Get GPU-aware load-balancing status and statistics (GET /config/gpu/status).",
			Annotations: roAnnotations("Get GPU monitoring status"),
		}, deps.passthrough("gpu_status", "/config/gpu/status"))
	})
	reg(ro("gpu_worker_metrics_get"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "gpu_worker_metrics_get",
			Description: "Get current GPU metrics for all tracked workers as reported by the metrics agent (GET /config/worker/metrics).",
			Annotations: roAnnotations("Get GPU worker metrics"),
		}, deps.passthrough("gpu_worker_metrics_get", "/config/worker/metrics"))
	})
	reg(ro("llamafw_status"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "llamafw_status",
			Description: "Get LlamaFirewall AI-security scanner status: enabled flag, server connection, policy, enabled scanners (GET /config/llamafirewall/status).",
			Annotations: roAnnotations("Get LlamaFirewall status"),
		}, deps.passthrough("llamafw_status", "/config/llamafirewall/status"))
	})
	reg(ro("llamafw_stats"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "llamafw_stats",
			Description: "Get LlamaFirewall scanning statistics: scans, blocks, per-scanner performance and decisions (GET /config/llamafirewall/stats).",
			Annotations: roAnnotations("Get LlamaFirewall stats"),
		}, deps.passthrough("llamafw_stats", "/config/llamafirewall/stats"))
	})
	reg(ro("pii_status"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "pii_status",
			Description: "Get PII-detection (Presidio) configuration and status (GET /config/pii/status).",
			Annotations: roAnnotations("Get PII detection status"),
		}, deps.passthrough("pii_status", "/config/pii/status"))
	})
	reg(ro("pii_stats"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "pii_stats",
			Description: "Get PII-detection statistics: scans, detections, blocks, errors (GET /config/pii/stats).",
			Annotations: roAnnotations("Get PII detection stats"),
		}, deps.passthrough("pii_stats", "/config/pii/stats"))
	})
	reg(ro("ai_traffic_report"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "ai_traffic_report",
			Description: "Composite AI-gateway traffic report from the loxilb_ai_* metric families: per-model/tenant " +
				"request counts by status, error ratio, rate-limit drops, active streams, latency quantiles " +
				"(request duration, L7 TTFB, PD TTFT) and KV-cache session-affinity counters. Values are " +
				"cumulative counters since process start; use promql_query rate() for rates.",
			Annotations: roAnnotations("AI traffic report"),
		}, deps.aiTrafficReport())
	})

	// ---- mutating, non-destructive (operator+) ----

	reg(mut("ai_apikey_create"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "ai_apikey_create",
			Description: "Create a tenant API key (POST /config/ai/apikey): allowed models, rps/burst/tokens-per-min " +
				"quotas, optional expiry. The raw key exists only once: by default it is written to a mode-0600 file " +
				"on the bridge host and only the file path is returned; pass reveal=true to return it inline instead (discouraged).",
			Annotations: mutAnnotations("Create AI API key", false),
		}, deps.aiApikeyCreate())
	})
	reg(mut("ai_apikey_update"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "ai_apikey_update",
			Description: "Update an API key's allowed-model list and/or enabled flag (PATCH /config/ai/apikey/{key_id}). Disabling a key is reversible; deleting is not.",
			Annotations: mutAnnotations("Update AI API key", true),
		}, deps.aiApikeyUpdate())
	})
	reg(mut("ai_ratelimit_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "ai_ratelimit_set",
			Description: "Create or update a tenant's AI rate limit (POST /config/ai/tenant/ratelimit): requests/s and " +
				"LLM tokens/min. There is no delete endpoint; to lift a limit set the quotas to 0 (unlimited).",
			Annotations: mutAnnotations("Set tenant AI rate limit", true),
		}, deps.aiRatelimitSet())
	})
	reg(mut("gpu_mode_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "gpu_mode_set",
			Description: "Enable or disable GPU-aware load balancing (POST /config/gpu/enable | /config/gpu/disable). Disabling reverts to standard CHWBL routing.",
			Annotations: mutAnnotations("Set GPU-aware mode", true),
		}, deps.gpuModeSet())
	})
	reg(mut("gpu_conversations_cleanup"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "gpu_conversations_cleanup",
			Description: "Remove stale GPU conversation mappings older than max_age_hours (POST /config/gpu/conversations/cleanup).",
			Annotations: mutAnnotations("Clean up GPU conversations", true),
		}, deps.gpuConversationsCleanup())
	})
	reg(mut("llamafw_enable_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "llamafw_enable_set",
			Description: "Enable or disable LlamaFirewall AI-security scanning (POST /config/llamafirewall/enable).",
			Annotations: mutAnnotations("Toggle LlamaFirewall", true),
		}, deps.enableFlagTool("llamafw_enable_set", "/config/llamafirewall/enable"))
	})
	reg(mut("llamafw_configure"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "llamafw_configure",
			Description: "Configure LlamaFirewall scanning (POST /config/llamafirewall/configure): server URL, timeout, " +
				"fail policy, block threshold, caching, scan/skip URL patterns. Only supplied fields are sent.",
			Annotations: mutAnnotations("Configure LlamaFirewall", true),
		}, deps.llamafwConfigure())
	})
	reg(mut("llamafw_scanners_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "llamafw_scanners_set",
			Description: "Enable/disable individual LlamaFirewall scanners (POST /config/llamafirewall/scanners): " +
				"prompt_guard, code_shield, regex, hidden_ascii, agent_alignment, pii_detection. Only supplied fields are sent.",
			Annotations: mutAnnotations("Set LlamaFirewall scanners", true),
		}, deps.llamafwScannersSet())
	})
	reg(mut("llamafw_health_check"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "llamafw_health_check",
			Description: "Trigger a connectivity/health check of the LlamaFirewall gRPC server (POST /config/llamafirewall/health).",
			Annotations: mutAnnotations("LlamaFirewall health check", true),
		}, deps.postSimple("llamafw_health_check", "/config/llamafirewall/health"))
	})
	reg(mut("pii_enable_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "pii_enable_set",
			Description: "Enable or disable PII detection for HTTP/HTTPS traffic (POST /config/pii/enable).",
			Annotations: mutAnnotations("Toggle PII detection", true),
		}, deps.enableFlagTool("pii_enable_set", "/config/pii/enable"))
	})
	reg(mut("pii_configure"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "pii_configure",
			Description: "Configure PII detection (POST /config/pii/configure): mode detect|mask|redact|anonymize, " +
				"direction, fail mode, scan mode, Presidio analyzer/anonymizer URLs, score threshold, timeout. Only supplied fields are sent.",
			Annotations: mutAnnotations("Configure PII detection", true),
		}, deps.piiConfigure())
	})
	reg(mut("pii_url_patterns_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "pii_url_patterns_set",
			Description: "Add, replace, or clear the URL patterns selecting which requests are PII-scanned (POST /config/pii/url-patterns).",
			Annotations: mutAnnotations("Set PII URL patterns", true),
		}, deps.piiURLPatternsSet())
	})

	// ---- destructive (admin, confirm-token) ----

	reg(dest("ai_apikey_delete"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "ai_apikey_delete",
			Description: "Permanently delete an API key by key_id (DELETE /config/ai/apikey/{key_id}). Irreversible — " +
				"clients using the key lose access immediately (consider ai_apikey_update enabled=false instead). " +
				"Two-step confirm-token flow: first call previews, second call with confirm_token executes.",
			Annotations: destAnnotations("Delete AI API key"),
		}, deps.aiApikeyDelete())
	})
}

// stripKeyMaterial removes any raw-key-shaped field from decoded REST
// responses before they reach model context (T5 defense in depth; list/get
// responses must never carry key material, but do not rely on it).
func stripKeyMaterial(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			lk := strings.ToLower(k)
			if lk == "raw_key" || lk == "rawkey" || lk == "api_key" || lk == "apikey" ||
				lk == "secret" || lk == "token" {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = stripKeyMaterial(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = stripKeyMaterial(val)
		}
		return out
	default:
		return v
	}
}

// ---- ai_apikey_list / ai_apikey_get ----

type apikeyListIn struct {
	Target   string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	TenantID string `json:"tenant_id,omitempty" jsonschema:"filter keys by tenant id"`
}

func (d *Deps) aiApikeyList() sdk.ToolHandlerFor[apikeyListIn, map[string]any] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in apikeyListIn) (*sdk.CallToolResult, map[string]any, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, nil, err
		}
		q := url.Values{}
		if in.TenantID != "" {
			q.Set("tenant_id", in.TenantID)
		}
		var raw any
		if err := c.GetQ(ctx, "/config/ai/apikey", q, &raw); err != nil {
			d.audit("ai_apikey_list", c.Name(), false, err.Error())
			return nil, nil, err
		}
		d.audit("ai_apikey_list", c.Name(), true, "")
		return nil, map[string]any{
			"target": c.Name(),
			"keys":   stripKeyMaterial(sanitizeAny(raw, 0)),
		}, nil
	}
}

type apikeyGetIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	KeyID  string `json:"key_id" jsonschema:"API key identifier from ai_apikey_list"`
}

func (d *Deps) aiApikeyGet() sdk.ToolHandlerFor[apikeyGetIn, map[string]any] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in apikeyGetIn) (*sdk.CallToolResult, map[string]any, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, nil, err
		}
		if err := validatePathSegment(in.KeyID); err != nil {
			return nil, nil, fmt.Errorf("key_id: %w", err)
		}
		var raw any
		if err := c.Get(ctx, "/config/ai/apikey/"+url.PathEscape(in.KeyID), &raw); err != nil {
			d.audit("ai_apikey_get", c.Name(), false, err.Error())
			return nil, nil, err
		}
		d.audit("ai_apikey_get", c.Name(), true, "")
		return nil, map[string]any{
			"target": c.Name(),
			"key":    stripKeyMaterial(sanitizeAny(raw, 0)),
		}, nil
	}
}

// ---- ai_apikey_create ----

type apikeyCreateIn struct {
	Target        string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	TenantID      string   `json:"tenant_id" jsonschema:"tenant that owns the key"`
	Name          string   `json:"name,omitempty" jsonschema:"human-readable key label"`
	AllowedModels []string `json:"allowed_models,omitempty" jsonschema:"model identifiers this key may access; empty allows all"`
	RateLimitRPS  int      `json:"rate_limit_rps,omitempty" jsonschema:"max requests per second for this key"`
	BurstSize     int      `json:"burst_size,omitempty" jsonschema:"burst capacity above the steady-state limit"`
	TokensPerMin  int      `json:"tokens_per_min,omitempty" jsonschema:"max LLM tokens per minute for this key"`
	ExpiresAt     string   `json:"expires_at,omitempty" jsonschema:"optional expiry timestamp (RFC3339)"`
	Reveal        bool     `json:"reveal,omitempty" jsonschema:"true to return the raw key inline instead of writing it to a file on the bridge host (discouraged: the key then enters model context)"`
}

type apikeyCreateOut struct {
	Target  string `json:"target"`
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file,omitempty"`
	// RawKey is set only when reveal=true was requested explicitly.
	RawKey string `json:"raw_key,omitempty"`
	Note   string `json:"note"`
}

func (d *Deps) aiApikeyCreate() sdk.ToolHandlerFor[apikeyCreateIn, apikeyCreateOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in apikeyCreateIn) (*sdk.CallToolResult, apikeyCreateOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, apikeyCreateOut{}, err
		}
		if strings.TrimSpace(in.TenantID) == "" {
			return nil, apikeyCreateOut{}, fmt.Errorf("tenant_id is required")
		}
		if !in.Reveal && d.SecretsDir == "" {
			return nil, apikeyCreateOut{}, fmt.Errorf("no secrets_dir configured on the bridge; " +
				"configure one or pass reveal=true to accept the key in the response")
		}
		body := map[string]any{"tenant_id": in.TenantID}
		if in.Name != "" {
			body["name"] = in.Name
		}
		if len(in.AllowedModels) > 0 {
			body["allowed_models"] = in.AllowedModels
		}
		if in.RateLimitRPS > 0 {
			body["rate_limit_rps"] = in.RateLimitRPS
		}
		if in.BurstSize > 0 {
			body["burst_size"] = in.BurstSize
		}
		if in.TokensPerMin > 0 {
			body["tokens_per_min"] = in.TokensPerMin
		}
		if in.ExpiresAt != "" {
			body["expires_at"] = in.ExpiresAt
		}
		var res struct {
			RawKey string `json:"raw_key"`
			KeyID  string `json:"key_id"`
		}
		if err := c.Post(ctx, "/config/ai/apikey", body, &res); err != nil {
			d.auditMut("ai_apikey_create", c.Name(), in, false, err.Error())
			return nil, apikeyCreateOut{}, err
		}
		out := apikeyCreateOut{Target: c.Name(), KeyID: clean(res.KeyID)}
		if in.Reveal {
			out.RawKey = res.RawKey
			out.Note = "raw key returned inline on explicit request; it is shown ONCE and cannot be retrieved again"
		} else {
			path, werr := writeSecretFile(d.SecretsDir, "apikey-"+sanitizeFileToken(res.KeyID), res.RawKey)
			if werr != nil {
				d.auditMut("ai_apikey_create", c.Name(), in, false, "secret file: "+werr.Error())
				return nil, apikeyCreateOut{}, fmt.Errorf("key %s created but writing the secret file failed: %w; "+
					"delete and re-create the key (the raw key is not recoverable)", clean(res.KeyID), werr)
			}
			out.KeyFile = path
			out.Note = "raw key written to key_file (mode 0600) on the bridge host; it is stored NOWHERE else and cannot be retrieved again"
		}
		d.auditMut("ai_apikey_create", c.Name(), in, true, "")
		return nil, out, nil
	}
}

// sanitizeFileToken reduces a server-supplied id to a safe filename fragment.
func sanitizeFileToken(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// writeSecretFile writes content to dir/<name>.key with 0600 perms (dir
// created 0700), refusing to overwrite an existing file.
func writeSecretFile(dir, name, content string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".key")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content + "\n"); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close()
}

// ---- ai_apikey_update ----

type apikeyUpdateIn struct {
	Target        string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	KeyID         string   `json:"key_id" jsonschema:"API key identifier"`
	AllowedModels []string `json:"allowed_models,omitempty" jsonschema:"replacement list of models the key may access"`
	Enabled       *bool    `json:"enabled,omitempty" jsonschema:"enable or disable the key"`
}

func (d *Deps) aiApikeyUpdate() sdk.ToolHandlerFor[apikeyUpdateIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in apikeyUpdateIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := validatePathSegment(in.KeyID); err != nil {
			return nil, mutOut{}, fmt.Errorf("key_id: %w", err)
		}
		body := map[string]any{}
		if in.AllowedModels != nil {
			body["allowed_models"] = in.AllowedModels
		}
		if in.Enabled != nil {
			body["enabled"] = *in.Enabled
		}
		if len(body) == 0 {
			return nil, mutOut{}, fmt.Errorf("no fields to update (allowed_models and/or enabled)")
		}
		var res any
		if err := c.Patch(ctx, "/config/ai/apikey/"+url.PathEscape(in.KeyID), body, &res); err != nil {
			d.auditMut("ai_apikey_update", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("ai_apikey_update", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- ai_apikey_delete ----

type apikeyDeleteIn struct {
	Target       string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	KeyID        string `json:"key_id" jsonschema:"API key identifier to delete"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"single-use token from the preview step; omit to preview"`
}

func (d *Deps) aiApikeyDelete() sdk.ToolHandlerFor[apikeyDeleteIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in apikeyDeleteIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := validatePathSegment(in.KeyID); err != nil {
			return nil, mutOut{}, fmt.Errorf("key_id: %w", err)
		}
		args := in
		args.ConfirmToken = ""
		if d.Confirm != nil && in.ConfirmToken == "" {
			preview := d.aiApikeyDeletePreview(ctx, c, in.KeyID)
			out, stop, err := d.gateDestructive("ai_apikey_delete", c.Name(), "", args, preview)
			if err != nil || stop {
				return nil, out, err
			}
		} else {
			if _, _, err := d.gateDestructive("ai_apikey_delete", c.Name(), in.ConfirmToken, args, nil); err != nil {
				return nil, mutOut{}, err
			}
		}
		var res any
		if err := c.Delete(ctx, "/config/ai/apikey/"+url.PathEscape(in.KeyID), &res); err != nil {
			d.auditMut("ai_apikey_delete", c.Name(), args, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("ai_apikey_delete", c.Name(), args, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// aiApikeyDeletePreview best-effort fetches the key summary about to be deleted.
func (d *Deps) aiApikeyDeletePreview(ctx context.Context, c *client.Client, keyID string) any {
	var raw any
	if err := c.Get(ctx, "/config/ai/apikey/"+url.PathEscape(keyID), &raw); err != nil {
		return map[string]any{"error": "preview unavailable: " + clean(err.Error())}
	}
	return map[string]any{"deleting_key": stripKeyMaterial(sanitizeAny(raw, 0))}
}

// ---- ai_ratelimit_get / ai_ratelimit_set ----

type ratelimitGetIn struct {
	Target   string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	TenantID string `json:"tenant_id" jsonschema:"tenant identifier"`
}

func (d *Deps) aiRatelimitGet() sdk.ToolHandlerFor[ratelimitGetIn, map[string]any] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in ratelimitGetIn) (*sdk.CallToolResult, map[string]any, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, nil, err
		}
		if err := validatePathSegment(in.TenantID); err != nil {
			return nil, nil, fmt.Errorf("tenant_id: %w", err)
		}
		var raw any
		if err := c.Get(ctx, "/config/ai/tenant/ratelimit/"+url.PathEscape(in.TenantID), &raw); err != nil {
			d.audit("ai_ratelimit_get", c.Name(), false, err.Error())
			return nil, nil, err
		}
		d.audit("ai_ratelimit_get", c.Name(), true, "")
		return nil, map[string]any{"target": c.Name(), "ratelimit": sanitizeAny(raw, 0)}, nil
	}
}

type ratelimitSetIn struct {
	Target       string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	TenantID     string `json:"tenant_id" jsonschema:"tenant identifier"`
	RPS          int    `json:"rps" jsonschema:"max requests per second (0 = unlimited)"`
	TokensPerMin int    `json:"tokens_per_min" jsonschema:"max LLM tokens per minute (0 = unlimited)"`
}

func (d *Deps) aiRatelimitSet() sdk.ToolHandlerFor[ratelimitSetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in ratelimitSetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if strings.TrimSpace(in.TenantID) == "" {
			return nil, mutOut{}, fmt.Errorf("tenant_id is required")
		}
		if in.RPS < 0 || in.TokensPerMin < 0 {
			return nil, mutOut{}, fmt.Errorf("rps and tokens_per_min must be >= 0")
		}
		body := map[string]any{
			"tenant_id":      in.TenantID,
			"rps":            in.RPS,
			"tokens_per_min": in.TokensPerMin,
		}
		var res any
		if err := c.Post(ctx, "/config/ai/tenant/ratelimit", body, &res); err != nil {
			d.auditMut("ai_ratelimit_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("ai_ratelimit_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- ai_kv_inventory_get ----

type kvInventoryIn struct {
	Target    string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	ServiceID int64  `json:"service_id" jsonschema:"numeric AI service identifier"`
	EpIdx     int    `json:"ep_idx" jsonschema:"endpoint index within the service"`
	MaxBlocks int    `json:"max_blocks,omitempty" jsonschema:"cap on returned block hashes (default 50, max 500); total is always reported"`
}

type kvInventoryOut struct {
	Target    string `json:"target"`
	ServiceID int64  `json:"service_id"`
	EpIdx     int    `json:"ep_idx"`
	HashAlgo  string `json:"hash_algo,omitempty"`
	Total     int    `json:"total"`
	Returned  int    `json:"returned"`
	Blocks    []any  `json:"blocks,omitempty"`
}

func (d *Deps) aiKvInventoryGet() sdk.ToolHandlerFor[kvInventoryIn, kvInventoryOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in kvInventoryIn) (*sdk.CallToolResult, kvInventoryOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, kvInventoryOut{}, err
		}
		if in.ServiceID < 0 || in.EpIdx < 0 {
			return nil, kvInventoryOut{}, fmt.Errorf("service_id and ep_idx must be >= 0")
		}
		limit := in.MaxBlocks
		if limit <= 0 {
			limit = 50
		}
		if limit > 500 {
			limit = 500
		}
		q := url.Values{
			"service_id": {strconv.FormatInt(in.ServiceID, 10)},
			"ep_idx":     {strconv.Itoa(in.EpIdx)},
		}
		var env struct {
			HashAlgo string `json:"hash_algo"`
			Blocks   []any  `json:"blocks"`
			Total    int    `json:"total"`
		}
		if err := c.GetQ(ctx, "/config/ai/kv/inventory", q, &env); err != nil {
			d.audit("ai_kv_inventory_get", c.Name(), false, err.Error())
			return nil, kvInventoryOut{}, err
		}
		out := kvInventoryOut{
			Target:    c.Name(),
			ServiceID: in.ServiceID,
			EpIdx:     in.EpIdx,
			HashAlgo:  clean(env.HashAlgo),
			Total:     env.Total,
		}
		if out.Total == 0 {
			out.Total = len(env.Blocks)
		}
		blocks := env.Blocks
		if len(blocks) > limit {
			blocks = blocks[:limit]
		}
		for _, b := range blocks {
			out.Blocks = append(out.Blocks, sanitizeAny(b, 0))
		}
		out.Returned = len(out.Blocks)
		d.audit("ai_kv_inventory_get", c.Name(), true, "")
		return nil, out, nil
	}
}

// ---- gpu_mode_set / gpu_conversations_cleanup ----

type gpuModeIn struct {
	Target  string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Enabled bool   `json:"enabled" jsonschema:"true to enable GPU-aware routing, false to disable"`
}

func (d *Deps) gpuModeSet() sdk.ToolHandlerFor[gpuModeIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in gpuModeIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		path := "/config/gpu/disable"
		if in.Enabled {
			path = "/config/gpu/enable"
		}
		var res any
		if err := c.Post(ctx, path, nil, &res); err != nil {
			d.auditMut("gpu_mode_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("gpu_mode_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type gpuCleanupIn struct {
	Target      string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	MaxAgeHours int    `json:"max_age_hours,omitempty" jsonschema:"delete conversation mappings older than this (default 1)"`
}

func (d *Deps) gpuConversationsCleanup() sdk.ToolHandlerFor[gpuCleanupIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in gpuCleanupIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		path := "/config/gpu/conversations/cleanup"
		if in.MaxAgeHours > 0 {
			path += "?max_age_hours=" + strconv.Itoa(in.MaxAgeHours)
		}
		var res any
		if err := c.Post(ctx, path, nil, &res); err != nil {
			d.auditMut("gpu_conversations_cleanup", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("gpu_conversations_cleanup", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- shared simple mutators ----

type enableFlagIn struct {
	Target  string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Enabled bool   `json:"enabled" jsonschema:"true to enable, false to disable"`
}

// enableFlagTool POSTs {"enabled": bool} to a fixed path.
func (d *Deps) enableFlagTool(tool, path string) sdk.ToolHandlerFor[enableFlagIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in enableFlagIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		var res any
		if err := c.Post(ctx, path, map[string]any{"enabled": in.Enabled}, &res); err != nil {
			d.auditMut(tool, c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut(tool, c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// postSimple POSTs an empty body to a fixed path (trigger-style endpoints).
func (d *Deps) postSimple(tool, path string) sdk.ToolHandlerFor[targetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in targetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		var res any
		if err := c.Post(ctx, path, nil, &res); err != nil {
			d.auditMut(tool, c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut(tool, c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- llamafw_configure / llamafw_scanners_set ----

type llamafwConfigureIn struct {
	Target             string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	ServerURL          string   `json:"server_url,omitempty" jsonschema:"LlamaFirewall gRPC server URL, e.g. localhost:50052"`
	TimeoutSec         int      `json:"timeout_sec,omitempty" jsonschema:"request timeout seconds (1-300)"`
	FailClosed         *bool    `json:"fail_closed,omitempty" jsonschema:"true blocks on scanner error, false allows"`
	BlockThreshold     *float64 `json:"block_threshold,omitempty" jsonschema:"minimum confidence score to block (0.0-1.0)"`
	CacheEnabled       *bool    `json:"cache_enabled,omitempty" jsonschema:"cache identical scan results"`
	CacheTTLSec        int      `json:"cache_ttl_sec,omitempty" jsonschema:"cache TTL seconds"`
	ConnectionPoolSize int      `json:"connection_pool_size,omitempty" jsonschema:"reusable gRPC connections (1-100)"`
	ScanPatterns       []string `json:"scan_patterns,omitempty" jsonschema:"URL patterns to scan (empty = all)"`
	SkipPatterns       []string `json:"skip_patterns,omitempty" jsonschema:"URL patterns to skip"`
}

func (d *Deps) llamafwConfigure() sdk.ToolHandlerFor[llamafwConfigureIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in llamafwConfigureIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		body := map[string]any{}
		if in.ServerURL != "" {
			body["server_url"] = in.ServerURL
		}
		if in.TimeoutSec > 0 {
			body["timeout_sec"] = in.TimeoutSec
		}
		if in.FailClosed != nil {
			body["fail_closed"] = *in.FailClosed
		}
		if in.BlockThreshold != nil {
			if *in.BlockThreshold < 0 || *in.BlockThreshold > 1 {
				return nil, mutOut{}, fmt.Errorf("block_threshold: %g out of range 0.0-1.0", *in.BlockThreshold)
			}
			body["block_threshold"] = *in.BlockThreshold
		}
		if in.CacheEnabled != nil {
			body["cache_enabled"] = *in.CacheEnabled
		}
		if in.CacheTTLSec > 0 {
			body["cache_ttl_sec"] = in.CacheTTLSec
		}
		if in.ConnectionPoolSize > 0 {
			body["connection_pool_size"] = in.ConnectionPoolSize
		}
		if in.ScanPatterns != nil {
			body["scan_patterns"] = in.ScanPatterns
		}
		if in.SkipPatterns != nil {
			body["skip_patterns"] = in.SkipPatterns
		}
		if len(body) == 0 {
			return nil, mutOut{}, fmt.Errorf("no fields to set")
		}
		var res any
		if err := c.Post(ctx, "/config/llamafirewall/configure", body, &res); err != nil {
			d.auditMut("llamafw_configure", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("llamafw_configure", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type llamafwScannersIn struct {
	Target         string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	PromptGuard    *bool  `json:"prompt_guard,omitempty" jsonschema:"ML-based prompt injection detection"`
	CodeShield     *bool  `json:"code_shield,omitempty" jsonschema:"insecure code pattern detection"`
	Regex          *bool  `json:"regex,omitempty" jsonschema:"credential/API key leak detection"`
	HiddenASCII    *bool  `json:"hidden_ascii,omitempty" jsonschema:"zero-width/invisible character detection"`
	AgentAlignment *bool  `json:"agent_alignment,omitempty" jsonschema:"AI agent misalignment detection"`
	PIIDetection   *bool  `json:"pii_detection,omitempty" jsonschema:"PII detection (complementary to Presidio)"`
}

func (d *Deps) llamafwScannersSet() sdk.ToolHandlerFor[llamafwScannersIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in llamafwScannersIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		body := map[string]any{}
		set := func(k string, v *bool) {
			if v != nil {
				body[k] = *v
			}
		}
		set("prompt_guard", in.PromptGuard)
		set("code_shield", in.CodeShield)
		set("regex", in.Regex)
		set("hidden_ascii", in.HiddenASCII)
		set("agent_alignment", in.AgentAlignment)
		set("pii_detection", in.PIIDetection)
		if len(body) == 0 {
			return nil, mutOut{}, fmt.Errorf("no scanners to set")
		}
		var res any
		if err := c.Post(ctx, "/config/llamafirewall/scanners", body, &res); err != nil {
			d.auditMut("llamafw_scanners_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("llamafw_scanners_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- pii_configure / pii_url_patterns_set ----

type piiConfigureIn struct {
	Target         string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Mode           string   `json:"mode,omitempty" jsonschema:"detect|mask|redact|anonymize"`
	Direction      string   `json:"direction,omitempty" jsonschema:"both|request|response"`
	FailMode       string   `json:"fail_mode,omitempty" jsonschema:"open|closed (behavior when Presidio is unreachable)"`
	ScanMode       string   `json:"scan_mode,omitempty" jsonschema:"full|truncate (large body handling)"`
	AnalyzerURL    string   `json:"analyzer_url,omitempty" jsonschema:"Presidio analyzer gRPC endpoint"`
	AnonymizerURL  string   `json:"anonymizer_url,omitempty" jsonschema:"Presidio anonymizer gRPC endpoint"`
	ScoreThreshold *float64 `json:"score_threshold,omitempty" jsonschema:"minimum PII confidence score (0.0-1.0)"`
	TimeoutMs      int      `json:"timeout_ms,omitempty" jsonschema:"Presidio request timeout milliseconds"`
}

func (d *Deps) piiConfigure() sdk.ToolHandlerFor[piiConfigureIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in piiConfigureIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		oneOf := func(field, v string, allowed ...string) error {
			if v == "" {
				return nil
			}
			for _, a := range allowed {
				if strings.EqualFold(v, a) {
					return nil
				}
			}
			return fmt.Errorf("%s: %q (want %s)", field, v, strings.Join(allowed, "|"))
		}
		if err := oneOf("mode", in.Mode, "detect", "mask", "redact", "anonymize"); err != nil {
			return nil, mutOut{}, err
		}
		if err := oneOf("direction", in.Direction, "both", "request", "response"); err != nil {
			return nil, mutOut{}, err
		}
		if err := oneOf("fail_mode", in.FailMode, "open", "closed"); err != nil {
			return nil, mutOut{}, err
		}
		if err := oneOf("scan_mode", in.ScanMode, "full", "truncate"); err != nil {
			return nil, mutOut{}, err
		}
		body := map[string]any{}
		setS := func(k, v string) {
			if v != "" {
				body[k] = strings.ToLower(v)
			}
		}
		setS("mode", in.Mode)
		setS("direction", in.Direction)
		setS("fail_mode", in.FailMode)
		setS("scan_mode", in.ScanMode)
		if in.AnalyzerURL != "" {
			body["analyzer_url"] = in.AnalyzerURL
		}
		if in.AnonymizerURL != "" {
			body["anonymizer_url"] = in.AnonymizerURL
		}
		if in.ScoreThreshold != nil {
			if *in.ScoreThreshold < 0 || *in.ScoreThreshold > 1 {
				return nil, mutOut{}, fmt.Errorf("score_threshold: %g out of range 0.0-1.0", *in.ScoreThreshold)
			}
			body["score_threshold"] = *in.ScoreThreshold
		}
		if in.TimeoutMs > 0 {
			body["timeout_ms"] = in.TimeoutMs
		}
		if len(body) == 0 {
			return nil, mutOut{}, fmt.Errorf("no fields to set")
		}
		var res any
		if err := c.Post(ctx, "/config/pii/configure", body, &res); err != nil {
			d.auditMut("pii_configure", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("pii_configure", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type piiURLPatternIn struct {
	Pattern string `json:"pattern" jsonschema:"URL pattern (e.g. /api/v1/chat*)"`
	Exclude bool   `json:"exclude,omitempty" jsonschema:"true to exclude matching URLs from scanning"`
}

type piiURLPatternsIn struct {
	Target   string            `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Mode     string            `json:"mode" jsonschema:"add|replace|clear"`
	Patterns []piiURLPatternIn `json:"patterns,omitempty" jsonschema:"URL patterns (max 64; not needed for mode=clear)"`
}

func (d *Deps) piiURLPatternsSet() sdk.ToolHandlerFor[piiURLPatternsIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in piiURLPatternsIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		mode := strings.ToLower(in.Mode)
		switch mode {
		case "add", "replace", "clear":
		default:
			return nil, mutOut{}, fmt.Errorf("mode: %q (want add|replace|clear)", in.Mode)
		}
		if mode != "clear" && len(in.Patterns) == 0 {
			return nil, mutOut{}, fmt.Errorf("patterns: at least one pattern is required for mode %s", mode)
		}
		if len(in.Patterns) > 64 {
			return nil, mutOut{}, fmt.Errorf("patterns: %d exceeds the maximum of 64", len(in.Patterns))
		}
		body := map[string]any{"mode": mode}
		if len(in.Patterns) > 0 {
			pats := make([]map[string]any, 0, len(in.Patterns))
			for i, p := range in.Patterns {
				if p.Pattern == "" {
					return nil, mutOut{}, fmt.Errorf("patterns[%d].pattern is required", i)
				}
				pat := map[string]any{"pattern": p.Pattern}
				if p.Exclude {
					pat["exclude"] = true
				}
				pats = append(pats, pat)
			}
			body["patterns"] = pats
		}
		var res any
		if err := c.Post(ctx, "/config/pii/url-patterns", body, &res); err != nil {
			d.auditMut("pii_url_patterns_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("pii_url_patterns_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- ai_traffic_report ----

type trafficReportIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
}

type latencySummary struct {
	Count float64 `json:"count"`
	SumS  float64 `json:"sum_seconds"`
	P50S  float64 `json:"p50_seconds"`
	P95S  float64 `json:"p95_seconds"`
	P99S  float64 `json:"p99_seconds"`
}

type trafficReportOut struct {
	Target string `json:"target"`
	// Requests: cumulative loxilb_ai_requests_total broken down by
	// model/tenant/status, plus the derived non-2xx ratio.
	RequestsByModelTenantStatus []map[string]any `json:"requests_by_model_tenant_status,omitempty"`
	RequestsTotal               float64          `json:"requests_total"`
	RequestsNon2xx              float64          `json:"requests_non_2xx"`
	ErrorRatio                  float64          `json:"error_ratio"`
	RateLimitDrops              []map[string]any `json:"rate_limit_drops,omitempty"`
	RateLimitDropsTotal         float64          `json:"rate_limit_drops_total"`
	ModelNotAllowed             []map[string]any `json:"model_not_allowed,omitempty"`
	ActiveStreams               []map[string]any `json:"active_streams,omitempty"`
	RequestDuration             *latencySummary  `json:"request_duration,omitempty"`
	ProxyTTFB                   *latencySummary  `json:"proxy_ttfb,omitempty"`
	PDDecodeTTFT                *latencySummary  `json:"pd_decode_ttft,omitempty"`
	KVParamsFound               float64          `json:"kv_params_found"`
	KVParamsMissing             float64          `json:"kv_params_missing"`
	PDSessionHits               float64          `json:"pd_session_hits"`
	NormalSessionHits           float64          `json:"normal_session_hits"`
	Caveats                     []string         `json:"caveats"`
}

func (d *Deps) aiTrafficReport() sdk.ToolHandlerFor[trafficReportIn, trafficReportOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in trafficReportIn) (*sdk.CallToolResult, trafficReportOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, trafficReportOut{}, err
		}
		text, err := c.MetricsText(ctx)
		if err != nil {
			d.audit("ai_traffic_report", c.Name(), false, err.Error())
			return nil, trafficReportOut{}, err
		}
		fams, err := client.ParseFamilies(text, []string{
			"loxilb_ai_*", "loxilb_proxy_http_ttfb_seconds",
		}, 2000)
		if err != nil {
			return nil, trafficReportOut{}, err
		}
		byName := map[string]client.Family{}
		for _, f := range fams {
			byName[f.Name] = f
		}

		out := trafficReportOut{
			Target: c.Name(),
			Caveats: []string{
				f12Caveat,
				"all values are cumulative since loxilb start; for rates use promql_query with rate()",
			},
		}
		if f, ok := byName["loxilb_ai_requests_total"]; ok {
			for _, s := range f.Samples {
				out.RequestsTotal += s.Value
				status := s.Labels["status"]
				if !strings.HasPrefix(status, "2") {
					out.RequestsNon2xx += s.Value
				}
				out.RequestsByModelTenantStatus = append(out.RequestsByModelTenantStatus, map[string]any{
					"model": clean(s.Labels["model"]), "tenant": clean(s.Labels["tenant"]),
					"status": clean(status), "count": s.Value,
				})
			}
			if out.RequestsTotal > 0 {
				out.ErrorRatio = out.RequestsNon2xx / out.RequestsTotal
			}
		}
		if f, ok := byName["loxilb_ai_rate_limit_hits_total"]; ok {
			for _, s := range f.Samples {
				out.RateLimitDropsTotal += s.Value
				out.RateLimitDrops = append(out.RateLimitDrops, map[string]any{
					"tenant": clean(s.Labels["tenant"]), "reason": clean(s.Labels["reason"]),
					"count": s.Value,
				})
			}
		}
		if f, ok := byName["loxilb_ai_model_not_allowed_total"]; ok {
			for _, s := range f.Samples {
				out.ModelNotAllowed = append(out.ModelNotAllowed, map[string]any{
					"model": clean(s.Labels["model"]), "tenant": clean(s.Labels["tenant"]),
					"count": s.Value,
				})
			}
		}
		if f, ok := byName["loxilb_ai_active_streams"]; ok {
			for _, s := range f.Samples {
				out.ActiveStreams = append(out.ActiveStreams, map[string]any{
					"model": clean(s.Labels["model"]), "streams": s.Value,
				})
			}
		}
		out.RequestDuration = summarizeHistogram(byName["loxilb_ai_request_duration_seconds"])
		out.ProxyTTFB = summarizeHistogram(byName["loxilb_proxy_http_ttfb_seconds"])
		out.PDDecodeTTFT = summarizeHistogram(byName["loxilb_ai_pd_decode_ttft_seconds"])
		out.KVParamsFound = sumFamily(byName["loxilb_ai_pd_kv_params_found_total"])
		out.KVParamsMissing = sumFamily(byName["loxilb_ai_pd_kv_params_missing_total"])
		out.PDSessionHits = sumFamily(byName["loxilb_ai_pd_session_hits_total"])
		out.NormalSessionHits = sumFamily(byName["loxilb_ai_normal_session_hits_total"])

		d.audit("ai_traffic_report", c.Name(), true, "")
		return nil, out, nil
	}
}

func sumFamily(f client.Family) float64 {
	var total float64
	for _, s := range f.Samples {
		total += s.Value
	}
	return total
}

// summarizeHistogram aggregates a parsed histogram family (possibly many
// label sets) into overall count/sum and estimated p50/p95/p99 via linear
// interpolation over the merged cumulative buckets. Returns nil when the
// family is absent or empty.
func summarizeHistogram(f client.Family) *latencySummary {
	if len(f.Samples) == 0 {
		return nil
	}
	buckets := map[float64]float64{} // le -> cumulative count (summed over label sets)
	var count, sum float64
	for _, s := range f.Samples {
		if le, ok := s.Labels["le"]; ok {
			bound, err := strconv.ParseFloat(le, 64) // handles "+Inf"
			if err != nil {
				continue
			}
			buckets[bound] += s.Value
			continue
		}
		switch s.Labels["series"] {
		case "count":
			count += s.Value
		case "sum":
			sum += s.Value
		}
	}
	if count == 0 || len(buckets) == 0 {
		return nil
	}
	bounds := make([]float64, 0, len(buckets))
	for b := range buckets {
		bounds = append(bounds, b)
	}
	sort.Float64s(bounds)
	quantile := func(q float64) float64 {
		target := q * count
		prevBound, prevCum := 0.0, 0.0
		for _, b := range bounds {
			cum := buckets[b]
			if cum >= target {
				if math.IsInf(b, 1) { // +Inf bucket: no upper bound information
					return prevBound
				}
				if cum == prevCum {
					return b
				}
				return prevBound + (b-prevBound)*(target-prevCum)/(cum-prevCum)
			}
			prevBound, prevCum = b, cum
		}
		return prevBound
	}
	return &latencySummary{
		Count: count,
		SumS:  sum,
		P50S:  quantile(0.50),
		P95S:  quantile(0.95),
		P99S:  quantile(0.99),
	}
}
