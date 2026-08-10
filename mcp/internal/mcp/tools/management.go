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
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

// RegisterManagement adds the management CRUD tools. Read tools are
// viewer+, non-destructive mutations operator+, destructive tools
// admin-only behind the confirm-token flow.
func RegisterManagement(s *sdk.Server, role guard.Role, pol *guard.Policy, deps *Deps) {
	reg := func(meta guard.ToolMeta, add func()) {
		meta.Domain = domainMgmt
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

	reg(ro("endpoint_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "endpoint_list",
			Description: "List endpoint health-probe entries: host, probe type/port, retries, delays, current state (GET /config/endpoint/all).",
			Annotations: roAnnotations("List endpoints"),
		}, deps.passthrough("endpoint_list", "/config/endpoint/all"))
	})
	reg(ro("fw_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "fw_list",
			Description: "List firewall rules with match arguments and options (GET /config/firewall/all).",
			Annotations: roAnnotations("List firewall rules"),
		}, deps.passthrough("fw_list", "/config/firewall/all"))
	})
	reg(ro("ipfilter_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "ipfilter_list",
			Description: "List IP filter (allow/deny CIDR) entries (GET /config/ipfilter/all).",
			Annotations: roAnnotations("List IP filters"),
		}, deps.passthrough("ipfilter_list", "/config/ipfilter/all"))
	})
	reg(ro("secrate_get"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "secrate_get",
			Description: "Get security rate-limit config: SYN-flood, conn-rate, UDP-flood thresholds and whitelist (GET /config/securityrate/all).",
			Annotations: roAnnotations("Get security rate config"),
		}, deps.passthrough("secrate_get", "/config/securityrate/all"))
	})
	reg(ro("net_route_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_route_list",
			Description: "List routes (GET /config/route/all).",
			Annotations: roAnnotations("List routes"),
		}, deps.passthrough("net_route_list", "/config/route/all"))
	})
	reg(ro("net_vlan_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_vlan_list",
			Description: "List VLAN bridges and members (GET /config/vlan/all).",
			Annotations: roAnnotations("List VLANs"),
		}, deps.passthrough("net_vlan_list", "/config/vlan/all"))
	})
	reg(ro("net_vxlan_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_vxlan_list",
			Description: "List VxLAN tunnels and peers (GET /config/tunnel/vxlan/all).",
			Annotations: roAnnotations("List VxLANs"),
		}, deps.passthrough("net_vxlan_list", "/config/tunnel/vxlan/all"))
	})
	reg(ro("net_neighbor_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_neighbor_list",
			Description: "List neighbor (ARP) entries (GET /config/neighbor/all).",
			Annotations: roAnnotations("List neighbors"),
		}, deps.passthrough("net_neighbor_list", "/config/neighbor/all"))
	})
	reg(ro("net_ip_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_ip_list",
			Description: "List interface IP addresses; ip_version 4 (default) or 6 (GET /config/ipv4address/all | /config/ipv6address/all).",
			Annotations: roAnnotations("List interface IPs"),
		}, deps.netIPList())
	})
	reg(ro("net_port_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_port_list",
			Description: "List device ports/interfaces with state and statistics (GET /config/port/all).",
			Annotations: roAnnotations("List ports"),
		}, deps.passthrough("net_port_list", "/config/port/all"))
	})
	reg(ro("bgp_neigh_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "bgp_neigh_list",
			Description: "List BGP neighbors with session state (GET /config/bgp/neigh/all).",
			Annotations: roAnnotations("List BGP neighbors"),
		}, deps.passthrough("bgp_neigh_list", "/config/bgp/neigh/all"))
	})
	reg(ro("bgp_policy_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "bgp_policy_list",
			Description: "List BGP policy definitions (GET /config/bgp/policy/definitions/all).",
			Annotations: roAnnotations("List BGP policies"),
		}, deps.passthrough("bgp_policy_list", "/config/bgp/policy/definitions/all"))
	})
	reg(ro("session_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "session_list",
			Description: "List subscriber sessions (GET /config/session/all).",
			Annotations: roAnnotations("List sessions"),
		}, deps.passthrough("session_list", "/config/session/all"))
	})
	reg(ro("session_ulcl_list"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "session_ulcl_list",
			Description: "List session ULCL classifier entries (GET /config/sessionulcl/all).",
			Annotations: roAnnotations("List ULCL entries"),
		}, deps.passthrough("session_ulcl_list", "/config/sessionulcl/all"))
	})
	reg(ro("config_params_get"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "config_params_get",
			Description: "Get operational parameters (log level) (GET /config/params).",
			Annotations: roAnnotations("Get operational params"),
		}, deps.passthrough("config_params_get", "/config/params"))
	})
	reg(ro("config_export"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "config_export",
			Description: "Export the full running configuration snapshot (GET /config/export). Secret-shaped fields are masked before returning.",
			Annotations: roAnnotations("Export configuration"),
		}, deps.configExport())
	})

	// ---- mutating, non-destructive (operator+) ----

	reg(mut("lb_create"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "lb_create",
			Description: "Create a load-balancer rule (POST /config/loadbalancer): external_ip, port, protocol, endpoints, " +
				"optional name/sel/mode and service_extra for advanced serviceArguments fields " +
				"(e.g. AI mode 4: host, path_prefix, path_match_mode, model_name, sse_mode).",
			Annotations: mutAnnotations("Create LB rule", true),
		}, deps.lbCreate())
	})
	reg(mut("endpoint_host_state_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "endpoint_host_state_set",
			Description: "Set an endpoint host's administrative probe state, e.g. drain/undrain a backend (POST /config/endpointhoststate).",
			Annotations: mutAnnotations("Set endpoint host state", true),
		}, deps.endpointHostStateSet())
	})
	reg(mut("fw_create"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "fw_create",
			Description: "Create a firewall rule (POST /config/firewall): match on source/destination CIDR, port ranges, protocol; action allow|drop|trap|redirect.",
			Annotations: mutAnnotations("Create firewall rule", true),
		}, deps.fwCreate())
	})
	reg(mut("ipfilter_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "ipfilter_set",
			Description: "Add or remove an IP filter CIDR entry (POST|DELETE /config/ipfilter). filter_type v4|v6, action allow|deny; set remove=true to delete an entry.",
			Annotations: mutAnnotations("Set IP filter", true),
		}, deps.ipfilterSet())
	})
	reg(mut("secrate_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "secrate_set",
			Description: "Set security rate-limit config: SYN-flood, conn-rate and UDP-flood thresholds, whitelist IPs (POST /config/securityrate). Only supplied fields are sent.",
			Annotations: mutAnnotations("Set security rate config", true),
		}, deps.secrateSet())
	})
	reg(mut("secrate_reset"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "secrate_reset",
			Description: "Reset security rate-limit counters/state (PUT /config/securityrate/reset).",
			Annotations: mutAnnotations("Reset security rate state", true),
		}, deps.secrateReset())
	})
	reg(mut("net_route_create"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "net_route_create",
			Description: "Create a static route (POST /config/route): destination CIDR and gateway.",
			Annotations: mutAnnotations("Create route", true),
		}, deps.netRouteCreate())
	})
	reg(mut("bgp_neigh_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "bgp_neigh_set",
			Description: "Create or update a BGP neighbor (POST /config/bgp/neigh): ip_address, remote_as, optional remote_port/multi_hop.",
			Annotations: mutAnnotations("Set BGP neighbor", true),
		}, deps.bgpNeighSet())
	})
	reg(mut("bgp_global_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "bgp_global_set",
			Description: "Set BGP global config (POST /config/bgp/global): router_id, local_as, optional listen_port/next-hop-self.",
			Annotations: mutAnnotations("Set BGP global config", true),
		}, deps.bgpGlobalSet())
	})
	reg(mut("bgp_policy_apply"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "bgp_policy_apply",
			Description: "Apply BGP policies to a neighbor (POST /config/bgp/policy/apply): ip_address, policy_type import|export, policy names, route_action accept|reject.",
			Annotations: mutAnnotations("Apply BGP policy", true),
		}, deps.bgpPolicyApply())
	})
	reg(mut("config_params_set"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "config_params_set",
			Description: "Set operational parameters (POST /config/params): log_level one of trace|debug|info|warning|error|critical|emergency|alert|notice.",
			Annotations: mutAnnotations("Set operational params", true),
		}, deps.configParamsSet())
	})

	// ---- destructive (admin, confirm-token) ----

	reg(dest("lb_delete"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "lb_delete",
			Description: "Delete a load-balancer rule by name, or by external_ip+port+protocol; AI/fullproxy rules additionally " +
				"need host_url/path_prefix/path_match_mode/model_name. Two-step: first call returns a preview and a " +
				"single-use confirm_token (TTL-bound); repeat the call with identical arguments plus confirm_token to execute.",
			Annotations: destAnnotations("Delete LB rule"),
		}, deps.lbDelete())
	})
	reg(dest("fw_delete"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "fw_delete",
			Description: "Delete a firewall rule matching the given arguments (DELETE /config/firewall). " +
				"Two-step confirm-token flow: first call previews, second call with confirm_token executes.",
			Annotations: destAnnotations("Delete firewall rule"),
		}, deps.fwDelete())
	})
	reg(dest("net_route_delete"), func() {
		sdk.AddTool(s, &sdk.Tool{
			Name: "net_route_delete",
			Description: "Delete a route by destination CIDR (DELETE /config/route/destinationIPNet/...). " +
				"Two-step confirm-token flow: first call previews, second call with confirm_token executes.",
			Annotations: destAnnotations("Delete route"),
		}, deps.netRouteDelete())
	})
	if deps.AllowImport {
		reg(dest("config_import"), func() {
			sdk.AddTool(s, &sdk.Tool{
				Name: "config_import",
				Description: "Import (replace) the running configuration from a JSON snapshot (POST /config/import). " +
					"Requires --allow-import. Two-step confirm-token flow: first call previews, second call with confirm_token executes.",
				Annotations: destAnnotations("Import configuration"),
			}, deps.configImport())
		})
	}
}

// mutOut is the shared result of mutating tools. Destructive tools stopped at
// the preview step return action "preview" plus a confirm_token; executed
// calls return action "executed".
type mutOut struct {
	Target            string `json:"target"`
	Action            string `json:"action"` // preview | executed
	Result            any    `json:"result,omitempty" jsonschema:"tool-specific result of an executed mutation (arbitrary JSON)"`
	ConfirmToken      string `json:"confirm_token,omitempty"`
	ConfirmExpiresSec int    `json:"confirm_expires_sec,omitempty"`
	Preview           any    `json:"preview,omitempty" jsonschema:"object(s) a destructive call would change; present on action=preview (arbitrary JSON)"`
	Warning           string `json:"warning,omitempty"`
}

// gateDestructive implements the shared preview→confirm step (threat T4).
// args must be the input struct with its ConfirmToken field cleared. It
// returns (previewOut, true, nil) when the call must stop at the preview,
// and (zero, false, nil) when execution may proceed.
func (d *Deps) gateDestructive(tool, target, confirmToken string, args any, preview any) (mutOut, bool, error) {
	if d.Confirm == nil {
		return mutOut{}, false, nil // --no-confirm
	}
	// Autopilot tools (§3.7) skip the preview→confirm round trip; the bypass
	// is audited separately from the tool_call line the execution writes.
	if confirmToken == "" && d.Autopilot != nil && d.Autopilot(tool) {
		var argMap map[string]any
		if raw, err := json.Marshal(args); err == nil {
			_ = json.Unmarshal(raw, &argMap)
		}
		d.Audit.Log(guard.Event{
			Kind: guard.EventAutopilot, Tool: tool, Target: target,
			Args: guard.Redact(argMap), OK: true,
		})
		return mutOut{}, false, nil
	}
	binding, err := guard.BindArgs(tool, target, args)
	if err != nil {
		return mutOut{}, false, err
	}
	if confirmToken == "" {
		tok, err := d.Confirm.Issue(binding)
		if err != nil {
			return mutOut{}, false, err
		}
		return mutOut{
			Target:            target,
			Action:            "preview",
			ConfirmToken:      tok,
			ConfirmExpiresSec: int(guard.DefaultConfirmTTL.Seconds()),
			Preview:           preview,
			Warning: "NO CHANGE MADE. To execute, call " + tool + " again with identical " +
				"arguments plus this confirm_token before it expires. The token is single-use " +
				"and bound to these exact arguments.",
		}, true, nil
	}
	if err := d.Confirm.Redeem(confirmToken, binding); err != nil {
		d.auditMut(tool, target, args, false, "confirm: "+err.Error())
		return mutOut{}, false, err
	}
	return mutOut{}, false, nil
}

// ---- validation helpers ----

func validIP(s, field string) error {
	if net.ParseIP(s) == nil {
		return fmt.Errorf("%s: invalid IP address %q", field, s)
	}
	return nil
}

func validCIDR(s, field string) error {
	if _, _, err := net.ParseCIDR(s); err != nil {
		return fmt.Errorf("%s: invalid CIDR %q", field, s)
	}
	return nil
}

func validPort(p int, field string) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("%s: port %d out of range 1-65535", field, p)
	}
	return nil
}

func validL4Proto(s string) error {
	switch strings.ToLower(s) {
	case "tcp", "udp", "sctp", "icmp":
		return nil
	}
	return fmt.Errorf("protocol: %q (want tcp|udp|sctp|icmp)", s)
}

// protoNumber maps a protocol name to its IP protocol number (firewall model).
func protoNumber(s string) (int, error) {
	switch strings.ToLower(s) {
	case "":
		return 0, nil
	case "icmp":
		return 1, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "sctp":
		return 132, nil
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 255 {
		return n, nil
	}
	return 0, fmt.Errorf("protocol: %q (want tcp|udp|sctp|icmp or 0-255)", s)
}

// ---- net_ip_list ----

type netIPListIn struct {
	Target    string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	IPVersion int    `json:"ip_version,omitempty" jsonschema:"4 (default) or 6"`
}

func (d *Deps) netIPList() sdk.ToolHandlerFor[netIPListIn, map[string]any] {
	return func(ctx context.Context, req *sdk.CallToolRequest, in netIPListIn) (*sdk.CallToolResult, map[string]any, error) {
		path := "/config/ipv4address/all"
		switch in.IPVersion {
		case 0, 4:
		case 6:
			path = "/config/ipv6address/all"
		default:
			return nil, nil, fmt.Errorf("ip_version: %d (want 4 or 6)", in.IPVersion)
		}
		h := d.passthrough("net_ip_list", path)
		return h(ctx, req, targetIn{Target: in.Target})
	}
}

// ---- config_export ----

type configExportIn struct {
	Target     string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Components string `json:"components,omitempty" jsonschema:"comma-separated component list to export; empty for all"`
}

func (d *Deps) configExport() sdk.ToolHandlerFor[configExportIn, map[string]any] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in configExportIn) (*sdk.CallToolResult, map[string]any, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, nil, err
		}
		q := url.Values{}
		if in.Components != "" {
			q.Set("components", in.Components)
		}
		var raw any
		if err := c.GetQ(ctx, "/config/export", q, &raw); err != nil {
			d.audit("config_export", c.Name(), false, err.Error())
			return nil, nil, err
		}
		d.audit("config_export", c.Name(), true, "")
		// Mask secret-shaped fields; do NOT sanitizeAny-cap the config (it must
		// round-trip through config_import), only redact.
		return nil, map[string]any{
			"target": c.Name(),
			"config": guard.RedactDeep(raw),
			"note":   "secret-shaped fields are masked",
		}, nil
	}
}

// ---- lb_create ----

type lbEndpointIn struct {
	IP     string `json:"ip" jsonschema:"endpoint IP address"`
	Port   int    `json:"port" jsonschema:"endpoint target port"`
	Weight int    `json:"weight,omitempty" jsonschema:"endpoint weight (default 1)"`
}

type lbCreateIn struct {
	Target       string         `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	ExternalIP   string         `json:"external_ip" jsonschema:"service VIP"`
	Port         int            `json:"port" jsonschema:"service port"`
	Protocol     string         `json:"protocol" jsonschema:"tcp|udp|sctp|icmp"`
	Name         string         `json:"name,omitempty" jsonschema:"optional service name"`
	Sel          int            `json:"sel,omitempty" jsonschema:"endpoint selector: 0 rr (default), 1 hash, 2 priority, 3 persist, 4 lc"`
	Mode         int            `json:"mode,omitempty" jsonschema:"LB mode: 0 default, 1 onearm, 2 fullnat, 3 dsr, 4 fullproxy/AI"`
	BGP          bool           `json:"bgp,omitempty" jsonschema:"advertise service via BGP"`
	Monitor      bool           `json:"monitor,omitempty" jsonschema:"enable endpoint liveness monitoring"`
	Timeout      int            `json:"timeout,omitempty" jsonschema:"session inactivity timeout seconds"`
	Endpoints    []lbEndpointIn `json:"endpoints" jsonschema:"backend endpoints (at least one)"`
	ServiceExtra map[string]any `json:"service_extra,omitempty" jsonschema:"additional serviceArguments fields passed through verbatim (e.g. host, path_prefix, path_match_mode, model_name, sse_mode for AI mode 4)"`
	ConfirmToken string         `json:"confirm_token,omitempty" jsonschema:"unused for lb_create; present for schema symmetry"`
}

func (d *Deps) lbCreate() sdk.ToolHandlerFor[lbCreateIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in lbCreateIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := validIP(in.ExternalIP, "external_ip"); err != nil {
			return nil, mutOut{}, err
		}
		if err := validPort(in.Port, "port"); err != nil {
			return nil, mutOut{}, err
		}
		if err := validL4Proto(in.Protocol); err != nil {
			return nil, mutOut{}, err
		}
		if len(in.Endpoints) == 0 {
			return nil, mutOut{}, fmt.Errorf("endpoints: at least one endpoint is required")
		}
		svc := map[string]any{
			"externalIP": in.ExternalIP,
			"port":       in.Port,
			"protocol":   strings.ToLower(in.Protocol),
			"sel":        in.Sel,
			"mode":       in.Mode,
		}
		if in.Name != "" {
			svc["name"] = in.Name
		}
		if in.BGP {
			svc["BGP"] = true
		}
		if in.Monitor {
			svc["monitor"] = true
		}
		if in.Timeout > 0 {
			svc["inactiveTimeOut"] = in.Timeout
		}
		for k, v := range in.ServiceExtra {
			if _, taken := svc[k]; taken {
				return nil, mutOut{}, fmt.Errorf("service_extra: %q conflicts with a typed argument", k)
			}
			svc[k] = v
		}
		eps := make([]map[string]any, 0, len(in.Endpoints))
		for i, ep := range in.Endpoints {
			if err := validIP(ep.IP, fmt.Sprintf("endpoints[%d].ip", i)); err != nil {
				return nil, mutOut{}, err
			}
			if err := validPort(ep.Port, fmt.Sprintf("endpoints[%d].port", i)); err != nil {
				return nil, mutOut{}, err
			}
			w := ep.Weight
			if w <= 0 {
				w = 1
			}
			eps = append(eps, map[string]any{"endpointIP": ep.IP, "targetPort": ep.Port, "weight": w})
		}
		body := map[string]any{"serviceArguments": svc, "endpoints": eps}
		var res any
		if err := c.Post(ctx, "/config/loadbalancer", body, &res); err != nil {
			d.auditMut("lb_create", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("lb_create", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- lb_delete ----

type lbDeleteIn struct {
	Target        string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Name          string `json:"name,omitempty" jsonschema:"delete by service name (alternative to external_ip/port/protocol)"`
	ExternalIP    string `json:"external_ip,omitempty" jsonschema:"service VIP"`
	Port          int    `json:"port,omitempty" jsonschema:"service port"`
	PortMax       int    `json:"port_max,omitempty" jsonschema:"upper bound of a port-range rule"`
	Protocol      string `json:"protocol,omitempty" jsonschema:"tcp|udp|sctp|icmp"`
	HostURL       string `json:"host_url,omitempty" jsonschema:"host of an AI/fullproxy rule (serviceArguments.host)"`
	PathPrefix    string `json:"path_prefix,omitempty" jsonschema:"path prefix of an AI/fullproxy rule"`
	PathMatchMode string `json:"path_match_mode,omitempty" jsonschema:"path match mode of the rule (prefix|exact|disabled)"`
	ModelName     string `json:"model_name,omitempty" jsonschema:"model name of an AI rule"`
	BGP           bool   `json:"bgp,omitempty" jsonschema:"rule was BGP-advertised"`
	ConfirmToken  string `json:"confirm_token,omitempty" jsonschema:"single-use token from the preview step; omit to preview"`
}

func (d *Deps) lbDelete() sdk.ToolHandlerFor[lbDeleteIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in lbDeleteIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		byName := in.Name != ""
		if !byName {
			if in.ExternalIP == "" || in.Port == 0 || in.Protocol == "" {
				return nil, mutOut{}, fmt.Errorf("either name or external_ip+port+protocol is required")
			}
			if err := validIP(in.ExternalIP, "external_ip"); err != nil {
				return nil, mutOut{}, err
			}
			if err := validPort(in.Port, "port"); err != nil {
				return nil, mutOut{}, err
			}
			if err := validL4Proto(in.Protocol); err != nil {
				return nil, mutOut{}, err
			}
		} else if err := validatePathSegment(in.Name); err != nil {
			return nil, mutOut{}, fmt.Errorf("name: %w", err)
		}

		args := in
		args.ConfirmToken = ""
		if d.Confirm != nil && in.ConfirmToken == "" {
			preview := d.lbDeletePreview(ctx, c, in)
			out, stop, err := d.gateDestructive("lb_delete", c.Name(), "", args, preview)
			if err != nil || stop {
				return nil, out, err
			}
		} else {
			if _, _, err := d.gateDestructive("lb_delete", c.Name(), in.ConfirmToken, args, nil); err != nil {
				return nil, mutOut{}, err
			}
		}

		var path string
		q := url.Values{}
		switch {
		case byName:
			path = "/config/loadbalancer/name/" + url.PathEscape(in.Name)
		case in.HostURL != "" || in.PathPrefix != "" || in.ModelName != "":
			host := in.HostURL
			if host == "" {
				host = "any"
			}
			path = fmt.Sprintf("/config/loadbalancer/hosturl/%s/externalipaddress/%s/port/%d/protocol/%s",
				url.PathEscape(host), url.PathEscape(in.ExternalIP), in.Port, url.PathEscape(strings.ToLower(in.Protocol)))
			if in.PathPrefix != "" {
				q.Set("path_prefix", in.PathPrefix)
			}
			if in.PathMatchMode != "" {
				q.Set("path_match_mode", in.PathMatchMode)
			}
			if in.ModelName != "" {
				q.Set("model_name", in.ModelName)
			}
		case in.PortMax > 0:
			path = fmt.Sprintf("/config/loadbalancer/externalipaddress/%s/port/%d/portmax/%d/protocol/%s",
				url.PathEscape(in.ExternalIP), in.Port, in.PortMax, url.PathEscape(strings.ToLower(in.Protocol)))
		default:
			path = fmt.Sprintf("/config/loadbalancer/externalipaddress/%s/port/%d/protocol/%s",
				url.PathEscape(in.ExternalIP), in.Port, url.PathEscape(strings.ToLower(in.Protocol)))
		}
		if in.BGP {
			q.Set("bgp", "true")
		}
		var res any
		if err := c.DeleteQ(ctx, path, q, &res); err != nil {
			d.auditMut("lb_delete", c.Name(), args, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("lb_delete", c.Name(), args, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// lbDeletePreview best-effort fetches the rule(s) the delete would remove.
func (d *Deps) lbDeletePreview(ctx context.Context, c resolvedClient, in lbDeleteIn) any {
	rules, err := c.LBRules(ctx)
	if err != nil {
		return map[string]any{"error": "preview unavailable: " + clean(err.Error())}
	}
	var match []any
	for _, r := range rules {
		svc, _ := r["serviceArguments"].(map[string]any)
		if svc == nil {
			continue
		}
		name, _ := svc["name"].(string)
		extIP, _ := svc["externalIP"].(string)
		port, _ := svc["port"].(float64)
		proto, _ := svc["protocol"].(string)
		if in.Name != "" {
			if name != in.Name {
				continue
			}
		} else if extIP != in.ExternalIP || int(port) != in.Port || !strings.EqualFold(proto, in.Protocol) {
			continue
		}
		match = append(match, sanitizeAny(r, 0))
	}
	return map[string]any{"matching_rules": match, "match_count": len(match)}
}

// resolvedClient is the client surface preview helpers need (test seam).
type resolvedClient interface {
	Name() string
	LBRules(ctx context.Context) ([]map[string]any, error)
}

// ---- endpoint_host_state_set ----

type epHostStateIn struct {
	Target   string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	HostName string `json:"host_name" jsonschema:"endpoint host (IP or name) to change"`
	Port     int    `json:"port,omitempty" jsonschema:"endpoint port (0 for all)"`
	Protocol string `json:"protocol,omitempty" jsonschema:"endpoint probe protocol"`
	State    string `json:"state" jsonschema:"administrative state to set (e.g. green=serve, red=drain)"`
}

func (d *Deps) endpointHostStateSet() sdk.ToolHandlerFor[epHostStateIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in epHostStateIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if in.HostName == "" || in.State == "" {
			return nil, mutOut{}, fmt.Errorf("host_name and state are required")
		}
		body := map[string]any{"hostName": in.HostName, "state": in.State}
		if in.Port > 0 {
			body["epPort"] = in.Port
		}
		if in.Protocol != "" {
			body["epProto"] = strings.ToLower(in.Protocol)
		}
		var res any
		if err := c.Post(ctx, "/config/endpointhoststate", body, &res); err != nil {
			d.auditMut("endpoint_host_state_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("endpoint_host_state_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- fw_create / fw_delete ----

type fwMatchIn struct {
	SourceIP   string `json:"source_ip,omitempty" jsonschema:"source CIDR to match"`
	DestIP     string `json:"dest_ip,omitempty" jsonschema:"destination CIDR to match"`
	MinSrcPort int    `json:"min_src_port,omitempty"`
	MaxSrcPort int    `json:"max_src_port,omitempty"`
	MinDstPort int    `json:"min_dst_port,omitempty"`
	MaxDstPort int    `json:"max_dst_port,omitempty"`
	Protocol   string `json:"protocol,omitempty" jsonschema:"tcp|udp|sctp|icmp or IP protocol number"`
	PortName   string `json:"port_name,omitempty" jsonschema:"ingress interface name"`
	Preference int    `json:"preference,omitempty" jsonschema:"rule priority (higher wins)"`
}

func (m *fwMatchIn) validate() error {
	if m.SourceIP != "" {
		if err := validCIDR(m.SourceIP, "source_ip"); err != nil {
			return err
		}
	}
	if m.DestIP != "" {
		if err := validCIDR(m.DestIP, "dest_ip"); err != nil {
			return err
		}
	}
	if _, err := protoNumber(m.Protocol); err != nil {
		return err
	}
	return nil
}

// ruleArguments builds the REST FirewallRuleEntry from the typed match.
func (m *fwMatchIn) ruleArguments() map[string]any {
	args := map[string]any{}
	set := func(k string, v any, use bool) {
		if use {
			args[k] = v
		}
	}
	set("sourceIP", m.SourceIP, m.SourceIP != "")
	set("destinationIP", m.DestIP, m.DestIP != "")
	set("minSourcePort", m.MinSrcPort, m.MinSrcPort > 0)
	set("maxSourcePort", m.MaxSrcPort, m.MaxSrcPort > 0)
	set("minDestinationPort", m.MinDstPort, m.MinDstPort > 0)
	set("maxDestinationPort", m.MaxDstPort, m.MaxDstPort > 0)
	if n, _ := protoNumber(m.Protocol); n > 0 {
		args["protocol"] = n
	}
	set("portName", m.PortName, m.PortName != "")
	set("preference", m.Preference, m.Preference > 0)
	return args
}

type fwCreateIn struct {
	Target       string    `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Match        fwMatchIn `json:"match" jsonschema:"traffic match arguments"`
	Action       string    `json:"action" jsonschema:"allow|drop|trap|redirect"`
	RedirectPort string    `json:"redirect_port,omitempty" jsonschema:"interface for action=redirect"`
	Mark         int       `json:"mark,omitempty" jsonschema:"firewall mark to set"`
	Record       bool      `json:"record,omitempty" jsonschema:"record matching flows"`
}

func (d *Deps) fwCreate() sdk.ToolHandlerFor[fwCreateIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in fwCreateIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := in.Match.validate(); err != nil {
			return nil, mutOut{}, err
		}
		opts := map[string]any{}
		switch strings.ToLower(in.Action) {
		case "allow":
			opts["allow"] = true
		case "drop":
			opts["drop"] = true
		case "trap":
			opts["trap"] = true
		case "redirect":
			if in.RedirectPort == "" {
				return nil, mutOut{}, fmt.Errorf("redirect_port is required for action=redirect")
			}
			opts["redirect"] = true
			opts["redirectPortName"] = in.RedirectPort
		default:
			return nil, mutOut{}, fmt.Errorf("action: %q (want allow|drop|trap|redirect)", in.Action)
		}
		if in.Mark > 0 {
			opts["fwMark"] = in.Mark
		}
		if in.Record {
			opts["record"] = true
		}
		body := map[string]any{"ruleArguments": in.Match.ruleArguments(), "opts": opts}
		var res any
		if err := c.Post(ctx, "/config/firewall", body, &res); err != nil {
			d.auditMut("fw_create", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("fw_create", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type fwDeleteIn struct {
	Target       string    `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Match        fwMatchIn `json:"match" jsonschema:"match arguments of the rule to delete"`
	ConfirmToken string    `json:"confirm_token,omitempty" jsonschema:"single-use token from the preview step; omit to preview"`
}

func (d *Deps) fwDelete() sdk.ToolHandlerFor[fwDeleteIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in fwDeleteIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := in.Match.validate(); err != nil {
			return nil, mutOut{}, err
		}
		args := in
		args.ConfirmToken = ""
		preview := map[string]any{"delete_match": args.Match}
		out, stop, err := d.gateDestructive("fw_delete", c.Name(), in.ConfirmToken, args, preview)
		if err != nil || stop {
			return nil, out, err
		}
		q := url.Values{}
		setQ := func(k, v string) {
			if v != "" {
				q.Set(k, v)
			}
		}
		setQ("sourceIP", in.Match.SourceIP)
		setQ("destinationIP", in.Match.DestIP)
		if in.Match.MinSrcPort > 0 {
			q.Set("minSourcePort", strconv.Itoa(in.Match.MinSrcPort))
		}
		if in.Match.MaxSrcPort > 0 {
			q.Set("maxSourcePort", strconv.Itoa(in.Match.MaxSrcPort))
		}
		if in.Match.MinDstPort > 0 {
			q.Set("minDestinationPort", strconv.Itoa(in.Match.MinDstPort))
		}
		if in.Match.MaxDstPort > 0 {
			q.Set("maxDestinationPort", strconv.Itoa(in.Match.MaxDstPort))
		}
		if n, _ := protoNumber(in.Match.Protocol); n > 0 {
			q.Set("protocol", strconv.Itoa(n))
		}
		setQ("portName", in.Match.PortName)
		if in.Match.Preference > 0 {
			q.Set("preference", strconv.Itoa(in.Match.Preference))
		}
		var res any
		if err := c.DeleteQ(ctx, "/config/firewall", q, &res); err != nil {
			d.auditMut("fw_delete", c.Name(), args, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("fw_delete", c.Name(), args, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- ipfilter_set ----

type ipfilterSetIn struct {
	Target     string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	FilterType string `json:"filter_type" jsonschema:"v4|v6"`
	CIDR       string `json:"cidr" jsonschema:"CIDR to allow or deny"`
	Action     string `json:"action,omitempty" jsonschema:"allow|deny (required unless remove=true)"`
	Zone       int    `json:"zone,omitempty" jsonschema:"optional zone id"`
	Priority   int    `json:"priority,omitempty" jsonschema:"optional priority"`
	Remove     bool   `json:"remove,omitempty" jsonschema:"true to delete the entry instead of adding it"`
}

func (d *Deps) ipfilterSet() sdk.ToolHandlerFor[ipfilterSetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in ipfilterSetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		ft := strings.ToLower(in.FilterType)
		if ft != "v4" && ft != "v6" {
			return nil, mutOut{}, fmt.Errorf("filter_type: %q (want v4|v6)", in.FilterType)
		}
		if err := validCIDR(in.CIDR, "cidr"); err != nil {
			return nil, mutOut{}, err
		}
		var res any
		if in.Remove {
			q := url.Values{"filterType": {ft}, "cidr": {in.CIDR}}
			if in.Zone > 0 {
				q.Set("zone", strconv.Itoa(in.Zone))
			}
			if err := c.DeleteQ(ctx, "/config/ipfilter", q, &res); err != nil {
				d.auditMut("ipfilter_set", c.Name(), in, false, err.Error())
				return nil, mutOut{}, err
			}
		} else {
			act := strings.ToLower(in.Action)
			if act != "allow" && act != "deny" {
				return nil, mutOut{}, fmt.Errorf("action: %q (want allow|deny)", in.Action)
			}
			body := map[string]any{"filterType": ft, "cidr": in.CIDR, "action": act}
			if in.Zone > 0 {
				body["zone"] = in.Zone
			}
			if in.Priority > 0 {
				body["priority"] = in.Priority
			}
			if err := c.Post(ctx, "/config/ipfilter", body, &res); err != nil {
				d.auditMut("ipfilter_set", c.Name(), in, false, err.Error())
				return nil, mutOut{}, err
			}
		}
		d.auditMut("ipfilter_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- secrate_set / secrate_reset ----

type secrateSetIn struct {
	Target          string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	SynEnabled      *bool    `json:"syn_enabled,omitempty" jsonschema:"enable SYN-flood protection"`
	SynThreshold    int      `json:"syn_threshold,omitempty" jsonschema:"SYN/s threshold"`
	CookieThreshold int      `json:"cookie_threshold,omitempty" jsonschema:"SYN-cookie activation threshold"`
	ConnRateEnabled *bool    `json:"conn_rate_enabled,omitempty" jsonschema:"enable new-connection rate limiting"`
	RatePerSec      int      `json:"rate_per_sec,omitempty" jsonschema:"new connections per second"`
	UDPEnabled      *bool    `json:"udp_enabled,omitempty" jsonschema:"enable UDP flood protection"`
	UDPPktThreshold int      `json:"udp_pkt_threshold,omitempty" jsonschema:"UDP packets/s threshold"`
	UDPBandwidthMB  int      `json:"udp_bandwidth_mb,omitempty" jsonschema:"UDP bandwidth cap MB/s"`
	WhitelistIPs    []string `json:"whitelist_ips,omitempty" jsonschema:"CIDRs bypassing the limits"`
}

func (d *Deps) secrateSet() sdk.ToolHandlerFor[secrateSetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in secrateSetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		body := map[string]any{}
		if in.SynEnabled != nil {
			body["synEnabled"] = *in.SynEnabled
		}
		if in.SynThreshold > 0 {
			body["synThreshold"] = in.SynThreshold
		}
		if in.CookieThreshold > 0 {
			body["cookieThreshold"] = in.CookieThreshold
		}
		if in.ConnRateEnabled != nil {
			body["connRateEnabled"] = *in.ConnRateEnabled
		}
		if in.RatePerSec > 0 {
			body["ratePerSec"] = in.RatePerSec
		}
		if in.UDPEnabled != nil {
			body["udpEnabled"] = *in.UDPEnabled
		}
		if in.UDPPktThreshold > 0 {
			body["udpPktThreshold"] = in.UDPPktThreshold
		}
		if in.UDPBandwidthMB > 0 {
			body["udpBandwidthMB"] = in.UDPBandwidthMB
		}
		if in.WhitelistIPs != nil {
			for i, cidr := range in.WhitelistIPs {
				if err := validCIDR(cidr, fmt.Sprintf("whitelist_ips[%d]", i)); err != nil {
					return nil, mutOut{}, err
				}
			}
			body["whitelistIps"] = in.WhitelistIPs
		}
		if len(body) == 0 {
			return nil, mutOut{}, fmt.Errorf("no fields to set")
		}
		var res any
		if err := c.Post(ctx, "/config/securityrate", body, &res); err != nil {
			d.auditMut("secrate_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("secrate_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

func (d *Deps) secrateReset() sdk.ToolHandlerFor[targetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in targetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		var res any
		if err := c.Put(ctx, "/config/securityrate/reset", nil, &res); err != nil {
			d.auditMut("secrate_reset", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("secrate_reset", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- net_route_create / net_route_delete ----

type routeCreateIn struct {
	Target   string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	DestCIDR string `json:"dest_cidr" jsonschema:"destination network CIDR"`
	Gateway  string `json:"gateway" jsonschema:"next-hop gateway IP"`
}

func (d *Deps) netRouteCreate() sdk.ToolHandlerFor[routeCreateIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in routeCreateIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := validCIDR(in.DestCIDR, "dest_cidr"); err != nil {
			return nil, mutOut{}, err
		}
		if err := validIP(in.Gateway, "gateway"); err != nil {
			return nil, mutOut{}, err
		}
		body := map[string]any{"destinationIPNet": in.DestCIDR, "gateway": in.Gateway, "protocol": "static"}
		var res any
		if err := c.Post(ctx, "/config/route", body, &res); err != nil {
			d.auditMut("net_route_create", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("net_route_create", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type routeDeleteIn struct {
	Target       string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	DestCIDR     string `json:"dest_cidr" jsonschema:"destination network CIDR of the route to delete"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"single-use token from the preview step; omit to preview"`
}

func (d *Deps) netRouteDelete() sdk.ToolHandlerFor[routeDeleteIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in routeDeleteIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		ip, ipnet, err := net.ParseCIDR(in.DestCIDR)
		if err != nil {
			return nil, mutOut{}, fmt.Errorf("dest_cidr: invalid CIDR %q", in.DestCIDR)
		}
		ones, _ := ipnet.Mask.Size()

		args := in
		args.ConfirmToken = ""
		preview := map[string]any{"delete_route": in.DestCIDR}
		out, stop, err := d.gateDestructive("net_route_delete", c.Name(), in.ConfirmToken, args, preview)
		if err != nil || stop {
			return nil, out, err
		}
		path := fmt.Sprintf("/config/route/destinationIPNet/%s/%d", url.PathEscape(ip.String()), ones)
		var res any
		if err := c.Delete(ctx, path, &res); err != nil {
			d.auditMut("net_route_delete", c.Name(), args, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("net_route_delete", c.Name(), args, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- bgp tools ----

type bgpNeighSetIn struct {
	Target     string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	IPAddress  string `json:"ip_address" jsonschema:"neighbor IP"`
	RemoteAs   int    `json:"remote_as" jsonschema:"neighbor AS number"`
	RemotePort int    `json:"remote_port,omitempty" jsonschema:"neighbor BGP port (default 179)"`
	MultiHop   bool   `json:"multi_hop,omitempty" jsonschema:"enable eBGP multihop"`
}

func (d *Deps) bgpNeighSet() sdk.ToolHandlerFor[bgpNeighSetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in bgpNeighSetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := validIP(in.IPAddress, "ip_address"); err != nil {
			return nil, mutOut{}, err
		}
		if in.RemoteAs <= 0 {
			return nil, mutOut{}, fmt.Errorf("remote_as: %d (must be positive)", in.RemoteAs)
		}
		body := map[string]any{"ipAddress": in.IPAddress, "remoteAs": in.RemoteAs}
		if in.RemotePort > 0 {
			body["remotePort"] = in.RemotePort
		}
		if in.MultiHop {
			body["setMultiHop"] = true
		}
		var res any
		if err := c.Post(ctx, "/config/bgp/neigh", body, &res); err != nil {
			d.auditMut("bgp_neigh_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("bgp_neigh_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type bgpGlobalSetIn struct {
	Target         string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	RouterID       string `json:"router_id,omitempty" jsonschema:"BGP router id (IP form)"`
	LocalAs        int    `json:"local_as,omitempty" jsonschema:"local AS number"`
	ListenPort     int    `json:"listen_port,omitempty" jsonschema:"BGP listen port"`
	SetNextHopSelf bool   `json:"set_next_hop_self,omitempty" jsonschema:"advertise self as next hop"`
}

func (d *Deps) bgpGlobalSet() sdk.ToolHandlerFor[bgpGlobalSetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in bgpGlobalSetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if in.RouterID != "" {
			if err := validIP(in.RouterID, "router_id"); err != nil {
				return nil, mutOut{}, err
			}
		}
		body := map[string]any{}
		if in.RouterID != "" {
			body["routerId"] = in.RouterID
		}
		if in.LocalAs > 0 {
			body["localAs"] = in.LocalAs
		}
		if in.ListenPort > 0 {
			body["listenPort"] = in.ListenPort
		}
		if in.SetNextHopSelf {
			body["SetNextHopSelf"] = true
		}
		if len(body) == 0 {
			return nil, mutOut{}, fmt.Errorf("no fields to set")
		}
		var res any
		if err := c.Post(ctx, "/config/bgp/global", body, &res); err != nil {
			d.auditMut("bgp_global_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("bgp_global_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

type bgpPolicyApplyIn struct {
	Target      string   `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	IPAddress   string   `json:"ip_address" jsonschema:"neighbor IP the policy applies to"`
	PolicyType  string   `json:"policy_type" jsonschema:"import|export"`
	Policies    []string `json:"policies" jsonschema:"policy definition names to apply"`
	RouteAction string   `json:"route_action,omitempty" jsonschema:"accept|reject (default policy result)"`
}

func (d *Deps) bgpPolicyApply() sdk.ToolHandlerFor[bgpPolicyApplyIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in bgpPolicyApplyIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if err := validIP(in.IPAddress, "ip_address"); err != nil {
			return nil, mutOut{}, err
		}
		pt := strings.ToLower(in.PolicyType)
		if pt != "import" && pt != "export" {
			return nil, mutOut{}, fmt.Errorf("policy_type: %q (want import|export)", in.PolicyType)
		}
		if len(in.Policies) == 0 {
			return nil, mutOut{}, fmt.Errorf("policies: at least one policy name is required")
		}
		body := map[string]any{"ipAddress": in.IPAddress, "policyType": pt, "policies": in.Policies}
		if in.RouteAction != "" {
			body["routeAction"] = strings.ToLower(in.RouteAction)
		}
		var res any
		if err := c.Post(ctx, "/config/bgp/policy/apply", body, &res); err != nil {
			d.auditMut("bgp_policy_apply", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("bgp_policy_apply", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- config_params_set ----

var validLogLevels = map[string]bool{
	"trace": true, "debug": true, "info": true, "warning": true, "error": true,
	"critical": true, "emergency": true, "alert": true, "notice": true,
}

type paramsSetIn struct {
	Target   string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	LogLevel string `json:"log_level" jsonschema:"trace|debug|info|warning|error|critical|emergency|alert|notice"`
}

func (d *Deps) configParamsSet() sdk.ToolHandlerFor[paramsSetIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in paramsSetIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		lvl := strings.ToLower(in.LogLevel)
		if !validLogLevels[lvl] {
			return nil, mutOut{}, fmt.Errorf("log_level: %q", in.LogLevel)
		}
		var res any
		if err := c.Post(ctx, "/config/params", map[string]any{"logLevel": lvl}, &res); err != nil {
			d.auditMut("config_params_set", c.Name(), in, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("config_params_set", c.Name(), in, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}

// ---- config_import ----

type configImportIn struct {
	Target       string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	ConfigJSON   string `json:"config_json" jsonschema:"full configuration snapshot (JSON text, as produced by config_export)"`
	ConfirmToken string `json:"confirm_token,omitempty" jsonschema:"single-use token from the preview step; omit to preview"`
}

func (d *Deps) configImport() sdk.ToolHandlerFor[configImportIn, mutOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in configImportIn) (*sdk.CallToolResult, mutOut, error) {
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, mutOut{}, err
		}
		if strings.TrimSpace(in.ConfigJSON) == "" {
			return nil, mutOut{}, fmt.Errorf("config_json is required")
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(in.ConfigJSON), &parsed); err != nil {
			return nil, mutOut{}, fmt.Errorf("config_json: not valid JSON: %w", err)
		}
		args := in
		args.ConfirmToken = ""
		keys := make([]string, 0, len(parsed))
		for k := range parsed {
			keys = append(keys, clean(k))
		}
		preview := map[string]any{
			"import_sections": keys,
			"import_bytes":    len(in.ConfigJSON),
			"warning":         "config_import REPLACES the running configuration of the target",
		}
		out, stop, err := d.gateDestructive("config_import", c.Name(), in.ConfirmToken, args, preview)
		if err != nil || stop {
			return nil, out, err
		}
		var res any
		if err := c.PostMultipartFile(ctx, "/config/import", "configuration",
			"loxilb-config.json", []byte(in.ConfigJSON), &res); err != nil {
			d.auditMut("config_import", c.Name(), map[string]any{"import_bytes": len(in.ConfigJSON)}, false, err.Error())
			return nil, mutOut{}, err
		}
		d.auditMut("config_import", c.Name(), map[string]any{"import_bytes": len(in.ConfigJSON)}, true, "")
		return nil, mutOut{Target: c.Name(), Action: "executed", Result: sanitizeAny(res, 0)}, nil
	}
}
