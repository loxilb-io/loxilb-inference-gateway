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

// loxilb-mcp is the standalone MCP bridge for loxilb management, analysis,
// monitoring, and AI-gateway operations. See docs/MCP-DESIGN.md.
//
// Examples:
//
//	# local dev against a default loxilb, stdio transport
//	loxilb-mcp --target-url http://127.0.0.1:11111
//
//	# testbed: config file with named targets + client tokens, HTTP transport
//	loxilb-mcp --config /etc/loxilb-mcp.yaml --transport http --listen 127.0.0.1:8891
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	mcpbridge "github.com/loxilb-io/loxilb/pkg/mcp"
	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
)

func main() {
	var (
		configPath   = flag.String("config", "", "path to loxilb-mcp YAML config (targets, clients, audit_dir)")
		targetURL    = flag.String("target-url", "", "config-less single target URL (stdio dev mode), e.g. http://127.0.0.1:11111")
		transport    = flag.String("transport", "stdio", "MCP transport: stdio | http")
		listen       = flag.String("listen", "127.0.0.1:8891", "listen address for --transport http")
		tlsCert      = flag.String("tls-cert", "", "TLS certificate for HTTP transport")
		tlsKey       = flag.String("tls-key", "", "TLS private key for HTTP transport")
		tlsClientCA  = flag.String("tls-client-ca", "", "CA bundle for mTLS client verification")
		insecureHTTP = flag.Bool("insecure-http", false, "LAB ONLY: allow plaintext HTTP on a non-loopback bind")
		readOnly     = flag.Bool("read-only", false, "register only read-only tools")
		noConfirm    = flag.Bool("no-confirm", false, "CI ONLY: destructive tools execute without the preview/confirm-token step")
		allowImport  = flag.Bool("allow-import", false, "enable the config_import tool (replaces running config; admin+confirm gated)")
		allowTools   = flag.String("allow-tools", "", "comma-separated glob allowlist of tool names")
		denyTools    = flag.String("deny-tools", "", "comma-separated glob denylist of tool names (wins over allow)")
		autopilot    = flag.String("autopilot-tools", "", "comma-separated EXACT names of destructive tools allowed to run without the confirm-token step (closed-loop use; default none)")
		domains      = flag.String("enable-domains", "", "comma-separated domains to enable (mgmt,analysis,monitoring,ai); empty = all")
		roleFlag     = flag.String("role", "admin", "role for the stdio session: viewer | operator | admin")
		auditDir     = flag.String("audit-dir", "", "audit log directory (default: config audit_dir, else ~/.loxilb-mcp)")
		secretsDir   = flag.String("secrets-dir", "", "directory for secret files such as created API keys (default: config secrets_dir, else <audit-dir>/secrets)")
		promURL      = flag.String("prometheus-url", "", "external Prometheus base URL enabling promql_* tools (overrides config)")
		amURL        = flag.String("alertmanager-url", "", "Alertmanager base URL enabling alerts_active (overrides config)")
		alertRules   = flag.String("alert-rules", "", "Prometheus alert-rules YAML enabling alerts_catalog (overrides config)")
		openapiSpec  = flag.String("openapi-spec", "", "swagger spec file served as the loxilb://spec/openapi resource (overrides config)")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("loxilb-mcp %s\n", mcpbridge.Version)
		return
	}

	overrides := backendOverrides{
		prometheusURL:   *promURL,
		alertmanagerURL: *amURL,
		alertRulesPath:  *alertRules,
		openapiSpecPath: *openapiSpec,
	}
	if err := run(*configPath, *targetURL, *transport, *listen, *tlsCert, *tlsKey,
		*tlsClientCA, *insecureHTTP, *readOnly, *noConfirm, *allowImport,
		*allowTools, *denyTools, *autopilot, *domains, *roleFlag, *auditDir, *secretsDir, overrides); err != nil {
		fmt.Fprintf(os.Stderr, "loxilb-mcp: %v\n", err)
		os.Exit(1)
	}
}

type backendOverrides struct {
	prometheusURL   string
	alertmanagerURL string
	alertRulesPath  string
	openapiSpecPath string
}

func run(configPath, targetURL, transport, listen, tlsCert, tlsKey, tlsClientCA string,
	insecureHTTP, readOnly, noConfirm, allowImport bool,
	allowTools, denyTools, autopilotTools, domains, roleFlag, auditDir, secretsDir string,
	overrides backendOverrides) error {

	// stdio mode must not log to stdout (it carries the protocol).
	log.SetOutput(os.Stderr)

	var cfg *mcpbridge.Config
	switch {
	case configPath != "" && targetURL != "":
		return fmt.Errorf("--config and --target-url are mutually exclusive")
	case configPath != "":
		var err error
		if cfg, err = mcpbridge.LoadConfig(configPath); err != nil {
			return err
		}
	case targetURL != "":
		if transport != "stdio" {
			return fmt.Errorf("--target-url is stdio-only; HTTP mode requires --config with client tokens")
		}
		cfg = mcpbridge.QuickConfig(targetURL)
	default:
		return fmt.Errorf("one of --config or --target-url is required")
	}
	if overrides.prometheusURL != "" {
		cfg.PrometheusURL = overrides.prometheusURL
	}
	if overrides.alertmanagerURL != "" {
		cfg.AlertmanagerURL = overrides.alertmanagerURL
	}
	if overrides.alertRulesPath != "" {
		cfg.AlertRulesPath = overrides.alertRulesPath
	}
	if overrides.openapiSpecPath != "" {
		cfg.OpenapiSpecPath = overrides.openapiSpecPath
	}

	pol := &guard.Policy{
		ReadOnly:  readOnly,
		Allow:     splitCSV(allowTools),
		Deny:      splitCSV(denyTools),
		Autopilot: append(splitCSV(autopilotTools), cfg.AutopilotTools...),
	}
	if len(pol.Autopilot) > 0 {
		log.Printf("WARNING: autopilot tools execute WITHOUT confirm-token: %s",
			strings.Join(pol.Autopilot, ", "))
	}
	if d := splitCSV(domains); len(d) > 0 {
		pol.Domains = map[string]bool{}
		for _, name := range d {
			pol.Domains[name] = true
		}
	}

	dir := auditDir
	if dir == "" {
		dir = cfg.AuditDir
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home for audit dir: %w", err)
		}
		dir = filepath.Join(home, ".loxilb-mcp")
	}
	aud, err := guard.OpenAuditor(dir)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer aud.Close()

	// Secret files (ai_apikey_create raw keys, T5) default next to the audit
	// log so a single 0700 tree holds all bridge-local sensitive state.
	if secretsDir != "" {
		cfg.SecretsDir = secretsDir
	}
	if cfg.SecretsDir == "" {
		cfg.SecretsDir = filepath.Join(dir, "secrets")
	}

	bridge, err := mcpbridge.NewBridge(cfg, pol, aud)
	if err != nil {
		return err
	}
	if noConfirm {
		log.Printf("WARNING: --no-confirm: destructive tools execute without the confirm-token step")
		bridge.SetNoConfirm()
	}
	bridge.AllowImport = allowImport

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch transport {
	case "stdio":
		role, err := guard.ParseRole(roleFlag)
		if err != nil {
			return err
		}
		return bridge.RunStdio(ctx, role)
	case "http":
		return bridge.RunHTTP(ctx, mcpbridge.HTTPOptions{
			Listen:       listen,
			TLSCert:      tlsCert,
			TLSKey:       tlsKey,
			TLSClientCA:  tlsClientCA,
			InsecureHTTP: insecureHTTP,
		})
	default:
		return fmt.Errorf("unknown transport %q (want stdio|http)", transport)
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
