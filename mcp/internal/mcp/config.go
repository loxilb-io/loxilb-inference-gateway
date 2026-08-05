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

// Package mcp assembles the loxilb-mcp bridge: configuration, MCP server
// construction, and the stdio / streamable-HTTP transports with the security
// posture defined in docs/MCP-DESIGN.md §2.2.
package mcp

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

// Target is one loxilb instance the bridge can talk to.
type Target struct {
	URL                string `yaml:"url"`
	Username           string `yaml:"username"`
	Password           string `yaml:"password"`
	PasswordEnv        string `yaml:"password_env"`
	Token              string `yaml:"token"`
	TokenEnv           string `yaml:"token_env"`
	TLSCA              string `yaml:"tls_ca"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	TimeoutSec         int    `yaml:"timeout_sec"`
}

// ClientToken authenticates one MCP client in HTTP mode.
type ClientToken struct {
	Name     string `yaml:"name"`
	Role     string `yaml:"role"`
	Token    string `yaml:"token"`
	TokenEnv string `yaml:"token_env"`
}

// Config is the bridge configuration file (YAML, mode 0600 recommended).
type Config struct {
	DefaultTarget string            `yaml:"default_target"`
	Targets       map[string]Target `yaml:"targets"`
	Clients       []ClientToken     `yaml:"clients"`
	AuditDir      string            `yaml:"audit_dir"`

	// Optional observability backends.
	PrometheusURL   string `yaml:"prometheus_url"`
	AlertmanagerURL string `yaml:"alertmanager_url"`
	// AlertRulesPath points at a Prometheus alerting-rules YAML
	// (e.g. deploy/monitoring/prometheus/rules/loxilb-alerts.yml); enables
	// the alerts_catalog tool and the loxilb://docs/alerts resource.
	AlertRulesPath string `yaml:"alert_rules_path"`
	// OpenapiSpecPath points at the swagger spec served as
	// loxilb://spec/openapi.
	OpenapiSpecPath string `yaml:"openapi_spec_path"`
	// SecretsDir receives files holding secret material that must never
	// enter model context (ai_apikey_create raw keys, threat T5). The CLI
	// defaults it to <audit dir>/secrets; empty here AND no CLI default
	// makes ai_apikey_create require reveal=true.
	SecretsDir string `yaml:"secrets_dir"`
	// AutopilotTools lists destructive tools allowed to execute without
	// the confirm-token step (exact names, §3.7). Default empty: every
	// destructive tool requires preview→confirm.
	AutopilotTools []string `yaml:"autopilot_tools"`
}

// LoadConfig reads and validates a YAML config file. Unknown fields error.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// QuickConfig builds a config-less single-target setup (dev convenience,
// stdio mode only).
func QuickConfig(url string) *Config {
	return &Config{
		DefaultTarget: "default",
		Targets:       map[string]Target{"default": {URL: url}},
	}
}

func (c *Config) validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("no targets configured")
	}
	if c.DefaultTarget == "" {
		if len(c.Targets) == 1 {
			for name := range c.Targets {
				c.DefaultTarget = name
			}
		} else {
			return fmt.Errorf("default_target required when multiple targets are configured")
		}
	}
	if _, ok := c.Targets[c.DefaultTarget]; !ok {
		return fmt.Errorf("default_target %q not in targets", c.DefaultTarget)
	}
	for name, t := range c.Targets {
		if t.URL == "" {
			return fmt.Errorf("target %q: url required", name)
		}
		if t.Password != "" && t.PasswordEnv != "" {
			return fmt.Errorf("target %q: set password or password_env, not both", name)
		}
	}
	seen := map[string]bool{}
	for i, cl := range c.Clients {
		if cl.Name == "" {
			return fmt.Errorf("clients[%d]: name required", i)
		}
		if seen[cl.Name] {
			return fmt.Errorf("clients[%d]: duplicate name %q", i, cl.Name)
		}
		seen[cl.Name] = true
		if _, err := guard.ParseRole(cl.Role); err != nil {
			return fmt.Errorf("client %q: %w", cl.Name, err)
		}
		if (cl.Token == "") == (cl.TokenEnv == "") {
			return fmt.Errorf("client %q: exactly one of token or token_env required", cl.Name)
		}
	}
	return nil
}

// resolveEnv returns v, or the env var content when envKey is set.
func resolveEnv(v, envKey, what string) (string, error) {
	if envKey == "" {
		return v, nil
	}
	ev := os.Getenv(envKey)
	if ev == "" {
		return "", fmt.Errorf("%s: env %s is empty or unset", what, envKey)
	}
	return ev, nil
}

// GuardClients materializes the client token list (resolving env refs).
func (c *Config) GuardClients() ([]guard.Client, error) {
	out := make([]guard.Client, 0, len(c.Clients))
	for _, cl := range c.Clients {
		role, err := guard.ParseRole(cl.Role)
		if err != nil {
			return nil, err
		}
		token, err := resolveEnv(cl.Token, cl.TokenEnv, "client "+cl.Name)
		if err != nil {
			return nil, err
		}
		gc, err := guard.NewClient(cl.Name, role, token)
		if err != nil {
			return nil, err
		}
		out = append(out, gc)
	}
	return out, nil
}

func (t Target) timeout() time.Duration {
	if t.TimeoutSec > 0 {
		return time.Duration(t.TimeoutSec) * time.Second
	}
	return 0
}
