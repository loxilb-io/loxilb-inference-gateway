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

// Package client is the thin, hand-rolled loxilb REST client used by
// loxilb-mcp. It intentionally does not import pkg/loxinet: the bridge
// consumes only the public REST surface.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	basePath       = "/netlox/v1"
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 16 << 20 // hard cap on any response body we read
	maxErrSnippet  = 512
)

// Options configures a Client for one loxilb target.
type Options struct {
	URL                string // e.g. http://192.168.80.9:11111
	Username           string // set when the target runs --userservice
	Password           string
	Token              string // pre-provisioned token (alternative to login)
	CAFile             string // extra CA for https targets
	InsecureSkipVerify bool   // lab-only: accept self-signed target certs
	Timeout            time.Duration
}

// Client talks to a single loxilb instance.
type Client struct {
	name string
	base string
	hc   *http.Client
	user string
	pass string

	mu    sync.Mutex
	token string
}

// New builds a client; it performs no I/O (auth happens lazily on 401).
func New(name string, o Options) (*Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("target %q: invalid url %q", name, o.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("target %q: unsupported scheme %q", name, u.Scheme)
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if u.Scheme == "https" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, fmt.Errorf("target %q: read ca file: %w", name, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("target %q: no certs parsed from %s", name, o.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		tlsCfg.InsecureSkipVerify = o.InsecureSkipVerify
		tr.TLSClientConfig = tlsCfg
	}
	return &Client{
		name:  name,
		base:  strings.TrimRight(o.URL, "/"),
		hc:    &http.Client{Timeout: timeout, Transport: tr},
		user:  o.Username,
		pass:  o.Password,
		token: o.Token,
	}, nil
}

// Name returns the configured target name.
func (c *Client) Name() string { return c.name }

// Base returns the target's base URL (targets_list).
func (c *Client) Base() string { return c.base }

func (c *Client) getToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

func (c *Client) setToken(t string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = t
}

// login authenticates against loxilb --userservice (POST /auth/login).
func (c *Client) login(ctx context.Context) error {
	if c.user == "" {
		return errors.New("received 401 and no credentials configured for target " +
			c.name + " (is loxilb running --userservice? configure username/password_env " +
			"or token_env for this target — see docs/MCP-OPERATIONS.md)")
	}
	body, _ := json.Marshal(map[string]string{"username": c.user, "password": c.pass})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+basePath+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("target %s: login: %w", c.name, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("target %s: login failed: %s", c.name, statusSnippet(resp.StatusCode, raw))
	}
	var lr struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &lr); err != nil || lr.Token == "" {
		return fmt.Errorf("target %s: login: no token in response", c.name)
	}
	c.setToken(lr.Token)
	return nil
}

// do performs one JSON request against basePath+path, transparently
// re-authenticating once on 401 when credentials are configured.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	run := func() (*http.Response, error) {
		var body io.Reader
		if in != nil {
			b, err := json.Marshal(in)
			if err != nil {
				return nil, err
			}
			body = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+basePath+path, body)
		if err != nil {
			return nil, err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/json")
		if t := c.getToken(); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
		return c.hc.Do(req)
	}

	resp, err := run()
	if err != nil {
		return fmt.Errorf("target %s: %s %s: %w", c.name, method, path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrSnippet))
		resp.Body.Close()
		if err := c.login(ctx); err != nil {
			return err
		}
		if resp, err = run(); err != nil {
			return fmt.Errorf("target %s: %s %s (post-login): %w", c.name, method, path, err)
		}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("target %s: %s %s: read body: %w", c.name, method, path, err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("target %s: %s %s: %s", c.name, method, path,
			statusSnippet(resp.StatusCode, raw))
	}
	// 204-style success responses carry no body (e.g. DELETE /config/ai/apikey).
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("target %s: %s %s: decode: %w", c.name, method, path, err)
		}
	}
	return nil
}

func statusSnippet(code int, body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > maxErrSnippet {
		s = s[:maxErrSnippet] + "..."
	}
	if s == "" {
		return fmt.Sprintf("HTTP %d", code)
	}
	return fmt.Sprintf("HTTP %d: %s", code, s)
}

// Get performs a GET against basePath+path and decodes the JSON response
// into out. path must start with "/" and is caller-controlled only —
// never derived from tool arguments without validation.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// GetQ is Get with URL-encoded query parameters.
func (c *Client) GetQ(ctx context.Context, path string, q url.Values, out any) error {
	if len(q) > 0 {
		path = path + "?" + q.Encode()
	}
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// VersionInfo is the GET /version payload.
type VersionInfo struct {
	Version   string `json:"version"`
	BuildInfo string `json:"buildInfo"`
}

// Version fetches GET /version.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	var v VersionInfo
	err := c.do(ctx, http.MethodGet, "/version", nil, &v)
	return v, err
}

// LBRules fetches GET /config/loadbalancer/all. Entries are returned loosely
// typed; callers compact them for LLM consumption.
func (c *Client) LBRules(ctx context.Context) ([]map[string]any, error) {
	var env struct {
		LbAttr []map[string]any `json:"lbAttr"`
	}
	if err := c.do(ctx, http.MethodGet, "/config/loadbalancer/all", nil, &env); err != nil {
		return nil, err
	}
	return env.LbAttr, nil
}

// Conntrack is one entry of GET /config/conntrack/all.
type Conntrack struct {
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      int64  `json:"sourcePort"`
	DestinationPort int64  `json:"destinationPort"`
	Protocol        string `json:"protocol"`
	State           string `json:"conntrackState"`
	Act             string `json:"conntrackAct"`
	ServName        string `json:"servName"`
	Packets         int64  `json:"packets"`
	Bytes           int64  `json:"bytes"`
	AgeMs           uint64 `json:"ageMs"`
}

// Conntracks fetches GET /config/conntrack/all.
func (c *Client) Conntracks(ctx context.Context) ([]Conntrack, error) {
	var env struct {
		CtAttr []Conntrack `json:"ctAttr"`
	}
	if err := c.do(ctx, http.MethodGet, "/config/conntrack/all", nil, &env); err != nil {
		return nil, err
	}
	return env.CtAttr, nil
}

// MetricsText scrapes GET /metrics (Prometheus exposition text).
func (c *Client) MetricsText(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+basePath+"/metrics", nil)
	if err != nil {
		return "", err
	}
	if t := c.getToken(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("target %s: GET /metrics: %w", c.name, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", fmt.Errorf("target %s: GET /metrics: read: %w", c.name, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The metrics endpoint 401s when --userservice is on; re-auth and retry once.
		if err := c.login(ctx); err != nil {
			return "", err
		}
		return c.MetricsText(ctx)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("target %s: GET /metrics: %s", c.name, statusSnippet(resp.StatusCode, raw))
	}
	return string(raw), nil
}
