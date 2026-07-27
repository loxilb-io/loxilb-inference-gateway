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

package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb/pkg/mcp/client"
	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
	"github.com/loxilb-io/loxilb/pkg/mcp/tools"
)

// Version is the loxilb-mcp bridge version.
const Version = "0.1.0"

const serverName = "loxilb-mcp"

// Bridge wires config, policy, audit, and per-target REST clients together.
type Bridge struct {
	cfg        *Config
	pol        *guard.Policy
	aud        *guard.Auditor
	clients    map[string]*client.Client
	tokens     []guard.Client
	limiter    *rateLimiter
	prom       *client.PromClient
	am         *client.AlertmanagerClient
	alertRules []tools.AlertRule
	confirm    *guard.Confirmer // nil = --no-confirm

	// AllowImport enables the config_import tool (--allow-import).
	AllowImport bool
}

// SetNoConfirm disables the destructive-tool confirm-token flow (CI only).
// Must be called before BuildServer/Run*.
func (b *Bridge) SetNoConfirm() { b.confirm = nil }

// NewBridge constructs the bridge and its REST clients (no I/O performed).
func NewBridge(cfg *Config, pol *guard.Policy, aud *guard.Auditor) (*Bridge, error) {
	if pol == nil {
		pol = &guard.Policy{}
	}
	b := &Bridge{
		cfg:     cfg,
		pol:     pol,
		aud:     aud,
		clients: make(map[string]*client.Client, len(cfg.Targets)),
		limiter: newRateLimiter(10, 20),
		confirm: guard.NewConfirmer(0),
	}
	for name, t := range cfg.Targets {
		pass, err := resolveEnv(t.Password, t.PasswordEnv, "target "+name+" password")
		if err != nil {
			return nil, err
		}
		token, err := resolveEnv(t.Token, t.TokenEnv, "target "+name+" token")
		if err != nil {
			return nil, err
		}
		c, err := client.New(name, client.Options{
			URL:                t.URL,
			Username:           t.Username,
			Password:           pass,
			Token:              token,
			CAFile:             t.TLSCA,
			InsecureSkipVerify: t.InsecureSkipVerify,
			Timeout:            t.timeout(),
		})
		if err != nil {
			return nil, err
		}
		b.clients[name] = c
	}
	toks, err := cfg.GuardClients()
	if err != nil {
		return nil, err
	}
	b.tokens = toks

	if cfg.PrometheusURL != "" {
		if b.prom, err = client.NewPromClient(cfg.PrometheusURL, 0); err != nil {
			return nil, err
		}
	}
	if cfg.AlertmanagerURL != "" {
		if b.am, err = client.NewAlertmanagerClient(cfg.AlertmanagerURL, 0); err != nil {
			return nil, err
		}
	}
	if cfg.AlertRulesPath != "" {
		if b.alertRules, err = tools.LoadAlertRules(cfg.AlertRulesPath); err != nil {
			return nil, fmt.Errorf("alert_rules_path: %w", err)
		}
	}
	return b, nil
}

// resolve maps a tool-supplied target name to a client. Only names present in
// the config resolve — URL-shaped or unknown values are rejected (anti-SSRF,
// docs/MCP-DESIGN.md §2.2 T7).
func (b *Bridge) resolve(name string) (*client.Client, error) {
	if name == "" {
		name = b.cfg.DefaultTarget
	}
	c, ok := b.clients[name]
	if !ok {
		return nil, fmt.Errorf("unknown target %q (configured: %s)",
			name, strings.Join(b.targetNames(), ", "))
	}
	return c, nil
}

func (b *Bridge) targetNames() []string {
	names := make([]string, 0, len(b.clients))
	for n := range b.clients {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// resolveAll returns every target client sorted by name (fan-out).
func (b *Bridge) resolveAll() []*client.Client {
	names := b.targetNames()
	out := make([]*client.Client, 0, len(names))
	for _, n := range names {
		out = append(out, b.clients[n])
	}
	return out
}

// BuildServer constructs an MCP server exposing exactly the tools the given
// role is permitted to use.
func (b *Bridge) BuildServer(role guard.Role) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: serverName, Version: Version}, nil)
	deps := &tools.Deps{
		Resolve:      b.resolve,
		Targets:      b.targetNames(),
		Audit:        b.aud,
		Prom:         b.prom,
		Alertmanager: b.am,
		AlertRules:   b.alertRules,
		Confirm:      b.confirm,
		AllowImport:  b.AllowImport,
		SecretsDir:   b.cfg.SecretsDir,
		Autopilot:    b.pol.AutopilotAllowed,
		ResolveAll:   b.resolveAll,
	}
	tools.RegisterSeed(s, role, b.pol, deps)
	tools.RegisterAnalysis(s, role, b.pol, deps)
	tools.RegisterMonitoring(s, role, b.pol, deps)
	tools.RegisterManagement(s, role, b.pol, deps)
	tools.RegisterAI(s, role, b.pol, deps)
	tools.RegisterDiagnose(s, role, b.pol, deps)
	tools.RegisterFleet(s, role, b.pol, deps)
	b.registerResources(s)
	b.registerPrompts(s)
	return s
}

// RunStdio serves a single MCP session over stdin/stdout with the given role
// (stdio inherits the local user's authority; default admin).
func (b *Bridge) RunStdio(ctx context.Context, role guard.Role) error {
	return b.BuildServer(role).Run(ctx, &sdk.StdioTransport{})
}

// HTTPOptions configures the streamable-HTTP transport.
type HTTPOptions struct {
	Listen         string // host:port
	TLSCert        string
	TLSKey         string
	TLSClientCA    string // enables mTLS when set
	InsecureHTTP   bool   // allow plaintext on a non-loopback bind (lab only)
	SessionTimeout time.Duration
}

type ctxKey int

const clientCtxKey ctxKey = 0

// HTTPHandler builds the full middleware chain:
// cross-origin protection → bearer auth (+rate limit) → streamable MCP.
func (b *Bridge) HTTPHandler() (http.Handler, error) {
	if len(b.tokens) == 0 {
		return nil, errors.New("HTTP mode requires at least one client token " +
			"(clients: in the config file); refusing to serve unauthenticated")
	}

	// One MCP server per role: tools/list reflects exactly what the caller
	// may do, and sessions of different tiers never share a server.
	servers := map[guard.Role]*sdk.Server{}
	for _, t := range b.tokens {
		if _, ok := servers[t.Role]; !ok {
			servers[t.Role] = b.BuildServer(t.Role)
		}
	}

	inner := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		cl, ok := r.Context().Value(clientCtxKey).(guard.Client)
		if !ok {
			return nil // unauthenticated requests never reach here
		}
		return servers[cl.Role]
	}, &sdk.StreamableHTTPOptions{SessionTimeout: 30 * time.Minute})

	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			b.aud.Log(guard.Event{Kind: guard.EventAuthReject, Remote: r.RemoteAddr,
				Err: "missing bearer token"})
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		cl, ok := guard.VerifyToken(b.tokens, token)
		if !ok {
			b.aud.Log(guard.Event{Kind: guard.EventAuthReject, Remote: r.RemoteAddr,
				Err: "invalid bearer token"})
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !b.limiter.allow(cl.Name) {
			b.aud.Log(guard.Event{Kind: guard.EventRateLimit, Client: cl.Name,
				Remote: r.RemoteAddr})
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		inner.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), clientCtxKey, cl)))
	})

	// Go 1.25 stdlib cross-origin protection: rejects browser-originated
	// cross-origin requests (Sec-Fetch-Site / Origin-vs-Host); requests
	// without browser markers (MCP clients, curl) pass. Combined with the
	// SDK's localhost Host-header check this covers DNS rebinding (T1).
	protection := http.NewCrossOriginProtection()
	protection.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.aud.Log(guard.Event{Kind: guard.EventOriginReject, Remote: r.RemoteAddr,
			Err: "origin " + r.Header.Get("Origin")})
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
	}))
	return protection.Handler(authed), nil
}

// RunHTTP serves streamable MCP over HTTP(S) until ctx is cancelled.
// Plaintext on a non-loopback bind is refused unless InsecureHTTP is set
// (docs/MCP-DESIGN.md §2.2 T2).
func (b *Bridge) RunHTTP(ctx context.Context, opts HTTPOptions) error {
	useTLS := opts.TLSCert != "" || opts.TLSKey != ""
	if useTLS && (opts.TLSCert == "" || opts.TLSKey == "") {
		return errors.New("both --tls-cert and --tls-key are required for TLS")
	}
	if !useTLS && !listenIsLoopback(opts.Listen) {
		if !opts.InsecureHTTP {
			return fmt.Errorf("refusing plaintext HTTP with bearer auth on non-loopback %q; "+
				"use TLS, bind loopback (+SSH tunnel), or pass --insecure-http (lab only)", opts.Listen)
		}
		log.Printf("WARNING: serving bearer-authenticated MCP over PLAINTEXT on %s; "+
			"tokens are exposed to the network (lab use only)", opts.Listen)
	}

	handler, err := b.HTTPHandler()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              opts.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if opts.TLSClientCA != "" {
		pem, err := os.ReadFile(opts.TLSClientCA)
		if err != nil {
			return fmt.Errorf("read tls client ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certs parsed from %s", opts.TLSClientCA)
		}
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientCAs:  pool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
	}

	errCh := make(chan error, 1)
	go func() {
		if useTLS {
			errCh <- srv.ListenAndServeTLS(opts.TLSCert, opts.TLSKey)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()
	log.Printf("%s %s serving MCP (streamable HTTP%s) on %s",
		serverName, Version, map[bool]string{true: "S"}[useTLS], opts.Listen)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}

func listenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if host == "" {
		return false // ":8891" binds all interfaces
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// rateLimiter is a simple per-client token bucket (T8).
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rps     float64
	burst   float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rps, burst float64) *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, rps: rps, burst: burst}
}

func (rl *rateLimiter) allow(name string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	bk, ok := rl.buckets[name]
	if !ok {
		bk = &bucket{tokens: rl.burst, last: now}
		rl.buckets[name] = bk
	}
	bk.tokens += now.Sub(bk.last).Seconds() * rl.rps
	if bk.tokens > rl.burst {
		bk.tokens = rl.burst
	}
	bk.last = now
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}
