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

// Package guard implements the server-side security policy layer of
// loxilb-mcp: client roles, tool gating (read-only mode, allow/deny lists,
// per-domain enablement) and token verification. See docs/MCP-DESIGN.md §2.2.
package guard

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"path"
	"strings"
)

// Role is the authorization tier attached to a client token.
type Role int

const (
	// RoleViewer may only call read-only tools.
	RoleViewer Role = iota
	// RoleOperator may additionally call non-destructive mutating tools.
	RoleOperator
	// RoleAdmin may call every tool, including destructive ones.
	RoleAdmin
)

// ParseRole converts a config string into a Role.
func ParseRole(s string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer, nil
	case "operator":
		return RoleOperator, nil
	case "admin":
		return RoleAdmin, nil
	}
	return RoleViewer, fmt.Errorf("unknown role %q (want viewer|operator|admin)", s)
}

func (r Role) String() string {
	switch r {
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return "viewer"
}

// ToolMeta describes a tool for policy decisions.
type ToolMeta struct {
	Name        string
	Domain      string // mgmt | analysis | monitoring | ai
	Mutating    bool
	Destructive bool
}

// Policy holds the server-wide tool gating configuration. The zero value
// permits every tool for an admin role with all domains enabled.
type Policy struct {
	ReadOnly bool
	Allow    []string        // glob patterns; empty means "all"
	Deny     []string        // glob patterns; deny wins over allow
	Domains  map[string]bool // nil means all domains enabled
	// Autopilot names destructive tools that may execute WITHOUT the
	// preview→confirm-token step (docs/MCP-DESIGN.md §3.7 closed-loop
	// tuning). Exact tool names only — globs are deliberately not
	// supported for a confirm-bypass surface. Role tiers still apply.
	Autopilot []string
}

// Permits reports whether a client with the given role may see/call the tool.
// Evaluation order: role tier, read-only mode, domain gate, deny list, allow list.
func (p *Policy) Permits(role Role, t ToolMeta) bool {
	if t.Mutating && role == RoleViewer {
		return false
	}
	if t.Destructive && role != RoleAdmin {
		return false
	}
	if p == nil {
		return true
	}
	if p.ReadOnly && t.Mutating {
		return false
	}
	if p.Domains != nil && !p.Domains[t.Domain] {
		return false
	}
	if matchAny(p.Deny, t.Name) {
		return false
	}
	if len(p.Allow) > 0 && !matchAny(p.Allow, t.Name) {
		return false
	}
	return true
}

// AutopilotAllowed reports whether the named tool may skip the confirm-token
// step. Exact match only; a nil policy has no autopilot tools.
func (p *Policy) AutopilotAllowed(name string) bool {
	if p == nil {
		return false
	}
	for _, t := range p.Autopilot {
		if strings.TrimSpace(t) == name {
			return true
		}
	}
	return false
}

func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}

// MinTokenLen is the minimum accepted client token length in bytes.
// 32 bytes (256 bits of entropy for random tokens) is recommended.
const MinTokenLen = 16

// Client is an authenticated MCP client identity.
type Client struct {
	Name string
	Role Role

	tokenHash [sha256.Size]byte
}

// NewClient builds a client identity from a bearer token.
func NewClient(name string, role Role, token string) (Client, error) {
	if len(token) < MinTokenLen {
		return Client{}, fmt.Errorf("client %q: token shorter than %d bytes", name, MinTokenLen)
	}
	return Client{Name: name, Role: role, tokenHash: sha256.Sum256([]byte(token))}, nil
}

// VerifyToken finds the client matching the presented bearer token.
// Comparison is constant-time over SHA-256 digests; every registered client
// is checked so timing does not reveal which (if any) entry matched.
func VerifyToken(clients []Client, presented string) (Client, bool) {
	var (
		found  Client
		gotOne int
	)
	h := sha256.Sum256([]byte(presented))
	for _, c := range clients {
		if subtle.ConstantTimeCompare(h[:], c.tokenHash[:]) == 1 {
			found = c
			gotOne = 1
		}
	}
	return found, gotOne == 1
}
