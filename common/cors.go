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

// cors.go — the CORS origin-allowlist manager (moved here from
// api/apiutils/cors so the REST handlers, the HTTP middleware and the
// config snapshot/restore hooks all share one store without layering
// inversions).
//
// State model (the fail-open fix):
//
//   - UNCONFIGURED (factory default): no explicit configuration was ever
//     applied. Cross-origin is open (wildcard behavior) — the historical
//     development-friendly default for a fresh gateway.
//   - CONFIGURED: an explicit allowlist (possibly EMPTY) or an explicit
//     wildcard opt-in exists. An empty configured allowlist means "no
//     cross-origin caller is allowed" and is NEVER silently re-seeded
//     back to the wildcard — deleting the last origin used to fall open
//     to `*` (with credentials), turning an operator's lockdown into an
//     open gateway.
//
// The configured state is desired configuration and round-trips through
// the config snapshot (the "cors" domain): before persistence existed,
// every reboot silently reverted a configured allowlist to the open
// default.
package common

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// CORSConfig is the exported/persisted desired CORS configuration (the
// snapshot "cors" domain payload). Origins is the normalized explicit
// allowlist; Wildcard is the explicit allow-all opt-in (mutually exclusive
// with a non-empty Origins list). A nil *CORSConfig everywhere means
// "unconfigured" (factory default).
type CORSConfig struct {
	// Origins - normalized origin allowlist (no "*" entries; use Wildcard).
	Origins []string `json:"origins"`
	// Wildcard - explicit allow-all opt-in.
	Wildcard bool `json:"wildcard,omitempty"`
}

// CORSManager guards the origin allowlist. All methods are safe for
// concurrent use.
type CORSManager struct {
	mutex      sync.RWMutex
	origins    map[string]bool
	wildcard   bool
	configured bool
}

// corsMgr is the process-wide instance.
var corsMgr CORSManager

// GetCORSManager returns the process-wide CORS manager.
func GetCORSManager() *CORSManager {
	return &corsMgr
}

// normalizeOrigin trims an origin; empty and bare-"*" values are the
// caller's responsibility to reject (AddOrigin/SetConfig do).
func normalizeOrigin(origin string) string {
	return strings.TrimSpace(origin)
}

// GetOrigin returns the effective allowed-origin set in the historical
// map shape the REST GET handler renders: {"*": true} while the wildcard
// behavior is active (unconfigured factory default, or explicit opt-in),
// otherwise a copy of the explicit allowlist — which may be EMPTY when the
// operator deleted every origin (deny-all; deliberately NOT re-seeded).
func (c *CORSManager) GetOrigin() map[string]bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if !c.configured || c.wildcard {
		return map[string]bool{"*": true}
	}
	out := make(map[string]bool, len(c.origins))
	for o := range c.origins {
		out[o] = true
	}
	return out
}

// AddOrigin adds one origin to the explicit allowlist, ending wildcard
// behavior (both the factory default and an explicit opt-in).
func (c *CORSManager) AddOrigin(origin string) error {
	origin = normalizeOrigin(origin)
	if origin == "" || origin == "*" {
		return fmt.Errorf("cors: invalid origin %q", origin)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.configured && !c.wildcard && c.origins[origin] {
		return fmt.Errorf("origin %s already exists in allowed origins", origin)
	}
	if !c.configured || c.wildcard {
		c.origins = make(map[string]bool)
	}
	if c.origins == nil {
		c.origins = make(map[string]bool)
	}
	c.origins[origin] = true
	c.configured = true
	c.wildcard = false
	return nil
}

// RemoveOrigin removes one origin from the explicit allowlist. Removing
// the LAST origin leaves an empty configured allowlist (deny-all): it must
// NOT fall open to the wildcard — that silent re-seed turned an operator
// lockdown into `*` + credentials.
func (c *CORSManager) RemoveOrigin(origin string) error {
	origin = normalizeOrigin(origin)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.configured || c.wildcard || !c.origins[origin] {
		return fmt.Errorf("origin %s not found in allowed origins", origin)
	}
	delete(c.origins, origin)
	return nil
}

// IsAllowed reports whether the given origin may be granted cross-origin
// access: always while wildcard behavior is active, allowlist membership
// otherwise.
func (c *CORSManager) IsAllowed(origin string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if !c.configured || c.wildcard {
		return true
	}
	return c.origins[origin]
}

// WildcardActive reports whether allow-all behavior is in effect
// (unconfigured factory default, or explicit wildcard opt-in). The HTTP
// middleware branches on this: wildcard responses carry
// "Access-Control-Allow-Origin: *" and NO credentials grant.
func (c *CORSManager) WildcardActive() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return !c.configured || c.wildcard
}

// ExportConfig returns the explicit desired configuration, or nil while
// unconfigured (the factory default is not configuration and is not
// persisted). Origins are sorted for deterministic capture.
func (c *CORSManager) ExportConfig() *CORSConfig {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if !c.configured {
		return nil
	}
	out := &CORSConfig{Wildcard: c.wildcard, Origins: make([]string, 0, len(c.origins))}
	for o := range c.origins {
		out.Origins = append(out.Origins, o)
	}
	sort.Strings(out.Origins)
	return out
}

// SetConfig replaces the whole configuration (overwrite/Set semantics —
// the snapshot restore path). A nil cfg is rejected: use ResetConfig to
// return to the unconfigured factory default.
func (c *CORSManager) SetConfig(cfg *CORSConfig) error {
	if cfg == nil {
		return fmt.Errorf("cors: nil config (use reset for the factory default)")
	}
	if cfg.Wildcard && len(cfg.Origins) > 0 {
		return fmt.Errorf("cors: wildcard and an explicit origin list are mutually exclusive")
	}
	origins := make(map[string]bool, len(cfg.Origins))
	for _, o := range cfg.Origins {
		o = normalizeOrigin(o)
		if o == "" || o == "*" {
			return fmt.Errorf("cors: invalid origin %q in config", o)
		}
		origins[o] = true
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.origins = origins
	c.wildcard = cfg.Wildcard
	c.configured = true
	return nil
}

// ResetConfig discards any explicit configuration, returning to the
// unconfigured factory default (open). Used by the snapshot wipe: "remove
// this domain's config" for CORS means unconfigure, exactly the state a
// fresh gateway boots with — never a synthetic deny-all that a failed
// restore would then leave behind.
func (c *CORSManager) ResetConfig() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.origins = nil
	c.wildcard = false
	c.configured = false
}
