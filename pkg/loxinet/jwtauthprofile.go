/*
 * Copyright (c) 2026 LoxiLB Authors
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

package loxinet

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/jwtauth"
)

// JWTAuthProfileH holds the configured JWT auth profiles and the verifier
// runtime behind them. The stored cmn mods are the desired configuration
// (what GET and snapshots report); the jwtauth.Manager holds the live key
// lifecycles. The two are updated together under mu.
type JWTAuthProfileH struct {
	mu       sync.Mutex
	profiles map[string]cmn.JWTAuthProfileMod
	mgr      *jwtauth.Manager

	// ruleRefs reports the idents of LB rules referencing a profile name.
	// Deletion is refused while any exist: a rule pointing at a vanished
	// profile would fail closed (503) on every request, which is safe but
	// silent — refusing the delete keeps the misconfiguration loud and at
	// the operator's console. The LB-rule surface gains its profile field
	// with the bearer admission arm; until then nothing can reference a
	// profile and this returns nil.
	ruleRefs func(name string) []string
}

// JWTAuthProfileInit builds the profile holder with a live manager.
func JWTAuthProfileInit() *JWTAuthProfileH {
	return &JWTAuthProfileH{
		profiles: make(map[string]cmn.JWTAuthProfileMod),
		mgr:      jwtauth.New(),
		ruleRefs: func(string) []string { return nil },
	}
}

// jwtProfileFromMod maps the wire/config shape onto the verifier's profile.
// Field-for-field; defaults are applied by the jwtauth package itself so
// GET and snapshots keep reporting exactly what the operator configured.
func jwtProfileFromMod(pm *cmn.JWTAuthProfileMod) jwtauth.Profile {
	return jwtauth.Profile{
		Name:                     pm.Name,
		Issuer:                   pm.Issuer,
		JWKSURL:                  pm.JWKSURL,
		Audiences:                pm.Audiences,
		Algs:                     pm.Algs,
		LeewaySec:                pm.LeewaySec,
		RefreshSec:               pm.RefreshSec,
		TenantClaim:              pm.TenantClaim,
		UserClaim:                pm.UserClaim,
		ModelsClaim:              pm.ModelsClaim,
		RolesClaim:               pm.RolesClaim,
		ModelRolePrefix:          pm.ModelRolePrefix,
		UsernameClaim:            pm.UsernameClaim,
		ModelAuthz:               pm.ModelAuthz,
		DefaultTenant:            pm.DefaultTenant,
		ForwardIdentity:          pm.ForwardIdentity,
		AuthorizationPassthrough: pm.AuthorizationPassthrough,
	}
}

// ProfileAdd creates or replaces a profile. Replacement restarts the key
// lifecycle fail-closed (the manager handles the unchanged-re-set no-op).
func (h *JWTAuthProfileH) ProfileAdd(pm *cmn.JWTAuthProfileMod) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.mgr.SetProfile(jwtProfileFromMod(pm)); err != nil {
		return JwtAuthProfileArgErr, err
	}
	h.profiles[pm.Name] = *pm
	tk.LogIt(tk.LogInfo, "[JWTAuth] profile %s stored (issuer %s)\n", pm.Name, pm.Issuer)
	return 0, nil
}

// ProfileDel removes a profile, refusing while LB rules reference it.
func (h *JWTAuthProfileH) ProfileDel(name string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.profiles[name]; !ok {
		return JwtAuthProfileNoExistErr, fmt.Errorf("jwt auth profile %s does not exist", name)
	}
	if refs := h.ruleRefs(name); len(refs) > 0 {
		return JwtAuthProfileRefErr, fmt.Errorf("jwt auth profile %s is referenced by rule(s): %s",
			name, strings.Join(refs, ", "))
	}
	h.mgr.RemoveProfile(name)
	delete(h.profiles, name)
	tk.LogIt(tk.LogInfo, "[JWTAuth] profile %s deleted\n", name)
	return 0, nil
}

// ProfileGet returns the configured profiles in stable name order.
func (h *JWTAuthProfileH) ProfileGet() ([]cmn.JWTAuthProfileMod, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]cmn.JWTAuthProfileMod, 0, len(h.profiles))
	for _, pm := range h.profiles {
		out = append(out, pm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Manager exposes the verifier runtime for the admission wiring.
func (h *JWTAuthProfileH) Manager() *jwtauth.Manager {
	return h.mgr
}

// ProfileExists reports whether a profile name is configured. Rule
// create/update uses it to refuse a reference to a profile that is not
// there (the mirror image of the ruleRefs delete guard).
func (h *JWTAuthProfileH) ProfileExists(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.profiles[name]
	return ok
}

// ProfileUpstreamPolicy returns the two upstream-hygiene switches of a
// profile: whether verified X-Auth-* identity headers are injected, and
// whether the client's Authorization header rides through to the backend
// instead of being stripped. ok is false for an unknown profile — callers
// on the admission path treat that as strip-everything/forward-nothing,
// the fail-safe posture.
func (h *JWTAuthProfileH) ProfileUpstreamPolicy(name string) (forwardIdentity, authzPassthrough, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	pm, found := h.profiles[name]
	if !found {
		return false, false, false
	}
	return pm.ForwardIdentity, pm.AuthorizationPassthrough, true
}

// error codes
const (
	JwtAuthProfileErrBase = iota - 118000
	JwtAuthProfileArgErr
	JwtAuthProfileNoExistErr
	JwtAuthProfileRefErr
)
