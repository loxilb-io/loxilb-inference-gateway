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

// l7policy.go — the desired-state registry for dedicated L7_POLICY
// resources (policy + ordered child rules attached to an L4 LB by its
// stable opaque id).
//
// The store lives control-plane side (here, not in the REST handler) so
// that BOTH intake paths share one registry with one lock: the REST CRUD
// handlers (api/restapi/handler/l7policy.go) and the config
// snapshot/restore engine (pkg/snapshot), whose boot replay drives
// cmn.NetHookInterface directly without ever touching the REST layer. A
// handler-hosted store made L7 policies invisible to snapshot capture —
// a REJECT policy silently became allow-all after every reboot.
//
// Semantics:
//   - Ids are stable across persist/restore: an empty Id is minted
//     server-side (UUID) and written back; a caller-supplied Id is honored
//     when unique; a duplicate Id with different content is a conflict.
//   - One policy per load-balancer: the sockproxy attach is keyed by the
//     rule's VIP:port:proto, so a second policy on the same LB would
//     silently overwrite the first's routes while both sat in the store —
//     restore order, not operator intent, would then pick the winner.
//     Refused loudly instead (the L7 API is unreleased; no back-compat
//     debt).
//   - Re-adding a byte-identical policy is the idempotent-exists no-op
//     ("l7policy-exists error"), so a boot-replay retry that already
//     applied the policy does not fail the whole domain.

package loxinet

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/google/uuid"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// l7PolMux guards l7PolReg. A dedicated lock (not mh.mtx): Add/Del resolve
// the referenced LB through NetLbRuleGet, which takes the module lock
// internally.
var l7PolMux sync.RWMutex

// l7PolReg is the L7 policy registry, keyed by stable policy id. Values
// are deep copies owned by the registry; they are never handed out by
// reference.
var l7PolReg = map[string]*cmn.L7PolicyArg{}

// copyL7Policy returns a deep copy of p (nested rule slices and action
// pointers included), so registry entries never alias caller-owned or
// handed-out memory.
func copyL7Policy(p *cmn.L7PolicyArg) *cmn.L7PolicyArg {
	if p == nil {
		return nil
	}
	out := &cmn.L7PolicyArg{Id: p.Id, Name: p.Name, LbId: p.LbId}
	for ri := range p.Rules {
		r := &p.Rules[ri]
		rule := cmn.L7RuleArg{Position: r.Position, SessionPersistence: r.SessionPersistence}
		for si := range r.MatchSets {
			set := cmn.L7MatchSetArg{
				Conditions: append([]cmn.L7ConditionArg(nil), r.MatchSets[si].Conditions...),
			}
			rule.MatchSets = append(rule.MatchSets, set)
		}
		rule.Action.Kind = r.Action.Kind
		if r.Action.Forward != nil {
			fwd := &cmn.L7ForwardArg{
				PoolId:      r.Action.Forward.PoolId,
				BackendRefs: append([]cmn.L7BackendRefArg(nil), r.Action.Forward.BackendRefs...),
			}
			rule.Action.Forward = fwd
		}
		if r.Action.Redirect != nil {
			red := *r.Action.Redirect
			rule.Action.Redirect = &red
		}
		if r.Action.Reject != nil {
			rej := *r.Action.Reject
			rule.Action.Reject = &rej
		}
		rule.InsertHeaders = append([]cmn.L7HeaderFilterArg(nil), r.InsertHeaders...)
		out.Rules = append(out.Rules, rule)
	}
	return out
}

// findLbRuleByOpaqueID resolves an LB rule by its stable opaque id via the
// same hook surface REST uses. Returns nil (no error) when absent.
func (na *NetAPIStruct) findLbRuleByOpaqueID(id string) (*cmn.LbRuleMod, error) {
	rules, err := na.NetLbRuleGet()
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].Serv.Id == id {
			return &rules[i], nil
		}
	}
	return nil, nil
}

// NetL7PolicyGet - return every stored L7 policy as deep copies, sorted by
// id (map enumeration order must not leak into GET responses or captured
// snapshot documents).
func (na *NetAPIStruct) NetL7PolicyGet() ([]cmn.L7PolicyArg, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	l7PolMux.RLock()
	defer l7PolMux.RUnlock()
	out := make([]cmn.L7PolicyArg, 0, len(l7PolReg))
	for _, p := range l7PolReg {
		out = append(out, *copyL7Policy(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out, nil
}

// NetL7PolicyAdd - validate, resolve the referenced LB, attach the route IR
// to the running sockproxy rule and store the policy. Mints a UUID id when
// the caller supplied none (written back to p.Id).
func (na *NetAPIStruct) NetL7PolicyAdd(p *cmn.L7PolicyArg) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	if err := cmn.ValidateL7Policy(p); err != nil {
		return RuleErrBase, err
	}

	l7PolMux.Lock()
	defer l7PolMux.Unlock()

	if p.Id == "" {
		p.Id = uuid.NewString()
	} else if existing, ok := l7PolReg[p.Id]; ok {
		if reflect.DeepEqual(existing, copyL7Policy(p)) {
			// Byte-identical re-add: idempotent no-op (boot-replay
			// retries must not fail the whole domain over it).
			return RuleErrBase, errors.New("l7policy-exists error")
		}
		return RuleErrBase, fmt.Errorf("l7policy-exist error: cant modify existing policy %s (delete and re-create)", p.Id)
	}
	for _, other := range l7PolReg {
		if other.LbId == p.LbId && other.Id != p.Id {
			// One policy per LB: the attach is keyed by the rule's
			// VIP:port:proto, so a second policy would silently overwrite
			// the first's routes at the dataplane.
			return RuleErrBase, fmt.Errorf("l7policy-exist error: cant attach to load-balancer %s (policy %s is already attached)", p.LbId, other.Id)
		}
	}

	lb, err := na.findLbRuleByOpaqueID(p.LbId)
	if err != nil {
		return RuleErrBase, fmt.Errorf("l7policy: resolve load-balancer %q: %w", p.LbId, err)
	}
	if lb == nil {
		return RuleErrBase, fmt.Errorf("l7policy: load-balancer %q not found", p.LbId)
	}

	if _, err := na.NetL7PolicyApply(lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto, p.Rules); err != nil {
		return RuleErrBase, err
	}

	l7PolReg[p.Id] = copyL7Policy(p)
	tk.LogIt(tk.LogInfo, "l7policy %s attached to LB id=%s VIP=%s:%d/%s (%d rules)\n",
		p.Id, p.LbId, lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto, len(p.Rules))
	return 0, nil
}

// NetL7PolicyDel - detach the policy's routes from the dataplane and remove
// the stored resource. A missing referenced LB is not a delete error (the
// sockproxy rule, and with it the attach, was torn down with the LB), but a
// live LB whose detach fails keeps the store entry: dropping it anyway
// would leave the dataplane enforcing a policy the control plane no longer
// reports.
func (na *NetAPIStruct) NetL7PolicyDel(id string) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	l7PolMux.Lock()
	defer l7PolMux.Unlock()

	pol, ok := l7PolReg[id]
	if !ok {
		return RuleErrBase, errors.New("l7policy not-exists error")
	}
	lb, err := na.findLbRuleByOpaqueID(pol.LbId)
	if err != nil {
		return RuleErrBase, fmt.Errorf("l7policy: resolve load-balancer %q: %w", pol.LbId, err)
	}
	if lb != nil {
		if _, derr := na.NetL7PolicyRemove(lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto); derr != nil {
			return RuleErrBase, fmt.Errorf("l7policy: detach %s: %w", id, derr)
		}
	}
	delete(l7PolReg, id)
	tk.LogIt(tk.LogInfo, "l7policy %s detached from LB id=%s\n", id, pol.LbId)
	return 0, nil
}
