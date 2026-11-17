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

package loxinet

import (
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// halfCloseResolve returns the half-close mode a rule will store (enum
// sp_hold_mode): on create the declared value, on a replace the stored one
// unless the request names the field, where inherit returns it to unset.
//
// hold is refused where the data plane would never hold a client, or has not
// been shown to: a service that is not fullproxy (only the proxy relays an
// answer it could hold a client for), one whose clients speak TLS (the hold
// leaves TLS connections alone), and a P/D service (not yet measured). The
// check is on the rule as it will stand after a replace - the mode it keeps
// and the P/D switch it is given - so neither order slips through: hold on a
// P/D rule, nor P/D switched on under a stored hold. The security mode cannot
// change on a live rule, so a replace is judged on the stored one, whatever
// the request says. A snapshot restore replay is let through as unset with a
// warning instead, so that one field cannot keep the rule from coming back.
func halfCloseResolve(eRule *ruleEnt, serv *cmn.LbServiceArg, mode cmn.LBMode) (uint8, error) {
	next, err := cmn.HalfCloseModeToRule(serv.HalfCloseMode)
	if err != nil {
		return 0, err
	}
	if eRule != nil && !serv.HalfCloseModePresent && serv.HalfCloseMode == "" {
		next = eRule.halfCloseMode
	}
	if next != cmn.HalfCloseRuleHold {
		return next, nil
	}
	sec := serv.Security
	if eRule != nil {
		sec = eRule.secMode
	}
	why := halfCloseHoldRefusal(mode, sec, serv.PDDisaggMode)
	if why == "" {
		return next, nil
	}
	if serv.RestoreReplay {
		tk.LogIt(tk.LogWarning, "lb-rule %s:%d: half_close_mode hold restored where it is %s: dropped\n",
			serv.ServIP, serv.ServPort, why)
		return cmn.HalfCloseRuleUnset, nil
	}
	return 0, cmn.NewValidationError("half_close_mode", "half_close_mode hold is %s", why)
}

// halfCloseHoldRefusal says why a service cannot take hold, or "" when it
// can. One answer for every place that asks: refusing a service's own hold,
// the mode the data plane gets for a service that leaves its own unset, and
// the read-back of where a service's mode in force comes from. Were they
// to ask different questions, the mode sent and the mode shown could part.
func halfCloseHoldRefusal(mode cmn.LBMode, sec cmn.LBSec, pd bool) string {
	switch {
	case mode != cmn.LBModeFullProxy:
		return "available on fullproxy services only"
	case sec != cmn.LBServPlain:
		return "not available on a service whose clients use TLS: TLS connections are never held"
	case pd:
		return "not available on a P/D (pd_disagg_mode) service yet"
	}
	return ""
}

// halfCloseRefusal - halfCloseHoldRefusal for a stored rule.
func (r *ruleEnt) halfCloseRefusal() string {
	mode := cmn.LBModeDefault
	if lba, ok := r.act.action.(*ruleLBActs); ok {
		mode = lba.mode
	}
	return halfCloseHoldRefusal(mode, r.secMode, r.pdDisaggMode)
}

// halfCloseDpMode - the mode the data plane gets for a rule: its own, or
// for a rule that leaves it unset, unset (the process default) where the
// rule could take hold and off where it could not, so that the default never
// reaches a rule that hold is refused on.
func (r *ruleEnt) halfCloseDpMode() uint8 {
	if r.halfCloseMode != cmn.HalfCloseRuleUnset {
		return r.halfCloseMode
	}
	if r.halfCloseRefusal() != "" {
		return cmn.HalfCloseRuleOff
	}
	return cmn.HalfCloseRuleUnset
}

// halfCloseEffective - the mode in force for new holds on a rule, and where
// it came from, given the process-wide settings: blocked over the rule's own
// mode, the rule's own over the default. The same check as halfCloseDpMode
// says whether the default reaches the rule.
func (r *ruleEnt) halfCloseEffective(cfg cmn.HalfCloseConfig) *cmn.HalfCloseEffectiveArg {
	cfg = cfg.Normalized()
	switch {
	case !cfg.Allow:
		return &cmn.HalfCloseEffectiveArg{Mode: cmn.HalfCloseModeOff, Source: cmn.HalfCloseSourceBlocked}
	case r.halfCloseMode != cmn.HalfCloseRuleUnset:
		return &cmn.HalfCloseEffectiveArg{Mode: cmn.HalfCloseModeFromRule(r.halfCloseMode),
			Source: cmn.HalfCloseSourceRule}
	}
	if why := r.halfCloseRefusal(); why != "" {
		return &cmn.HalfCloseEffectiveArg{Mode: cmn.HalfCloseModeOff,
			Source: cmn.HalfCloseSourceDefault, NotApplied: why}
	}
	return &cmn.HalfCloseEffectiveArg{Mode: cfg.DefaultMode, Source: cmn.HalfCloseSourceDefault}
}
