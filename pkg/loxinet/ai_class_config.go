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
	"github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
)

// aiObjectiveStrictResolve returns the ai_objective_strict a rule will
// store: the request's value, or on a replace that does not carry the
// field, the stored one. Nothing is refused: the switch is read only where
// the admission gate runs, as the default reservation is.
func aiObjectiveStrictResolve(eRule *ruleEnt, serv *cmn.LbServiceArg) bool {
	if eRule != nil && !serv.AIObjectiveStrictPresent && !serv.AIObjectiveStrict {
		return eRule.aiObjectiveStrict
	}
	return serv.AIObjectiveStrict
}

// aiClassConfigSource says where the objectives and classes in force came
// from: the key store, the last-known-good file, or nowhere (no store, or
// nothing read yet).
func aiClassConfigSource() string {
	svc := mh.AIKeyService.Load()
	if svc == nil {
		return cmn.AIClassSourceNone
	}
	src, _, _ := svc.ClassSource()
	return src
}

// aiClassStoreHealth fills the key store's reachability into a read-back:
// nothing without a key store.
func aiClassStoreHealth(eff *cmn.FcEffectiveArg) {
	svc := mh.AIKeyService.Load()
	if svc == nil {
		return
	}
	reachable, lastOK := svc.StoreHealth()
	eff.StoreReachable = &reachable
	if !lastOK.IsZero() {
		eff.StoreLastRead = &lastOK
	}
}

// aiClassLKGIntervals is what loxilb_ai_class_config_lkg_intervals_total
// reports: the refresh intervals served from the last-known-good file.
func aiClassLKGIntervals() uint64 {
	svc := mh.AIKeyService.Load()
	if svc == nil {
		return 0
	}
	_, _, n := svc.ClassSource()
	return n
}

func init() {
	prometheus.SetAIClassLKGIntervalsSource(aiClassLKGIntervals)
}
