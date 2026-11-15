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

package loxinlp

import (
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// replaySavedLbRule hands one rule of the saved lbconfig.txt to the rule
// layer, marked as a replay so that the saved configuration is kept whole. A
// rule that is refused all the same is logged and the replay goes on with the
// next one.
func replaySavedLbRule(lb *cmn.LbRuleMod) {
	lb.Serv.BootReplay = true
	if _, err := hooks.NetLbRuleAdd(lb); err != nil {
		tk.LogIt(tk.LogError, "nlp: LB %s:%d/%s of the saved configuration was not applied: %v\n",
			lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto, err)
	}
}
