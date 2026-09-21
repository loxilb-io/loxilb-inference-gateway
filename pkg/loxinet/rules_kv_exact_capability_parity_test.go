/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestKvExactCapabilityMatchesAdmission is the reason the seed predicate has
// exactly one definition.
//
// The capability surface exists so a client can stop submitting rules that
// cannot succeed. That is only worth anything if its verdict is the verdict
// admission would reach. A surface that reports ready while admission refuses
// is worse than no surface at all: it turns a loud, explainable refusal into
// a control the operator is invited to use and then denied.
//
// So for each environment, this asserts that what the capability surface
// reads (cmn.KvExactSeedPrecondition) and what a real admission call decides
// agree -- on the verdict, on the stable reason code, and on the sentence.
// It fails the moment someone reintroduces a second copy of the predicate.
func TestKvExactCapabilityMatchesAdmission(t *testing.T) {
	envs := []struct {
		name    string
		seed    string
		present bool
	}{
		{"seed absent", "", false},
		{"seed empty", "", true},
		{"seed valid", "0", true},
		{"seed exactly at the bound", strings.Repeat("s", cmn.KvExactSeedMaxLen), true},
		{"seed one byte over", strings.Repeat("s", cmn.KvExactSeedMaxLen+1), true},
	}

	for _, env := range envs {
		t.Run(env.name, func(t *testing.T) {
			getenv := func(name string) (string, bool) {
				if name != cmn.KvExactSeedEnv {
					return "", false
				}
				return env.seed, env.present
			}

			// What the capability surface would publish.
			surface := cmn.KvExactSeedPrecondition(getenv)

			// What admission actually decides for a vLLM exact rule that is
			// otherwise entirely valid, so the seed is the only variable.
			deps := admissionDeps(func(d *kvExactAdmissionDeps) { d.getenv = getenv })
			_, admitErr := kvExactRuntimeValidate("vllm", 3, "model-a", "", "", deps)

			if surface == nil {
				if admitErr != nil {
					t.Fatalf("capability reports READY but admission refused: %v", admitErr)
				}
				return
			}

			if admitErr == nil {
				t.Fatalf("capability reports NOT ready (%s) but admission accepted the rule", surface.Reason)
			}
			var admitted *cmn.ServerPreconditionError
			if !errors.As(admitErr, &admitted) {
				t.Fatalf("admission refused with a non-precondition error: %#v", admitErr)
			}
			if admitted.Reason != surface.Reason {
				t.Errorf("reason code drift: admission %q, capability %q", admitted.Reason, surface.Reason)
			}
			if admitted.Error() != surface.Error() {
				t.Errorf("message drift:\n admission:  %q\n capability: %q", admitted.Error(), surface.Error())
			}
		})
	}
}
