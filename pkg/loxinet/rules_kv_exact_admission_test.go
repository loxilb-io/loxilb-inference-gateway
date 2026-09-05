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

// admissionDeps builds a deps set with sane defaults; individual tests
// override the knobs they exercise.
func admissionDeps(over func(*kvExactAdmissionDeps)) kvExactAdmissionDeps {
	d := kvExactAdmissionDeps{
		getenv:         func(string) (string, bool) { return "0", true },
		tokenizerReady: func(string) bool { return true },
		profileByID:    func(string) (*ModelPromptProfile, uint64, bool) { return nil, 0, false },
		chatRenderer:   func(string) bool { return true },
		contractRef: func(engineFamily string) (KvEngineContractRef, error) {
			return KvEngineContractRef{ID: engineFamily + "-contract-v1", Gen: 1}, nil
		},
	}
	if over != nil {
		over(&d)
	}
	return d
}

func testProfile(supported []string, aliasPolicy string, aliases []string) *ModelPromptProfile {
	return &ModelPromptProfile{
		ProfileID:      "prof-a",
		BaseModel:      "Qwen/Qwen3-32B",
		SupportedApis:  supported,
		AliasPolicy:    aliasPolicy,
		AllowedAliases: aliases,
	}
}

// TestKvExactAdmissionCommonCore: the tokenizer and model_name requirements
// are ENGINE-NEUTRAL. The same missing-tokenizer mutation must 4xx all three
// exact engines — an sglang or trtllm exact rule without a loadable Gateway
// tokenizer populates inventories forever and never scores Tier 1.5.
func TestKvExactAdmissionCommonCore(t *testing.T) {
	for _, eng := range []string{"vllm", "sglang", "trtllm"} {
		t.Run(eng+" tokenizer missing", func(t *testing.T) {
			deps := admissionDeps(func(d *kvExactAdmissionDeps) {
				d.tokenizerReady = func(string) bool { return false }
			})
			_, err := kvExactRuntimeValidate(eng, 3, "model-a", "", "", deps)
			if err == nil || !strings.Contains(err.Error(), "tokenizer") {
				t.Fatalf("engine %s: want tokenizer rejection, got %v", eng, err)
			}
		})
		t.Run(eng+" model required", func(t *testing.T) {
			_, err := kvExactRuntimeValidate(eng, 3, "", "", "", admissionDeps(nil))
			if err == nil || !strings.Contains(err.Error(), "model_name") {
				t.Fatalf("engine %s: want model_name rejection, got %v", eng, err)
			}
		})
		t.Run(eng+" ready admits", func(t *testing.T) {
			res, err := kvExactRuntimeValidate(eng, 3, "model-a", "", "", admissionDeps(nil))
			if err != nil {
				t.Fatalf("engine %s: unexpected rejection: %v", eng, err)
			}
			if res.Strict {
				t.Fatalf("engine %s: profile-less rule must not be strict", eng)
			}
		})
	}
}

// TestKvExactAdmissionSeedIsVllmAddendum: the NONE-hash seed contract is a
// vLLM addendum, never common core. sglang has no seed in its hash contract
// (raw parent||tokens), so a missing seed env must fail vllm ONLY.
func TestKvExactAdmissionSeedIsVllmAddendum(t *testing.T) {
	noSeed := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.getenv = func(string) (string, bool) { return "", false }
	})
	if _, err := kvExactRuntimeValidate("vllm", 1, "model-a", "", "", noSeed); err == nil ||
		!strings.Contains(err.Error(), "LLB_KV_NONE_HASH_SEED") {
		t.Fatalf("vllm without seed: want seed rejection, got %v", err)
	}
	for _, eng := range []string{"sglang", "trtllm"} {
		if _, err := kvExactRuntimeValidate(eng, 3, "model-a", "", "", noSeed); err != nil {
			t.Fatalf("%s must not carry the vllm seed contract: %v", eng, err)
		}
	}
	long := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.getenv = func(string) (string, bool) { return "123456789012345678901234", true }
	})
	if _, err := kvExactRuntimeValidate("vllm", 1, "model-a", "", "", long); err == nil ||
		!strings.Contains(err.Error(), "23 bytes") {
		t.Fatalf("vllm long seed: want length rejection, got %v", err)
	}
}

// TestKvExactAdmissionOffMode: kvExactMode=0 skips every KV check but still
// rejects dead config (a profile or api-mode declaration with no exact tier).
func TestKvExactAdmissionOffMode(t *testing.T) {
	called := false
	deps := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.tokenizerReady = func(string) bool { called = true; return false }
		d.getenv = func(string) (string, bool) { return "", false }
	})
	if _, err := kvExactRuntimeValidate("vllm", 0, "", "", "", deps); err != nil {
		t.Fatalf("mode 0 must admit: %v", err)
	}
	if called {
		t.Fatal("tokenizer readiness must not be evaluated with kvExactMode=0")
	}
	if _, err := kvExactRuntimeValidate("vllm", 0, "m", "", "prof-a", deps); err == nil {
		t.Fatal("kvModelProfile without kvExactMode must be rejected as dead config")
	}
	// Through the FULL admission path, not the pure function: the pure-fn
	// call alone left the mode-0 early return untested, and the live L-2
	// leg proved that path admitted the dead declaration (HTTP 200).
	if _, err := kvExactRuntimeValidate("vllm", 0, "m", KvExactApiChat, "", deps); err == nil {
		t.Fatal("kvExactApiMode without kvExactMode must be rejected as dead config")
	}
}

func TestKvExactApiModeValidate(t *testing.T) {
	for _, ok := range []string{"", KvExactApiCompletions, KvExactApiChat, KvExactApiBoth} {
		if err := kvExactApiModeValidate(ok, 1); err != nil {
			t.Fatalf("api mode %q: unexpected rejection: %v", ok, err)
		}
	}
	if err := kvExactApiModeValidate("chat_completions", 1); err == nil {
		t.Fatal("unknown api mode admitted")
	}
}

// TestKvExactAdmissionProfileResolution: naming a profile makes the rule
// strict — unknown profiles, alias-policy violations and surface supersets
// are all fresh-POST rejections.
func TestKvExactAdmissionProfileResolution(t *testing.T) {
	withProfile := func(p *ModelPromptProfile) kvExactAdmissionDeps {
		return admissionDeps(func(d *kvExactAdmissionDeps) {
			d.profileByID = func(id string) (*ModelPromptProfile, uint64, bool) {
				if id == p.ProfileID {
					return p, 7, true
				}
				return nil, 0, false
			}
		})
	}

	t.Run("unknown profile rejected", func(t *testing.T) {
		_, err := kvExactRuntimeValidate("vllm", 1, "m", "", "no-such-prof", admissionDeps(nil))
		if err == nil || !strings.Contains(err.Error(), "not a published") {
			t.Fatalf("want unknown-profile rejection, got %v", err)
		}
	})

	t.Run("alias policy base_model_only", func(t *testing.T) {
		p := testProfile([]string{"completions"}, KvAliasPolicyBaseModelOnly, nil)
		if _, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", "", "prof-a", withProfile(p)); err != nil {
			t.Fatalf("base model must be served: %v", err)
		}
		if _, err := kvExactRuntimeValidate("vllm", 1, "my-alias", "", "prof-a", withProfile(p)); err == nil {
			t.Fatal("non-base model admitted under base_model_only")
		}
	})

	t.Run("alias policy list", func(t *testing.T) {
		p := testProfile([]string{"completions"}, KvAliasPolicyList, []string{"my-alias"})
		if _, err := kvExactRuntimeValidate("vllm", 1, "my-alias", "", "prof-a", withProfile(p)); err != nil {
			t.Fatalf("allowed alias must be served: %v", err)
		}
		if _, err := kvExactRuntimeValidate("vllm", 1, "other-alias", "", "prof-a", withProfile(p)); err == nil {
			t.Fatal("unlisted alias admitted")
		}
	})

	t.Run("surface must be subset of profile", func(t *testing.T) {
		p := testProfile([]string{"completions"}, KvAliasPolicyBaseModelOnly, nil)
		if _, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", KvExactApiChat, "prof-a", withProfile(p)); err == nil {
			t.Fatal("chat surface admitted against a completions-only profile")
		}
		if _, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", KvExactApiBoth, "prof-a", withProfile(p)); err == nil {
			t.Fatal("both surfaces admitted against a completions-only profile")
		}
		pc := testProfile([]string{"chat"}, KvAliasPolicyBaseModelOnly, nil)
		if _, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", KvExactApiCompletions, "prof-a", withProfile(pc)); err == nil {
			t.Fatal("completions surface admitted against a chat-only profile")
		}
	})

	t.Run("absent api mode inherits profile surfaces", func(t *testing.T) {
		// completions-only profile + no renderer: admits, because chat was
		// neither declared nor inherited.
		p := testProfile([]string{"completions"}, KvAliasPolicyBaseModelOnly, nil)
		deps := withProfile(p)
		deps.chatRenderer = func(string) bool { return false }
		if _, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", "", "prof-a", deps); err != nil {
			t.Fatalf("completions-only inheritance must not require a renderer: %v", err)
		}
		// chat-capable profile + no renderer: inherited chat surface refuses.
		pc := testProfile([]string{"chat", "completions"}, KvAliasPolicyBaseModelOnly, nil)
		depsC := withProfile(pc)
		depsC.chatRenderer = func(string) bool { return false }
		if _, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", "", "prof-a", depsC); err == nil {
			t.Fatal("inherited chat surface admitted without a renderer — the silent-fallback shape")
		}
	})

	t.Run("strict success composes validated components", func(t *testing.T) {
		p := testProfile([]string{"chat", "completions"}, KvAliasPolicyBaseModelOnly, nil)
		res, err := kvExactRuntimeValidate("sglang", 3, "Qwen/Qwen3-32B", "", "prof-a", withProfile(p))
		if err != nil {
			t.Fatalf("strict admission failed: %v", err)
		}
		if !res.Strict {
			t.Fatal("profile-bound rule must be strict")
		}
		if res.Comps.Profile.ID != "prof-a" || res.Comps.Profile.Gen != 7 {
			t.Fatalf("profile ref = %+v", res.Comps.Profile)
		}
		if res.Comps.Contract.ID != "sglang-contract-v1" || res.Comps.Contract.Gen != 1 {
			t.Fatalf("contract ref = %+v", res.Comps.Contract)
		}
		if err := kvValidateBindingComponents(&res.Comps); err != nil {
			t.Fatalf("composed components must pre-validate: %v", err)
		}
	})
}

// TestKvExactAdmissionChatRefusal: a declared chat surface without a
// validated renderer is a refusal — never the silent untemplated fallback
// that mis-hashes every chat request.
func TestKvExactAdmissionChatRefusal(t *testing.T) {
	noRenderer := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.chatRenderer = func(string) bool { return false }
	})
	for _, mode := range []string{KvExactApiChat, KvExactApiBoth} {
		if _, err := kvExactRuntimeValidate("vllm", 1, "model-a", mode, "", noRenderer); err == nil ||
			!strings.Contains(err.Error(), "renderer") {
			t.Fatalf("explicit %s without renderer: want refusal, got %v", mode, err)
		}
	}
	// Absent declaration on a legacy rule keeps today's behavior — the
	// documented migration surface, not a silent widening.
	if _, err := kvExactRuntimeValidate("vllm", 1, "model-a", "", "", noRenderer); err != nil {
		t.Fatalf("legacy absent api mode must not require a renderer: %v", err)
	}
	if _, err := kvExactRuntimeValidate("vllm", 1, "model-a", KvExactApiCompletions, "", noRenderer); err != nil {
		t.Fatalf("completions-only declaration must not require a renderer: %v", err)
	}
}

// TestKvExactAdmissionFailClosedWithoutContractSource: strict admission with
// no engine-contract registry registered must refuse — never compose a
// binding over an unproven contract identity.
func TestKvExactAdmissionFailClosedWithoutContractSource(t *testing.T) {
	p := testProfile([]string{"completions"}, KvAliasPolicyBaseModelOnly, nil)
	deps := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.profileByID = func(string) (*ModelPromptProfile, uint64, bool) { return p, 3, true }
		d.contractRef = func(string) (KvEngineContractRef, error) {
			return KvEngineContractRef{}, ErrKvNoContractSource
		}
	})
	_, err := kvExactRuntimeValidate("vllm", 1, "Qwen/Qwen3-32B", "", "prof-a", deps)
	if err == nil || !errors.Is(err, ErrKvNoContractSource) {
		t.Fatalf("want fail-closed ErrKvNoContractSource, got %v", err)
	}
	// The legacy profile-less path must stay unaffected by the missing
	// registry — that is the documented migration behavior.
	depsLegacy := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.contractRef = func(string) (KvEngineContractRef, error) {
			return KvEngineContractRef{}, ErrKvNoContractSource
		}
	})
	if _, err := kvExactRuntimeValidate("vllm", 1, "model-a", "", "", depsLegacy); err != nil {
		t.Fatalf("legacy rule must not need a contract source: %v", err)
	}
}

func TestKvExactBindingImmutabilityCheck(t *testing.T) {
	if err := kvExactBindingImmutabilityCheck("p", "p", "chat", "chat"); err != nil {
		t.Fatalf("unchanged fields rejected: %v", err)
	}
	if err := kvExactBindingImmutabilityCheck("p", "q", "chat", "chat"); err == nil {
		t.Fatal("profile change admitted on a live rule")
	}
	if err := kvExactBindingImmutabilityCheck("p", "p", "chat", "both"); err == nil {
		t.Fatal("api-mode change admitted on a live rule")
	}
	// Migration attach is the ONE sanctioned transition: profile-less ->
	// strict admits (legacy and restored rules earn their way in); the
	// reverse (dropping the profile) stays a live-rebind refusal.
	if err := kvExactBindingImmutabilityCheck("", "p", "chat", "chat"); err != nil {
		t.Fatalf("migration attach (\"\" -> profile) refused: %v", err)
	}
	if err := kvExactBindingImmutabilityCheck("p", "", "chat", "chat"); err == nil {
		t.Fatal("profile drop admitted on a live rule")
	}
}

// TestKvChatTemplateSupported: the admission renderer probe answers exactly
// what the serving path would do — models served by a published chat profile
// render, models without one refuse.
func TestKvChatTemplateSupported(t *testing.T) {
	kvTestPublishQwen25Profile(t, "Qwen/Qwen2.5-7B-Instruct")
	if !kvChatTemplateSupported("Qwen/Qwen2.5-7B-Instruct") {
		t.Fatal("profiled model must report a renderer")
	}
	if kvChatTemplateSupported("meta-llama/Llama-3.1-8B-Instruct") {
		t.Fatal("model without a published chat profile must refuse")
	}
}

func TestKvProfileServesModel(t *testing.T) {
	p := testProfile([]string{"completions"}, KvAliasPolicyList, []string{"served-alias"})
	if !kvProfileServesModel(p, "Qwen/Qwen3-32B") {
		t.Fatal("base model not served")
	}
	// Slug identity: the same normalization the registry index and the
	// tokenizer path use ("/" -> "__").
	if !kvProfileServesModel(p, "Qwen__Qwen3-32B") {
		t.Fatal("slug-form base model not served")
	}
	if !kvProfileServesModel(p, "served-alias") {
		t.Fatal("allowed alias not served")
	}
	if kvProfileServesModel(p, "other") {
		t.Fatal("unlisted model served")
	}
	base := testProfile([]string{"completions"}, KvAliasPolicyBaseModelOnly, []string{"served-alias"})
	if kvProfileServesModel(base, "served-alias") {
		t.Fatal("alias served under base_model_only")
	}
}

// AddLbRule wraps every create-time KV validation refusal in the typed
// cmn.KvAdmissionError the API layer classifies as HTTP 400 — without the
// wrap, refusal wordings the message classifier does not know surface as
// internal 500s (observed live on an unknown kvModelProfile).
func TestKvAdmissionRefuseWrapsTyped(t *testing.T) {
	plain := errors.New(`kvModelProfile "ghost" is not a published model-prompt profile`)
	wrapped := kvAdmissionRefuse(plain)
	var adm *cmn.KvAdmissionError
	if !errors.As(wrapped, &adm) {
		t.Fatal("plain refusal did not wrap into cmn.KvAdmissionError")
	}
	if adm.Reason != "" {
		t.Fatalf("plain refusal must carry no reason code, got %q", adm.Reason)
	}
	if wrapped.Error() != plain.Error() {
		t.Fatalf("operator-facing wording changed: %q", wrapped.Error())
	}

	// A typed engine-contract refusal contributes its stable reason code.
	contract := kvContractRefusal("kvZmqPort is meaningless for kv-engine-type llamacpp (no KV event transport)")
	wrapped = kvAdmissionRefuse(contract)
	if !errors.As(wrapped, &adm) {
		t.Fatal("contract refusal did not wrap into cmn.KvAdmissionError")
	}
	if adm.Reason != KvReasonCapabilityUnavailable {
		t.Fatalf("contract reason code lost: got %q want %q", adm.Reason, KvReasonCapabilityUnavailable)
	}
	// The typed contract error stays reachable through the wrap.
	var ce *KvContractError
	if !errors.As(wrapped, &ce) {
		t.Fatal("KvContractError no longer reachable through the admission wrap")
	}
}

// TestKvEngineAdmissionCapabilityBeforeDependencies: the admission sequence
// must answer with the engine's capability refusal before any
// runtime-dependency refusal. A dependency message reads as fixable
// ("stage a tokenizer ... before retry", "model_name is required") — for a
// shape the capability guard forbids outright, that hint promises a retry
// path the guard would then refuse, so the capability answer has to win.
func TestKvEngineAdmissionCapabilityBeforeDependencies(t *testing.T) {
	// llama.cpp with kvExactMode and NO staged tokenizer: under a
	// dependency-first order this answers "tokenizer is required ... before
	// retry" — unfulfillable, the engine has no KV event plane.
	noTok := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.tokenizerReady = func(string) bool { return false }
	})
	serv := &cmn.LbServiceArg{KvEngineType: "llamacpp", KvExactMode: 3, ModelName: "m-a"}
	if _, err := kvEngineAdmissionValidate(serv, noTok); err == nil ||
		!strings.Contains(err.Error(), "kvExactMode is unsupported for kv-engine-type llamacpp") {
		t.Fatalf("llamacpp+kvExactMode without tokenizer: want the capability refusal, got %v", err)
	}

	// Same precedence when model_name is absent (the other dependency gate).
	serv = &cmn.LbServiceArg{KvEngineType: "llamacpp", KvExactMode: 3}
	if _, err := kvEngineAdmissionValidate(serv, noTok); err == nil ||
		!strings.Contains(err.Error(), "kvExactMode is unsupported for kv-engine-type llamacpp") {
		t.Fatalf("llamacpp+kvExactMode without model_name: want the capability refusal, got %v", err)
	}

	// TRT-LLM: a forbidden knob (real kvZmqPort) must out-rank the missing
	// model_name dependency the same way.
	serv = &cmn.LbServiceArg{KvEngineType: "trtllm", KvExactMode: 3, KvZmqPort: 5561}
	if _, err := kvEngineAdmissionValidate(serv, noTok); err == nil ||
		!strings.Contains(err.Error(), "kvZmqPort is meaningless for kv-engine-type trtllm") {
		t.Fatalf("trtllm+kvZmqPort without model_name: want the capability refusal, got %v", err)
	}

	// Engines whose guards pass keep their dependency-first answers
	// unchanged: vllm still reports the missing model_name.
	serv = &cmn.LbServiceArg{KvEngineType: "vllm", KvExactMode: 1}
	if _, err := kvEngineAdmissionValidate(serv, noTok); err == nil ||
		!strings.Contains(err.Error(), "model_name is required for vllm kvExactMode") {
		t.Fatalf("vllm missing model_name: dependency answer changed: %v", err)
	}
}
