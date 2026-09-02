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
	"net"
	"testing"
	"time"
)

func kvDataplaneTestSetup(t *testing.T) {
	t.Helper()
	KvBindingReset()
	KvSvcContractReset()
	t.Cleanup(func() {
		KvBindingReset()
		KvSvcContractReset()
	})
}

func kvTestRegister(svcID uint32, ident string, apiMode uint8) {
	KvSvcContractRegister(svcID, ident, net.ParseIP("10.0.0.1"), 9100, 6, apiMode)
}

// TestKvContractPackLayout pins the exact bit layout of the packed word
// against literal expected values — the Go mirror of KV_CONTRACT_PACK in
// loxilb-ebpf/common/sockproxy_kv_exact.h. If this test moves, the C macro
// must move in the same paired commits.
func TestKvContractPackLayout(t *testing.T) {
	got := KvContractPack(0x11223344, 0x5566, 0x77, 0x88)
	want := uint64(0x1122334455667788)
	if got != want {
		t.Fatalf("pack layout drifted from the C macro: got 0x%x want 0x%x", got, want)
	}
	if KvContractPack(7, 0, KvContractAPIChat, 1) != 0x0000000700000201 {
		t.Fatalf("pack(7, 0, chat, 1) = 0x%x", KvContractPack(7, 0, KvContractAPIChat, 1))
	}
	// The fenced word of any real generation is never zero — the legacy
	// passthrough (word==0) is unreachable through packing a live gen.
	if KvContractPack(1, 0, KvContractAPIBoth, 0) == 0 {
		t.Fatalf("fenced gen-1 word must stay non-zero")
	}
}

// TestKvContractCodeMirror pins the typed bridge codes to the C header's
// LLB_KV_TOK_ERR_* values.
func TestKvContractCodeMirror(t *testing.T) {
	codes := map[string][2]int{
		"request":     {KvTokErrRequest, -1},
		"unsupported": {KvTokErrUnsupported, -2},
		"profile":     {KvTokErrProfile, -3},
		"renderer":    {KvTokErrRenderer, -4},
		"tokenizer":   {KvTokErrTokenizer, -5},
		"unknown":     {KvTokErrUnknown, -6},
		"not_ready":   {KvTokErrNotReady, -7},
	}
	for name, pair := range codes {
		if pair[0] != pair[1] {
			t.Fatalf("code %s drifted from the C mirror: %d != %d", name, pair[0], pair[1])
		}
	}
}

func TestKvContractAPIModeByte(t *testing.T) {
	if kvContractAPIModeByte(true, true) != KvContractAPIBoth {
		t.Fatalf("both surfaces must map to BOTH")
	}
	if kvContractAPIModeByte(true, false) != KvContractAPIChat {
		t.Fatalf("chat-only must map to CHAT")
	}
	if kvContractAPIModeByte(false, true) != KvContractAPICompletions {
		t.Fatalf("completions-only must map to COMPLETIONS")
	}
	// Degenerate no-surface pair narrows, never widens.
	if kvContractAPIModeByte(false, false) == KvContractAPIBoth {
		t.Fatalf("no-surface pair must never widen to BOTH")
	}
}

// TestKvSvcContractRegisterFencesUntilAck: registration fences (deny set);
// only the full install ACK — readback match plus binding-digest check —
// clears it.
func TestKvSvcContractRegisterFencesUntilAck(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(41, "rule-fence", KvContractAPIBoth)

	if !kvSvcDenied(41) {
		t.Fatalf("registered strict rule must start fenced")
	}
	if rc := kvBridgeGate(41, 0); rc != KvTokErrNotReady {
		t.Fatalf("bridge gate on a fenced svc must return NOT_READY, got %d", rc)
	}

	b, err := KvBindingAllocate("rule-fence", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	var calls int
	setter := func(vip net.IP, port uint16, proto uint8,
		gen uint32, apiMode, eligible uint8) (uint64, bool) {
		calls++
		if port != 9100 || proto != 6 {
			t.Fatalf("setter got wrong service key %v:%d/%d", vip, port, proto)
		}
		if eligible != 0 {
			t.Fatalf("contract install must stay fenced (eligible=0), got %d", eligible)
		}
		return KvContractPack(gen, 0, apiMode, eligible), true
	}
	if err := kvDataplaneContractInstall(41, setter, 3, 0); err != nil {
		t.Fatalf("install: %v", err)
	}
	if calls != 1 {
		t.Fatalf("install must ACK on the first good attempt, got %d calls", calls)
	}
	if kvSvcDenied(41) {
		t.Fatalf("full ACK must clear the deny entry")
	}
	if f := kvSvcContractFault(41); f != "" {
		t.Fatalf("full ACK must clear the fault, got %q", f)
	}
	if rc := kvBridgeGate(41, b.BindingGen); rc != 0 {
		t.Fatalf("gate must pass a resolvable generation after ACK, got %d", rc)
	}
}

// TestKvContractInstallReadbackMismatchKeepsFence: a readback that differs
// from the requested word is a failed ACK — the rule stays Go-fenced.
func TestKvContractInstallReadbackMismatchKeepsFence(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(42, "rule-mismatch", KvContractAPIBoth)
	if _, err := KvBindingAllocate("rule-mismatch", kvTestComponents(1)); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	setter := func(_ net.IP, _ uint16, _ uint8,
		gen uint32, apiMode, eligible uint8) (uint64, bool) {
		return KvContractPack(gen+1, 0, apiMode, eligible), true // stale/corrupt readback
	}
	if err := kvDataplaneContractInstall(42, setter, 2, 0); err == nil {
		t.Fatalf("readback mismatch must fail the install")
	}
	if !kvSvcDenied(42) {
		t.Fatalf("readback mismatch must keep the rule fenced")
	}
	if f := kvSvcContractFault(42); f != "dataplane_ack_mismatch" {
		t.Fatalf("fault reason: got %q", f)
	}
}

// TestKvContractInstallSetterFailureKeepsFence: C-side failure (entry
// missing, lock, whatever) never clears the fence.
func TestKvContractInstallSetterFailureKeepsFence(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(43, "rule-cfail", KvContractAPIBoth)
	if _, err := KvBindingAllocate("rule-cfail", kvTestComponents(1)); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	setter := func(_ net.IP, _ uint16, _ uint8,
		_ uint32, _, _ uint8) (uint64, bool) {
		return 0, false
	}
	if err := kvDataplaneContractInstall(43, setter, 2, 0); err == nil {
		t.Fatalf("setter failure must fail the install")
	}
	if !kvSvcDenied(43) || kvSvcContractFault(43) != "dataplane_setter_failed" {
		t.Fatalf("setter failure must keep fence + record fault, denied=%v fault=%q",
			kvSvcDenied(43), kvSvcContractFault(43))
	}
}

// TestKvContractInstallNoSetterKeepsFence: before the datapath registers its
// setter, nothing can clear a fence — fail-closed by construction.
func TestKvContractInstallNoSetterKeepsFence(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(44, "rule-nosetter", KvContractAPIBoth)
	if err := kvDataplaneContractInstall(44, nil, 1, 0); err == nil {
		t.Fatalf("nil setter must fail the install")
	}
	if !kvSvcDenied(44) || kvSvcContractFault(44) != "no_dataplane_setter" {
		t.Fatalf("nil setter must keep fence, denied=%v fault=%q",
			kvSvcDenied(44), kvSvcContractFault(44))
	}
}

// TestKvContractInstallBindingMissingKeepsFence: a registered strict rule
// whose binding state is absent (restore-replay window, crash between
// snapshot domains) stays fenced with the binding_state_missing fault — the
// visible ENFORCEMENT_FAULT shape, never silently legacy.
func TestKvContractInstallBindingMissingKeepsFence(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(45, "rule-nobinding", KvContractAPIBoth)
	setter := func(_ net.IP, _ uint16, _ uint8,
		gen uint32, apiMode, eligible uint8) (uint64, bool) {
		return KvContractPack(gen, 0, apiMode, eligible), true
	}
	if err := kvDataplaneContractInstall(45, setter, 2, 0); err == nil {
		t.Fatalf("missing binding must fail the install")
	}
	if !kvSvcDenied(45) || kvSvcContractFault(45) != "binding_state_missing" {
		t.Fatalf("missing binding must keep fence, denied=%v fault=%q",
			kvSvcDenied(45), kvSvcContractFault(45))
	}
}

// TestKvContractInstallConvergesOnConcurrentReallocation: §17.3's ACK-path
// identity rule — a generation whose binding changed between want-computation
// and readback is NOT accepted; the retry converges on the newest generation.
func TestKvContractInstallConvergesOnConcurrentReallocation(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(46, "rule-race", KvContractAPIBoth)
	b1, err := KvBindingAllocate("rule-race", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	var calls int
	var installedGen uint32
	setter := func(_ net.IP, _ uint16, _ uint8,
		gen uint32, apiMode, eligible uint8) (uint64, bool) {
		calls++
		if calls == 1 {
			// A component change races the first install: by the time the
			// word for gen1 is on the wire, gen2 is the current binding.
			if _, err := KvBindingAllocate("rule-race", kvTestComponents(2)); err != nil {
				t.Fatalf("re-allocate: %v", err)
			}
		}
		installedGen = gen
		return KvContractPack(gen, 0, apiMode, eligible), true
	}
	if err := kvDataplaneContractInstall(46, setter, 3, 0); err != nil {
		t.Fatalf("install must converge after the race: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 attempts (stale ACK rejected, retry ACKs), got %d", calls)
	}
	cur, _ := KvBindingCurrent("rule-race")
	if installedGen != cur.BindingGen || installedGen == b1.BindingGen {
		t.Fatalf("final word must carry the NEWEST generation: installed %d current %d old %d",
			installedGen, cur.BindingGen, b1.BindingGen)
	}
	if kvSvcDenied(46) {
		t.Fatalf("converged install must clear the fence")
	}
}

// TestKvSvcContractDeregisterClears: teardown drops both the fence and the
// identity registration.
func TestKvSvcContractDeregisterClears(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(47, "rule-gone", KvContractAPIBoth)
	KvSvcContractDeregister(47)
	if kvSvcDenied(47) {
		t.Fatalf("deregistered svc must not stay denied")
	}
	if _, ok := kvSvcRuleIdent(47); ok {
		t.Fatalf("deregistered svc must drop its identity")
	}
	if _, ok := kvSvcByRuleIdent("rule-gone"); ok {
		t.Fatalf("reverse index must drop with the entry")
	}
}

// TestKvBridgeGateResolution: the strict-path generation carried across the
// CGO boundary must resolve immutably — an unknown or foreign generation is
// a profile_resolution_fault; a live one passes.
func TestKvBridgeGateResolution(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(48, "rule-resolve", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-resolve", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	// Clear the fence so gate outcomes isolate the resolution half.
	kvSvcContractOutcome(48, false, "")

	if rc := kvBridgeGate(48, b.BindingGen); rc != 0 {
		t.Fatalf("live generation must pass the gate, got %d", rc)
	}
	if rc := kvBridgeGate(48, b.BindingGen+100); rc != KvTokErrProfile {
		t.Fatalf("unknown generation must be a profile fault, got %d", rc)
	}
	// A strict generation on an UNREGISTERED svc (registry lost the entry)
	// cannot resolve — fault, never silent legacy.
	if rc := kvBridgeGate(999, b.BindingGen); rc != KvTokErrProfile {
		t.Fatalf("unregistered svc with a generation must be a profile fault, got %d", rc)
	}
	// Legacy shape: svc 0 / gen 0 passes untouched.
	if rc := kvBridgeGate(0, 0); rc != 0 {
		t.Fatalf("legacy (0,0) must pass the gate, got %d", rc)
	}
}

// TestKvBridgeTokenizeTypedCodes: completions bridge — legacy failures keep
// the pre-contract collapsed -1 (metric/behavior compatibility); the same failure
// on a strict path is a typed runtime fault.
func TestKvBridgeTokenizeTypedCodes(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(49, "rule-tok", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-tok", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(49, false, "")

	// Request-class inputs: identical on legacy and strict (I-12 spirit).
	if _, rc := kvBridgeTokenize(0, 0, "", "m", 16); rc != KvTokErrRequest {
		t.Fatalf("legacy empty text: got %d", rc)
	}
	if _, rc := kvBridgeTokenize(49, b.BindingGen, "", "m", 16); rc != KvTokErrRequest {
		t.Fatalf("strict empty text: got %d", rc)
	}

	// Tokenizer unavailable (no staged tokenizer in the unit env):
	// legacy -> -1 exactly as before the contract gate; strict -> tokenizer runtime fault.
	if _, rc := kvBridgeTokenize(0, 0, "hello", "kv-p3/legacy-no-tok", 16); rc != KvTokErrRequest {
		t.Fatalf("legacy tokenizer-missing must stay -1, got %d", rc)
	}
	if _, rc := kvBridgeTokenize(49, b.BindingGen, "hello", "kv-p3/strict-no-tok", 16); rc != KvTokErrTokenizer {
		t.Fatalf("strict tokenizer-missing must be TOKENIZER fault, got %d", rc)
	}

	// The deny fence outranks everything.
	kvSvcContractOutcome(49, true, "dataplane_ack_mismatch")
	if _, rc := kvBridgeTokenize(49, b.BindingGen, "hello", "kv-p3/strict-no-tok", 16); rc != KvTokErrNotReady {
		t.Fatalf("fenced svc must return NOT_READY before any resolution, got %d", rc)
	}
}

// TestKvBridgeTokenizeChatTypedCodes: chat bridge classification — excluded
// features refuse on strict paths only; a template-less model is -1 on
// legacy (today's behavior) and a renderer fault on strict.
func TestKvBridgeTokenizeChatTypedCodes(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(50, "rule-chat", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-chat", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(50, false, "")

	const clean = `{"messages":[{"role":"user","content":"hi"}]}`
	const withTools = `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function"}]}`
	// A model with no registered template and no prefix match.
	const noTplModel = "acme/no-template-model"

	// No messages: request-class everywhere.
	if _, rc := kvBridgeTokenizeChat(0, 0, `{"messages":[]}`, noTplModel, 16); rc != KvTokErrRequest {
		t.Fatalf("legacy no-messages: got %d", rc)
	}
	if _, rc := kvBridgeTokenizeChat(50, b.BindingGen, `{"messages":[]}`, noTplModel, 16); rc != KvTokErrRequest {
		t.Fatalf("strict no-messages: got %d", rc)
	}

	// Excluded feature: strict refuses (UNSUPPORTED, request-class); legacy
	// keeps its pre-contract path (here: template-less model -> -1, NOT -2).
	if _, rc := kvBridgeTokenizeChat(50, b.BindingGen, withTools, noTplModel, 16); rc != KvTokErrUnsupported {
		t.Fatalf("strict tools body must be UNSUPPORTED, got %d", rc)
	}
	if _, rc := kvBridgeTokenizeChat(0, 0, withTools, noTplModel, 16); rc != KvTokErrRequest {
		t.Fatalf("legacy tools body must keep today's -1, got %d", rc)
	}

	// Renderer availability: legacy template-less -> -1 (today); strict
	// template-less -> renderer fault (admission guaranteed a renderer, so
	// its absence at serving time is a runtime fault).
	if _, rc := kvBridgeTokenizeChat(0, 0, clean, noTplModel, 16); rc != KvTokErrRequest {
		t.Fatalf("legacy no-template must stay -1, got %d", rc)
	}
	if _, rc := kvBridgeTokenizeChat(50, b.BindingGen, clean, noTplModel, 16); rc != KvTokErrRenderer {
		t.Fatalf("strict no-template must be RENDERER fault, got %d", rc)
	}
}

// TestKvChatExcludedFeature: the plan-§4 detector itself.
func TestKvChatExcludedFeature(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"clean", `{"messages":[{"role":"user","content":"hi"}]}`, ""},
		{"tools", `{"messages":[],"tools":[{"type":"function"}]}`, "tools"},
		{"tool_choice", `{"messages":[],"tool_choice":"auto"}`, "tools"},
		{"cache_salt", `{"messages":[],"cache_salt":"abc"}`, "cache_salt"},
		{"prompt_embeds", `{"messages":[],"prompt_embeds":"ZGF0YQ=="}`, "prompt_embeds"},
		{"template_kwargs", `{"messages":[],"chat_template_kwargs":{"enable_thinking":false}}`, "template_kwargs"},
		{"multimodal", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"x"}}]}]}`, "multimodal"},
		{"text_parts_ok", `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, ""},
		{"null_tools_ok", `{"messages":[],"tools":null}`, ""},
	}
	for _, c := range cases {
		if got := kvChatExcludedFeature(c.body); got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// TestKvSvcContractKickInstall: the restore path re-runs the install by rule
// identity once the kvexactbinding domain lands the authoritative binding.
func TestKvSvcContractKickInstall(t *testing.T) {
	kvDataplaneTestSetup(t)
	kvTestRegister(51, "rule-kick", KvContractAPIBoth)
	if _, err := KvBindingAllocate("rule-kick", kvTestComponents(1)); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	// The kick goes through the registered production setter; install a fake.
	done := make(chan struct{})
	KvRegisterContractSetter(func(_ net.IP, _ uint16, _ uint8,
		gen uint32, apiMode, eligible uint8) (uint64, bool) {
		defer close(done)
		return KvContractPack(gen, 0, apiMode, eligible), true
	})
	t.Cleanup(func() { KvRegisterContractSetter(nil) })

	KvSvcContractKickInstall("rule-kick")
	<-done
	// The async goroutine clears the fence just after the setter returns;
	// poll briefly for the outcome write.
	deadline := time.Now().Add(2 * time.Second)
	for kvSvcDenied(51) {
		if time.Now().After(deadline) {
			t.Fatalf("kicked install must clear the fence")
		}
		time.Sleep(time.Millisecond)
	}
}
