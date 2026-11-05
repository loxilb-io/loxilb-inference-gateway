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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// Golden vectors for the tools-aware render: captured from vLLM 0.30.0's
// /tokenize with messages+tools (see the fixture's _note). Synthetic tools
// and prompts only.
type kvToolsVectorFixture struct {
	ProfileID        string `json:"profile_id"`
	BaseModel        string `json:"base_model"`
	ModelType        string `json:"model_type"`
	TemplateFixture  string `json:"template_fixture"`
	TemplateSha256   string `json:"template_sha256"`
	TokenizerFixture string `json:"tokenizer_fixture"`
	TokenizerSha256  string `json:"tokenizer_sha256"`
	RenderPolicy     struct {
		AddGenerationPrompt bool   `json:"addGenerationPrompt"`
		EosToken            string `json:"eosToken"`
	} `json:"render_policy"`
	Cases map[string]struct {
		Note     string          `json:"note"`
		Expect   string          `json:"expect"` // "match" | "refuse"
		Reason   string          `json:"reason"`
		Request  json.RawMessage `json:"request"`
		Rendered string          `json:"rendered"`
		TokenIDs []uint32        `json:"token_ids"`
	} `json:"cases"`
}

func loadKvToolsVectors(t *testing.T) *kvToolsVectorFixture {
	t.Helper()
	data, err := os.ReadFile(kvHashFixturePath(t, "kv_chat_tools_vectors.json"))
	if err != nil {
		t.Skipf("tools vector fixture not found: %v", err)
	}
	var f kvToolsVectorFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse tools vector fixture: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("tools vector fixture has zero cases")
	}
	return &f
}

func kvToolsSortedCases(f *kvToolsVectorFixture) []string {
	names := make([]string, 0, len(f.Cases))
	for n := range f.Cases {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// kvTestPublishToolsTarget publishes the attested target profile from the
// banked template artifact (the same bytes the demo profile pins: digest
// checked) behind the fixture's base model and returns the entry.
func kvTestPublishToolsTarget(t *testing.T, f *kvToolsVectorFixture) *kvProfileEntry {
	t.Helper()
	src, err := os.ReadFile(kvHashFixturePath(t, f.TemplateFixture))
	if err != nil {
		t.Skipf("banked template missing: %v", err)
	}
	sum := sha256.Sum256(src)
	if got := hex.EncodeToString(sum[:]); got != f.TemplateSha256 {
		t.Fatalf("banked template digest %s != fixture %s", got, f.TemplateSha256)
	}
	prev := kvProfileReg.Load()
	e := &kvProfileEntry{
		Profile: ModelPromptProfile{
			ProfileID:      f.ProfileID,
			BaseModel:      f.BaseModel,
			ModelType:      f.ModelType,
			TemplateSha256: f.TemplateSha256,
			SupportedApis:  []string{KvProfileAPICompletions, KvProfileAPIChat},
			AliasPolicy:    KvAliasPolicyBaseModelOnly,
			RenderPolicy: KvRenderPolicy{
				AddGenerationPrompt: f.RenderPolicy.AddGenerationPrompt,
				EosToken:            f.RenderPolicy.EosToken,
			},
		},
		TemplateBytes: src,
	}
	gen := &kvProfileGeneration{
		Gen:      kvProfileRegGen.Add(1),
		Profiles: map[string]*kvProfileEntry{},
		ByModel:  map[string]*kvProfileEntry{},
	}
	if prev != nil {
		gen.SourceRoot = prev.SourceRoot
		for k, v := range prev.Profiles {
			gen.Profiles[k] = v
		}
		for k, v := range prev.ByModel {
			gen.ByModel[k] = v
		}
	}
	e.Gen = gen.Gen
	gen.Profiles[e.Profile.ProfileID] = e
	gen.ByModel[kvModelSlug(f.BaseModel)] = e
	kvProfileReg.Store(gen)
	t.Cleanup(func() { kvProfileReg.Store(prev) })
	return e
}

// kvTestToolsTokenizer loads the banked tokenizer (same digest as the demo
// profile's) through the production backend; nil when unavailable.
func kvTestToolsTokenizer(t *testing.T, f *kvToolsVectorFixture) KvTokenizer {
	t.Helper()
	path := kvHashFixturePath(t, f.TokenizerFixture)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("banked tokenizer missing (%v): token ids not checked", err)
		return nil
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != f.TokenizerSha256 {
		t.Fatalf("banked tokenizer digest %s != fixture %s", got, f.TokenizerSha256)
	}
	tok := NewHFTokenizerBackend().LoadModel(path)
	if tok == nil {
		t.Logf("tokenizer backend unavailable: token ids not checked")
		return nil
	}
	t.Cleanup(tok.Close)
	return tok
}

// kvTestManifestVersion stubs the manifest read for the gate.
func kvTestManifestVersion(t *testing.T, version string) {
	t.Helper()
	prev := kvToolsExactManifestLoad
	kvToolsExactManifestLoad = func(profileID string) (*KvAttestManifest, bool) {
		if version == "" {
			return nil, false
		}
		return &KvAttestManifest{ProfileID: profileID, ImageDigest: "sha256:test", EngineVersion: version}, true
	}
	kvToolsExactVerdicts.Clear()
	t.Cleanup(func() {
		kvToolsExactManifestLoad = prev
		kvToolsExactVerdicts.Clear()
	})
}

// kvRenderToolsCase renders a fixture body the way the strict bridge does on
// the tools-aware path (parse, then render) and returns the refusal reason
// ("" on success).
func kvRenderToolsCase(t *testing.T, e *kvProfileEntry, body string) (string, string) {
	t.Helper()
	addGen := e.Profile.RenderPolicy.AddGenerationPrompt
	if feature := kvChatExcludedFeatureOpts(body, addGen, true); feature != "" {
		return "", feature
	}
	if tf := kvChatTemplateFeatureOpts(body, string(e.TemplateBytes), kvChatToolsModeledKeys); tf != "" {
		return "", tf
	}
	req, reason := kvChatToolsParse(body)
	if reason != "" {
		return "", reason
	}
	out, err := kvRenderChatToolsReq(e, req, time.Now)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out, ""
}

// TestKvToolsExactFlagDefaultOff: the flag resolves to off from an unset or
// explicitly-off environment, and garbage is off.
func TestKvToolsExactFlagDefaultOff(t *testing.T) {
	for _, v := range []string{"", "0", "false", "no", "off", "garbage"} {
		t.Setenv("LOXILB_KV_TOOLS_EXACT", v)
		if kvResolveToolsExact() {
			t.Fatalf("LOXILB_KV_TOOLS_EXACT=%q resolved on, want off", v)
		}
	}
	for _, v := range []string{"1", "true", "yes", "on", "TRUE"} {
		t.Setenv("LOXILB_KV_TOOLS_EXACT", v)
		if !kvResolveToolsExact() {
			t.Fatalf("LOXILB_KV_TOOLS_EXACT=%q resolved off, want on", v)
		}
	}
}

// TestKvToolsExactOffIsByteIdentical: with the flag off, every tools-carrying
// vector is refused as "tools" and every kwargs-carrying one as
// "template_kwargs" exactly as before, the plain render context still
// carries tools=None, and the strict bridge never reaches the tools path
// (the gate is false before any profile check).
func TestKvToolsExactOffIsByteIdentical(t *testing.T) {
	defer kvToolsExactSetForTest(false)()
	f := loadKvToolsVectors(t)
	e := kvTestPublishToolsTarget(t, f)
	for _, name := range kvToolsSortedCases(f) {
		c := f.Cases[name]
		body := string(c.Request)
		var top map[string]json.RawMessage
		_ = json.Unmarshal(c.Request, &top)
		want := ""
		switch {
		case kvJSONPresent(top["tools"]) || kvJSONPresent(top["tool_choice"]):
			want = "tools"
		case kvJSONPresent(top["chat_template_kwargs"]):
			want = "template_kwargs"
		}
		if got := kvChatExcludedFeature(body, true); got != want {
			t.Fatalf("%s: flag off, excluded feature = %q, want %q", name, got, want)
		}
		// The variant the bridge consults only behind the gate must agree
		// when asked without the lift.
		if got := kvChatExcludedFeatureOpts(body, true, false); got != want {
			t.Fatalf("%s: flag off, excluded feature (opts) = %q, want %q", name, got, want)
		}
	}
	// The plain context is untouched: tools and documents None.
	ctx := kvJinjaChatContextShaped([]kvChatMessage{{Role: "user", Content: "q"}}, e.Profile.RenderPolicy, time.Now, nil)
	if ctx["tools"] != nil || ctx["documents"] != nil {
		t.Fatalf("plain render context carries tools=%v documents=%v, want None", ctx["tools"], ctx["documents"])
	}
	want := map[string]any{"messages": ctx["messages"], "tools": nil, "documents": nil,
		"add_generation_prompt": true, "eos_token": "<|im_end|>"}
	if !reflect.DeepEqual(ctx, want) {
		t.Fatalf("plain render context changed: %#v", ctx)
	}
	// Gate: off means ineligible even for the attested target.
	b := &KvExactBinding{Components: KvExactBindingComponents{
		Profile: KvModelProfileRef{ID: f.ProfileID}, Contract: KvEngineContractRef{ID: "vllm-kv-map-v2"}}}
	kvTestManifestVersion(t, kvToolsExactEngineVersion)
	if kvToolsExactEligible(b, e) {
		t.Fatal("flag off: gate reports eligible")
	}
}

// TestKvToolsExactGate: the gate opens only for the attested target — this
// profile id, this template digest, a vLLM contract and a manifest declaring
// engine 0.30.0 — and the verdict is cached per profile generation.
func TestKvToolsExactGate(t *testing.T) {
	defer kvToolsExactSetForTest(true)()
	f := loadKvToolsVectors(t)
	e := kvTestPublishToolsTarget(t, f)
	vllm := &KvExactBinding{Components: KvExactBindingComponents{
		Profile: KvModelProfileRef{ID: f.ProfileID}, Contract: KvEngineContractRef{ID: "vllm-kv-map-v2"}}}

	kvTestManifestVersion(t, kvToolsExactEngineVersion)
	if !kvToolsExactEligible(vllm, e) {
		t.Fatal("attested target refused")
	}
	other := *vllm
	other.Components.Contract.ID = "sglang-kv-v1"
	if kvToolsExactEligible(&other, e) {
		t.Fatal("non-vLLM contract accepted")
	}
	otherProfile := *vllm
	otherProfile.Components.Profile.ID = "someone-else"
	if kvToolsExactEligible(&otherProfile, e) {
		t.Fatal("binding naming another profile accepted")
	}
	drift := kvTestEntryLike(e, func(p *ModelPromptProfile) { p.TemplateSha256 = "00" })
	if kvToolsExactEligible(vllm, drift) {
		t.Fatal("template digest drift accepted")
	}
	renamed := kvTestEntryLike(e, func(p *ModelPromptProfile) { p.ProfileID = "qwen3-32b-fp8-v2" })
	vllm2 := *vllm
	vllm2.Components.Profile.ID = renamed.Profile.ProfileID
	if kvToolsExactEligible(&vllm2, renamed) {
		t.Fatal("another profile id accepted")
	}

	kvTestManifestVersion(t, "0.31.0")
	e2 := kvTestPublishToolsTarget(t, f) // new generation: cache miss
	if kvToolsExactEligible(vllm, e2) {
		t.Fatal("engine 0.31.0 accepted")
	}
	kvTestManifestVersion(t, "")
	e3 := kvTestPublishToolsTarget(t, f)
	if kvToolsExactEligible(vllm, e3) {
		t.Fatal("missing manifest accepted")
	}
}

// kvTestLogCapture collects logrus entries emitted while a test runs.
type kvTestLogCapture struct {
	mu      sync.Mutex
	entries []string
}

func (h *kvTestLogCapture) Levels() []log.Level { return log.AllLevels }
func (h *kvTestLogCapture) Fire(e *log.Entry) error {
	h.mu.Lock()
	h.entries = append(h.entries, e.Message)
	h.mu.Unlock()
	return nil
}
func (h *kvTestLogCapture) matching(sub string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, m := range h.entries {
		if strings.Contains(m, sub) {
			out = append(out, m)
		}
	}
	return out
}

func kvTestCaptureLog(t *testing.T) *kvTestLogCapture {
	t.Helper()
	h := &kvTestLogCapture{}
	logger := log.StandardLogger()
	prevLevel := logger.GetLevel()
	logger.SetLevel(log.DebugLevel)
	logger.AddHook(h)
	t.Cleanup(func() {
		logger.SetLevel(prevLevel)
		// logrus has no RemoveHook: replace the level map without this hook.
		hooks := log.LevelHooks{}
		for lvl, hs := range logger.Hooks {
			for _, x := range hs {
				if x != h {
					hooks[lvl] = append(hooks[lvl], x)
				}
			}
		}
		logger.ReplaceHooks(hooks)
	})
	return h
}

// TestKvToolsExactFlagLogsOnce: resolving the flag logs its value exactly once
// whichever way it resolves, and the second resolution never re-reads the
// environment.
func TestKvToolsExactFlagLogsOnce(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"", "disabled (LOXILB_KV_TOOLS_EXACT unset)"},
		{"0", "disabled (LOXILB_KV_TOOLS_EXACT=\"0\")"},
		{"1", "ENABLED"},
		{"maybe", "invalid LOXILB_KV_TOOLS_EXACT"},
	} {
		t.Setenv("LOXILB_KV_TOOLS_EXACT", tc.env)
		h := kvTestCaptureLog(t)
		kvResolveToolsExact()
		if got := h.matching("tools-aware exact rendering"); len(got) != 1 || !strings.Contains(got[0], tc.want) {
			if len(got) == 0 {
				got = h.matching("LOXILB_KV_TOOLS_EXACT")
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Fatalf("env %q: flag log lines %q, want one containing %q", tc.env, got, tc.want)
			}
		}
	}
	// Once resolved, the environment is not consulted again.
	prevOn := kvToolsExactOn
	kvToolsExactOnce = sync.Once{}
	t.Cleanup(func() {
		kvToolsExactOnce = sync.Once{}
		kvToolsExactSetForTest(prevOn)
	})
	t.Setenv("LOXILB_KV_TOOLS_EXACT", "1")
	h := kvTestCaptureLog(t)
	KvToolsExactInit()
	t.Setenv("LOXILB_KV_TOOLS_EXACT", "0")
	KvToolsExactInit()
	if !kvToolsExactEnabled() {
		t.Fatal("flag re-read after boot resolution")
	}
	if got := h.matching("tools-aware exact rendering"); len(got) != 1 {
		t.Fatalf("boot resolution logged %d times: %q", len(got), got)
	}
}

// TestKvToolsExactPublishVerdict: the profile-side verdict names the first
// failing leg, and a registry publish logs one OPEN/CLOSED line per profile.
func TestKvToolsExactPublishVerdict(t *testing.T) {
	f := loadKvToolsVectors(t)
	e := kvTestPublishToolsTarget(t, f)
	kvTestManifestVersion(t, kvToolsExactEngineVersion)

	restore := kvToolsExactSetForTest(false)
	if open, reason := kvToolsExactProfileVerdict(e); open || !strings.Contains(reason, "LOXILB_KV_TOOLS_EXACT is off") {
		t.Fatalf("flag off: open=%v reason=%q", open, reason)
	}
	restore()
	defer kvToolsExactSetForTest(true)()

	if open, reason := kvToolsExactProfileVerdict(e); !open || reason != "" {
		t.Fatalf("attested target: open=%v reason=%q", open, reason)
	}
	other := kvTestEntryLike(e, func(p *ModelPromptProfile) { p.ProfileID = "someone-else" })
	if open, reason := kvToolsExactProfileVerdict(other); open || !strings.Contains(reason, "not the attested target") {
		t.Fatalf("other profile: open=%v reason=%q", open, reason)
	}
	drift := kvTestEntryLike(e, func(p *ModelPromptProfile) { p.TemplateSha256 = "00" })
	if open, reason := kvToolsExactProfileVerdict(drift); open || !strings.Contains(reason, "template sha256") {
		t.Fatalf("template drift: open=%v reason=%q", open, reason)
	}
	kvTestManifestVersion(t, "0.31.0")
	e2 := kvTestPublishToolsTarget(t, f)
	if open, reason := kvToolsExactProfileVerdict(e2); open || !strings.Contains(reason, `manifest engineVersion "0.31.0"`) {
		t.Fatalf("engine 0.31.0: open=%v reason=%q", open, reason)
	}
	kvTestManifestVersion(t, "")
	e3 := kvTestPublishToolsTarget(t, f)
	if open, reason := kvToolsExactProfileVerdict(e3); open || !strings.Contains(reason, "no deployment manifest") {
		t.Fatalf("missing manifest: open=%v reason=%q", open, reason)
	}

	// One line per profile per publish: the target OPEN, another CLOSED.
	kvTestManifestVersion(t, kvToolsExactEngineVersion)
	e4 := kvTestPublishToolsTarget(t, f)
	gen := kvProfileReg.Load()
	gen.Profiles["zz-other"] = kvTestEntryLike(e4, func(p *ModelPromptProfile) { p.ProfileID = "zz-other" })
	h := kvTestCaptureLog(t)
	kvToolsExactLogPublish(gen)
	opened := h.matching("tools-exact gate OPEN for profile " + f.ProfileID)
	closed := h.matching("tools-exact gate CLOSED for profile zz-other")
	if len(opened) != 1 || len(closed) != 1 {
		t.Fatalf("publish verdict lines: open=%q closed=%q", opened, closed)
	}
	if !strings.Contains(closed[0], "not the attested target") {
		t.Fatalf("closed reason: %q", closed[0])
	}

	// The binding leg: a non-vLLM contract logs CLOSED once per binding.
	h2 := kvTestCaptureLog(t)
	sglang := &KvExactBinding{RuleIdent: "rule-x", Components: KvExactBindingComponents{
		Profile: KvModelProfileRef{ID: f.ProfileID}, Contract: KvEngineContractRef{ID: "sglang-kv-v1"}}}
	for i := 0; i < 3; i++ {
		if kvToolsExactEligible(sglang, e4) {
			t.Fatal("non-vLLM contract accepted")
		}
	}
	if got := h2.matching("tools-exact gate CLOSED for rule rule-x"); len(got) != 1 {
		t.Fatalf("contract verdict logged %d times: %q", len(got), got)
	}
}

// TestKvToolsVectors: every positive vector renders byte-for-byte to the
// engine's prompt and (when the banked tokenizer loads) to its token ids;
// every refusal vector is refused with the predicted reason; v4 (reordered
// tools) differs from v2; the tool_choice variants equal v2.
func TestKvToolsVectors(t *testing.T) {
	defer kvToolsExactSetForTest(true)()
	f := loadKvToolsVectors(t)
	e := kvTestPublishToolsTarget(t, f)
	tok := kvTestToolsTokenizer(t, f)
	ids := map[string][]uint32{}
	for _, name := range kvToolsSortedCases(f) {
		c := f.Cases[name]
		t.Run(name, func(t *testing.T) {
			body := string(c.Request)
			if name == "v1_no_tools" {
				// Regression: the plain path (no tools) is what renders it.
				if feature := kvChatExcludedFeature(body, true); feature != "" {
					t.Fatalf("no-tools body refused: %q", feature)
				}
				msgs, ok := kvParseChatMessages(body)
				if !ok {
					t.Fatal("parse")
				}
				got, ok := kvRenderChatTemplate(f.BaseModel, msgs)
				if !ok || got != c.Rendered {
					t.Fatalf("plain render mismatch:\n got  %q\n want %q", got, c.Rendered)
				}
				// And the tools-aware path renders the same bytes.
				got2, reason := kvRenderToolsCase(t, e, body)
				if reason != "" || got2 != got {
					t.Fatalf("tools path differs on a no-tools body: reason=%q\n got  %q\n want %q", reason, got2, got)
				}
			}
			got, reason := kvRenderToolsCase(t, e, body)
			switch c.Expect {
			case "match":
				if reason != "" {
					t.Fatalf("refused as %q, want a render", reason)
				}
				if got != c.Rendered {
					t.Fatalf("render mismatch:\n got  %q\n want %q", got, c.Rendered)
				}
				if tok != nil {
					enc := tok.Encode(got, false)
					if !reflect.DeepEqual(enc, c.TokenIDs) {
						t.Fatalf("token ids differ (%d vs %d): first diff at %d", len(enc), len(c.TokenIDs), kvFirstDiff(enc, c.TokenIDs))
					}
					ids[name] = enc
				}
			case "refuse":
				if reason == "" {
					t.Fatalf("rendered %q, want refusal %q", got, c.Reason)
				}
				if reason != c.Reason {
					t.Fatalf("refused as %q, want %q", reason, c.Reason)
				}
			default:
				t.Fatalf("unknown expect %q", c.Expect)
			}
		})
	}
	if f.Cases["v2_tools_full"].Rendered == f.Cases["v4_tools_reordered"].Rendered {
		t.Fatal("v2 and v4 render identically: reordered tools must hash differently")
	}
	if tok != nil && reflect.DeepEqual(ids["v2_tools_full"], ids["v4_tools_reordered"]) {
		t.Fatal("v2 and v4 token ids identical")
	}
	for _, v := range []string{"v6a_tool_choice_none", "v6b_tool_choice_named", "v6c_tool_choice_required"} {
		if f.Cases[v].Rendered != f.Cases["v2_tools_full"].Rendered {
			t.Fatalf("%s renders differently from v2", v)
		}
	}
	// chat_template_kwargs: enable_thinking false appends the empty think
	// block after the generation prompt, with and without tools; true,
	// absent, {}, null and preserve_thinking alone render like the
	// kwargs-less body.
	const think = "<think>\n\n</think>\n\n"
	v1, v2 := f.Cases["v1_no_tools"].Rendered, f.Cases["v2_tools_full"].Rendered
	if got := f.Cases["k1_thinking_false_no_tools"].Rendered; got != v1+think {
		t.Fatalf("k1 is not v1 + think block: %q", got)
	}
	if got := f.Cases["k3_thinking_false_tools"].Rendered; got != v2+think {
		t.Fatalf("k3 is not v2 + think block: %q", got)
	}
	for _, k := range []string{"k2_thinking_true_no_tools", "k5_preserve_thinking_only", "k6_kwargs_empty_object", "k12_kwargs_null"} {
		if f.Cases[k].Rendered != v1 {
			t.Fatalf("%s renders differently from v1", k)
		}
	}
	if f.Cases["k4_thinking_true_tools"].Rendered != v2 {
		t.Fatal("k4 renders differently from v2")
	}
	if !strings.HasSuffix(f.Cases["k7_harness_shape"].Rendered, "<|im_start|>assistant\n"+think) {
		t.Fatal("k7 (harness shape) does not end with the generation prompt and the think block")
	}
}

// TestKvToolsKwargs: the allowlist itself. Absent and null are no kwargs,
// each known key needs a JSON boolean, only enable_thinking reaches the
// context, and anything else is refused with its own reason.
func TestKvToolsKwargs(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		want   map[string]any
		reason string
	}{
		{"absent", "", nil, ""},
		{"null", "null", nil, ""},
		{"empty", "{}", nil, ""},
		{"thinking_false", `{"enable_thinking":false}`, map[string]any{"enable_thinking": false}, ""},
		{"thinking_true", `{"enable_thinking":true}`, map[string]any{"enable_thinking": true}, ""},
		{"preserve_only", `{"preserve_thinking":true}`, nil, ""},
		{"harness", `{"enable_thinking": false, "preserve_thinking": true}`, map[string]any{"enable_thinking": false}, ""},
		{"unknown_key", `{"enable_thinking":false,"verbosity":true}`, nil, kvToolsRefuseKwargsKey},
		{"override_key", `{"add_generation_prompt":false}`, nil, kvToolsRefuseKwargsKey},
		{"tools_key", `{"tools":null}`, nil, kvToolsRefuseKwargsKey},
		{"string_value", `{"enable_thinking":"false"}`, nil, kvToolsRefuseKwargsValue},
		{"number_value", `{"enable_thinking":0}`, nil, kvToolsRefuseKwargsValue},
		{"null_value", `{"enable_thinking":null}`, nil, kvToolsRefuseKwargsValue},
		{"preserve_string", `{"preserve_thinking":"yes"}`, nil, kvToolsRefuseKwargsValue},
		{"string", `"enable_thinking=false"`, nil, kvToolsRefuseKwargs},
		{"array", `[true]`, nil, kvToolsRefuseKwargs},
		{"number", `1`, nil, kvToolsRefuseKwargs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := kvChatToolsKwargs(json.RawMessage(c.raw))
			if reason != c.reason {
				t.Fatalf("reason %q, want %q", reason, c.reason)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("kwargs %#v, want %#v", got, c.want)
			}
		})
	}
	// Through the body parser: the kwargs ride on the request and the
	// refusal reasons come out unchanged.
	f := loadKvToolsVectors(t)
	req, reason := kvChatToolsParse(string(f.Cases["k7_harness_shape"].Request))
	if reason != "" || !reflect.DeepEqual(req.Kwargs, map[string]any{"enable_thinking": false}) {
		t.Fatalf("harness body: reason %q kwargs %#v", reason, req.Kwargs)
	}
	req, reason = kvChatToolsParse(string(f.Cases["v2_tools_full"].Request))
	if reason != "" || req.Kwargs != nil {
		t.Fatalf("v2 body: reason %q kwargs %#v, want none", reason, req.Kwargs)
	}
}

// TestKvToolsKwargsTemplateReads pins the proof behind the allowlist against
// the banked template: a key that reaches the context is one the template
// reads (as a whole word), and a key that is dropped is never mentioned, so
// dropping it is what the engine's resolve_chat_template_kwargs does too.
func TestKvToolsKwargsTemplateReads(t *testing.T) {
	f := loadKvToolsVectors(t)
	e := kvTestPublishToolsTarget(t, f)
	src := string(e.TemplateBytes)
	for k, reaches := range kvChatToolsKwargsAllow {
		if got := kvTemplateMentions(src, k); got != reaches {
			t.Fatalf("template mentions %q = %v, allowlist says reaches the context = %v", k, got, reaches)
		}
	}
	// And the one read is read only at the generation prompt, as the
	// vectors assume (k1 = v1 + think block).
	if n := strings.Count(src, "enable_thinking"); n != 2 {
		t.Fatalf("template mentions enable_thinking %d times, want 2 (one `is defined` and one `is false` test)", n)
	}
}

// kvTestEntryLike is a fresh entry carrying e's profile (mutated) and
// template bytes; entries hold a sync.Once and must not be copied.
func kvTestEntryLike(e *kvProfileEntry, mutate func(*ModelPromptProfile)) *kvProfileEntry {
	n := &kvProfileEntry{Profile: e.Profile, Gen: e.Gen, TemplateBytes: e.TemplateBytes}
	mutate(&n.Profile)
	return n
}

// kvTestBodyWith rewrites a request body's top-level keys through f.
func kvTestBodyWith(t *testing.T, raw json.RawMessage, f func(top map[string]json.RawMessage)) string {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	f(top)
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// kvReachedTokenizer reports a bridge code that proves the render ran: the
// request was tokenized, or it failed only for want of a staged tokenizer.
func kvReachedTokenizer(rc int) bool { return rc >= 0 || rc == KvTokErrTokenizer }

func kvFirstDiff(a, b []uint32) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestKvToolsBridgeStrictPath drives the strict bridge end to end with a
// strict binding on the attested target: flag off → UNSUPPORTED for a tools
// body (today's behavior); flag on → the body reaches the tokenizer (the
// tokenizer fault proves the render ran), a plain body is unaffected, the
// refusal vectors stay UNSUPPORTED, and a non-target profile keeps refusing.
func TestKvToolsBridgeStrictPath(t *testing.T) {
	f := loadKvToolsVectors(t)
	kvDataplaneTestSetup(t)
	e := kvTestPublishToolsTarget(t, f)
	kvTestManifestVersion(t, kvToolsExactEngineVersion)
	comps := kvTestComponents(1)
	comps.Profile.ID = f.ProfileID
	comps.Contract.ID = "vllm-kv-map-v2"
	kvTestRegister(61, "rule-tools-target", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-tools-target", comps)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(61, false, "")
	_ = e

	tools := string(f.Cases["v2_tools_full"].Request)
	plain := string(f.Cases["v1_no_tools"].Request)
	kwargsOnly := string(f.Cases["k1_thinking_false_no_tools"].Request)
	harness := string(f.Cases["k7_harness_shape"].Request)

	restore := kvToolsExactSetForTest(false)
	if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, tools, f.BaseModel, 16); rc != KvTokErrUnsupported {
		t.Fatalf("flag off, tools body: rc %d, want UNSUPPORTED %d", rc, KvTokErrUnsupported)
	}
	for _, body := range []string{kwargsOnly, harness} {
		if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, body, f.BaseModel, 16); rc != KvTokErrUnsupported {
			t.Fatalf("flag off, kwargs body: rc %d, want UNSUPPORTED %d", rc, KvTokErrUnsupported)
		}
	}
	if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, plain, f.BaseModel, 16); !kvReachedTokenizer(rc) {
		t.Fatalf("flag off, plain body: rc %d, want the render to reach the tokenizer", rc)
	}
	restore()

	defer kvToolsExactSetForTest(true)()
	if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, tools, f.BaseModel, 16); !kvReachedTokenizer(rc) {
		t.Fatalf("flag on, tools body: rc %d, want the render to reach the tokenizer", rc)
	}
	for _, body := range []string{kwargsOnly, harness} {
		if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, body, f.BaseModel, 16); !kvReachedTokenizer(rc) {
			t.Fatalf("flag on, kwargs body: rc %d, want the render to reach the tokenizer", rc)
		}
	}
	if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, plain, f.BaseModel, 16); !kvReachedTokenizer(rc) {
		t.Fatalf("flag on, plain body: rc %d, want the render to reach the tokenizer", rc)
	}
	for _, name := range kvToolsSortedCases(f) {
		c := f.Cases[name]
		if c.Expect != "refuse" {
			continue
		}
		if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, string(c.Request), f.BaseModel, 16); rc != KvTokErrUnsupported {
			t.Fatalf("flag on, %s: rc %d, want UNSUPPORTED %d", name, rc, KvTokErrUnsupported)
		}
	}
	// Other excluded features still refuse on the tools path.
	withSalt := kvTestBodyWith(t, f.Cases["v2_tools_full"].Request, func(top map[string]json.RawMessage) {
		top["cache_salt"] = json.RawMessage(`"x"`)
	})
	if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, withSalt, f.BaseModel, 16); rc != KvTokErrUnsupported {
		t.Fatalf("flag on, tools+cache_salt: rc %d, want UNSUPPORTED %d", rc, KvTokErrUnsupported)
	}
	// A message key the template reads and the parser does not model.
	withName := kvTestBodyWith(t, f.Cases["v2_tools_full"].Request, func(top map[string]json.RawMessage) {
		top["messages"] = json.RawMessage(`[{"role":"user","content":"q","name":"bob"}]`)
	})
	if _, rc := kvBridgeTokenizeChat(61, b.BindingGen, withName, f.BaseModel, 16); rc != KvTokErrUnsupported {
		t.Fatalf("flag on, message name: rc %d, want UNSUPPORTED %d", rc, KvTokErrUnsupported)
	}

	// A different profile (same template bytes, another id) stays refused.
	const otherModel = "acme/other-qwen3"
	kvTestPublishChatProfile(t, otherModel, string(e.TemplateBytes),
		KvRenderPolicy{AddGenerationPrompt: true, EosToken: "<|im_end|>"})
	comps2 := kvTestComponents(1)
	comps2.Profile.ID = "test-chat-profile"
	comps2.Contract.ID = "vllm-kv-map-v2"
	kvTestRegister(62, "rule-other-profile", KvContractAPIBoth)
	b2, err := KvBindingAllocate("rule-other-profile", comps2)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	kvSvcContractOutcome(62, false, "")
	for _, name := range []string{"v2_tools_full", "k1_thinking_false_no_tools", "k7_harness_shape"} {
		otherBody := kvTestBodyWith(t, f.Cases[name].Request, func(top map[string]json.RawMessage) {
			top["model"] = json.RawMessage(`"` + otherModel + `"`)
		})
		if _, rc := kvBridgeTokenizeChat(62, b2.BindingGen, otherBody, otherModel, 16); rc != KvTokErrUnsupported {
			t.Fatalf("flag on, other profile, %s: rc %d, want UNSUPPORTED %d", name, rc, KvTokErrUnsupported)
		}
	}
}

// TestKvPyFloatRepr pins Python's float.__repr__ for the values json.dumps
// prints inside tool schemas and arguments.
func TestKvPyFloatRepr(t *testing.T) {
	cases := map[float64]string{
		1.0: "1.0", 2.5: "2.5", 0.5: "0.5", 0.1: "0.1", 100000.0: "100000.0",
		1e6: "1000000.0", 1e15: "1000000000000000.0", 1e16: "1e+16", 1.5e20: "1.5e+20",
		0.0001: "0.0001", 0.00001: "1e-05", 1.2345678901234568e+17: "1.2345678901234568e+17",
		-2.5: "-2.5", -1e-7: "-1e-07", 123.456: "123.456", 3.0e-5: "3e-05", 1e22: "1e+22",
	}
	for f, want := range cases {
		if got := kvJjPyFloatRepr(f); got != want {
			t.Errorf("repr(%v) = %q, want %q", f, got, want)
		}
	}
	if got := kvJjPyFloatRepr(negZero()); got != "-0.0" {
		t.Errorf("repr(-0.0) = %q", got)
	}
}

func negZero() float64 {
	z := 0.0
	return -z
}

// TestKvJSONOrderedDecode pins json.loads semantics: key order kept, a
// duplicate key keeps its first position with the last value, integer vs
// float by literal form, and tojson re-emits with Python's formatting.
func TestKvJSONOrderedDecode(t *testing.T) {
	v, err := kvJjJSONValue([]byte(` {"b": 1, "a": [1.0, 2, "x", null, true], "b": 1E6, "c": {"z": -0.0, "y": 1e-05}} `))
	if err != nil {
		t.Fatal(err)
	}
	j := &kvJjPyJSON{indent: -1, itemSep: ", ", keySep: ": "}
	got, err := j.dump(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"b": 1000000.0, "a": [1.0, 2, "x", null, true], "c": {"z": -0.0, "y": 1e-05}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if _, err := kvJjJSONValue([]byte(`{"a": 1} x`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := kvJjJSONValue([]byte(`{"a": 123456789012345678901234567890}`)); err == nil {
		t.Fatal("integer past int64 accepted")
	}
}

// TestKvToolsVectorsLiveOracle re-checks every positive vector against a live
// engine's /tokenize when KV_TOOLS_ORACLE_URL names one (an http://host:port
// whose /tokenize reaches vLLM 0.30.0 serving the target). Skipped otherwise.
func TestKvToolsVectorsLiveOracle(t *testing.T) {
	url := os.Getenv("KV_TOOLS_ORACLE_URL")
	if url == "" {
		t.Skip("KV_TOOLS_ORACLE_URL not set")
	}
	defer kvToolsExactSetForTest(true)()
	f := loadKvToolsVectors(t)
	e := kvTestPublishToolsTarget(t, f)
	tok := kvTestToolsTokenizer(t, f)
	if tok == nil {
		t.Skip("tokenizer backend unavailable")
	}
	client := &http.Client{Timeout: 60 * time.Second}
	for _, name := range kvToolsSortedCases(f) {
		c := f.Cases[name]
		if c.Expect != "match" {
			continue
		}
		// Append the /tokenize knob by text: re-marshaling through a Go map
		// would sort the keys and change what the engine renders.
		raw := append([]byte(nil), bytes.TrimSpace(c.Request)...) // copy: never alias the fixture
		raw = append(raw[:len(raw)-1], []byte(`,"add_generation_prompt":true}`)...)
		resp, err := client.Post(url+"/tokenize", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: oracle: %v", name, err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var o struct {
			Tokens []uint32 `json:"tokens"`
		}
		if err := json.Unmarshal(out, &o); err != nil || len(o.Tokens) == 0 {
			t.Fatalf("%s: oracle answered %d: %.200s", name, resp.StatusCode, out)
		}
		got, reason := kvRenderToolsCase(t, e, string(c.Request))
		if reason != "" {
			t.Fatalf("%s: refused %q", name, reason)
		}
		enc := tok.Encode(got, false)
		if !reflect.DeepEqual(enc, o.Tokens) {
			t.Fatalf("%s: live oracle ids differ (%d vs %d), first diff %d", name, len(enc), len(o.Tokens), kvFirstDiff(enc, o.Tokens))
		}
		t.Logf("%s: %d ids match the live oracle", name, len(enc))
	}
}

// kvTestToolsBody67 builds a 67-tool request in the shape of the demo
// workload (agent-style tools, roughly 330 tokens each) from the v2 vector's
// tools, so the render cost of the real tool count can be measured offline.
func kvTestToolsBody67(t testing.TB, f *kvToolsVectorFixture) string {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(f.Cases["v2_tools_full"].Request, &top); err != nil {
		t.Fatal(err)
	}
	var tools []map[string]any
	if err := json.Unmarshal(top["tools"], &tools); err != nil {
		t.Fatal(err)
	}
	long := "Use this tool when the user asks for it or when a previous tool result references an identifier that must be followed up. " +
		"Prefer it over shell access because it validates arguments, respects the workspace's permission model and returns a structured result. " +
		"Large results are truncated to 200 items; pass cursor to continue. Set dry_run to preview. Errors come back as an error object; do not retry on permission_denied."
	out := make([]any, 0, 67)
	for i := 0; len(out) < 67; i++ {
		src := tools[i%len(tools)]
		raw, _ := json.Marshal(src)
		var tool map[string]any
		_ = json.Unmarshal(raw, &tool)
		fn := tool["function"].(map[string]any)
		fn["name"] = fn["name"].(string) + "_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		fn["description"] = fn["description"].(string) + " " + long
		out = append(out, tool)
	}
	raw, _ := json.Marshal(out)
	top["tools"] = raw
	body, _ := json.Marshal(top)
	return string(body)
}

// BenchmarkKvToolsRender67 measures parse + render of a 67-tool request on
// the tools-aware path (the demo's per-request CPU cost before tokenization).
func BenchmarkKvToolsRender67(b *testing.B) {
	t := &testing.T{}
	f := loadKvToolsVectors(t)
	if f == nil {
		b.Skip("fixture missing")
	}
	e := kvTestPublishToolsTarget(t, f)
	body := kvTestToolsBody67(b, f)
	b.ReportMetric(float64(len(body)), "body_bytes")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, reason := kvChatToolsParse(body)
		if reason != "" {
			b.Fatalf("refused %q", reason)
		}
		if _, err := kvRenderChatToolsReq(e, req, time.Now); err != nil {
			b.Fatal(err)
		}
	}
}
