// SPDX-License-Identifier: Apache-2.0
//
// ai_kv_jinja_test.go — template-executor vs HF-oracle render parity.
//
// The executor's correctness bar is byte-identity with the engine's own
// renderer. Ground truth is cicd/common/kv_hash/fixtures/
// kv_chat_render_parity.json, generated OFFLINE by the HF-sidecar oracle
// (gen_chat_render_fixtures.py) from the SAME digest-pinned template
// artifacts the profiles serve — so expectations come from transformers'
// Jinja environment, never from the executor itself (non-circular). Every
// banked model × case must render byte-identically through the banked
// template artifact.

package loxinet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// kvTestPublishChatProfile publishes an in-memory profile generation in
// which a chat-declaring profile (chat + completions, base_model_only)
// serves modelName with the given template source. Any generation already
// published (e.g. a suite's on-disk registry root) is carried forward —
// its SourceRoot and other profiles stay resolvable — with the chat profile
// overlaid on top. The previous generation is restored on cleanup. Tests use
// this instead of the on-disk trust root — artifact trust and digest pinning
// have their own registry tests.
func kvTestPublishChatProfile(t *testing.T, modelName, templateSrc string, pol KvRenderPolicy) {
	t.Helper()
	prev := kvProfileReg.Load()
	e := &kvProfileEntry{
		Profile: ModelPromptProfile{
			ProfileID:     "test-chat-profile",
			BaseModel:     modelName,
			SupportedApis: []string{KvProfileAPICompletions, KvProfileAPIChat},
			AliasPolicy:   KvAliasPolicyBaseModelOnly,
			RenderPolicy:  pol,
		},
		TemplateBytes: []byte(templateSrc),
	}
	gen := &kvProfileGeneration{
		Gen:      kvProfileRegGen.Add(1),
		Profiles: map[string]*kvProfileEntry{},
		ByModel:  map[string]*kvProfileEntry{},
	}
	if prev != nil {
		gen.SourceRoot = prev.SourceRoot
		gen.SetDigest = prev.SetDigest
		for k, v := range prev.Profiles {
			gen.Profiles[k] = v
		}
		for k, v := range prev.ByModel {
			gen.ByModel[k] = v
		}
	}
	e.Gen = gen.Gen
	gen.Profiles[e.Profile.ProfileID] = e
	gen.ByModel[kvModelSlug(modelName)] = e
	kvProfileReg.Store(gen)
	t.Cleanup(func() { kvProfileReg.Store(prev) })
}

type kvRenderParityFixture struct {
	TransformersVersion string `json:"transformers_version"`
	Models              map[string]struct {
		TemplateSha256 string `json:"template_sha256"`
		BosToken       string `json:"bos_token"`
		EosToken       string `json:"eos_token"`
		Cases          map[string]struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Rendered                       string `json:"rendered"`
			TemplatedIds                   []int  `json:"templated_ids"`
			EncodeRenderedMatchesTemplated bool   `json:"encode_rendered_matches_templated"`
		} `json:"cases"`
	} `json:"models"`
}

func kvHashFixturePath(t *testing.T, parts ...string) string {
	t.Helper()
	wd, _ := os.Getwd()
	base := []string{wd, "..", "..", "cicd", "common", "kv_hash", "fixtures"}
	return filepath.Join(append(base, parts...)...)
}

func loadRenderParityFixture(t *testing.T) *kvRenderParityFixture {
	t.Helper()
	data, err := os.ReadFile(kvHashFixturePath(t, "kv_chat_render_parity.json"))
	if err != nil {
		t.Skipf("render parity fixture not found: %v", err)
	}
	var f kvRenderParityFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse render parity fixture: %v", err)
	}
	if len(f.Models) == 0 {
		t.Fatal("render parity fixture has zero models")
	}
	return &f
}

// TestKvJinjaOracleParity renders every fixture case for every banked model
// through the banked template artifact and requires byte-identity with the
// HF oracle's output. The banked artifact's digest must also match the
// digest the oracle generated from — a skew here means the goldens no longer
// describe the artifact the profiles pin.
func TestKvJinjaOracleParity(t *testing.T) {
	f := loadRenderParityFixture(t)
	for slug, model := range f.Models {
		slug, model := slug, model
		t.Run(slug, func(t *testing.T) {
			src, err := os.ReadFile(kvHashFixturePath(t, "templates", slug, "chat_template.jinja"))
			if err != nil {
				t.Fatalf("banked template missing for %s: %v", slug, err)
			}
			sum := sha256.Sum256(src)
			if got := hex.EncodeToString(sum[:]); got != model.TemplateSha256 {
				t.Fatalf("banked template digest %s != oracle digest %s (regenerate goldens)", got, model.TemplateSha256)
			}
			tpl, err := kvJinjaCompile(string(src))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			for name, c := range model.Cases {
				name, c := name, c
				t.Run(name, func(t *testing.T) {
					if !c.EncodeRenderedMatchesTemplated {
						t.Fatalf("oracle recorded encode(render) != templated ids — the one-tokenizer-path invariant broke upstream")
					}
					msgs := make([]any, 0, len(c.Messages))
					for _, m := range c.Messages {
						msgs = append(msgs, map[string]any{"role": m.Role, "content": m.Content})
					}
					ctx := map[string]any{
						"messages":              msgs,
						"add_generation_prompt": true,
					}
					if model.BosToken != "" {
						ctx["bos_token"] = model.BosToken
					}
					if model.EosToken != "" {
						ctx["eos_token"] = model.EosToken
					}
					got, err := tpl.Render(ctx)
					if err != nil {
						t.Fatalf("render: %v", err)
					}
					if got != c.Rendered {
						t.Fatalf("render mismatch:\n got:  %q\n want: %q", got, c.Rendered)
					}
				})
			}
		})
	}
}

// TestKvJinjaProfileRenderPath drives the same oracle cases through the FULL
// serving seam (kvRenderChatTemplate over a published profile) for one
// model, proving the profile lookup, render-policy plumbing, and executor
// compose to the oracle's bytes — not just the bare interpreter.
func TestKvJinjaProfileRenderPath(t *testing.T) {
	f := loadRenderParityFixture(t)
	const slug = "NousResearch__Meta-Llama-3.1-8B-Instruct"
	model, ok := f.Models[slug]
	if !ok {
		t.Skipf("fixture lacks %s", slug)
	}
	src, err := os.ReadFile(kvHashFixturePath(t, "templates", slug, "chat_template.jinja"))
	if err != nil {
		t.Fatalf("banked template missing: %v", err)
	}
	kvTestPublishChatProfile(t, "NousResearch/Meta-Llama-3.1-8B-Instruct", string(src),
		KvRenderPolicy{AddGenerationPrompt: true, BosToken: model.BosToken, EosToken: model.EosToken})
	for name, c := range model.Cases {
		msgs := make([]kvChatMessage, 0, len(c.Messages))
		for _, m := range c.Messages {
			msgs = append(msgs, kvChatMessage{Role: m.Role, Content: m.Content})
		}
		got, ok := kvRenderChatTemplate("NousResearch/Meta-Llama-3.1-8B-Instruct", msgs)
		if !ok {
			t.Fatalf("%s: profile render path returned ok=false", name)
		}
		if got != c.Rendered {
			t.Fatalf("%s: profile render mismatch:\n got:  %q\n want: %q", name, got, c.Rendered)
		}
	}
}

// TestKvJinjaBosTokenRequired: Llama-3.1's template concatenates bos_token.
// A profile that fails to declare it must fail the render loudly (undefined
// concatenation), never emit different bytes than the engine caches.
func TestKvJinjaBosTokenRequired(t *testing.T) {
	src, err := os.ReadFile(kvHashFixturePath(t, "templates",
		"NousResearch__Meta-Llama-3.1-8B-Instruct", "chat_template.jinja"))
	if err != nil {
		t.Skipf("banked template missing: %v", err)
	}
	kvTestPublishChatProfile(t, "m-bosless", string(src),
		KvRenderPolicy{AddGenerationPrompt: true})
	if out, ok := kvRenderChatTemplate("m-bosless",
		[]kvChatMessage{{Role: "user", Content: "hi"}}); ok {
		t.Fatalf("render must fail without bos_token, got %q", out)
	}
}

// TestKvChatSupportRequiresChatDeclaration: a published profile that serves
// the model but declares only completions must NOT report chat support, even
// if template bytes happen to be present — the declared API surface is the
// authority, and admission must refuse a chat rule against it.
func TestKvChatSupportRequiresChatDeclaration(t *testing.T) {
	prev := kvProfileReg.Load()
	e := &kvProfileEntry{
		Profile: ModelPromptProfile{
			ProfileID:     "test-completions-only",
			BaseModel:     "m-completions-only",
			SupportedApis: []string{KvProfileAPICompletions},
			AliasPolicy:   KvAliasPolicyBaseModelOnly,
			RenderPolicy:  KvRenderPolicy{AddGenerationPrompt: true},
		},
		TemplateBytes: []byte("rendered"),
	}
	gen := &kvProfileGeneration{
		Gen:      kvProfileRegGen.Add(1),
		Profiles: map[string]*kvProfileEntry{e.Profile.ProfileID: e},
		ByModel:  map[string]*kvProfileEntry{kvModelSlug("m-completions-only"): e},
	}
	e.Gen = gen.Gen
	kvProfileReg.Store(gen)
	t.Cleanup(func() { kvProfileReg.Store(prev) })

	if kvChatTemplateSupported("m-completions-only") {
		t.Fatal("completions-only profile must not report chat support")
	}
	if out, ok := kvRenderChatTemplate("m-completions-only",
		[]kvChatMessage{{Role: "user", Content: "hi"}}); ok {
		t.Fatalf("completions-only profile must not render chat, got %q", out)
	}
}

// TestKvJinjaCompileRefusals: constructs outside the supported subset are
// compile errors, so a bad template refuses the profile generation at
// publish time instead of faulting the first chat request.
func TestKvJinjaCompileRefusals(t *testing.T) {
	for _, src := range []string{
		"{% include 'x' %}",
		"{% macro f() %}{% endmacro %}",
		"{% if x %}unterminated",
		"{{ messages",
		"{% for m messages %}{% endfor %}",
	} {
		if _, err := kvJinjaCompile(src); err == nil {
			t.Errorf("compile accepted unsupported template %q", src)
		}
	}
}

// TestKvJinjaRenderFaults: in-subset templates whose evaluation hits an
// out-of-domain value must error (surfacing as a runtime fault on strict
// paths), never render partial or different bytes.
func TestKvJinjaRenderFaults(t *testing.T) {
	ctx := func() map[string]any {
		return map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		}
	}
	for _, src := range []string{
		"{{ messages[3].content }}",                    // index out of range
		"{{ undefinedvar + 'x' }}",                     // undefined concat
		"{% for m in messages[0].tools %}{% endfor %}", // iterate undefined
		"{{ messages | bogusfilter }}",                 // unknown filter
		"{{ messages[0].content.frob() }}",             // unknown method
	} {
		tpl, err := kvJinjaCompile(src)
		if err != nil {
			t.Fatalf("compile %q: %v", src, err)
		}
		if out, err := tpl.Render(ctx()); err == nil {
			t.Errorf("render of %q succeeded with %q, want error", src, out)
		}
	}
}
