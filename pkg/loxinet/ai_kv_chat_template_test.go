// SPDX-License-Identifier: Apache-2.0
//
// ai_kv_chat_template_test.go — Gap-B1 regression guard.
//
// Asserts loxilb's Go chat-template renderer reproduces vLLM's
// tokenizer.apply_chat_template(tokenize=False, add_generation_prompt=True)
// output byte-for-byte. Ground truth (rendered_exact + messages) is committed at
// cicd/common/kv_hash/fixtures/kv_chat_template_parity.json, generated live on
// the real Qwen/Qwen2.5-7B-Instruct model — so expectations come from vLLM, not
// from loxilb's own renderer (non-circular).
//
// Because -01 made the shared Encode path WithEncodeSpecialTokens and it
// was confirmed live that Encode(rendered) == apply_chat_template(tokenize=True),
// asserting the rendered STRING matches is sufficient to guarantee token_id
// parity for chat. The end-to-end token_id parity is additionally backstopped by
// the live :9003 Mooncake tier15_hits gate (03).
//
// This file is in package loxinet (which uses cgo) and therefore builds/runs on
// Linux only (pkg/loxinet does not build on macOS); the local gate is gofmt. The
// renderer logic was additionally verified standalone on macOS against the same
// fixture during development.

package loxinet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type chatParityFixture struct {
	Model string `json:"model"`
	Cases map[string]struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		RenderedExact string `json:"rendered_exact"`
		TemplatedLen  int    `json:"templated_len"`
	} `json:"cases"`
}

func loadChatParityFixture(t *testing.T) *chatParityFixture {
	t.Helper()
	wd, _ := os.Getwd()
	path := filepath.Join(wd, "..", "..", "cicd", "common", "kv_hash",
		"fixtures", "kv_chat_template_parity.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("chat parity fixture not found at %s: %v", path, err)
	}
	var f chatParityFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("chat parity fixture has zero cases")
	}
	return &f
}

// TestChatTemplate_RenderMatchesVLLM asserts kvRenderChatTemplate reproduces
// vLLM's apply_chat_template string for every fixture case (default-system
// injection, per-message format, and generation prompt all included).
func TestChatTemplate_RenderMatchesVLLM(t *testing.T) {
	f := loadChatParityFixture(t)
	for name, c := range f.Cases {
		name, c := name, c
		t.Run(name, func(t *testing.T) {
			msgs := make([]kvChatMessage, 0, len(c.Messages))
			for _, m := range c.Messages {
				msgs = append(msgs, kvChatMessage{Role: m.Role, Content: m.Content})
			}
			got, ok := kvRenderChatTemplate(f.Model, msgs)
			if !ok {
				t.Fatalf("kvRenderChatTemplate returned ok=false for model %q (template must be registered)", f.Model)
			}
			if got != c.RenderedExact {
				t.Fatalf("rendered mismatch for case %s:\n got:  %q\n want: %q", name, got, c.RenderedExact)
			}
		})
	}
}

// TestChatTemplate_ParseMessagesFromBody asserts kvParseChatMessages extracts the
// ordered role/content turns from a raw chat request body, and that rendering the
// parsed messages still matches vLLM — i.e. the body→messages→render pipeline the
// cgo export (llb_ai_kv_tokenize_chat) drives is faithful end to end.
func TestChatTemplate_ParseMessagesFromBody(t *testing.T) {
	f := loadChatParityFixture(t)
	for name, c := range f.Cases {
		name, c := name, c
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"model": f.Model, "messages": c.Messages})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			msgs, ok := kvParseChatMessages(string(body))
			if !ok {
				t.Fatalf("kvParseChatMessages ok=false for body %s", body)
			}
			if len(msgs) != len(c.Messages) {
				t.Fatalf("parsed %d messages, want %d", len(msgs), len(c.Messages))
			}
			got, ok := kvRenderChatTemplate(f.Model, msgs)
			if !ok || got != c.RenderedExact {
				t.Fatalf("body→messages→render mismatch for %s:\n got:  %q\n want: %q", name, got, c.RenderedExact)
			}
		})
	}
}

// TestChatTemplate_ContentPartsJoinWithNewline pins the engine's
// string-content-format part handling: multiple text parts in one message are
// joined with "\n" before rendering. A bare concatenation renders different
// bytes than the engine caches — live vLLM v0.28.0 answered one extra token
// (the joining "\n") on every endpoint for a two-part message, so any other
// separator silently mis-hashes strict chat traffic.
func TestChatTemplate_ContentPartsJoinWithNewline(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"Content-part probe: "},` +
		`{"type":"text","text":"two text segments, one prompt."}]}]}`
	msgs, ok := kvParseChatMessages(body)
	if !ok || len(msgs) != 1 {
		t.Fatalf("parse failed: ok=%v msgs=%d", ok, len(msgs))
	}
	want := "Content-part probe: \ntwo text segments, one prompt."
	if msgs[0].Content != want {
		t.Fatalf("content-part join mismatch:\n got:  %q\n want: %q", msgs[0].Content, want)
	}
	// Single-part content must stay byte-identical (no separator introduced).
	one := `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"solo"}]}]}`
	msgs, ok = kvParseChatMessages(one)
	if !ok || msgs[0].Content != "solo" {
		t.Fatalf("single-part content changed: %q", msgs[0].Content)
	}
}

// TestChatTemplate_UnknownModelNoTemplate asserts a non-Qwen model with no
// registered template returns ok=false (so the caller falls back instead of
// mis-hashing with a guessed template).
func TestChatTemplate_UnknownModelNoTemplate(t *testing.T) {
	if _, ok := kvRenderChatTemplate("meta-llama/Llama-3.1-8B-Instruct",
		[]kvChatMessage{{Role: "user", Content: "hi"}}); ok {
		t.Fatal("expected ok=false for unregistered non-Qwen model, got ok=true")
	}
}
