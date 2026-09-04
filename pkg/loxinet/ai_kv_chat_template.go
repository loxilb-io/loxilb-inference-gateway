/*
 * Copyright (c) 2025 LoxiLB Authors
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

/*
 * ai_kv_chat_template.go — chat-template parity for KV-exact.
 *
 * For /v1/chat/completions, engines cache the tokens of the
 * CHAT-TEMPLATE-APPLIED prompt, not the raw user-message text.
 * daulet/tokenizers has no apply_chat_template, so loxilb renders the
 * template itself and feeds the rendered string through the SAME Encode path
 * completions uses (WithEncodeSpecialTokens, add_special_tokens=false).
 *
 * This is correct because — confirmed live on Qwen/Qwen2.5-7B-Instruct and
 * re-proven per model by the offline HF oracle
 * (cicd/common/kv_hash/fixtures/kv_chat_render_parity.json) —
 *   Encode(apply_chat_template(msgs, tokenize=False)) == apply_chat_template(msgs, tokenize=True)
 * for every case, so one tokenizer path serves both chat and completions.
 *
 * Rendering is profile-driven: the model resolves to a published
 * ModelPromptProfile whose digest-pinned template artifact is executed by the
 * in-process Jinja executor (ai_kv_jinja.go) over the request's messages.
 * There are deliberately NO per-model Go renderers and NO vendor-prefix
 * fallback: template dialects vary within a vendor line (Qwen3 renders
 * without Qwen2.5's default system prompt, for example), so a model without
 * a published profile must fall back, never inherit a relative's template.
 */

package loxinet

import (
	"encoding/json"
	"strings"
)

// kvChatMessage is one role/content turn extracted from a chat request body.
type kvChatMessage struct {
	Role    string
	Content string
}

// kvJinjaChatContext builds the render context the engine's own renderer
// receives: the message list, the generation-prompt knob, and the tokenizer's
// special-token strings (HF passes special_tokens_map into
// apply_chat_template; a template referencing a token the profile does not
// declare fails the render loudly instead of rendering different bytes).
func kvJinjaChatContext(messages []kvChatMessage, pol KvRenderPolicy) map[string]any {
	msgs := make([]any, 0, len(messages))
	for _, m := range messages {
		msgs = append(msgs, map[string]any{"role": m.Role, "content": m.Content})
	}
	ctx := map[string]any{
		"messages":              msgs,
		"add_generation_prompt": pol.AddGenerationPrompt,
	}
	if pol.BosToken != "" {
		ctx["bos_token"] = pol.BosToken
	}
	if pol.EosToken != "" {
		ctx["eos_token"] = pol.EosToken
	}
	return ctx
}

// kvRenderChatTemplate renders the chat-template-applied prompt for modelName
// through its published profile's pinned template artifact. Returns ok=false
// when no chat-declaring profile serves the exact model or the render fails —
// the caller must NOT route such a request through KV-exact chat tokenization
// (it would silently mis-hash); it should fall back rather than guess a
// template.
func kvRenderChatTemplate(modelName string, messages []kvChatMessage) (string, bool) {
	e, ok := kvProfileByModel(modelName)
	if !ok || !kvProfileDeclaresChat(&e.Profile) {
		return "", false
	}
	tpl, err := e.chatTemplate()
	if err != nil {
		return "", false
	}
	out, err := tpl.Render(kvJinjaChatContext(messages, e.Profile.RenderPolicy))
	if err != nil || out == "" {
		return "", false
	}
	return out, true
}

// kvProfileDeclaresChat reports whether a profile declares the chat surface.
func kvProfileDeclaresChat(p *ModelPromptProfile) bool {
	for _, a := range p.SupportedApis {
		if a == KvProfileAPIChat {
			return true
		}
	}
	return false
}

// kvChatTemplateSupported reports whether a validated chat renderer exists
// for modelName: a published profile serves the model, declares chat, and its
// pinned template artifact compiles. Admission consults this so a declared
// chat surface is refused at create time exactly when the serving path would
// have to fall back untemplated. It deliberately does NOT execute the
// template — support is a property of the published identity, and a render
// error on live traffic is a runtime fault the bridge already fences
// (kvBridgeTokenizeChat), never a reason to admit-then-degrade.
func kvChatTemplateSupported(modelName string) bool {
	e, ok := kvProfileByModel(modelName)
	if !ok || !kvProfileDeclaresChat(&e.Profile) {
		return false
	}
	_, err := e.chatTemplate()
	return err == nil
}

// kvParseChatMessages extracts the ordered role/content turns from a raw chat
// request body (the JSON loxilb's C side has in its receive buffer). Content may
// be a plain string or the OpenAI array form ([{type:"text",text:"..."}]); the
// text segments are joined with "\n" to match the engine's string-content-format
// part handling. Returns ok=false on parse failure or no messages.
func kvParseChatMessages(body string) ([]kvChatMessage, bool) {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return nil, false
	}
	if len(req.Messages) == 0 {
		return nil, false
	}
	out := make([]kvChatMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		out = append(out, kvChatMessage{Role: m.Role, Content: kvExtractMessageContent(m.Content)})
	}
	return out, true
}

// kvExtractMessageContent normalizes a chat message "content" field (string or
// OpenAI content-part array) into plain text. Multiple text parts are joined
// with "\n": string-content-format chat templates receive parts joined that
// way by the engine's request parser, so any other separator renders (and
// therefore tokenizes and hashes) different bytes than the engine caches.
func kvExtractMessageContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		texts := make([]string, 0, len(parts))
		for _, p := range parts {
			if p.Type == "text" {
				texts = append(texts, p.Text)
			}
		}
		return strings.Join(texts, "\n")
	}
	return ""
}

// kvChatExcludedFeature inspects a raw chat request body for the plan-§4
// excluded-feature vocabulary and returns the first feature found ("" =
// none). Consulted on STRICT bridge paths only (kvBridgeTokenizeChat):
// requests carrying these features hash differently engine-side than the
// gateway's plain-text render, so a strict rule refuses to score them
// (request-class UNSUPPORTED — never readiness-affecting, I-12) instead of
// routing a mis-hashed prefix. Legacy rules keep today's behavior untouched.
func kvChatExcludedFeature(body string) string {
	var req struct {
		Tools              json.RawMessage `json:"tools"`
		ToolChoice         json.RawMessage `json:"tool_choice"`
		CacheSalt          json.RawMessage `json:"cache_salt"`
		PromptEmbeds       json.RawMessage `json:"prompt_embeds"`
		ChatTemplateKwargs json.RawMessage `json:"chat_template_kwargs"`
		Messages           []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return ""
	}
	present := func(raw json.RawMessage) bool {
		return len(raw) > 0 && string(raw) != "null"
	}
	switch {
	case present(req.Tools) || present(req.ToolChoice):
		return "tools"
	case present(req.CacheSalt):
		return "cache_salt"
	case present(req.PromptEmbeds):
		return "prompt_embeds"
	case present(req.ChatTemplateKwargs):
		return "template_kwargs"
	}
	for _, m := range req.Messages {
		var parts []struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(m.Content, &parts); err == nil {
			for _, p := range parts {
				if p.Type != "" && p.Type != "text" {
					return "multimodal"
				}
			}
		}
	}
	return ""
}
