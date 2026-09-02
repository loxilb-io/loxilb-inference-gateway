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
 * ai_kv_chat_template.go — Gap-B1: chat-template parity for KV-exact.
 *
 * For /v1/chat/completions, vLLM caches the tokens of the CHAT-TEMPLATE-APPLIED
 * prompt, not the raw user-message text. loxilb previously hashed the raw
 * first-user-message content un-templated, so its KV-exact block hashes never
 * matched vLLM's inventory (the Rung-1 blocker). daulet/tokenizers has no
 * apply_chat_template, so loxilb renders the template itself, in Go, and then
 * feeds the rendered string through the SAME Encode path completions uses
 * (WithEncodeSpecialTokens, add_special_tokens=false).
 *
 * This is correct because — confirmed live on Qwen/Qwen2.5-7B-Instruct
 * (cicd/common/kv_hash/fixtures/kv_chat_template_parity.json) —
 *   Encode(apply_chat_template(msgs, tokenize=False)) == apply_chat_template(msgs, tokenize=True)
 * for every case, so one tokenizer path serves both chat and completions.
 *
 * v1 hardcodes the Qwen2.5/ChatML template keyed by model slug, with a registry
 * seam for future models (one-model-per-rule production target; the full Qwen2.5
 * Jinja template additionally handles tool-calls — deferred, out of v1 scope).
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

// kvChatTemplateFn renders an ordered message list into the model's
// chat-template-applied prompt string (with the generation prompt appended,
// matching vLLM's add_generation_prompt=True).
type kvChatTemplateFn func(messages []kvChatMessage) string

// qwenDefaultSystem is the system message Qwen2.5-Instruct's chat template
// injects when the request supplies no system message. Verified verbatim
// against vLLM apply_chat_template (kv_chat_template_parity.json).
const qwenDefaultSystem = "You are Qwen, created by Alibaba Cloud. You are a helpful assistant."

// kvChatTemplateRegistry maps a model slug (modelName with "/" -> "__") to its
// chat-template renderer. v1 ships the Qwen2.5 family; add entries here as new
// models gain one-model-per-rule deployments.
var kvChatTemplateRegistry = map[string]kvChatTemplateFn{
	"Qwen__Qwen2.5-7B-Instruct": renderChatMLQwen,
}

// renderChatMLQwen renders the Qwen2.5 / ChatML template:
//
//	[<|im_start|>system\n{default or supplied system}<|im_end|>\n]
//	(<|im_start|>{role}\n{content}<|im_end|>\n)*
//	<|im_start|>assistant\n
//
// If the first message is role=system it is used verbatim and the default is NOT
// injected; otherwise the Qwen default system block is prepended. The trailing
// "<|im_start|>assistant\n" is the generation prompt (add_generation_prompt=True).
func renderChatMLQwen(messages []kvChatMessage) string {
	var b strings.Builder
	hasSystem := len(messages) > 0 && messages[0].Role == "system"
	if !hasSystem {
		b.WriteString("<|im_start|>system\n")
		b.WriteString(qwenDefaultSystem)
		b.WriteString("<|im_end|>\n")
	}
	for _, m := range messages {
		b.WriteString("<|im_start|>")
		b.WriteString(m.Role)
		b.WriteString("\n")
		b.WriteString(m.Content)
		b.WriteString("<|im_end|>\n")
	}
	b.WriteString("<|im_start|>assistant\n")
	return b.String()
}

// kvRenderChatTemplate renders the chat-template-applied prompt for modelName.
// Returns ok=false when no template is known for the model — the caller must NOT
// route such a request through KV-exact chat tokenization (it would silently
// mis-hash); it should fall back rather than guess a template.
//
// As a seam, any unrecognized "Qwen__*" slug falls back to the ChatML/Qwen
// renderer (the whole Qwen2.5 family shares this template).
func kvRenderChatTemplate(modelName string, messages []kvChatMessage) (string, bool) {
	slug := kvModelSlug(modelName)
	if fn, ok := kvChatTemplateRegistry[slug]; ok {
		return fn(messages), true
	}
	if strings.HasPrefix(slug, "Qwen__") {
		return renderChatMLQwen(messages), true
	}
	return "", false
}

// kvChatTemplateSupported reports whether a validated chat renderer exists
// for modelName. Deliberately a wrapper over kvRenderChatTemplate so this
// answer can never drift from the decision the serving path actually makes —
// admission refuses a declared chat surface exactly when the serving path
// would have to fall back untemplated.
func kvChatTemplateSupported(modelName string) bool {
	_, ok := kvRenderChatTemplate(modelName, nil)
	return ok
}

// kvParseChatMessages extracts the ordered role/content turns from a raw chat
// request body (the JSON loxilb's C side has in its receive buffer). Content may
// be a plain string or the OpenAI array form ([{type:"text",text:"..."}]); the
// text segments are concatenated. Returns ok=false on parse failure or no
// messages.
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
// OpenAI content-part array) into plain text.
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
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "text" {
				b.WriteString(p.Text)
			}
		}
		return b.String()
	}
	return ""
}

// kvTokenizeChatBody renders modelName's chat template over the messages in the
// raw chat request body, then tokenizes the rendered prompt through the shared
// Encode path (WithEncodeSpecialTokens) so the token_ids are byte-identical to
// vLLM's cached chat prompt. Returns nil if the body has no messages, no chat
// template is known, or tokenization fails.
func kvTokenizeChatBody(body, modelName string, maxTokens int) []uint32 {
	msgs, ok := kvParseChatMessages(body)
	if !ok || len(msgs) == 0 {
		return nil
	}
	rendered, ok := kvRenderChatTemplate(modelName, msgs)
	if !ok || rendered == "" {
		return nil
	}
	return kvTokenizeWithCache(rendered, modelName, maxTokens)
}
