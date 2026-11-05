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

/*
 * ai_kv_chat_tools.go — tools-aware chat rendering for KV-exact (default off).
 *
 * A strict chat rule refuses requests that carry `tools` or `tool_choice`
 * (kvChatExcludedFeature returns "tools"): the gateway rendered role/content
 * only, while the engine hands the template the tool list and the assistant's
 * tool_calls, so the two prompts never matched. This file reproduces what
 * vLLM 0.30.0 hands the Qwen3 template for such requests, so the gateway's
 * hash chain equals the engine's.
 *
 * Scope is deliberately narrow and gated twice:
 *   - LOXILB_KV_TOOLS_EXACT must be set (resolved once at boot and logged
 *     either way, default off; with it off every function here is
 *     unreachable and the bridge is byte-identical to the previous release);
 *   - the rule's binding must name the one attested target: profile
 *     kvToolsExactProfileID with the pinned template digest, a vLLM engine
 *     contract, and a deployment manifest declaring engine version
 *     kvToolsExactEngineVersion. Every other profile keeps today's
 *     UNSUPPORTED refusal — nothing here was verified for them. The verdict
 *     (OPEN, or CLOSED with the failing leg) is logged once per profile at
 *     every registry publish.
 *
 * Preprocessing parity with vLLM v0.30.0 (file:line at the v0.30.0 tag):
 *   - tools: vllm/renderers/online_renderer.py:228-233 passes
 *     [tool.model_dump() for tool in request.tools] to the template.
 *     ChatCompletionToolsParam (vllm/entrypoints/openai/chat_completion/
 *     protocol.py:184-201) serializes {type, function, defer_loading} in
 *     declaration order and drops unknown keys and a None defer_loading;
 *     FunctionDefinition (vllm/entrypoints/generate/base/protocol.py:246-261)
 *     serializes {name, description, parameters, strict, defer_loading},
 *     keeps description/parameters as null when omitted, drops unknown keys
 *     and a None strict/defer_loading. The tool-level defer_loading is
 *     propagated into the function when the function's is None
 *     (protocol.py:189-193). `parameters` is dict[str, Any]: request order.
 *   - tool_choice: the request validator (vllm/entrypoints/openai/
 *     chat_completion/protocol.py:912-979, check_tool_usage) refuses an
 *     empty tools array, a tool_choice other than "none" without tools, a
 *     string other than auto/none/required, and a named choice that is not
 *     one of the tools. The render is independent of tool_choice: the
 *     engine runs without --exclude-tools-when-tool-choice-none, so "none"
 *     keeps the tools (online_renderer.py:228-231), and named/required only
 *     shape the structured output. Verified live with return_token_ids on
 *     /v1/chat/completions: auto, none, named and required rendered the same
 *     prompt ids as /tokenize.
 *   - messages: vllm/entrypoints/chat_utils.py:2004-2080
 *     (_parse_chat_message_content) builds {role, content} with content ""
 *     for null, text parts joined by "\n" (chat_utils.py:1838-1848); an
 *     assistant turn keeps tool_calls when present and not None, and copies
 *     a string `reasoning` to both reasoning and reasoning_content — the
 *     request's own `reasoning_content` key is NOT copied; a tool turn keeps
 *     tool_call_id. chat_utils.py:2081-2155 (_postprocess_messages) drops an
 *     empty tool_calls list and replaces each function.arguments string by
 *     json.loads of it: "" or None become {}, valid JSON that is not an
 *     object becomes {}, malformed JSON is coerced to {} with a warning.
 *   - The template filter `tojson` is transformers' override
 *     (utils/chat_template_utils.py:481-495): json.dumps with
 *     ensure_ascii=False, sort_keys=False and the default ", " / ": "
 *     separators; numbers print with Python's repr (1.0, 1e-05, 1000000.0).
 *   - /tokenize with messages+tools runs the same preprocess_chat
 *     (vllm/entrypoints/serve/tokenize/serving.py:70-92), which is why it is
 *     a valid oracle for the golden vectors.
 *
 * Where the engine coerces input the gateway cannot reproduce exactly
 * (malformed tool_call arguments, NaN/Infinity literals Python's json accepts,
 * integers past int64, non-string reasoning that a message-type union
 * silently drops), the gateway refuses the request (UNSUPPORTED, request
 * class) instead of guessing.
 */

package loxinet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/loxilb-io/loxilb/pkg/enginecontract"
	log "github.com/sirupsen/logrus"
)

// ---- feature flag ----

var (
	kvToolsExactOnce sync.Once
	kvToolsExactOn   bool
)

// kvResolveToolsExact reads LOXILB_KV_TOOLS_EXACT once and logs the resolved
// value once, whichever way it went, so the first log lines of a process say
// whether the tools-aware path exists. Anything but an explicit truthy value
// is off; garbage is off with a warning.
func kvResolveToolsExact() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("LOXILB_KV_TOOLS_EXACT")))
	switch v {
	case "1", "true", "yes", "on":
		log.Infof("kv-chat: tools-aware exact rendering ENABLED for the attested target (LOXILB_KV_TOOLS_EXACT=%q); the gate verdict is logged per profile publish", v)
		return true
	case "":
		log.Infof("kv-chat: tools-aware exact rendering disabled (LOXILB_KV_TOOLS_EXACT unset); tools/tool_choice stay UNSUPPORTED on strict rules")
		return false
	case "0", "false", "no", "off":
		log.Infof("kv-chat: tools-aware exact rendering disabled (LOXILB_KV_TOOLS_EXACT=%q); tools/tool_choice stay UNSUPPORTED on strict rules", v)
		return false
	}
	log.Warnf("kv-chat: invalid LOXILB_KV_TOOLS_EXACT=%q (want 0|1), keeping the default off", v)
	return false
}

// kvToolsExactEnabled reports the flag, resolved once.
func kvToolsExactEnabled() bool {
	kvToolsExactOnce.Do(func() { kvToolsExactOn = kvResolveToolsExact() })
	return kvToolsExactOn
}

// KvToolsExactInit resolves the flag at boot (before the profile registry is
// published, so the publish-time gate verdict sees the final value). It is
// idempotent: a later call never re-reads the environment.
func KvToolsExactInit() {
	kvToolsExactEnabled()
}

// kvToolsExactSetForTest pins the flag for a test and returns the restore
// function. The init-time resolution is marked done so the environment is
// never consulted mid-test.
func kvToolsExactSetForTest(on bool) func() {
	kvToolsExactOnce.Do(func() {})
	prev := kvToolsExactOn
	kvToolsExactOn = on
	return func() { kvToolsExactOn = prev }
}

// ---- attested target gate ----

// The one profile/engine combination the tools-aware render was verified
// against. The template digest is the identity the parity proof holds for;
// the engine version is checked through the profile's deployment manifest,
// the same trust root the attestor's identity probe compares /version to.
const (
	kvToolsExactProfileID     = "qwen3-32b-fp8-v1"
	kvToolsExactTemplateSha   = "a55ee1b1660128b7098723e0abcd92caa0788061051c62d51cbe87d9cf1974d8"
	kvToolsExactEngine        = "vllm"
	kvToolsExactEngineVersion = "0.30.0"
)

// kvToolsExactManifestLoad is the manifest reader (a seam for tests).
var kvToolsExactManifestLoad = kvAttestManifestLoad

// kvToolsExactVerdicts caches the manifest verdict per published profile
// generation (key "manifest\x00<profile>\x00<gen>") and the one-time log
// marker per (profile generation, engine contract) (key
// "contract\x00<profile>\x00<gen>\x00<contract>"): the manifest is a disk read
// and neither verdict can change without a registry reload, which mints a
// new generation.
var kvToolsExactVerdicts sync.Map

// kvToolsExactManifestVerdict is the manifest leg of the gate: the profile's
// deployment manifest must exist and declare the attested engine version.
// Cached per profile generation. The reason is "" when it passes.
func kvToolsExactManifestVerdict(e *kvProfileEntry) (bool, string) {
	key := "manifest\x00" + e.Profile.ProfileID + "\x00" + strconv.FormatUint(e.Gen, 10)
	if v, ok := kvToolsExactVerdicts.Load(key); ok {
		r := v.(string)
		return r == "", r
	}
	m, ok := kvToolsExactManifestLoad(e.Profile.ProfileID)
	reason := ""
	switch {
	case !ok || m == nil:
		reason = "no deployment manifest (manifests/" + e.Profile.ProfileID + ".yaml) beneath the profile root"
	case m.EngineVersion != kvToolsExactEngineVersion:
		reason = fmt.Sprintf("manifest engineVersion %q != attested %q", m.EngineVersion, kvToolsExactEngineVersion)
	}
	kvToolsExactVerdicts.Store(key, reason)
	return reason == "", reason
}

// kvToolsExactProfileVerdict is the profile side of the gate (everything but
// the rule binding): flag, profile id, template digest, manifest. The reason
// names the first failing leg; "" when the profile is the attested target.
func kvToolsExactProfileVerdict(e *kvProfileEntry) (bool, string) {
	if !kvToolsExactEnabled() {
		return false, "LOXILB_KV_TOOLS_EXACT is off"
	}
	if e == nil {
		return false, "no profile"
	}
	p := &e.Profile
	if p.ProfileID != kvToolsExactProfileID {
		return false, fmt.Sprintf("profile %q is not the attested target %q", p.ProfileID, kvToolsExactProfileID)
	}
	if p.TemplateSha256 != kvToolsExactTemplateSha {
		return false, fmt.Sprintf("template sha256 %.12s… != attested %.12s…", p.TemplateSha256, kvToolsExactTemplateSha)
	}
	return kvToolsExactManifestVerdict(e)
}

// kvToolsExactLogPublish logs the gate verdict once per profile for a freshly
// published registry generation: OPEN names the evidence the parity proof
// rests on, CLOSED names the first failing leg. The engine-contract leg is a
// property of each rule's binding, not of the profile, and is logged on first
// use per binding (kvToolsExactEligible).
func kvToolsExactLogPublish(gen *kvProfileGeneration) {
	if gen == nil {
		return
	}
	ids := make([]string, 0, len(gen.Profiles))
	for id := range gen.Profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := gen.Profiles[id]
		if open, reason := kvToolsExactProfileVerdict(e); open {
			log.Infof("kv-chat: tools-exact gate OPEN for profile %s gen %d (template sha256 %.12s…, manifest engineVersion %s); strict rules bound to it with a vllm engine contract render tools",
				id, gen.Gen, e.Profile.TemplateSha256, kvToolsExactEngineVersion)
		} else {
			log.Infof("kv-chat: tools-exact gate CLOSED for profile %s gen %d: %s; tools/tool_choice stay UNSUPPORTED", id, gen.Gen, reason)
		}
	}
}

// kvToolsExactEligible reports whether a strict rule's binding and resolved
// profile are the attested target and the flag is on. False keeps the
// request on the existing path, where "tools" is UNSUPPORTED.
func kvToolsExactEligible(b *KvExactBinding, e *kvProfileEntry) bool {
	if !kvToolsExactEnabled() || b == nil || e == nil {
		return false
	}
	if open, _ := kvToolsExactProfileVerdict(e); !open {
		return false
	}
	if b.Components.Profile.ID != e.Profile.ProfileID {
		return false
	}
	cp, ok := enginecontract.ProfileByID(b.Components.Contract.ID)
	if !ok || cp.Engine != kvToolsExactEngine {
		key := "contract\x00" + e.Profile.ProfileID + "\x00" + strconv.FormatUint(e.Gen, 10) + "\x00" + b.Components.Contract.ID
		if _, logged := kvToolsExactVerdicts.LoadOrStore(key, ""); !logged {
			log.Warnf("kv-chat: tools-exact gate CLOSED for rule %s (profile %s gen %d): engine contract %q is not a %s contract; tools/tool_choice stay UNSUPPORTED",
				b.RuleIdent, e.Profile.ProfileID, e.Gen, b.Components.Contract.ID, kvToolsExactEngine)
		}
		return false
	}
	return true
}

// kvChatToolsModeledKeys are the message keys the tools-aware parser gives
// the engine's meaning; kvChatTemplateFeatureOpts skips them. Every other key
// the template mentions keeps the textual refusal.
var kvChatToolsModeledKeys = map[string]bool{
	"tool_calls": true, "reasoning": true, "reasoning_content": true, "tool_call_id": true,
}

// ---- request model ----

// kvChatToolsRequest is the render context the engine builds for a
// tools-carrying chat request: messages in ConversationMessage shape and the
// model_dump'd tool list (nil when the request carries no tools).
type kvChatToolsRequest struct {
	Messages []any
	Tools    []any
}

// Refusal reasons (request class). Closed vocabulary.
const (
	kvToolsRefuseTools      = "tools"
	kvToolsRefuseToolChoice = "tool_choice"
	kvToolsRefuseToolCalls  = "tool_calls"
	kvToolsRefuseReasoning  = "reasoning"
	kvToolsRefuseToolCallID = "tool_call_id"
	kvToolsRefuseNumber     = "number_range"
	kvToolsRefuseUnparse    = "unparseable"
)

// kvChatToolsParse builds the engine's render context from a chat body.
// The second result is "" on success or the refusal reason.
func kvChatToolsParse(body string) (*kvChatToolsRequest, string) {
	top, msgs, ok := kvChatDecodeExact(body)
	if !ok || len(msgs) == 0 {
		return nil, kvToolsRefuseUnparse
	}
	tools, names, reason := kvChatToolsDicts(top["tools"])
	if reason != "" {
		return nil, reason
	}
	if reason := kvChatToolChoiceCheck(top["tool_choice"], tools != nil, names); reason != "" {
		return nil, reason
	}
	out := make([]any, 0, len(msgs))
	for _, m := range msgs {
		d, reason := kvChatToolsMessage(m)
		if reason != "" {
			return nil, reason
		}
		out = append(out, d)
	}
	return &kvChatToolsRequest{Messages: out, Tools: tools}, ""
}

// kvChatToolsDicts is [tool.model_dump() for tool in request.tools] with the
// pydantic validation that precedes it. nil tools (absent or null) is nil.
func kvChatToolsDicts(raw json.RawMessage) ([]any, map[string]bool, string) {
	if !kvJSONPresent(raw) {
		return nil, nil, ""
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, nil, kvToolsRefuseTools
	}
	if len(items) == 0 {
		// check_tool_usage: "`tools` must not be an empty array".
		return nil, nil, kvToolsRefuseTools
	}
	tools := make([]any, 0, len(items))
	names := make(map[string]bool, len(items))
	for _, it := range items {
		var t map[string]json.RawMessage
		if err := json.Unmarshal(it, &t); err != nil || t == nil {
			return nil, nil, kvToolsRefuseTools
		}
		// type: Literal["function"] = "function"
		if typ, present := t["type"]; present {
			s, ok := kvJSONString(typ)
			if !ok || s != "function" {
				return nil, nil, kvToolsRefuseTools
			}
		}
		var fn map[string]json.RawMessage
		if err := json.Unmarshal(t["function"], &fn); err != nil || fn == nil {
			return nil, nil, kvToolsRefuseTools
		}
		name, ok := kvJSONString(fn["name"])
		if !ok {
			return nil, nil, kvToolsRefuseTools
		}
		fd := kvJjNewDict()
		fd.set("name", name)
		// description: str | None = None — null when omitted, never dropped.
		if kvJSONPresent(fn["description"]) {
			s, ok := kvJSONString(fn["description"])
			if !ok {
				return nil, nil, kvToolsRefuseTools
			}
			fd.set("description", s)
		} else {
			fd.set("description", nil)
		}
		// parameters: dict[str, Any] | None = None — request key order kept.
		if kvJSONPresent(fn["parameters"]) {
			v, err := kvJjJSONValue(fn["parameters"])
			if err != nil {
				return nil, nil, kvToolsRefuseNumberOr(err)
			}
			if _, isDict := v.(*kvJjDict); !isDict {
				return nil, nil, kvToolsRefuseTools
			}
			fd.set("parameters", v)
		} else {
			fd.set("parameters", nil)
		}
		// strict / defer_loading: bool | None, emitted only when set.
		strict, ok := kvJSONOptBool(fn["strict"])
		if !ok {
			return nil, nil, kvToolsRefuseTools
		}
		if strict != nil {
			fd.set("strict", *strict)
		}
		fnDefer, ok := kvJSONOptBool(fn["defer_loading"])
		if !ok {
			return nil, nil, kvToolsRefuseTools
		}
		toolDefer, ok := kvJSONOptBool(t["defer_loading"])
		if !ok {
			return nil, nil, kvToolsRefuseTools
		}
		if toolDefer != nil && fnDefer == nil {
			// _propagate_defer_loading (protocol.py:189-193).
			fnDefer = toolDefer
		}
		if fnDefer != nil {
			fd.set("defer_loading", *fnDefer)
		}
		td := kvJjNewDict()
		td.set("type", "function")
		td.set("function", fd)
		if toolDefer != nil {
			td.set("defer_loading", *toolDefer)
		}
		tools = append(tools, td)
		names[name] = true
	}
	return tools, names, ""
}

// kvChatToolChoiceCheck is check_tool_usage (protocol.py:912-979) for the
// fields that decide acceptance; nothing here changes the render.
func kvChatToolChoiceCheck(raw json.RawMessage, haveTools bool, names map[string]bool) string {
	if len(raw) == 0 || string(raw) == "null" {
		// Absent defaults to "auto" with tools; null skips validation.
		return ""
	}
	if s, ok := kvJSONString(raw); ok {
		if s == "none" {
			return ""
		}
		if !haveTools {
			return kvToolsRefuseToolChoice
		}
		if s == "auto" || s == "required" {
			return ""
		}
		return kvToolsRefuseToolChoice
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil || !haveTools {
		return kvToolsRefuseToolChoice
	}
	if typ, present := obj["type"]; present {
		if s, ok := kvJSONString(typ); !ok || s != "function" {
			return kvToolsRefuseToolChoice
		}
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(obj["function"], &fn); err != nil || fn == nil {
		return kvToolsRefuseToolChoice
	}
	name, ok := kvJSONString(fn["name"])
	if !ok || name == "" || !names[name] {
		return kvToolsRefuseToolChoice
	}
	return ""
}

// kvChatToolsMessage is _parse_chat_message_content + _postprocess_messages
// for one message, as the Qwen3 template reads it.
func kvChatToolsMessage(m map[string]json.RawMessage) (*kvJjDict, string) {
	role, ok := kvJSONString(m["role"])
	if !ok {
		return nil, kvToolsRefuseUnparse
	}
	content, ok := kvExtractMessageContent(m["content"])
	if !ok {
		return nil, kvToolsRefuseUnparse
	}
	d := kvJjNewDict()
	d.set("role", role)
	d.set("content", content)
	switch role {
	case "assistant":
		if raw, present := m["tool_calls"]; present && kvJSONPresent(raw) {
			calls, reason := kvChatToolCalls(raw)
			if reason != "" {
				return nil, reason
			}
			if calls != nil {
				d.set("tool_calls", calls)
			}
		}
		// `reasoning` (str | None) is copied to reasoning and
		// reasoning_content; the request's own reasoning_content is not read
		// by the engine's message parser (chat_utils.py:2037-2042).
		if raw := m["reasoning"]; kvJSONPresent(raw) {
			s, ok := kvJSONString(raw)
			if !ok {
				return nil, kvToolsRefuseReasoning
			}
			d.set("reasoning", s)
			d.set("reasoning_content", s)
		}
		if raw := m["reasoning_content"]; kvJSONPresent(raw) {
			if _, ok := kvJSONString(raw); !ok {
				return nil, kvToolsRefuseReasoning
			}
		}
	case "tool":
		s, ok := kvJSONString(m["tool_call_id"])
		if !ok {
			return nil, kvToolsRefuseToolCallID
		}
		d.set("tool_call_id", s)
	}
	return d, ""
}

// kvChatToolCalls validates and post-processes an assistant turn's
// tool_calls. nil with "" means the list was empty and the engine dropped
// the key (chat_utils.py:2093-2096).
func kvChatToolCalls(raw json.RawMessage) ([]any, string) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, kvToolsRefuseToolCalls
	}
	if len(items) == 0 {
		return nil, ""
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		var c map[string]json.RawMessage
		if err := json.Unmarshal(it, &c); err != nil || c == nil {
			return nil, kvToolsRefuseToolCalls
		}
		// ChatCompletionMessageFunctionToolCallParam: id, type and function
		// are Required; a missing one is a 400 (no render to match).
		id, ok := kvJSONString(c["id"])
		if !ok {
			return nil, kvToolsRefuseToolCalls
		}
		if typ, ok := kvJSONString(c["type"]); !ok || typ != "function" {
			return nil, kvToolsRefuseToolCalls
		}
		var fn map[string]json.RawMessage
		if err := json.Unmarshal(c["function"], &fn); err != nil || fn == nil {
			return nil, kvToolsRefuseToolCalls
		}
		name, ok := kvJSONString(fn["name"])
		if !ok {
			return nil, kvToolsRefuseToolCalls
		}
		// arguments: str (an object is a 400 — verified against the engine).
		argStr, ok := kvJSONString(fn["arguments"])
		if !ok {
			return nil, kvToolsRefuseToolCalls
		}
		args, reason := kvChatToolCallArguments(argStr)
		if reason != "" {
			return nil, reason
		}
		fd := kvJjNewDict()
		fd.set("name", name)
		fd.set("arguments", args)
		cd := kvJjNewDict()
		cd.set("id", id)
		cd.set("type", "function")
		cd.set("function", fd)
		out = append(out, cd)
	}
	return out, ""
}

// kvChatToolCallArguments is the arguments branch of _postprocess_messages
// (chat_utils.py:2115-2152): "" -> {}, a JSON object -> that object (request
// key order), valid JSON that is not an object -> {}. Malformed JSON is
// where the engine coerces to {} after a warning; the gateway refuses it
// instead, because Python's json accepts literals (NaN, Infinity) Go's does
// not, and the two would disagree on which inputs are malformed.
func kvChatToolCallArguments(s string) (*kvJjDict, string) {
	if s == "" {
		return kvJjNewDict(), ""
	}
	v, err := kvJjJSONValue([]byte(s))
	if err != nil {
		if errors.Is(err, errKvJSONNumberRange) {
			return nil, kvToolsRefuseNumber
		}
		return nil, kvToolsRefuseToolCalls
	}
	if d, ok := v.(*kvJjDict); ok {
		return d, ""
	}
	return kvJjNewDict(), ""
}

// ---- render ----

// kvRenderChatToolsReq renders a tools-aware request through the profile's
// pinned template with the context vLLM builds: messages in
// ConversationMessage shape, the model_dump'd tools (None when absent),
// documents None, and the profile's render policy. Error classes follow
// kvRenderChatTemplateReq.
func kvRenderChatToolsReq(e *kvProfileEntry, req *kvChatToolsRequest, clock func() time.Time) (string, error) {
	tpl, err := e.chatTemplate()
	if err != nil {
		return "", errKvNoChatRenderer
	}
	pol := e.Profile.RenderPolicy
	ctx := map[string]any{
		"messages":              req.Messages,
		"tools":                 nil,
		"documents":             nil,
		"add_generation_prompt": pol.AddGenerationPrompt,
	}
	if req.Tools != nil {
		ctx["tools"] = req.Tools
	}
	if pol.BosToken != "" {
		ctx["bos_token"] = pol.BosToken
	}
	if pol.EosToken != "" {
		ctx["eos_token"] = pol.EosToken
	}
	if pol.ClockPolicy == KvClockPolicyUTCDate {
		ctx["strftime_now"] = kvJjStrftimeNow(func() time.Time { return clock().UTC() })
	}
	out, err := tpl.Render(ctx)
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", errors.New("kv-chat: template rendered no text for these messages")
	}
	return out, nil
}

// ---- JSON helpers ----

// kvJSONString decodes a JSON string value; ok=false for anything else
// (including absent and null).
func kvJSONString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// kvJSONOptBool decodes an optional `bool | None` field: nil for absent or
// null, the value for a boolean, ok=false for any other type.
func kvJSONOptBool(raw json.RawMessage) (*bool, bool) {
	if !kvJSONPresent(raw) {
		return nil, true
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, false
	}
	return &b, true
}

// errKvJSONNumberRange marks a numeric literal the gateway cannot carry with
// Python's semantics (an integer past int64, or a float that overflows).
var errKvJSONNumberRange = errors.New("kv-chat: numeric literal outside the reproducible range")

func kvToolsRefuseNumberOr(err error) string {
	if errors.Is(err, errKvJSONNumberRange) {
		return kvToolsRefuseNumber
	}
	return kvToolsRefuseTools
}

// kvJjJSONValue decodes a JSON document into the template value model with
// Python's json.loads semantics: objects keep key order (a duplicate key
// keeps its first position and last value), integer literals are ints,
// literals with a fraction or exponent are floats. Trailing data is an error.
func kvJjJSONValue(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := kvJjJSONDecode(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("kv-chat: trailing data after JSON value")
	}
	return v, nil
}

func kvJjJSONDecode(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return kvJjJSONFromToken(dec, tok)
}

func kvJjJSONFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			d := kvJjNewDict()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("kv-chat: object key is not a string")
				}
				v, err := kvJjJSONDecode(dec)
				if err != nil {
					return nil, err
				}
				d.set(k, v)
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, err
			}
			return d, nil
		case '[':
			out := []any{}
			for dec.More() {
				v, err := kvJjJSONDecode(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return out, nil
		}
		return nil, fmt.Errorf("kv-chat: unexpected delimiter %q", t)
	case string:
		return t, nil
	case bool:
		return t, nil
	case nil:
		return nil, nil
	case json.Number:
		lit := t.String()
		if strings.ContainsAny(lit, ".eE") {
			f, err := strconv.ParseFloat(lit, 64)
			if err != nil {
				return nil, errKvJSONNumberRange
			}
			return f, nil
		}
		i, err := strconv.ParseInt(lit, 10, 64)
		if err != nil {
			return nil, errKvJSONNumberRange
		}
		return int(i), nil
	}
	return nil, fmt.Errorf("kv-chat: unexpected JSON token %T", tok)
}
