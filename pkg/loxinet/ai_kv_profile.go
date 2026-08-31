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
 * ai_kv_profile.go — ModelPromptProfile: the engine-neutral identity a
 * KV-exact rule binds a model to.
 *
 * A profile pins everything that decides which bytes a chat/completions
 * request tokenizes to: base-model identity, tokenizer artifact + digest,
 * chat-template artifact + digest, render policy, and the alias/feature
 * policy. It deliberately owns NO engine semantics: cache geometry, hash
 * algorithms, wire schemas, and event planes belong to the engine contract
 * (see ai_kv_binding.go — KvEngineContractRef), and profile parsing rejects
 * unknown fields so an engine-owned field in a profile document is a load
 * error, not a silent no-op.
 *
 * Profiles are loaded from disk by the registry (ai_kv_profile_registry.go)
 * and referenced by rules through KvExactBinding (ai_kv_binding.go).
 */

package loxinet

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// KvModelProfileRef references a ModelPromptProfile at a specific registry
// generation. Both fields are scalars by design: a binding references exactly
// one profile at exactly one generation.
type KvModelProfileRef struct {
	ID  string
	Gen uint64
}

// KvRenderPolicy captures the template-render knobs that alter the rendered
// prompt bytes. It mirrors the engine's apply-chat-template call shape.
type KvRenderPolicy struct {
	// AddGenerationPrompt appends the assistant generation prompt, matching
	// the engine's add_generation_prompt=true default for chat serving.
	AddGenerationPrompt bool `yaml:"addGenerationPrompt"`
}

// Alias policies. "any" is deliberately not a value: an unconstrained alias
// set would let a request's model string select a template identity the
// operator never declared.
const (
	KvAliasPolicyBaseModelOnly = "base_model_only"
	KvAliasPolicyList          = "list"
)

// Supported API surface values for ModelPromptProfile.SupportedApis.
const (
	KvProfileAPIChat        = "chat"
	KvProfileAPICompletions = "completions"
)

// kvProfileKnownFeatures is the closed feature vocabulary for
// supportedFeatures/excludedFeatures. Unknown feature names are load errors:
// a typo in an exclusion list must not silently widen what a rule accepts.
var kvProfileKnownFeatures = map[string]bool{
	"plain": true, "system": true, "multi_turn": true,
	"tools": true, "tool_calls": true, "multimodal": true,
	"cache_salt": true, "lora_adapter": true, "prompt_embeds": true,
	"thinking": true, "template_kwargs": true,
}

// ModelPromptProfile is the engine-neutral model/prompt identity document.
// One profile describes one base model + tokenizer + chat-template identity;
// rules bind to it via KvExactBinding. Engine-owned configuration (cache
// geometry, hash contracts, event schemas) has no fields here on purpose and
// is rejected at parse time via strict decoding.
type ModelPromptProfile struct {
	// ProfileID is the registry key. Single path-safe segment.
	ProfileID string `yaml:"profileId"`
	// BaseModel is the served base-model identity (e.g. "Qwen/Qwen3-32B").
	// Every alias bound under this profile must serve this model.
	BaseModel string `yaml:"baseModel"`
	// TokenizerRevision records the upstream tokenizer revision the artifact
	// was taken from (audit identity; the digest below is the enforcement).
	TokenizerRevision string `yaml:"tokenizerRevision,omitempty"`
	// TokenizerArtifact locates tokenizer.json relative to the registry
	// artifact root (see ai_kv_profile_registry.go for locator rules).
	TokenizerArtifact string `yaml:"tokenizerArtifact"`
	// TokenizerSha256 pins the tokenizer artifact bytes. The registry refuses
	// to publish a profile whose artifact bytes do not hash to this value.
	TokenizerSha256 string `yaml:"tokenizerSha256"`
	// TemplateArtifact optionally locates the chat-template artifact
	// (required when SupportedApis includes "chat").
	TemplateArtifact string `yaml:"templateArtifact,omitempty"`
	// TemplateSha256 pins the template artifact bytes.
	TemplateSha256 string `yaml:"templateSha256,omitempty"`
	// TemplateContentFormat declares the template's message content format
	// ("string" or "openai").
	TemplateContentFormat string `yaml:"templateContentFormat,omitempty"`
	// RenderPolicy holds render knobs that change the rendered bytes.
	RenderPolicy KvRenderPolicy `yaml:"renderPolicy,omitempty"`
	// RendererEngine/RendererVersion identify what renders the template on
	// the serving path; OracleEngine/OracleVersion identify the parity oracle
	// the rendered output is validated against.
	RendererEngine  string `yaml:"rendererEngine,omitempty"`
	RendererVersion string `yaml:"rendererVersion,omitempty"`
	OracleEngine    string `yaml:"oracleEngine,omitempty"`
	OracleVersion   string `yaml:"oracleVersion,omitempty"`
	// SupportedApis declares the request surfaces this profile serves
	// ("chat", "completions"). Non-empty.
	SupportedApis []string `yaml:"supportedApis"`
	// AliasPolicy is base_model_only (only the base model name routes) or
	// list (AllowedAliases route additionally). There is no "any".
	AliasPolicy string `yaml:"aliasPolicy"`
	// AllowedAliases lists additional served model names; valid only with
	// AliasPolicy=list.
	AllowedAliases []string `yaml:"allowedAliases,omitempty"`
	// SupportedFeatures/ExcludedFeatures form the request-feature matrix.
	// Values come from the closed vocabulary kvProfileKnownFeatures.
	SupportedFeatures []string `yaml:"supportedFeatures,omitempty"`
	ExcludedFeatures  []string `yaml:"excludedFeatures,omitempty"`
}

var kvSha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// kvProfileIDRe constrains profile IDs to one path-safe segment.
var kvProfileIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// KvParseModelPromptProfile strictly decodes one profile document. Unknown
// fields are errors: engine-owned configuration must live in the engine
// contract, and a misplaced field must fail loudly rather than be ignored.
func KvParseModelPromptProfile(doc []byte) (*ModelPromptProfile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	var p ModelPromptProfile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("kv-profile: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the schema-level constraints of one profile document
// (cross-profile constraints — duplicate IDs, alias collisions — are the
// registry's job at publish time).
func (p *ModelPromptProfile) Validate() error {
	if p.ProfileID == "" || !kvProfileIDRe.MatchString(p.ProfileID) {
		return fmt.Errorf("kv-profile: profileId %q must be a single path-safe segment", p.ProfileID)
	}
	if p.BaseModel == "" {
		return errors.New("kv-profile: baseModel is required")
	}
	if p.TokenizerArtifact == "" {
		return errors.New("kv-profile: tokenizerArtifact is required")
	}
	if err := kvValidateArtifactLocator(p.TokenizerArtifact); err != nil {
		return fmt.Errorf("kv-profile: tokenizerArtifact: %w", err)
	}
	if !kvSha256HexRe.MatchString(p.TokenizerSha256) {
		return errors.New("kv-profile: tokenizerSha256 must be 64 lowercase hex chars")
	}
	if err := kvCheckContentAddress(p.TokenizerArtifact, p.TokenizerSha256); err != nil {
		return fmt.Errorf("kv-profile: tokenizerArtifact: %w", err)
	}
	if p.TemplateArtifact != "" {
		if err := kvValidateArtifactLocator(p.TemplateArtifact); err != nil {
			return fmt.Errorf("kv-profile: templateArtifact: %w", err)
		}
		if !kvSha256HexRe.MatchString(p.TemplateSha256) {
			return errors.New("kv-profile: templateSha256 must be 64 lowercase hex chars when templateArtifact is set")
		}
		if err := kvCheckContentAddress(p.TemplateArtifact, p.TemplateSha256); err != nil {
			return fmt.Errorf("kv-profile: templateArtifact: %w", err)
		}
		switch p.TemplateContentFormat {
		case "string", "openai":
		default:
			return fmt.Errorf("kv-profile: templateContentFormat %q must be \"string\" or \"openai\"", p.TemplateContentFormat)
		}
	} else if p.TemplateSha256 != "" {
		return errors.New("kv-profile: templateSha256 without templateArtifact")
	}
	if len(p.SupportedApis) == 0 {
		return errors.New("kv-profile: supportedApis must be non-empty")
	}
	seenAPI := map[string]bool{}
	for _, a := range p.SupportedApis {
		if a != KvProfileAPIChat && a != KvProfileAPICompletions {
			return fmt.Errorf("kv-profile: unsupported api %q", a)
		}
		if seenAPI[a] {
			return fmt.Errorf("kv-profile: duplicate api %q", a)
		}
		seenAPI[a] = true
	}
	if seenAPI[KvProfileAPIChat] && p.TemplateArtifact == "" {
		return errors.New("kv-profile: chat api requires templateArtifact")
	}
	switch p.AliasPolicy {
	case KvAliasPolicyBaseModelOnly:
		if len(p.AllowedAliases) != 0 {
			return errors.New("kv-profile: allowedAliases requires aliasPolicy \"list\"")
		}
	case KvAliasPolicyList:
		if len(p.AllowedAliases) == 0 {
			return errors.New("kv-profile: aliasPolicy \"list\" requires non-empty allowedAliases")
		}
	default:
		// "any" in particular is refused: it would let request strings select
		// a template identity the operator never declared for this rule.
		return fmt.Errorf("kv-profile: aliasPolicy %q must be %q or %q",
			p.AliasPolicy, KvAliasPolicyBaseModelOnly, KvAliasPolicyList)
	}
	seenAlias := map[string]bool{}
	for _, al := range p.AllowedAliases {
		if al == "" {
			return errors.New("kv-profile: empty alias")
		}
		if seenAlias[al] {
			return fmt.Errorf("kv-profile: duplicate alias %q", al)
		}
		seenAlias[al] = true
	}
	for _, f := range append(append([]string{}, p.SupportedFeatures...), p.ExcludedFeatures...) {
		if !kvProfileKnownFeatures[f] {
			return fmt.Errorf("kv-profile: unknown feature %q", f)
		}
	}
	sup := map[string]bool{}
	for _, f := range p.SupportedFeatures {
		sup[f] = true
	}
	for _, f := range p.ExcludedFeatures {
		if sup[f] {
			return fmt.Errorf("kv-profile: feature %q both supported and excluded", f)
		}
	}
	return nil
}

// kvCheckContentAddress requires a content-addressed locator's path digest to
// equal the pinned digest — a sha256/<x> file pinned to digest y would make
// the address lie about the bytes it names.
func kvCheckContentAddress(loc, pinned string) error {
	if rest, ok := strings.CutPrefix(loc, "sha256/"); ok && rest != pinned {
		return fmt.Errorf("content address %s does not match pinned digest %s", rest, pinned)
	}
	return nil
}

// kvValidateArtifactLocator enforces the artifact locator shape: a relative
// path of single, path-safe segments under the registry artifact root, or a
// content address "sha256/<digest>". Absolute paths, URLs, "..", empty
// segments, and separator characters inside segments are rejected.
func kvValidateArtifactLocator(loc string) error {
	if loc == "" {
		return errors.New("empty locator")
	}
	if strings.HasPrefix(loc, "/") {
		return errors.New("absolute paths are rejected")
	}
	if strings.Contains(loc, "://") {
		return errors.New("URLs are rejected")
	}
	segs := strings.Split(loc, "/")
	if segs[0] == "sha256" {
		if len(segs) != 2 || !kvSha256HexRe.MatchString(segs[1]) {
			return errors.New("content address must be sha256/<64-hex-digest>")
		}
		return nil
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return fmt.Errorf("invalid path segment %q", s)
		}
		if strings.ContainsAny(s, "\\:") {
			return fmt.Errorf("invalid character in segment %q", s)
		}
	}
	return nil
}
