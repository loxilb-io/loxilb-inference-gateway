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
	"strings"
	"testing"
)

const kvTestSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const kvTestShaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// kvValidProfileDoc is a minimal valid completions-only profile document.
func kvValidProfileDoc() string {
	return `
profileId: acme-m1-v1
baseModel: acme/m1
tokenizerArtifact: acme__m1/tokenizer.json
tokenizerSha256: ` + kvTestSha + `
supportedApis: [completions]
aliasPolicy: base_model_only
`
}

func TestKvProfileParseValid(t *testing.T) {
	p, err := KvParseModelPromptProfile([]byte(kvValidProfileDoc()))
	if err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	if p.ProfileID != "acme-m1-v1" || p.BaseModel != "acme/m1" {
		t.Fatalf("parsed identity wrong: %+v", p)
	}
}

func TestKvProfileParseValidChat(t *testing.T) {
	doc := `
profileId: acme-m1-chat
baseModel: acme/m1
tokenizerArtifact: acme__m1/tokenizer.json
tokenizerSha256: ` + kvTestSha + `
templateArtifact: acme__m1/template.jinja
templateSha256: ` + kvTestShaB + `
templateContentFormat: string
renderPolicy:
  addGenerationPrompt: true
supportedApis: [chat, completions]
aliasPolicy: list
allowedAliases: [m1-prod, m1-canary]
supportedFeatures: [plain, system, multi_turn]
excludedFeatures: [tools, multimodal, cache_salt]
`
	p, err := KvParseModelPromptProfile([]byte(doc))
	if err != nil {
		t.Fatalf("valid chat profile rejected: %v", err)
	}
	if !p.RenderPolicy.AddGenerationPrompt {
		t.Fatal("renderPolicy.addGenerationPrompt not parsed")
	}
}

// TestKvProfileRejectsEngineOwnedFields is the schema firewall: engine
// contract content (hash contracts, cache geometry) must be a parse error in
// a profile document, never silently ignored.
func TestKvProfileRejectsEngineOwnedFields(t *testing.T) {
	for _, extra := range []string{
		"hashContract:\n  algorithm: sha256_cbor\n",
		"cacheGeometry:\n  blockSize: 16\n",
		"blockSize: 16\n",
		"kvEventSchema: vllm-zmq-v1\n",
	} {
		doc := kvValidProfileDoc() + extra
		if _, err := KvParseModelPromptProfile([]byte(doc)); err == nil {
			t.Errorf("engine-owned field accepted in profile: %q", strings.SplitN(extra, ":", 2)[0])
		}
	}
}

func TestKvProfileValidationMatrix(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(p *ModelPromptProfile)
		wantErr string
	}{
		{"empty profileId", func(p *ModelPromptProfile) { p.ProfileID = "" }, "profileId"},
		{"path separator in profileId", func(p *ModelPromptProfile) { p.ProfileID = "a/b" }, "profileId"},
		{"dotdot profileId", func(p *ModelPromptProfile) { p.ProfileID = ".." }, "profileId"},
		{"empty baseModel", func(p *ModelPromptProfile) { p.BaseModel = "" }, "baseModel"},
		{"absolute artifact", func(p *ModelPromptProfile) { p.TokenizerArtifact = "/etc/passwd" }, "absolute"},
		{"dotdot artifact", func(p *ModelPromptProfile) { p.TokenizerArtifact = "../outside/tokenizer.json" }, "segment"},
		{"url artifact", func(p *ModelPromptProfile) { p.TokenizerArtifact = "https://x/y" }, "URL"},
		{"empty segment artifact", func(p *ModelPromptProfile) { p.TokenizerArtifact = "a//b" }, "segment"},
		{"bad digest", func(p *ModelPromptProfile) { p.TokenizerSha256 = "abc" }, "tokenizerSha256"},
		{"uppercase digest", func(p *ModelPromptProfile) { p.TokenizerSha256 = strings.ToUpper(kvTestSha) }, "tokenizerSha256"},
		{"content address digest mismatch", func(p *ModelPromptProfile) {
			p.TokenizerArtifact = "sha256/" + kvTestShaB
		}, "content address"},
		{"bad content address", func(p *ModelPromptProfile) { p.TokenizerArtifact = "sha256/nothex" }, "content address"},
		{"template digest without artifact", func(p *ModelPromptProfile) { p.TemplateSha256 = kvTestSha }, "templateSha256 without"},
		{"no apis", func(p *ModelPromptProfile) { p.SupportedApis = nil }, "supportedApis"},
		{"unknown api", func(p *ModelPromptProfile) { p.SupportedApis = []string{"embeddings"} }, "unsupported api"},
		{"duplicate api", func(p *ModelPromptProfile) { p.SupportedApis = []string{"completions", "completions"} }, "duplicate api"},
		{"chat without template", func(p *ModelPromptProfile) { p.SupportedApis = []string{"chat"} }, "chat api requires"},
		{"chat without addGenerationPrompt", func(p *ModelPromptProfile) {
			p.SupportedApis = []string{"chat"}
			p.TemplateArtifact = "acme__m1/template.jinja"
			p.TemplateSha256 = kvTestShaB
			p.TemplateContentFormat = "string"
		}, "addGenerationPrompt"},
		{"alias policy any", func(p *ModelPromptProfile) { p.AliasPolicy = "any" }, "aliasPolicy"},
		{"alias policy empty", func(p *ModelPromptProfile) { p.AliasPolicy = "" }, "aliasPolicy"},
		{"aliases without list policy", func(p *ModelPromptProfile) { p.AllowedAliases = []string{"x"} }, "allowedAliases"},
		{"list policy without aliases", func(p *ModelPromptProfile) { p.AliasPolicy = KvAliasPolicyList }, "requires non-empty"},
		{"unknown feature", func(p *ModelPromptProfile) { p.SupportedFeatures = []string{"telepathy"} }, "unknown feature"},
		{"feature both lists", func(p *ModelPromptProfile) {
			p.SupportedFeatures = []string{"tools"}
			p.ExcludedFeatures = []string{"tools"}
		}, "both supported and excluded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := KvParseModelPromptProfile([]byte(kvValidProfileDoc()))
			if err != nil {
				t.Fatalf("base doc invalid: %v", err)
			}
			tc.mutate(p)
			err = p.Validate()
			if err == nil {
				t.Fatalf("mutation accepted, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestKvProfileContentAddressedLocatorValid(t *testing.T) {
	p, err := KvParseModelPromptProfile([]byte(kvValidProfileDoc()))
	if err != nil {
		t.Fatalf("base doc invalid: %v", err)
	}
	p.TokenizerArtifact = "sha256/" + kvTestSha
	if err := p.Validate(); err != nil {
		t.Fatalf("matching content-addressed locator rejected: %v", err)
	}
}
