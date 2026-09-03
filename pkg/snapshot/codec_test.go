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

package snapshot

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// sampleDocument builds a Document with at least one item in every domain
// (including the bgp/ipsec composites) so encode/decode round-trip tests
// exercise every field, not just the zero value.
func sampleDocument() *Document {
	doc := NewDocument("0.9.8.6-beta", "gw-test-host", TriggerManual)
	doc.Domains = Domains{
		Endpoint: []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1", ProbeType: "tcp"}},
		LoadBalancer: []cmn.LbRuleMod{{
			Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"},
			Eps:  []cmn.LbEndPointArg{{EpIP: "10.0.0.1", EpPort: 8080}},
		}},
		KvExactBinding: []cmn.KvExactBindingMod{{
			RuleIdent:         "rule-kv-1",
			ModelProfileID:    "prof-qwen",
			ModelProfileGen:   3,
			EngineContractID:  "ec-vllm",
			EngineContractGen: 2,
		}},
		L7Policy: []cmn.L7PolicyArg{{
			Id:   "l7pol-1",
			Name: "content-routes",
			LbId: "lb-opaque-1",
			Rules: []cmn.L7RuleArg{{
				Position: 1,
				MatchSets: []cmn.L7MatchSetArg{{
					Conditions: []cmn.L7ConditionArg{{Field: "PATH", Op: "STARTS_WITH", Value: "/v1/"}},
				}},
				Action: cmn.L7ActionArg{Kind: "FORWARD", Forward: &cmn.L7ForwardArg{
					PoolId:      1,
					BackendRefs: []cmn.L7BackendRefArg{{Ep: 1, Weight: 10}},
				}},
				InsertHeaders:      []cmn.L7HeaderFilterArg{{Op: "SET", Name: "X-Route", Value: "v1"}},
				SessionPersistence: "HTTP_COOKIE",
			}, {
				Position: 2,
				MatchSets: []cmn.L7MatchSetArg{{
					Conditions: []cmn.L7ConditionArg{{Field: "HEADER", Op: "EQUAL_TO", Key: "X-Env", Value: "prod", Invert: true}},
				}},
				Action: cmn.L7ActionArg{Kind: "REJECT", Reject: &cmn.L7RejectArg{StatusCode: 403}},
			}},
		}},
		Firewall:    []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "1.2.3.4/32", DstIP: "5.6.7.8/32"}}},
		Policy:      []cmn.PolMod{{Ident: "pol1"}},
		Mirror:      []cmn.MirrGetMod{{Ident: "mirr1"}},
		Session:     []cmn.SessionMod{{Ident: "sess1"}},
		SessionUlCl: []cmn.SessionUlClMod{{Ident: "sess1"}},
		IPFilter: []cmn.IPFilterEntry{{
			IPFilterMod: cmn.IPFilterMod{FilterType: "whitelist", CIDR: "10.0.0.0/8", Action: "allow"},
		}},
		SecurityRate: &cmn.SecurityRateState{Config: cmn.SecurityRateConfig{SYNEnabled: true, SYNThreshold: 100}},
		BFD:          []cmn.BFDMod{{Instance: "bfd1", Port: 3784}},
		BGP: BGPDomain{
			Neighbors:         []cmn.GoBGPNeighGetMod{{Addr: "10.0.0.2", RemoteAS: 65001}},
			DefinedSets:       []cmn.GoBGPPolicyDefinedSetMod{{Name: "set1", DefinedTypeString: "prefix"}},
			PolicyDefinitions: []cmn.GoBGPPolicyDefinitionsMod{{Name: "pd1"}},
		},
		IPsec: IPsecDomain{
			Config: &cmn.IPsecConfig{FastPathEnabled: true, MTU: 1400},
			Tunnels: []*cmn.IPsecTunnel{{
				IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2"},
			}},
		},
	}
	return doc
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	orig := sampleDocument()
	// Truncate to what JSON round-trips (encoding/json time.Time keeps
	// nanosecond + zone precision through RFC3339Nano, so UTC-normalize
	// only; no truncation needed as long as we compare via re-encoding).
	orig.CreatedAt = orig.CreatedAt.Truncate(time.Second)

	encoded, err := Encode(orig)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if orig.Checksum == "" {
		t.Fatalf("Encode did not set doc.Checksum as documented")
	}
	if !strings.HasPrefix(orig.Checksum, "sha256:") {
		t.Fatalf("checksum missing sha256: prefix: %q", orig.Checksum)
	}

	decoded, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if err := VerifyChecksum(decoded); err != nil {
		t.Fatalf("VerifyChecksum on round-tripped doc: %v", err)
	}

	// Re-encode the decoded doc and compare bytes for exact equality --
	// stronger than field-by-field reflect.DeepEqual and also proves
	// canonical JSON is stable across a decode/encode cycle.
	reEncoded, err := Encode(decoded)
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatalf("round-trip not byte-identical:\nfirst:  %s\nsecond: %s", encoded, reEncoded)
	}
}

func TestChecksumTamperDetection(t *testing.T) {
	doc := sampleDocument()
	encoded, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := VerifyChecksum(decoded); err != nil {
		t.Fatalf("expected valid checksum before tamper, got: %v", err)
	}

	// Tamper with a domain field after decode, without recomputing the
	// checksum (simulating e.g. a corrupted/edited file on disk).
	decoded.Domains.Endpoint[0].Name = "tampered"
	if err := VerifyChecksum(decoded); err == nil {
		t.Fatalf("expected VerifyChecksum to detect tampering, got nil error")
	}
}

func TestVerifyChecksumMissing(t *testing.T) {
	doc := sampleDocument()
	// Checksum deliberately left unset (never Encode()'d).
	if err := VerifyChecksum(doc); err == nil {
		t.Fatalf("expected error verifying a document with no checksum")
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	doc := sampleDocument()
	encoded, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var asMap map[string]interface{}
	if err := json.Unmarshal(encoded, &asMap); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	asMap["totally_unknown_field"] = "should be rejected"
	polluted, err := json.Marshal(asMap)
	if err != nil {
		t.Fatalf("marshal polluted map: %v", err)
	}

	if _, err := Decode(bytes.NewReader(polluted)); err == nil {
		t.Fatalf("expected Decode to reject an unknown top-level field, got nil error")
	}
}

func TestDecodeRejectsUnknownNestedFields(t *testing.T) {
	doc := sampleDocument()
	encoded, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var asMap map[string]interface{}
	if err := json.Unmarshal(encoded, &asMap); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	domains, ok := asMap["domains"].(map[string]interface{})
	if !ok {
		t.Fatalf("domains key missing or wrong shape")
	}
	domains["unexpected_new_domain"] = []interface{}{}
	polluted, err := json.Marshal(asMap)
	if err != nil {
		t.Fatalf("marshal polluted map: %v", err)
	}
	if _, err := Decode(bytes.NewReader(polluted)); err == nil {
		t.Fatalf("expected Decode to reject an unknown nested field under domains, got nil error")
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	doc := sampleDocument()
	encoded, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	trailing := append(append([]byte{}, encoded...), []byte(`{"another":"doc"}`)...)
	if _, err := Decode(bytes.NewReader(trailing)); err == nil {
		t.Fatalf("expected Decode to reject trailing data after the document")
	}
}

func TestParseSchemaVersion(t *testing.T) {
	tests := []struct {
		in        string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{"1.0", 1, 0, false},
		{"1.2", 1, 2, false},
		{"2.0.7", 2, 0, false}, // patch ignored
		{"1", 0, 0, true},
		{"", 0, 0, true},
		{"a.b", 0, 0, true},
	}
	for _, tt := range tests {
		major, minor, err := ParseSchemaVersion(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSchemaVersion(%q): expected error, got none", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSchemaVersion(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if major != tt.wantMajor || minor != tt.wantMinor {
			t.Errorf("ParseSchemaVersion(%q) = (%d,%d), want (%d,%d)", tt.in, major, minor, tt.wantMajor, tt.wantMinor)
		}
	}
}

// TestSchemaVersionGateMatrix exercises the full §4.2 compatibility gate:
// same major + minor <= current is accepted; a newer major or newer minor
// is refused; a different (older or newer) major is refused outright since
// the policy only ever names "same major" as acceptable.
func TestSchemaVersionGateMatrix(t *testing.T) {
	const current = "1.2" // hypothetical "gateway understands up to 1.2"

	tests := []struct {
		name    string
		doc     string
		wantErr bool
	}{
		{"same version", "1.2", false},
		{"older minor", "1.1", false},
		{"much older minor", "1.0", false},
		{"newer minor", "1.3", true},
		{"newer major", "2.0", true},
		{"newer major with lower minor", "2.0", true},
		{"older major", "0.9", true},
		{"malformed version", "not-a-version", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSchemaVersionAgainst(tt.doc, current)
			if tt.wantErr && err == nil {
				t.Errorf("checkSchemaVersionAgainst(%q, %q): expected error, got nil", tt.doc, current)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("checkSchemaVersionAgainst(%q, %q): unexpected error: %v", tt.doc, current, err)
			}
		})
	}
}

func TestCheckSchemaVersionUsesPackageCurrent(t *testing.T) {
	// CheckSchemaVersion must gate against the package-level SchemaVersion
	// constant (currently "1.0"), not an arbitrary value.
	if err := CheckSchemaVersion(SchemaVersion); err != nil {
		t.Fatalf("CheckSchemaVersion(SchemaVersion) should always succeed, got: %v", err)
	}
}

func TestComputeChecksumDoesNotMutateInput(t *testing.T) {
	doc := sampleDocument()
	doc.Checksum = "sha256:preexisting"
	if _, err := ComputeChecksum(doc); err != nil {
		t.Fatalf("ComputeChecksum: %v", err)
	}
	if doc.Checksum != "sha256:preexisting" {
		t.Fatalf("ComputeChecksum must not mutate its input; Checksum changed to %q", doc.Checksum)
	}
}

func TestComputeChecksumDeterministic(t *testing.T) {
	doc := sampleDocument()
	a, err := ComputeChecksum(doc)
	if err != nil {
		t.Fatalf("ComputeChecksum: %v", err)
	}
	b, err := ComputeChecksum(doc)
	if err != nil {
		t.Fatalf("ComputeChecksum: %v", err)
	}
	if a != b {
		t.Fatalf("ComputeChecksum not deterministic: %q != %q", a, b)
	}
}
