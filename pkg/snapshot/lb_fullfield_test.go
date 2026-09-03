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

// Tag-driven full-field load-balancer round-trip: the fixture below sets
// EVERY persisted JSON field of LbRuleMod (recursively -- LbServiceArg,
// endpoint/secondary-IP/VIP/source args), and a reflection walk FAILS the
// test if a persisted field is zero-valued in the fixture. Adding a field
// to the LB wire model therefore forces this fixture (and so the
// round-trip proof) to grow with it -- coverage cannot silently rot to
// "the three fields someone thought of in 2026".

package snapshot

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// lbFixtureSkipFields are persisted-tag fields deliberately zero/absent in
// the fixture: transient request flags and runtime state the digest
// normalizes away (they are not desired state, so a round-trip makes no
// promise about them).
var lbFixtureSkipFields = map[string]bool{
	"LbServiceArg.Oper":      true, // transient attach/detach opcode
	"LbEndPointArg.State":    true, // runtime health
	"LbEndPointArg.Counters": true, // runtime traffic counters
}

// fullFieldLbRule is the fixture: every persisted field non-zero.
func fullFieldLbRule() cmn.LbRuleMod {
	adminUp := true
	return cmn.LbRuleMod{
		Serv: cmn.LbServiceArg{
			ServIP:                      "20.20.20.1",
			PrivateIP:                   "10.10.10.1",
			ServPort:                    8080,
			ServPortMax:                 8090,
			Proto:                       "tcp",
			BlockNum:                    7,
			Sel:                         cmn.LbSelHash,
			Bgp:                         true,
			Monitor:                     true,
			Security:                    cmn.LBServHTTPS,
			Mode:                        cmn.LBModeOneArm,
			InactiveTimeout:             240,
			Managed:                     true,
			ProbeType:                   "http",
			ProbePort:                   9000,
			ProbeReq:                    "/healthz",
			ProbeResp:                   "ok",
			ProbeTimeout:                5,
			ProbeRetries:                3,
			Name:                        "full-field-rule",
			PersistTimeout:              300,
			Snat:                        true,
			HostUrl:                     "svc.example.test",
			PathPrefix:                  "/v1",
			PathMatchMode:               "prefix",
			ProxyProtocolV2:             true,
			Egress:                      true,
			Id:                          "3c1f9df2-2f2e-4c3e-9d9b-2b6f6d1a0001",
			AdminStateUp:                &adminUp,
			ProjectId:                   "proj-full-field",
			Annotations:                 map[string]string{"octaviaProtocol": "TCP", "team": "gw"},
			ConnectionLimit:             512,
			TraceType:                   "sse",
			BackendProtocol:             "https",
			SessionHeaderName:           "x-session-id",
			ModelName:                   "qwen3-06b",
			SSEMode:                     true,
			ApiKeyAuth:                  "required",
			MaxStreamDurationSec:        600,
			BackendKeepaliveIntervalSec: 15,
			PDDisaggMode:                true,
			PDCacheAwareMode:            true,
			PDSessionTTLSec:             120,
			PDCacheThreshold:            60,
			PDBalanceAbsThreshold:       4,
			CbEnable:                    true,
			KvExactMode:                 1,
			KvBlockSize:                 16,
			KvHashAlgo:                  "sha256",
			KvZmqPort:                   5570,
			KvWarmupSec:                 30,
			KvEngineType:                "vllm",
			PDBootstrapPort:             8998,
			KvDpRankCount:               2,
			KvExactApiMode:              "chat",
			KvModelProfile:              "prof-qwen",
			CHWBLPrefixHashLevel:        3,
			CHWBLPrefixHashFlags:        1,
			CHWBLMeanLoadFactor:         125,
			CHWBLReplication:            2,
			CHWBLEnableCacheSalt:        true,
			MTLSFrontend: &cmn.MTLSFrontendConfig{
				ClientCertMode:   "require",
				ClientCAPath:     "/etc/loxilb/certs/frontend-ca.pem",
				ClientCACertData: "-----BEGIN CERTIFICATE-----fixture-----END CERTIFICATE-----",
				RequireClientCN:  true,
				ClientCNPattern:  "*.example.test",
				ClientCRLPath:    "/etc/loxilb/certs/frontend.crl",
			},
			MTLSBackend: &cmn.MTLSBackendConfig{
				VerifyServerCert: true,
				BackendCAPath:    "/etc/loxilb/certs/backend-ca.pem",
				ClientCertPath:   "/etc/loxilb/certs/backend-client.pem",
				ClientKeyPath:    "/etc/loxilb/certs/backend-client.key",
				ClientCertData:   "-----BEGIN CERTIFICATE-----fixture-----END CERTIFICATE-----",
				ClientKeyData:    "-----BEGIN PRIVATE KEY-----fixture-----END PRIVATE KEY-----",
			},
			TimeoutMemberConnect:  7,
			TimeoutMemberData:     50,
			TimeoutTcpInspect:     11,
			VipQosPolicyId:        "qos-policy-1",
			AlpnProtocols:         []string{"h2", "http/1.1"},
			TlsCiphers:            "TLS_AES_256_GCM_SHA384",
			TlsVersions:           []string{"1.2", "1.3"},
			HstsMaxAge:            31536000,
			HstsIncludeSubdomains: true,
			HstsPreload:           true,
			BackendCaCertId:       "cert-backend-ca",
			BackendClientCertId:   "cert-backend-client",
		},
		SecIPs:  []cmn.LbSecIPArg{{SecIP: "20.20.20.2"}},
		SecVIPs: []cmn.LbSecVIPArg{{Address: "20.20.20.3", SubnetId: "subnet-1", PortId: "port-1", Proto: "tcp"}},
		SrcIPs:  []cmn.LbAllowedSrcIPArg{{Prefix: "10.0.0.0/8"}},
		Eps: []cmn.LbEndPointArg{{
			EpIP:           "10.10.10.2",
			EpPort:         9090,
			Weight:         50,
			EpRole:         1,
			NixlPort:       9191,
			Backup:         true,
			SubnetId:       "subnet-2",
			MonitorAddress: "10.10.10.3",
		}},
	}
}

// requireNoZeroPersistedFields walks v recursively and reports every
// persisted JSON field (tag not "-" and not skipped) that is zero-valued.
func requireNoZeroPersistedFields(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			t.Errorf("%s: nil pointer -- persisted field absent from the full-field fixture", path)
			return
		}
		requireNoZeroPersistedFields(t, v.Elem(), path)
	case reflect.Struct:
		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.SplitN(f.Tag.Get("json"), ",", 2)[0]
			if tag == "-" || !f.IsExported() {
				continue
			}
			key := typ.Name() + "." + f.Name
			if lbFixtureSkipFields[key] {
				continue
			}
			fv := v.Field(i)
			switch fv.Kind() {
			case reflect.Struct, reflect.Pointer:
				requireNoZeroPersistedFields(t, fv, path+"."+f.Name)
			case reflect.Slice, reflect.Map:
				if fv.Len() == 0 {
					t.Errorf("%s.%s: empty -- persisted field absent from the full-field fixture", path, f.Name)
					continue
				}
				for j := 0; j < fv.Len(); j++ {
					var ev reflect.Value
					if fv.Kind() == reflect.Map {
						ev = fv.MapIndex(fv.MapKeys()[j])
					} else {
						ev = fv.Index(j)
					}
					if ev.Kind() == reflect.Struct || ev.Kind() == reflect.Pointer {
						requireNoZeroPersistedFields(t, ev, fmt.Sprintf("%s.%s[%d]", path, f.Name, j))
					}
				}
			default:
				if fv.IsZero() {
					t.Errorf("%s.%s: zero-valued -- set it in the full-field fixture (or add %s to the skip list with a rationale)", path, f.Name, key)
				}
			}
		}
	}
}

// TestLbRuleFixtureCoversEveryPersistedField is the self-maintenance gate:
// it fails when the LB wire model grows a persisted field the fixture does
// not set.
func TestLbRuleFixtureCoversEveryPersistedField(t *testing.T) {
	rule := fullFieldLbRule()
	requireNoZeroPersistedFields(t, reflect.ValueOf(rule), "LbRuleMod")
}

// TestLbRuleFullFieldRoundTrip proves the full-field rule survives (a) the
// document codec byte-identically and (b) an apply -> re-Get cycle with an
// identical content digest -- so no persisted LB field is dropped by
// either the encoding or the registry plumbing.
func TestLbRuleFullFieldRoundTrip(t *testing.T) {
	rule := fullFieldLbRule()

	doc := NewDocument("0.9.8.6-beta", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainLoadBalancer}
	doc.Domains.LoadBalancer = []cmn.LbRuleMod{rule}

	// (a) codec: encode -> decode -> re-encode byte-identical.
	enc, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Decode(bytes.NewReader(enc))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	reEnc, err := Encode(back)
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(enc, reEnc) {
		t.Fatalf("full-field LB document not byte-stable across decode/encode")
	}
	if !reflect.DeepEqual(back.Domains.LoadBalancer[0], rule) {
		t.Fatalf("full-field LB rule changed across codec round-trip:\n got %+v\nwant %+v", back.Domains.LoadBalancer[0], rule)
	}

	// (b) registry: apply -> re-Get -> digest-identical.
	hooks := newMockHooks()
	if _, _, err := applyLoadBalancer(hooks, doc, false); err != nil {
		t.Fatalf("applyLoadBalancer: %v", err)
	}
	after := &Document{}
	if err := getLoadBalancer(hooks, after); err != nil {
		t.Fatalf("getLoadBalancer: %v", err)
	}
	wantDigest, err := DomainDigest(DomainLoadBalancer, &doc.Domains)
	if err != nil {
		t.Fatalf("DomainDigest(doc): %v", err)
	}
	gotDigest, err := DomainDigest(DomainLoadBalancer, &after.Domains)
	if err != nil {
		t.Fatalf("DomainDigest(live): %v", err)
	}
	if wantDigest != gotDigest {
		t.Fatalf("full-field LB rule content drifted across apply/get:\n got %+v\nwant %+v", after.Domains.LoadBalancer, doc.Domains.LoadBalancer)
	}
}
