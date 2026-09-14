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

// A document written before sockmap acceleration existed carries no
// sockMapMode; live state always reports the canonical "off" for the same
// dataplane code 0. The two must digest identically, or boot VERIFY
// declares a content mismatch and quarantines an otherwise healthy
// document -- an upgrade that silently discards the operator's config.

package snapshot

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// lbRuleWithSockMapMode builds the identical rule twice, differing only in
// how the sockmap-off state is spelled on the wire.
func lbRuleWithSockMapMode(mode string) *Domains {
	adminUp := true
	return &Domains{
		LoadBalancer: []cmn.LbRuleMod{{
			Serv: cmn.LbServiceArg{
				ServIP:          "20.20.20.1",
				ServPort:        2020,
				Proto:           "tcp",
				Mode:            cmn.LBModeFullProxy,
				Name:            "up-l4",
				InactiveTimeout: 240,
				Id:              "336e62f4-ae66-4b50-8391-92b318a2bad4",
				AdminStateUp:    &adminUp,
				SockMapMode:     mode,
			},
			Eps: []cmn.LbEndPointArg{{
				EpIP:     "31.31.31.1",
				EpPort:   80,
				Weight:   1,
				State:    "active",
				Counters: "0:0",
			}},
		}},
	}
}

// TestSockMapModeDigestStableAcrossDocumentAge is the red twin for the
// persist-upgrade UP-01 failure: an absent sockMapMode (pre-sockmap
// document) and an explicit "off" (live read-back) describe the same
// desired state and must produce the same verify digest.
func TestSockMapModeDigestStableAcrossDocumentAge(t *testing.T) {
	// The document as a pre-sockmap gateway persisted it: the field did
	// not exist, so it unmarshals to the empty string.
	docDigest, err := DomainDigest(DomainLoadBalancer, lbRuleWithSockMapMode(""))
	if err != nil {
		t.Fatalf("digest of the pre-sockmap document: %v", err)
	}

	// The same rule read back from live state after apply: code 0 renders
	// as the canonical "off".
	liveDigest, err := DomainDigest(DomainLoadBalancer, lbRuleWithSockMapMode(cmn.SockMapModeOff))
	if err != nil {
		t.Fatalf("digest of the live read-back: %v", err)
	}

	if docDigest != liveDigest {
		t.Fatalf("sockMapMode spelling flips the verify digest by document age:\n"+
			"  pre-sockmap document (field absent) digests to %s\n"+
			"  live read-back (\"off\")             digests to %s\n"+
			"boot VERIFY would reject and quarantine the document",
			docDigest, liveDigest)
	}
}

// TestSockMapModeDigestStillSeparatesRealModes guards the fix from
// becoming a blanket erasure: canonicalizing the off spelling must not
// make a genuinely different acceleration mode digest the same.
func TestSockMapModeDigestStillSeparatesRealModes(t *testing.T) {
	offDigest, err := DomainDigest(DomainLoadBalancer, lbRuleWithSockMapMode(cmn.SockMapModeOff))
	if err != nil {
		t.Fatalf("digest off: %v", err)
	}
	for _, mode := range []string{cmn.SockMapModeBoth, cmn.SockMapModeRequest, cmn.SockMapModeResponse} {
		d, err := DomainDigest(DomainLoadBalancer, lbRuleWithSockMapMode(mode))
		if err != nil {
			t.Fatalf("digest %s: %v", mode, err)
		}
		if d == offDigest {
			t.Fatalf("sockMapMode %q digests identically to off: verify can no longer see the difference", mode)
		}
	}
}
