/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package handler

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

func TestPDThresholdLazyRawBodyBuffer(t *testing.T) {
	raw := &bytes.Buffer{}
	ctx := WithRawLoadbalancerBodyBuffer(t.Context(), raw)
	raw.WriteString(`{"serviceArguments":{"pd_cache_threshold":0}}`)
	got := rawLoadbalancerBodyFromContext(ctx)
	if !bytes.Equal(got, raw.Bytes()) {
		t.Fatalf("lazy raw body=%q, want %q", got, raw.Bytes())
	}
}

func TestPDThresholdRequestPresenceMapsDeclarations(t *testing.T) {
	cases := []struct {
		name                     string
		raw                      string
		cache, balance           int32
		wantCache, wantBalance   uint8
		wantCacheSet, wantBalSet bool
	}{
		{name: "omitted", raw: `{"serviceArguments":{}}`},
		{name: "legacy positive without raw", cache: 47, balance: 9, wantCache: 47, wantBalance: 9},
		{name: "explicit zero", raw: `{"serviceArguments":{"pd_cache_threshold":0,"pd_balance_abs_threshold":0}}`, wantCacheSet: true, wantBalSet: true},
		{name: "positive", raw: `{"serviceArguments":{"pd_cache_threshold":47,"pd_balance_abs_threshold":9}}`, cache: 47, balance: 9, wantCache: 47, wantBalance: 9, wantCacheSet: true, wantBalSet: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := newCreateParams("")
			params.Attr.ServiceArguments.PdCacheThreshold = tc.cache
			params.Attr.ServiceArguments.PdBalanceAbsThreshold = tc.balance
			params.HTTPRequest = params.HTTPRequest.WithContext(
				WithRawLoadbalancerBody(params.HTTPRequest.Context(), []byte(tc.raw)))

			prev := ApiHooks
			stub := &stubLbAddHook{}
			ApiHooks = stub
			defer func() { ApiHooks = prev }()

			ConfigPostLoadbalancer(params, nil)
			if stub.captured == nil {
				t.Fatal("POST did not reach NetLbRuleAdd")
			}
			got := stub.captured.Serv
			if got.PDCacheThreshold != tc.wantCache || got.PDBalanceAbsThreshold != tc.wantBalance {
				t.Fatalf("stored request=(%d,%d), want (%d,%d)", got.PDCacheThreshold, got.PDBalanceAbsThreshold, tc.wantCache, tc.wantBalance)
			}
			if got.PDCacheThresholdPresent != tc.wantCacheSet || got.PDBalanceAbsThresholdPresent != tc.wantBalSet {
				t.Fatalf("presence=(%v,%v), want (%v,%v)", got.PDCacheThresholdPresent, got.PDBalanceAbsThresholdPresent, tc.wantCacheSet, tc.wantBalSet)
			}
		})
	}
}

func TestPDThresholdNullRejectedBeforeRuleHook(t *testing.T) {
	for _, field := range []string{"pd_cache_threshold", "pd_balance_abs_threshold"} {
		t.Run(field, func(t *testing.T) {
			params := newCreateParams("")
			raw := []byte(`{"serviceArguments":{"` + field + `":null}}`)
			params.HTTPRequest = params.HTTPRequest.WithContext(
				WithRawLoadbalancerBody(params.HTTPRequest.Context(), raw))

			prev := ApiHooks
			stub := &stubLbAddHook{}
			ApiHooks = stub
			defer func() { ApiHooks = prev }()

			res := ConfigPostLoadbalancer(params, nil)
			errRes, ok := res.(*ErrorResponse)
			if !ok || errRes.Payload == nil || errRes.Payload.Code != http.StatusBadRequest {
				t.Fatalf("explicit null response=%T %#v, want HTTP 400", res, res)
			}
			if stub.captured != nil {
				t.Fatal("rejected null reached NetLbRuleAdd; stored/DP atomicity is broken")
			}
		})
	}
}

func TestPDThresholdPatchPresenceOverlaysCurrentDeclaration(t *testing.T) {
	cases := []struct {
		name                     string
		raw                      string
		cache, balance           int32
		wantCache, wantBalance   uint8
		wantCacheSet, wantBalSet bool
	}{
		{name: "omitted retains", raw: `{"serviceArguments":{"name":"rename-only"}}`, wantCache: 60, wantBalance: 7},
		{name: "zero resets", raw: `{"serviceArguments":{"pd_cache_threshold":0,"pd_balance_abs_threshold":0}}`, wantCacheSet: true, wantBalSet: true},
		{name: "positive replaces", raw: `{"serviceArguments":{"pd_cache_threshold":35,"pd_balance_abs_threshold":4}}`, cache: 35, balance: 4, wantCache: 35, wantBalance: 4, wantCacheSet: true, wantBalSet: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pres, err := parseLoadbalancerRequestPresence([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			params := newCreateParams("")
			params.Attr.ServiceArguments.PdCacheThreshold = tc.cache
			params.Attr.ServiceArguments.PdBalanceAbsThreshold = tc.balance
			got := params.Attr.ServiceArguments

			dst := cmn.LbServiceArg{PDCacheThreshold: 60, PDBalanceAbsThreshold: 7}
			pres.applyPDThresholds(&dst, got)
			if dst.PDCacheThreshold != tc.wantCache || dst.PDBalanceAbsThreshold != tc.wantBalance {
				t.Fatalf("overlay=(%d,%d), want (%d,%d)", dst.PDCacheThreshold, dst.PDBalanceAbsThreshold, tc.wantCache, tc.wantBalance)
			}
			if dst.PDCacheThresholdPresent != tc.wantCacheSet || dst.PDBalanceAbsThresholdPresent != tc.wantBalSet {
				t.Fatalf("presence=(%v,%v), want (%v,%v)", dst.PDCacheThresholdPresent, dst.PDBalanceAbsThresholdPresent, tc.wantCacheSet, tc.wantBalSet)
			}
		})
	}
}

func newPDThresholdPatchParams(raw string) operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams {
	req, _ := http.NewRequest(http.MethodPatch,
		"/config/loadbalancer/externalipaddress/20.20.20.5/port/8080/protocol/tcp", nil)
	req = req.WithContext(WithRawLoadbalancerBody(req.Context(), []byte(raw)))
	return operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams{
		HTTPRequest: req,
		IPAddress:   "20.20.20.5",
		Port:        8080,
		Proto:       "tcp",
		Attr: &models.LoadbalanceEntry{
			ServiceArguments: &models.LoadbalanceEntryServiceArguments{},
		},
	}
}

func TestPDThresholdPatchHandlerMapsExplicitZero(t *testing.T) {
	params := newPDThresholdPatchParams(
		`{"serviceArguments":{"pd_cache_threshold":0,"pd_balance_abs_threshold":0}}`)
	current := cmn.LbRuleMod{}
	current.Serv.ServIP = params.IPAddress
	current.Serv.ServPort = uint16(params.Port)
	current.Serv.Proto = params.Proto
	current.Serv.PDCacheThreshold = 60
	current.Serv.PDBalanceAbsThreshold = 7

	prev := ApiHooks
	stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
	ApiHooks = stub
	defer func() { ApiHooks = prev }()

	res := ConfigPatchLoadbalancer(params, nil)
	if _, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoOK); !ok {
		t.Fatalf("explicit zero response=%T, want PATCH 200", res)
	}
	if stub.captured == nil {
		t.Fatal("PATCH did not reach NetLbRuleAdd")
	}
	got := stub.captured.Serv
	if got.PDCacheThreshold != 0 || got.PDBalanceAbsThreshold != 0 ||
		!got.PDCacheThresholdPresent || !got.PDBalanceAbsThresholdPresent {
		t.Fatalf("PATCH zero declaration=(%d,%d,%v,%v), want (0,0,true,true)",
			got.PDCacheThreshold, got.PDBalanceAbsThreshold,
			got.PDCacheThresholdPresent, got.PDBalanceAbsThresholdPresent)
	}
}

func TestPDThresholdPatchNullRejectedBeforeRuleHook(t *testing.T) {
	for _, field := range []string{"pd_cache_threshold", "pd_balance_abs_threshold"} {
		t.Run(field, func(t *testing.T) {
			params := newPDThresholdPatchParams(
				`{"serviceArguments":{"` + field + `":null}}`)
			current := cmn.LbRuleMod{}
			current.Serv.ServIP = params.IPAddress
			current.Serv.ServPort = uint16(params.Port)
			current.Serv.Proto = params.Proto

			prev := ApiHooks
			stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
			ApiHooks = stub
			defer func() { ApiHooks = prev }()

			res := ConfigPatchLoadbalancer(params, nil)
			bad, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoBadRequest)
			if !ok {
				t.Fatalf("explicit null response=%T, want PATCH 400", res)
			}
			if bad.Payload == nil || bad.Payload.Code != http.StatusBadRequest ||
				bad.Payload.Message != field+" must not be null" {
				t.Fatalf("explicit null payload=%#v, want field-specific HTTP 400", bad.Payload)
			}
			if stub.captured != nil {
				t.Fatal("rejected PATCH null reached NetLbRuleAdd")
			}
		})
	}
}
