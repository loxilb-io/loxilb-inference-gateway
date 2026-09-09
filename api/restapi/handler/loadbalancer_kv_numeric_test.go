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
	"net/http"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

func TestKVNumericArgumentsBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		args    models.LoadbalanceEntryServiceArguments
		wantErr string
	}{
		{name: "zero sentinels"},
		{name: "block minimum", args: models.LoadbalanceEntryServiceArguments{KvBlockSize: 1}},
		{name: "block maximum", args: models.LoadbalanceEntryServiceArguments{KvBlockSize: int64(cmn.KVBlockSizeMax)}},
		{name: "block over maximum", args: models.LoadbalanceEntryServiceArguments{KvBlockSize: int64(cmn.KVBlockSizeMax) + 1}, wantErr: "kvBlockSize"},
		{name: "block negative", args: models.LoadbalanceEntryServiceArguments{KvBlockSize: -1}, wantErr: "kvBlockSize"},
		{name: "port maximum single rank", args: models.LoadbalanceEntryServiceArguments{KvExactMode: 3, KvZmqPort: 65535, KvDpRankCount: 1}},
		{name: "port overflow before cast", args: models.LoadbalanceEntryServiceArguments{KvExactMode: 3, KvZmqPort: 65536}, wantErr: "kvZmqPort"},
		{name: "rank maximum", args: models.LoadbalanceEntryServiceArguments{KvExactMode: 3, KvZmqPort: 65528, KvDpRankCount: 8}},
		{name: "rank over maximum", args: models.LoadbalanceEntryServiceArguments{KvDpRankCount: 9}, wantErr: "kvDpRankCount"},
		{name: "rank port overflow by one", args: models.LoadbalanceEntryServiceArguments{KvExactMode: 3, KvZmqPort: 65529, KvDpRankCount: 8}, wantErr: "kvZmqPort + kvDpRankCount - 1"},
		{name: "bootstrap maximum", args: models.LoadbalanceEntryServiceArguments{PdBootstrapPort: 65535}},
		{name: "bootstrap overflow before cast", args: models.LoadbalanceEntryServiceArguments{PdBootstrapPort: 65536}, wantErr: "pdBootstrapPort"},
	}

	pres, err := parseLoadbalancerRequestPresence([]byte(`{"serviceArguments":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pres.validateKVNumericArguments(&tt.args)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected rejection: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error=%v, want rejection containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestKVNumericNullRejectedBeforeRuleHook(t *testing.T) {
	for _, field := range []string{"kvBlockSize", "kvZmqPort", "kvDpRankCount", "pdBootstrapPort"} {
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
			if !ok || errRes.Payload == nil || errRes.Payload.Code != http.StatusBadRequest ||
				errRes.Payload.Message != field+" must not be null" {
				t.Fatalf("response=%T %#v, want field-specific HTTP 400", res, res)
			}
			if stub.captured != nil {
				t.Fatal("rejected null reached NetLbRuleAdd")
			}
		})
	}
}

func TestKVNumericNarrowingRejectedBeforeRuleHook(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*models.LoadbalanceEntryServiceArguments)
		wantErr string
	}{
		{name: "block over data path maximum", mutate: func(a *models.LoadbalanceEntryServiceArguments) { a.KvBlockSize = int64(cmn.KVBlockSizeMax) + 1 }, wantErr: "kvBlockSize"},
		{name: "port over uint16", mutate: func(a *models.LoadbalanceEntryServiceArguments) { a.KvZmqPort = 65536 }, wantErr: "kvZmqPort"},
		{name: "rank over contract", mutate: func(a *models.LoadbalanceEntryServiceArguments) { a.KvDpRankCount = 9 }, wantErr: "kvDpRankCount"},
		{name: "bootstrap over uint16", mutate: func(a *models.LoadbalanceEntryServiceArguments) { a.PdBootstrapPort = 65536 }, wantErr: "pdBootstrapPort"},
		{name: "aggregate overflow", mutate: func(a *models.LoadbalanceEntryServiceArguments) {
			a.KvExactMode, a.KvZmqPort, a.KvDpRankCount = 3, 65529, 8
		}, wantErr: "kvZmqPort + kvDpRankCount - 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := newCreateParams("")
			tt.mutate(params.Attr.ServiceArguments)

			prev := ApiHooks
			stub := &stubLbAddHook{}
			ApiHooks = stub
			defer func() { ApiHooks = prev }()

			res := ConfigPostLoadbalancer(params, nil)
			errRes, ok := res.(*ErrorResponse)
			if !ok || errRes.Payload == nil || errRes.Payload.Code != http.StatusBadRequest ||
				!strings.Contains(errRes.Payload.Message, tt.wantErr) {
				t.Fatalf("response=%T %#v, want HTTP 400 containing %q", res, res, tt.wantErr)
			}
			if stub.captured != nil {
				t.Fatal("rejected narrowing/overflow reached NetLbRuleAdd")
			}
		})
	}
}

func TestKVNumericPatchIsRejectedInsteadOfIgnored(t *testing.T) {
	for _, field := range []string{"kvBlockSize", "kvZmqPort", "kvDpRankCount", "pdBootstrapPort"} {
		t.Run(field, func(t *testing.T) {
			params := newPDThresholdPatchParams(`{"serviceArguments":{"` + field + `":0}}`)
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
			if !ok || bad.Payload == nil || bad.Payload.Code != http.StatusBadRequest ||
				bad.Payload.Message != "PATCH does not support field: "+field {
				t.Fatalf("response=%T %#v, want unsupported-field HTTP 400", res, res)
			}
			if stub.captured != nil {
				t.Fatal("unsupported PATCH field reached NetLbRuleAdd")
			}
		})
	}
}
