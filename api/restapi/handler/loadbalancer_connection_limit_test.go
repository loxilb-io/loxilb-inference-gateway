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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// The connectionLimit round trip: what a client declares on POST reaches the
// rule layer, PATCH overlays it only when the key is present, GET reports the
// stored value, and null is refused before any rule hook runs. The typed model
// and the raw body are both built from the same JSON, the way the generated
// binding and the presence middleware see one request.

func connectionLimitCreateParams(t *testing.T, raw string) operations.PostConfigLoadbalancerParams {
	t.Helper()
	var attr models.LoadbalanceEntry
	if err := json.Unmarshal([]byte(raw), &attr); err != nil {
		t.Fatalf("body: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "/config/loadbalancer", nil)
	req = req.WithContext(WithRawLoadbalancerBody(req.Context(), []byte(raw)))
	return operations.PostConfigLoadbalancerParams{HTTPRequest: req, Attr: &attr}
}

func connectionLimitPatchParams(t *testing.T, raw string) operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams {
	t.Helper()
	var attr models.LoadbalanceEntry
	if err := json.Unmarshal([]byte(raw), &attr); err != nil {
		t.Fatalf("body: %v", err)
	}
	if attr.ServiceArguments == nil {
		attr.ServiceArguments = &models.LoadbalanceEntryServiceArguments{}
	}
	req, _ := http.NewRequest(http.MethodPatch,
		"/config/loadbalancer/externalipaddress/20.20.20.5/port/8080/protocol/tcp", nil)
	req = req.WithContext(WithRawLoadbalancerBody(req.Context(), []byte(raw)))
	return operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams{
		HTTPRequest: req,
		IPAddress:   "20.20.20.5",
		Port:        8080,
		Proto:       "tcp",
		Attr:        &attr,
	}
}

const connectionLimitCreateBody = `{"serviceArguments":{"externalIP":"20.20.20.5","port":8080,"protocol":"tcp"%s},` +
	`"endpoints":[{"endpointIP":"127.0.0.1","targetPort":8081,"weight":1}]}`

func TestConnectionLimitCreateCopiesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	cases := []struct {
		name  string
		field string
		want  uint32
	}{
		{"declared", `,"connectionLimit":2`, 2},
		{"omitted is unlimited", ``, 0},
		{"explicit zero is unlimited", `,"connectionLimit":0`, 0},
		{"full width", `,"connectionLimit":4294967295`, 4294967295},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			raw := sprintfBody(connectionLimitCreateBody, c.field)
			ConfigPostLoadbalancer(connectionLimitCreateParams(t, raw), nil)
			if stub.captured == nil {
				t.Fatal("create handler never reached NetLbRuleAdd")
			}
			if got := stub.captured.Serv.ConnectionLimit; got != c.want {
				t.Fatalf("connectionLimit reached the rule layer as %d, want %d", got, c.want)
			}
		})
	}
}

func TestConnectionLimitCreateNullRejectedBeforeRuleHook(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	stub := &stubLbAddHook{}
	ApiHooks = stub

	raw := sprintfBody(connectionLimitCreateBody, `,"connectionLimit":null`)
	res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, raw), nil)
	if stub.captured != nil {
		t.Fatalf("null reached the rule layer as %d", stub.captured.Serv.ConnectionLimit)
	}
	if _, ok := res.(*ResultResponse); ok {
		t.Fatalf("null answered success: %T", res)
	}
}

func TestConnectionLimitReadBack(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.5"
	lb.Serv.ServPort = 8080
	lb.Serv.Proto = "tcp"

	lb.Serv.ConnectionLimit = 2
	if got := serializeLBRule(lb).ServiceArguments.ConnectionLimit; got != 2 {
		t.Fatalf("stored 2 read back as %d", got)
	}
	wire, err := json.Marshal(serializeLBRule(lb).ServiceArguments)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["connectionLimit"]; !ok || v.(float64) != 2 {
		t.Fatalf("wire connectionLimit = %v (present %v), want 2", v, ok)
	}

	lb.Serv.ConnectionLimit = 0
	wire, _ = json.Marshal(serializeLBRule(lb).ServiceArguments)
	m = map[string]any{}
	_ = json.Unmarshal(wire, &m)
	if _, ok := m["connectionLimit"]; ok {
		t.Fatal("unlimited must be absent on the wire")
	}
}

func TestConnectionLimitPatchOverlay(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	current := cmn.LbRuleMod{}
	current.Serv.ServIP = "20.20.20.5"
	current.Serv.ServPort = 8080
	current.Serv.Proto = "tcp"
	current.Serv.ConnectionLimit = 2

	cases := []struct {
		name string
		raw  string
		want uint32
	}{
		{"raised", `{"serviceArguments":{"connectionLimit":3}}`, 3},
		{"absent is preserved", `{"serviceArguments":{"name":"kept"}}`, 2},
		{"explicit zero clears", `{"serviceArguments":{"connectionLimit":0}}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
			ApiHooks = stub
			res := ConfigPatchLoadbalancer(connectionLimitPatchParams(t, c.raw), nil)
			if _, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoOK); !ok {
				t.Fatalf("response=%T, want PATCH 200", res)
			}
			if stub.captured == nil {
				t.Fatal("patch handler never reached NetLbRuleAdd")
			}
			if got := stub.captured.Serv.ConnectionLimit; got != c.want {
				t.Fatalf("merged connectionLimit = %d, want %d", got, c.want)
			}
		})
	}

	t.Run("null rejected before the rule hook", func(t *testing.T) {
		stub := &stubLbAddHook{rules: []cmn.LbRuleMod{current}}
		ApiHooks = stub
		res := ConfigPatchLoadbalancer(connectionLimitPatchParams(t, `{"serviceArguments":{"connectionLimit":null}}`), nil)
		if _, ok := res.(*operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoBadRequest); !ok {
			t.Fatalf("response=%T, want PATCH 400", res)
		}
		if stub.captured != nil {
			t.Fatal("null reached the rule layer")
		}
	})
}

func sprintfBody(format, field string) string {
	out := make([]byte, 0, len(format)+len(field))
	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) && format[i+1] == 's' {
			out = append(out, field...)
			i++
			continue
		}
		out = append(out, format[i])
	}
	return string(out)
}
