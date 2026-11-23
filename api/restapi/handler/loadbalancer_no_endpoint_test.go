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
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A rule with no endpoints: the REST layer hands an empty endpoint list and
// no_endpoint_status to the rule layer, which judges them, and reads such a
// rule back with "endpoints": [] and the status in force.

const noEndpointCreateBody = `{"serviceArguments":{"externalIP":"20.20.20.5","port":8080,"protocol":"tcp",` +
	`"mode":4,"host":"shop.example.com","path_prefix":"/down","path_match_mode":"prefix"%s},"endpoints":[]}`

func TestNoEndpointCreateReachesRuleLayer(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	for _, c := range []struct {
		name  string
		field string
		want  int
	}{
		{"omitted", ``, 0},
		{"503", `,"no_endpoint_status":503`, 503},
		{"500", `,"no_endpoint_status":500`, 500},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			res := ConfigPostLoadbalancer(connectionLimitCreateParams(t, sprintfBody(noEndpointCreateBody, c.field)), nil)
			if stub.captured == nil {
				t.Fatalf("an empty endpoint list never reached NetLbRuleAdd: %T", res)
			}
			if len(stub.captured.Eps) != 0 {
				t.Fatalf("endpoints reached the rule layer as %+v, want none", stub.captured.Eps)
			}
			if got := stub.captured.Serv.NoEndpointStatus; got != c.want {
				t.Fatalf("no_endpoint_status reached the rule layer as %d, want %d", got, c.want)
			}
		})
	}
}

func TestNoEndpointReadBack(t *testing.T) {
	lb := cmn.LbRuleMod{Serv: cmn.LbServiceArg{
		ServIP: "20.20.20.5", ServPort: 8080, Proto: "tcp", Mode: cmn.LBModeFullProxy,
		HostUrl: "shop.example.com", PathPrefix: "/down", NoEndpointStatus: 500,
	}}
	b, err := json.Marshal(serializeLBRule(lb))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"endpoints":[]`) {
		t.Fatalf("a rule with no endpoints reads back %s, want \"endpoints\":[]", b)
	}
	if !strings.Contains(string(b), `"no_endpoint_status":500`) {
		t.Fatalf("read back %s, want no_endpoint_status 500", b)
	}
	// The rule layer leaves the field unset on a rule that may not have no
	// endpoints; it is then absent.
	lb.Serv.NoEndpointStatus = 0
	b, _ = json.Marshal(serializeLBRule(lb))
	if strings.Contains(string(b), "no_endpoint_status") {
		t.Fatalf("an unset status reads back %s, want the field absent", b)
	}
}
