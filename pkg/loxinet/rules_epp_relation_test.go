/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	"gopkg.in/yaml.v3"
)

// The machine-readable relation LB-EPP-PD-FAILOPEN in api/swagger.yml and
// eppArgsValidate must give the same verdict. API consumers read the
// relation to refuse a body before sending it, so a stale relation refuses
// what the server accepts (or the reverse).

const eppPDRelationID = "LB-EPP-PD-FAILOPEN"

type relPredicate struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Values   []any  `yaml:"values"`
}

type relRule struct {
	ID      string         `yaml:"id"`
	Kind    string         `yaml:"kind"`
	When    []relPredicate `yaml:"when"`
	Require []relPredicate `yaml:"require"`
}

func loadEppPDRelation(t *testing.T) relRule {
	t.Helper()
	raw, err := os.ReadFile("../../api/swagger.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Relations struct {
			Version int         `yaml:"version"`
			Rules   []yaml.Node `yaml:"rules"`
		} `yaml:"x-loxilb-contract-relations"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Relations.Version != 1 {
		t.Fatalf("relation version %d: this test evaluates version 1", doc.Relations.Version)
	}
	for i := range doc.Relations.Rules {
		var probe struct {
			ID string `yaml:"id"`
		}
		if err := doc.Relations.Rules[i].Decode(&probe); err != nil {
			t.Fatal(err)
		}
		if probe.ID != eppPDRelationID {
			continue
		}
		var r relRule
		if err := doc.Relations.Rules[i].Decode(&r); err != nil {
			t.Fatalf("%s does not have the requires-all shape: %v", eppPDRelationID, err)
		}
		if r.Kind != "requires-all" || len(r.When) < 2 || len(r.Require) == 0 {
			t.Fatalf("%s changed shape: %+v", eppPDRelationID, r)
		}
		return r
	}
	t.Fatalf("%s is missing from api/swagger.yml", eppPDRelationID)
	return relRule{}
}

// lookup resolves an RFC 6901 pointer of the form /a/b in a decoded body.
func lookup(body map[string]any, pointer string) (any, bool) {
	var cur any = body
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// holds evaluates one predicate with the version 1 semantics of
// api/contract-relations.md. None of this relation's predicates declares a
// `missing` substitution, so an absent value makes the predicate false.
func holds(t *testing.T, body map[string]any, p relPredicate) bool {
	t.Helper()
	v, ok := lookup(body, p.Field)
	if !ok {
		return false
	}
	switch p.Operator {
	case "nonempty-string":
		s, isStr := v.(string)
		return isStr && s != ""
	case "in":
		for _, want := range p.Values {
			if fmt.Sprintf("%T:%v", v, v) == fmt.Sprintf("%T:%v", want, want) {
				return true
			}
		}
		return false
	}
	t.Fatalf("operator %q is not evaluated by this test", p.Operator)
	return false
}

// relationAllows reports whether the relation accepts the body.
func relationAllows(t *testing.T, r relRule, body map[string]any) bool {
	for _, p := range r.When {
		if !holds(t, body, p) {
			return true // not applicable
		}
	}
	for _, p := range r.Require {
		if !holds(t, body, p) {
			return false
		}
	}
	return true
}

func TestEppPDRelationAgreesWithValidator(t *testing.T) {
	rel := loadEppPDRelation(t)
	const epp = "pd-disaggregation-epp.llm-d.svc:9002"
	for _, tc := range []struct {
		name   string
		serv   cmn.LbServiceArg
		accept bool
	}{
		{"pd off", cmn.LbServiceArg{EppEndpoint: epp}, true},
		{"pd on, FailOpen", cmn.LbServiceArg{EppEndpoint: epp, PDDisaggMode: true,
			EppFailureMode: cmn.EppFailureModeFailOpen}, true},
		{"pd on, FailClose", cmn.LbServiceArg{EppEndpoint: epp, PDDisaggMode: true,
			EppFailureMode: cmn.EppFailureModeFailClose}, false},
		{"pd on, failure mode omitted", cmn.LbServiceArg{EppEndpoint: epp, PDDisaggMode: true}, false},
		// Outside the relation: no EPP, so it does not apply and the
		// validator ignores the inert failure mode.
		{"no EPP, pd on, FailClose", cmn.LbServiceArg{PDDisaggMode: true,
			EppFailureMode: cmn.EppFailureModeFailClose}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serv := tc.serv
			serv.Mode = cmn.LBModeFullProxy
			raw, err := json.Marshal(struct {
				ServiceArguments cmn.LbServiceArg `json:"serviceArguments"`
			}{serv})
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}

			check := serv
			gotServer := eppArgsValidate(&check, cmn.LBModeFullProxy) == nil
			gotRelation := relationAllows(t, rel, body)
			if gotServer != tc.accept {
				t.Fatalf("eppArgsValidate accepted=%v, want %v", gotServer, tc.accept)
			}
			if gotRelation != gotServer {
				t.Fatalf("%s accepted=%v but eppArgsValidate accepted=%v for %s",
					eppPDRelationID, gotRelation, gotServer, raw)
			}
		})
	}
}
