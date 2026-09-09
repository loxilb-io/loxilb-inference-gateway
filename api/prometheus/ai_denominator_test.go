/*
 * Copyright (c) 2025 LoxiLB Authors
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

package prometheus

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// TestRecordAIRequestDeniedIsADenominator states the contract the outcome label
// exists to provide: denials land under outcome="denied", completions under
// outcome="completed", the two never overlap, and summing them reproduces the
// unfiltered total a consumer uses as its denominator.
func TestRecordAIRequestDeniedIsADenominator(t *testing.T) {
	const tenant = "test-tenant-denominator"
	const model = "m-denominator"

	completed := func(status string) float64 {
		return getCounterValue(aiRequestsTotal, model, tenant, status, AIOutcomeCompleted)
	}
	denied := func(status string) float64 {
		return getCounterValue(aiRequestsTotal, model, tenant, status, AIOutcomeDenied)
	}

	before200, before429c, before429d := completed("200"), completed("429"), denied("429")

	RecordAIRequest(tenant, model, 200, 12)
	RecordAIRequestDenied(tenant, model, 429)

	if d := completed("200") - before200; d != 1.0 {
		t.Errorf("completed 200: want +1, got %f", d)
	}
	if d := denied("429") - before429d; d != 1.0 {
		t.Errorf("denied 429: want +1, got %f", d)
	}
	// The whole point of the label: a gate denial must not be readable as a
	// backend that answered 429 by itself.
	if d := completed("429") - before429c; d != 0.0 {
		t.Errorf("a denial leaked into outcome=completed: got %f", d)
	}

	total := (completed("200") - before200) +
		(completed("429") - before429c) +
		(denied("429") - before429d)
	if total != 2.0 {
		t.Errorf("sum by(outcome) must reproduce the total: want 2, got %f", total)
	}
}

// TestRecordAIRequestDeniedLeavesLatencyAlone pins the deliberate omission.
//
// aiRequestDurationSeconds measures SSE activation to stream completion. A
// denial has no such interval, and observing a gate-decision latency there
// would drag the served-latency quantiles toward zero exactly when denials
// spike -- an outage would look like a latency improvement.
func TestRecordAIRequestDeniedLeavesLatencyAlone(t *testing.T) {
	const tenant = "test-tenant-denial-latency"
	const model = "m-denial-latency"

	count := func() uint64 {
		m := &dto.Metric{}
		obs := aiRequestDurationSeconds.WithLabelValues(model, tenant)
		if err := obs.(interface{ Write(*dto.Metric) error }).Write(m); err != nil {
			t.Fatalf("reading histogram: %v", err)
		}
		return m.GetHistogram().GetSampleCount()
	}

	before := count()
	RecordAIRequestDenied(tenant, model, 503)
	RecordAIRequestDenied(tenant, model, 401)
	if got := count(); got != before {
		t.Errorf("denials must not be observed in the duration histogram: %d -> %d", before, got)
	}
}

// TestRecordAIRequestDeniedTenantIsEmptyNotAPlaceholder pins the documented
// label value for the arms that deny before a credential resolves. A consumer
// grouping by tenant has to be able to tell "denied before we knew who it was"
// from a tenant literally named "unknown".
func TestRecordAIRequestDeniedTenantIsEmptyNotAPlaceholder(t *testing.T) {
	const model = "m-anonymous-denial"

	before := getCounterValue(aiRequestsTotal, model, "", "401", AIOutcomeDenied)
	RecordAIRequestDenied("", model, 401)
	if d := getCounterValue(aiRequestsTotal, model, "", "401", AIOutcomeDenied) - before; d != 1.0 {
		t.Errorf("empty tenant must be recorded as the empty label value, got delta %f", d)
	}
}

// gateExports are the CGO exports through which the AI Gateway policy gate
// refuses a request. A non-zero return from any of them means the data plane
// writes the response itself and never dials a backend, so nothing downstream
// can count the request.
var gateExports = map[string]bool{
	"llb_ai_validate_key":        true,
	"llb_ai_ratelimit_check":     true,
	"llb_ai_token_quota_reserve": true,
}

// advisoryDecisionExports write a decision that never reaches a client, so
// counting one would inflate the total with a request nobody was refused.
//
// The value is the reason, and it is required rather than decorative: this is
// the map where a genuine denial could hide behind an assertion that it is not
// one, so the reason has to be re-checkable by whoever reads it next.
var advisoryDecisionExports = map[string]string{
	// Called at response completion to charge the tokens a served response
	// actually used, and every C call site passes result=NULL -- the branch
	// that writes a decision here is unreachable through them. Going over
	// quota while a response is in flight does not interrupt it; it latches
	// the quota, and the NEXT request is refused by llb_ai_ratelimit_check,
	// which is a gate export and does count. Counting here would count that
	// one request twice, once when it was served and once when a later one
	// was refused for it.
	"llb_ai_token_quota_consume": "charges a served response; C passes result=NULL and the latch denies the next request at the rate-limit gate",
}

// TestEveryGateDenialArmIsCounted derives the gate's deny arms from the source
// instead of listing them, and asserts each export that can produce one routes
// through recordGateDenial.
//
// It is here, in a package with no cgo, on purpose: pkg/loxinet cannot be test-
// built without the eBPF datapath archive, so a pin that lived there would run
// on the testbed and nowhere else. go/parser needs no build at all.
//
// The failure this catches is a silent one. A new deny arm that forgets to
// count leaves loxilb_ai_requests_total quietly short of a whole class of
// requests, and every ratio computed over it reads healthier than reality --
// with nothing red anywhere to say so.
func TestEveryGateDenialArmIsCounted(t *testing.T) {
	const src = "../../pkg/loxinet/ai_gateway_dp.go"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", src, err)
	}

	// Deny arms are found by their effect, not by name: writing a non-zero
	// value into result.decision is what makes the C gate refuse the request.
	denyArms := map[string]int{}
	recorders := map[string]bool{}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "decision" || i >= len(node.Rhs) {
						continue
					}
					if !isZeroDecision(node.Rhs[i]) {
						denyArms[name]++
					}
				}
			case *ast.CallExpr:
				if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "recordGateDenial" {
					recorders[name] = true
				}
			}
			return true
		})
	}

	for export := range gateExports {
		if !recorders[export] {
			t.Errorf("%s has %d deny arm(s) but never calls recordGateDenial: "+
				"requests it refuses will be missing from loxilb_ai_requests_total",
				export, denyArms[export])
		}
	}

	// Any OTHER function that writes a decision is an arm this test does not
	// know about. Fail rather than pass silently: these lists are the part most
	// likely to go stale, and the failure mode of a stale one is a denial class
	// missing from the total with nothing red to say so.
	for name, arms := range denyArms {
		if gateExports[name] || recorders[name] {
			continue
		}
		if reason, advisory := advisoryDecisionExports[name]; advisory {
			if reason == "" {
				t.Errorf("%s is listed as advisory with no reason -- state why "+
					"its decision never reaches a client", name)
			}
			continue
		}
		t.Errorf("%s writes %d non-zero decision(s) and is unclassified. Either "+
			"it can refuse a client, in which case add it to gateExports and "+
			"call recordGateDenial, or its decision never reaches one, in which "+
			"case add it to advisoryDecisionExports with the reason.", name, arms)
	}

	// A name in either list that no longer writes a decision is a pin held
	// against code that moved.
	for name := range gateExports {
		if denyArms[name] == 0 {
			t.Errorf("gateExports names %s, which writes no decision -- stale entry", name)
		}
	}
	for name := range advisoryDecisionExports {
		if denyArms[name] == 0 {
			t.Errorf("advisoryDecisionExports names %s, which writes no decision -- stale entry", name)
		}
	}
}

// isZeroDecision reports whether an expression assigned to result.decision is
// the allow verdict. Both the literal 0 and the named constant appear in the
// tree, and C.int(decision) -- a value only known at runtime -- is treated as
// potentially denying, which is the safe direction for this check.
func isZeroDecision(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.INT && v.Value == "0"
	case *ast.Ident:
		return v.Name == "aiDecisionAllow"
	}
	return false
}
