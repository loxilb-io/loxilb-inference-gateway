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

package opa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestApplyAllSuccess(t *testing.T) {
	var postCount, deleteCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			atomic.AddInt32(&postCount, 1)
			var mod cmn.FwRuleMod
			if err := json.NewDecoder(r.Body).Decode(&mod); err != nil {
				t.Errorf("failed to decode POST body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			atomic.AddInt32(&deleteCount, 1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	applier := NewRuleApplier(RuleApplierConfig{LoxiLBURL: srv.URL})

	ruleA := cmn.FwRuleArg{SrcIP: "10.0.0.1/32", DstIP: "10.0.0.2/32", Proto: 6, Pref: 100}
	ruleB := cmn.FwRuleArg{SrcIP: "10.0.0.3/32", DstIP: "10.0.0.4/32", Proto: 17, Pref: 200}
	ruleC := cmn.FwRuleArg{SrcIP: "10.0.0.5/32", DstIP: "10.0.0.6/32", Proto: 6, Pref: 300}

	diff := DiffResult{
		ToAdd: map[DiffKey]cmn.FwRuleArg{
			DiffKey("keyA"): ruleA,
			DiffKey("keyB"): ruleB,
		},
		OptsToAdd: map[DiffKey]cmn.FwOptArg{
			DiffKey("keyA"): {Drop: true},
			DiffKey("keyB"): {Allow: true},
		},
		ToDelete: map[DiffKey]cmn.FwRuleArg{
			DiffKey("keyC"): ruleC,
		},
		OptsToDelete: map[DiffKey]cmn.FwOptArg{
			DiffKey("keyC"): {Drop: true},
		},
	}

	result := applier.Apply(context.Background(), diff)

	if result.Added != 2 {
		t.Errorf("expected 2 added, got %d", result.Added)
	}
	if result.Deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", result.Deleted)
	}
	if result.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", result.Errors)
	}
	if atomic.LoadInt32(&postCount) != 2 {
		t.Errorf("expected 2 POST requests, got %d", atomic.LoadInt32(&postCount))
	}
	if atomic.LoadInt32(&deleteCount) != 1 {
		t.Errorf("expected 1 DELETE request, got %d", atomic.LoadInt32(&deleteCount))
	}
}

func TestApplyPartialFailure(t *testing.T) {
	var postCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n := atomic.AddInt32(&postCount, 1)
			// First POST succeeds, second fails
			if n == 1 {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	applier := NewRuleApplier(RuleApplierConfig{LoxiLBURL: srv.URL})

	diff := DiffResult{
		ToAdd: map[DiffKey]cmn.FwRuleArg{
			DiffKey("ok"):   {SrcIP: "10.0.0.1/32", DstIP: "10.0.0.2/32", Proto: 6, Pref: 100},
			DiffKey("fail"): {SrcIP: "10.0.0.3/32", DstIP: "10.0.0.4/32", Proto: 6, Pref: 200},
		},
		OptsToAdd: map[DiffKey]cmn.FwOptArg{
			DiffKey("ok"):   {Drop: true},
			DiffKey("fail"): {Drop: true},
		},
		ToDelete:     map[DiffKey]cmn.FwRuleArg{},
		OptsToDelete: map[DiffKey]cmn.FwOptArg{},
	}

	result := applier.Apply(context.Background(), diff)

	if result.Added != 1 {
		t.Errorf("expected 1 added, got %d", result.Added)
	}
	if result.Errors != 1 {
		t.Errorf("expected 1 error, got %d", result.Errors)
	}
}

func TestApplyContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	applier := NewRuleApplier(RuleApplierConfig{LoxiLBURL: srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	diff := DiffResult{
		ToAdd: map[DiffKey]cmn.FwRuleArg{
			DiffKey("a"): {SrcIP: "10.0.0.1/32", DstIP: "10.0.0.2/32", Proto: 6, Pref: 100},
			DiffKey("b"): {SrcIP: "10.0.0.3/32", DstIP: "10.0.0.4/32", Proto: 6, Pref: 200},
		},
		OptsToAdd: map[DiffKey]cmn.FwOptArg{
			DiffKey("a"): {Drop: true},
			DiffKey("b"): {Drop: true},
		},
		ToDelete:     map[DiffKey]cmn.FwRuleArg{},
		OptsToDelete: map[DiffKey]cmn.FwOptArg{},
	}

	result := applier.Apply(ctx, diff)

	// With a cancelled context, no rules should be applied successfully
	if result.Added != 0 {
		t.Errorf("expected 0 added with cancelled context, got %d", result.Added)
	}
}
