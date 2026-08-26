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

package loxinet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func lcpProps(model, build string, slots int64, sleeping bool) *llamacppProps {
	return &llamacppProps{TotalSlots: slots, ModelPath: model, BuildInfo: build, IsSleeping: sleeping}
}

// TestLlamacppProbeEvaluate — the advisory rules: a homogeneous awake fleet
// warns nothing; every skew axis (model, build, slots), a sleeping EP and a
// never-answering EP each produce a kind-tagged warning naming the endpoint.
func TestLlamacppProbeEvaluate(t *testing.T) {
	// consistent fleet → no warnings
	if w := llamacppProbeEvaluate(map[string]*llamacppProps{
		"10.0.0.1:8085": lcpProps("/m/a.gguf", "b100-aaa", 4, false),
		"10.0.0.2:8085": lcpProps("/m/a.gguf", "b100-aaa", 4, false),
	}); len(w) != 0 {
		t.Fatalf("consistent fleet: want 0 warnings, got %v", w)
	}

	// every skew at once, plus a sleeper and a dark EP
	warns := llamacppProbeEvaluate(map[string]*llamacppProps{
		"10.0.0.1:8085": lcpProps("/m/a.gguf", "b100-aaa", 4, false),
		"10.0.0.2:8085": lcpProps("/m/b.gguf", "b101-bbb", 8, true),
		"10.0.0.3:8085": nil,
	})
	kinds := map[string]int{}
	for _, w := range warns {
		kinds[w.Kind]++
		if !strings.Contains(w.Text, "10.0.0.") {
			t.Errorf("warning must name the endpoint, got %q", w.Text)
		}
	}
	for _, want := range []string{"model_mismatch", "build_mismatch", "slots_mismatch", "sleeping", "unanswered"} {
		if kinds[want] != 1 {
			t.Errorf("want exactly one %s warning, got %d (all: %v)", want, kinds[want], kinds)
		}
	}
}

// TestLlamacppFetchProps — the probe decodes the live /props shape (fields
// pinned against a real fleet run) and errors on non-200 / bad JSON.
func TestLlamacppFetchProps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/props" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_slots":4,"model_path":"/m/a.gguf","build_info":"b100-aaa","is_sleeping":false,"chat_template":"ignored"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := srv.Client()

	props, err := llamacppFetchProps(ctx, client, srv.URL+"/props")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if props.TotalSlots != 4 || props.ModelPath != "/m/a.gguf" ||
		props.BuildInfo != "b100-aaa" || props.IsSleeping {
		t.Fatalf("decoded props mismatch: %+v", props)
	}

	if _, err := llamacppFetchProps(ctx, client, srv.URL+"/nope"); err == nil {
		t.Fatal("non-200: want error, got nil")
	}
}

// TestLlamacppPropsURL — URL derivation from the rule's EP fields.
func TestLlamacppPropsURL(t *testing.T) {
	if got := llamacppPropsURL("10.0.0.7", 8085); got != "http://10.0.0.7:8085/props" {
		t.Fatalf("url: got %q", got)
	}
}
