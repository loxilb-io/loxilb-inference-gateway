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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	log "github.com/sirupsen/logrus"
)

// llama.cpp EP admission probe — the soft sibling of the TRT-LLM
// /server_info gate. Where the TRT-LLM gate must be HARD (a contract-
// mismatched endpoint would silently zero out Tier-1.5), a llamacpp rule has
// no routing correctness to protect: fleets are plain-LB converged, so the
// worst a skewed endpoint can do is degrade quality/latency uniformity.
// The probe therefore WARNS (log + counter), never refuses:
//   - model mismatch across the rule's EPs (answers differ per endpoint)
//   - build mismatch across the rule's EPs (rolling-release engine — a
//     mixed fleet silently drifts contracts)
//   - slot-count heterogeneity (uneven concurrency per EP behind one rule)
//   - a sleeping endpoint (its next request pays a full model reload;
//     fleet rail is to keep sleep mode off behind the VIP)

// llamacppProps mirrors the probe-relevant /props fields. /props is
// probe-safe: it neither wakes a sleeping server nor resets its idle timer.
type llamacppProps struct {
	TotalSlots int64  `json:"total_slots"`
	ModelPath  string `json:"model_path"`
	BuildInfo  string `json:"build_info"`
	IsSleeping bool   `json:"is_sleeping"`
}

const (
	// llamacppProbeFetchTimeout caps one /props request.
	llamacppProbeFetchTimeout = 5 * time.Second
	// llamacppProbeRetry paces re-probes of an unanswering endpoint (GGUF
	// load can hold /props behind the 503-loading window for minutes).
	llamacppProbeRetry = 30 * time.Second
	// llamacppProbeDeadline bounds the whole probe run — this is advisory
	// observability, not a gate, so it must never linger as a goroutine leak.
	llamacppProbeDeadline = 10 * time.Minute
)

// llamacppProbeEp is one endpoint to probe.
type llamacppProbeEp struct {
	IP   string
	Port uint16
}

// llamacppPropsURL derives the probe URL for one EP.
func llamacppPropsURL(ip string, port uint16) string {
	return fmt.Sprintf("http://%s:%d/props", ip, port)
}

// llamacppFetchProps performs one probe request.
func llamacppFetchProps(ctx context.Context, client *http.Client, url string) (*llamacppProps, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var props llamacppProps
	if err := json.Unmarshal(body, &props); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &props, nil
}

// llamacppProbeWarning is one advisory finding, kind-tagged for the counter.
type llamacppProbeWarning struct {
	Kind string // model_mismatch | build_mismatch | slots_mismatch | sleeping
	Text string
}

// llamacppProbeEvaluate applies the §advisory rules to the collected
// answers (keyed by "ip:port"; nil value = endpoint never answered inside
// the deadline — reported so a permanently dark EP is visible too).
//
// Pure function: unit-testable without a fixture (kvTrtllmAdmissionEvaluate
// precedent).
func llamacppProbeEvaluate(answers map[string]*llamacppProps) []llamacppProbeWarning {
	var warns []llamacppProbeWarning
	// deterministic order for stable logs/tests
	keys := make([]string, 0, len(answers))
	for k := range answers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var refKey string
	var ref *llamacppProps
	for _, k := range keys {
		p := answers[k]
		if p == nil {
			warns = append(warns, llamacppProbeWarning{Kind: "unanswered",
				Text: fmt.Sprintf("endpoint %s never answered /props inside the probe deadline", k)})
			continue
		}
		if p.IsSleeping {
			warns = append(warns, llamacppProbeWarning{Kind: "sleeping",
				Text: fmt.Sprintf("endpoint %s is sleeping — its next request pays a full model reload (keep --sleep-idle-seconds off behind a VIP)", k)})
		}
		if ref == nil {
			refKey, ref = k, p
			continue
		}
		if p.ModelPath != ref.ModelPath {
			warns = append(warns, llamacppProbeWarning{Kind: "model_mismatch",
				Text: fmt.Sprintf("endpoint %s serves model %q but %s serves %q — one rule, two models", k, p.ModelPath, refKey, ref.ModelPath)})
		}
		if p.BuildInfo != ref.BuildInfo {
			warns = append(warns, llamacppProbeWarning{Kind: "build_mismatch",
				Text: fmt.Sprintf("endpoint %s runs build %q but %s runs %q — rolling-release drift within one rule", k, p.BuildInfo, refKey, ref.BuildInfo)})
		}
		if p.TotalSlots != ref.TotalSlots {
			warns = append(warns, llamacppProbeWarning{Kind: "slots_mismatch",
				Text: fmt.Sprintf("endpoint %s has %d slots but %s has %d — uneven concurrency behind one rule", k, p.TotalSlots, refKey, ref.TotalSlots)})
		}
	}
	return warns
}

// LlamacppAdmissionProbe probes every EP of a llamacpp-typed rule once
// (retrying unanswering endpoints through the model-loading window), then
// logs + counts the advisory findings. Runs as a bounded goroutine from
// AddLbRule; a rule delete does not need to cancel it (it holds no rule
// state and expires by deadline).
func LlamacppAdmissionProbe(serviceID uint32, eps []llamacppProbeEp) {
	svc := fmt.Sprintf("%d", serviceID)
	prom.SetAiEngineInfo(svc, "llamacpp")

	ctx, cancel := context.WithTimeout(context.Background(), llamacppProbeDeadline)
	defer cancel()
	client := &http.Client{Timeout: llamacppProbeFetchTimeout}

	answers := make(map[string]*llamacppProps, len(eps))
	pending := make(map[string]llamacppProbeEp, len(eps))
	for _, ep := range eps {
		pending[fmt.Sprintf("%s:%d", ep.IP, ep.Port)] = ep
	}
	for len(pending) > 0 {
		for key, ep := range pending {
			props, err := llamacppFetchProps(ctx, client, llamacppPropsURL(ep.IP, ep.Port))
			if err == nil {
				answers[key] = props
				delete(pending, key)
			}
		}
		if len(pending) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			for key := range pending {
				answers[key] = nil
			}
			pending = nil
		case <-time.After(llamacppProbeRetry):
		}
	}

	warns := llamacppProbeEvaluate(answers)
	for _, w := range warns {
		log.Warnf("[LCP_PROBE] svc %s: %s", svc, w.Text)
		prom.IncLlamacppProbeWarning(svc, w.Kind)
	}
	if len(warns) == 0 {
		log.Infof("[LCP_PROBE] svc %s: %d endpoint(s) consistent (model/build/slots agree, none sleeping)", svc, len(answers))
	}
}
