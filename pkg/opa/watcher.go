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
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"

	promMetrics "github.com/loxilb-io/loxilb/api/prometheus"
)

const (
	defaultPollInterval = 30 * time.Second
	defaultInitialDelay = 10 * time.Second
	defaultOPAPolicy    = "loxilb/l4"
	defaultLoxiLBURL    = "http://localhost:11111"
	defaultStatePathW   = "/var/lib/loxilb/opa_l4_state.json"
)

// WatcherConfig holds all configuration for the OPA L4 policy watcher.
type WatcherConfig struct {
	// OPAURL is the base URL of the OPA server (required).
	OPAURL string
	// PolicyPath is the OPA policy path to query (default "loxilb/l4").
	PolicyPath string
	// PollInterval is how often to poll OPA for policy changes (default 30s).
	PollInterval time.Duration
	// InitialDelay is the delay before the first poll (default 10s).
	InitialDelay time.Duration
	// LoxiLBURL is the base URL of the LoxiLB REST API (default "http://localhost:11111").
	LoxiLBURL string
	// StatePath is the file path for persisting rule cache (default "/var/lib/loxilb/opa_l4_state.json").
	StatePath string
	// FailOpen if true allows traffic when OPA is unreachable; if false, existing rules are preserved.
	FailOpen bool
}

// WatcherStatus provides a snapshot of the watcher's current state.
type WatcherStatus struct {
	Config              WatcherConfig
	Running             bool
	LastSyncAt          time.Time
	RulesCount          int
	CircuitBreakerState CircuitBreakerState
	LastError           string
}

// Watcher orchestrates periodic OPA policy fetching, diffing, and rule application.
type Watcher struct {
	config     WatcherConfig
	fetcher    *PolicyFetcher
	cb         *CircuitBreaker
	cache      *RuleCache
	applier    *RuleApplier
	normalizer *RuleNormalizer
	differ     *StateDiffer
	cancel     context.CancelFunc
	status     WatcherStatus
	mu         sync.RWMutex
}

// NewWatcher creates a Watcher with sensible defaults applied to missing config fields.
func NewWatcher(config WatcherConfig) *Watcher {
	if config.PolicyPath == "" {
		config.PolicyPath = defaultOPAPolicy
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.InitialDelay == 0 {
		config.InitialDelay = defaultInitialDelay
	}
	if config.LoxiLBURL == "" {
		config.LoxiLBURL = defaultLoxiLBURL
	}
	if config.StatePath == "" {
		config.StatePath = defaultStatePathW
	}

	cb := NewCircuitBreaker()

	w := &Watcher{
		config:     config,
		fetcher:    NewPolicyFetcher(config.OPAURL, config.PolicyPath, cb),
		cb:         cb,
		cache:      NewRuleCache(config.StatePath),
		applier:    NewRuleApplier(RuleApplierConfig{LoxiLBURL: config.LoxiLBURL}),
		normalizer: NewRuleNormalizer(),
		differ:     NewStateDiffer(),
		status: WatcherStatus{
			Config: config,
		},
	}

	// Attempt to load persisted state
	if err := w.cache.Load(); err != nil {
		tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] failed to load state file: %v\n", err)
	}

	return w
}

// Start begins the polling loop in a background goroutine. It sleeps for
// InitialDelay before the first sync, then polls at PollInterval.
func (w *Watcher) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	w.mu.Lock()
	w.cancel = cancel
	w.status.Running = true
	w.mu.Unlock()

	tk.LogIt(tk.LogInfo, "[OPA-L4] watcher starting (poll=%v, delay=%v, opa=%s)\n",
		w.config.PollInterval, w.config.InitialDelay, w.config.OPAURL)

	go w.run(ctx)
}

// Stop cancels the polling context and marks the watcher as stopped.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	w.status.Running = false
	tk.LogIt(tk.LogInfo, "[OPA-L4] watcher stopped\n")
}

// GetStatus returns a snapshot of the current watcher status.
func (w *Watcher) GetStatus() WatcherStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s := w.status
	s.RulesCount = w.cache.Len()
	s.CircuitBreakerState = w.cb.State()
	return s
}

// run is the main loop executed in a goroutine.
func (w *Watcher) run(ctx context.Context) {
	// Initial delay
	select {
	case <-time.After(w.config.InitialDelay):
	case <-ctx.Done():
		return
	}

	// First sync immediately
	w.syncOnce(ctx)

	ticker := time.NewTicker(w.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.syncOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// syncOnce executes a single sync cycle: Fetch -> Normalize -> Diff -> Apply -> Update cache.
func (w *Watcher) syncOnce(ctx context.Context) {
	start := time.Now()
	// Observe the cycle duration on EVERY exit path — failure cycles were
	// previously invisible in the duration histogram (metrics audit).
	defer func() {
		promMetrics.ObserveOPASyncDuration(time.Since(start).Seconds())
	}()

	// Update circuit breaker metric
	promMetrics.SetOPACircuitBreakerState(float64(w.cb.State()))

	// Fetch policy from OPA (circuit breaker is checked inside Fetch)
	resp, err := w.fetcher.Fetch(ctx)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] fetch failed: %v\n", err)
		w.setLastError(err.Error())
		promMetrics.RecordOPASyncResult("failure")
		promMetrics.SetOPACircuitBreakerState(float64(w.cb.State()))
		return
	}

	// Normalize OPA response to LoxiLB rule format
	desiredRules, desiredOpts, err := w.normalizer.Normalize(resp)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] normalize failed: %v\n", err)
		w.cb.RecordFailure()
		w.setLastError(err.Error())
		promMetrics.RecordOPASyncResult("failure")
		return
	}

	// Diff current cache against desired state
	currentRules := w.cache.GetAllRules()
	currentOpts := w.cache.GetAllOpts()
	diffResult := w.differ.Diff(currentRules, desiredRules, currentOpts, desiredOpts)

	// Apply changes to LoxiLB
	applyResult := w.applier.Apply(ctx, diffResult)

	// Update cache for operations that actually SUCCEEDED (metrics audit):
	// a failed add stays out of the cache so the next diff retries it, and
	// the rules gauge reflects applied rules, not intent.
	for _, key := range applyResult.DeletedKeys {
		w.cache.Delete(key)
	}
	for _, key := range applyResult.AddedKeys {
		w.cache.Set(key, diffResult.ToAdd[key], diffResult.OptsToAdd[key])
	}

	// Persist cache to disk
	if err := w.cache.Save(); err != nil {
		tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] failed to save state: %v\n", err)
	}

	// Update metrics (duration is observed in the deferred block above)
	promMetrics.SetOPAFirewallRulesTotal(float64(w.cache.Len()))
	promMetrics.SetOPACircuitBreakerState(float64(w.cb.State()))

	if applyResult.Errors > 0 {
		promMetrics.RecordOPASyncResult("failure")
		w.setLastError("partial apply failure")
	} else {
		promMetrics.RecordOPASyncResult("success")
		w.setLastError("")
	}

	w.mu.Lock()
	w.status.LastSyncAt = time.Now()
	w.mu.Unlock()

	tk.LogIt(tk.LogInfo, "[OPA-L4] sync complete: added=%d deleted=%d errors=%d total=%d elapsed=%.3fs\n",
		applyResult.Added, applyResult.Deleted, applyResult.Errors, w.cache.Len(), time.Since(start).Seconds())
}

// setLastError updates the status last error message.
func (w *Watcher) setLastError(msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.LastError = msg
}
