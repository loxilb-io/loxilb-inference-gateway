/*
 * Copyright (c) 2026 LoxiLB Authors
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
package snapshot

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// §7 observability: these join the existing loxilb_ namespace on the
// default registry, served by GET /metrics (promhttp).

var (
	snapshotTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loxilb_snapshot_total",
		Help: "Snapshot documents captured, partitioned by trigger (manual, write-through, pre-restore, scheduled, pre-upgrade).",
	}, []string{"trigger"})

	restoreTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loxilb_restore_total",
		Help: "Restore pipeline runs, partitioned by mode (dry-run, commit, boot) and result (ok, rolled-back, ROLLBACK-FAILED, rejected, error).",
	}, []string{"mode", "result"})

	restoreDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "loxilb_restore_duration_seconds",
		Help:    "Wall-clock duration of restore pipeline runs, all modes.",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 14), // 5ms .. ~40s
	})

	lastRestoreTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "loxilb_last_restore_timestamp_seconds",
		Help: "Unix time of the last successfully committed restore (commit or boot mode; dry-runs excluded).",
	})

	bootConfigConflict = promauto.NewCounter(prometheus.CounterOpts{
		Name: "loxilb_boot_config_conflict_total",
		Help: "Boots that found BOTH snapshot.json and legacy *.txt config artifacts and had to arbitrate newest-wins (§6.2).",
	})

	configDirty = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "loxilb_config_dirty",
		Help: "1 when the running config carries mutations not yet persisted to snapshot.json; 0 once a write-through has covered every recorded mutation. Tracks the mutating config REST surface (same eligibility as auto-persist), so a sustained 1 means recent config changes would not survive a restart.",
	})
)

// Dirty tracking is a pair of sequence numbers, not a boolean: a mutation
// that lands while a persist is already capturing must keep the config
// dirty even though that persist completes successfully afterwards.
// mutationSeq advances on every successful mutating config call;
// persistedSeq advances to the mutationSeq observed BEFORE a successful
// persist's capture started. dirty == (persistedSeq != mutationSeq).
var (
	dirtyMu      sync.Mutex
	mutationSeq  uint64
	persistedSeq uint64
)

// MarkConfigMutated records one successful mutating config API call whose
// effect is not yet known to be persisted. Called by the REST layer's
// auto-persist middleware on every 2xx eligible mutation — including when
// auto-persist is disabled, where the gauge staying 1 is exactly the
// operational signal (nothing will ever write the mutations through).
func MarkConfigMutated() {
	dirtyMu.Lock()
	defer dirtyMu.Unlock()
	mutationSeq++
	configDirty.Set(1)
}

// beginPersistSeq returns the mutation watermark a starting persist can
// claim on success. Read BEFORE the capture: a mutation racing the capture
// may or may not be inside the document, so it must stay unclaimed (the
// safe direction — dirty over-reports for one debounce period, never
// under-reports).
func beginPersistSeq() uint64 {
	dirtyMu.Lock()
	defer dirtyMu.Unlock()
	return mutationSeq
}

// completePersistSeq marks the watermark persisted after a successful
// snapshot.json write and clears the dirty gauge iff no mutation landed
// since the persist began.
func completePersistSeq(seq uint64) {
	dirtyMu.Lock()
	defer dirtyMu.Unlock()
	if seq > persistedSeq {
		persistedSeq = seq
	}
	if persistedSeq == mutationSeq {
		configDirty.Set(0)
	}
}

// Additional restoreTotal result label values beyond the §5.2 Result.Result
// enum: the pipeline stopped before APPLY (nothing mutated), or the engine
// rejected the call outright (precondition error, no pipeline run).
const (
	resultLabelRejected = "rejected"
	resultLabelError    = "error"
)

func init() {
	// Pre-instantiate the closed-enum children so every series exists (at
	// 0) from the first scrape -- a labeled vec with no children is omitted
	// from /metrics entirely, which reads as "feature absent" on dashboards
	// and breaks rate() baselines (same discipline as dpu_doca_bf2_metrics).
	for _, t := range []Trigger{TriggerManual, TriggerPreRestore, TriggerScheduled, TriggerPreUpgrade, TriggerWriteThrough} {
		snapshotTotal.WithLabelValues(string(t))
	}
	for _, mode := range []string{string(ModeDryRun), string(ModeCommit), "boot"} {
		for _, result := range []string{ResultOK, ResultRolledBack, ResultRollbackFailed, resultLabelRejected, resultLabelError} {
			restoreTotal.WithLabelValues(mode, result)
		}
	}
}

// restoreResultLabel maps a Restore outcome to its restoreTotal result label.
func restoreResultLabel(result *Result, err error) string {
	if err != nil || result == nil {
		return resultLabelError
	}
	if result.Result == "" {
		return resultLabelRejected
	}
	return result.Result
}

// observeRestore records one Restore run. committed selects whether the
// last-restore timestamp gauge advances (successful commit/boot only).
func observeRestore(mode string, result *Result, err error, elapsed time.Duration, committed bool, at time.Time) {
	restoreTotal.WithLabelValues(mode, restoreResultLabel(result, err)).Inc()
	restoreDuration.Observe(elapsed.Seconds())
	if committed {
		lastRestoreTimestamp.Set(float64(at.Unix()))
	}
}

// BootConfigConflictInc records a §6.2 dual-artifact boot; called by the
// boot loader (api/loxinlp) when both snapshot.json and legacy *.txt
// configuration files exist and newest-wins arbitration ran.
func BootConfigConflictInc() { bootConfigConflict.Inc() }
