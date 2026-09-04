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

	persistTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "loxilb_persist_total",
		Help: "snapshot.json persist attempts (write-through, manual, auto-persist), partitioned by result (ok, error).",
	}, []string{"result"})

	autoPersistFailStreak = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "loxilb_autopersist_consecutive_failures",
		Help: "Consecutive auto-persist failures; 0 when the last persist succeeded. Nonzero means recent config changes may not survive a restart.",
	})
)

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
	for _, result := range []string{"ok", resultLabelError} {
		persistTotal.WithLabelValues(result)
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
