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

package snapshot

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// The §7 metrics are package-global (registered once on the default
// registry), so every assertion here is a before/after delta -- other tests
// in the package increment the same series.

// fixtureComponents scopes commits to the four domains restoreDoc populates,
// like TestRestoreCommitHappyPath -- the mock's securityrate singleton makes
// a full-domain verify fail.
var fixtureComponents = []string{DomainEndpoint, DomainLoadBalancer, DomainFirewall, DomainPolicy}

func restoreTotalValue(t *testing.T, mode, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(restoreTotal.WithLabelValues(mode, result))
}

func restoreDurationCount(t *testing.T) uint64 {
	t.Helper()
	m := &dto.Metric{}
	if err := restoreDuration.Write(m); err != nil {
		t.Fatalf("read duration histogram: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestMetricsCommitOKIncrementsRestoreAndSnapshotSeries(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	raw := encodeDoc(t, doc)
	engine := newTestEngine(hooks, t.TempDir())

	beforeOK := restoreTotalValue(t, "commit", ResultOK)
	beforePre := testutil.ToFloat64(snapshotTotal.WithLabelValues(string(TriggerPreRestore)))
	beforeDur := restoreDurationCount(t)

	result, err := engine.Restore(raw, RestoreOptions{Mode: ModeCommit, Components: fixtureComponents})
	if err != nil || result.Result != ResultOK {
		t.Fatalf("commit failed: err=%v result=%+v", err, result)
	}

	if got := restoreTotalValue(t, "commit", ResultOK) - beforeOK; got != 1 {
		t.Errorf("restore_total{commit,ok} delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(snapshotTotal.WithLabelValues(string(TriggerPreRestore))) - beforePre; got != 1 {
		t.Errorf("snapshot_total{pre-restore} delta = %v, want 1 (PRESERVE ran once)", got)
	}
	if got := restoreDurationCount(t) - beforeDur; got != 1 {
		t.Errorf("restore_duration observation delta = %v, want 1", got)
	}
}

func TestMetricsParseFailureCountsAsRejected(t *testing.T) {
	engine := newTestEngine(newMockHooks(), t.TempDir())
	before := restoreTotalValue(t, "dry-run", resultLabelRejected)

	result, err := engine.Restore([]byte(`{"not":"a snapshot"`), RestoreOptions{})
	if err != nil {
		t.Fatalf("engine error (want in-band rejection): %v", err)
	}
	if result.Result != "" {
		t.Fatalf("result = %q, want empty (pipeline stopped at PARSE)", result.Result)
	}
	if got := restoreTotalValue(t, "dry-run", resultLabelRejected) - before; got != 1 {
		t.Errorf("restore_total{dry-run,rejected} delta = %v, want 1", got)
	}
}

func TestMetricsLastRestoreTimestampAdvancesOnCommitNotDryRun(t *testing.T) {
	hooks := newMockHooks()
	raw := encodeDoc(t, restoreDoc("0.9.8.6-beta"))

	fixed := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	engine := newTestEngine(hooks, t.TempDir())
	engine.Now = func() time.Time { return fixed }

	lastRestoreTimestamp.Set(0)
	if result, err := engine.Restore(raw, RestoreOptions{Mode: ModeDryRun, Components: fixtureComponents}); err != nil || result.Result != ResultOK {
		t.Fatalf("dry-run failed: err=%v result=%+v", err, result)
	}
	if got := testutil.ToFloat64(lastRestoreTimestamp); got != 0 {
		t.Errorf("dry-run moved last_restore_timestamp to %v, want 0", got)
	}

	if result, err := engine.Restore(raw, RestoreOptions{Mode: ModeCommit, Components: fixtureComponents}); err != nil || result.Result != ResultOK {
		t.Fatalf("commit failed: err=%v result=%+v", err, result)
	}
	if got := testutil.ToFloat64(lastRestoreTimestamp); got != float64(fixed.Unix()) {
		t.Errorf("last_restore_timestamp = %v, want %v", got, fixed.Unix())
	}
}

func TestMetricsCaptureCountsTrigger(t *testing.T) {
	hooks := newMockHooks()
	before := testutil.ToFloat64(snapshotTotal.WithLabelValues(string(TriggerManual)))
	if _, err := Capture(hooks, "0.9.8.6-beta", "test-host", TriggerManual, nil); err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if got := testutil.ToFloat64(snapshotTotal.WithLabelValues(string(TriggerManual))) - before; got != 1 {
		t.Errorf("snapshot_total{manual} delta = %v, want 1", got)
	}
}

func TestRestoreResultLabelMapping(t *testing.T) {
	cases := []struct {
		name   string
		result *Result
		err    error
		want   string
	}{
		{"engine error", nil, errors.New("precondition"), resultLabelError},
		{"pre-apply stop", &Result{}, nil, resultLabelRejected},
		{"ok", &Result{Result: ResultOK}, nil, ResultOK},
		{"rolled back", &Result{Result: ResultRolledBack}, nil, ResultRolledBack},
		{"rollback failed", &Result{Result: ResultRollbackFailed}, nil, ResultRollbackFailed},
	}
	for _, c := range cases {
		if got := restoreResultLabel(c.result, c.err); got != c.want {
			t.Errorf("%s: label = %q, want %q", c.name, got, c.want)
		}
	}
}
