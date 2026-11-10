// Copyright (c) 2026 NetLOX Inc
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/options"
)

func saveMetricsLifecycleHooks(t *testing.T) {
	t.Helper()
	oldCheck, oldOff := metricsCheckInit, metricsTurnOff
	t.Cleanup(func() { metricsCheckInit, metricsTurnOff = oldCheck, oldOff })
}

func TestMetricsPostRefusesStoppingGeneration(t *testing.T) {
	withMetricsState(t, false, false, false)
	saveMetricsLifecycleHooks(t)
	metricsCheckInit = func() error { return fmt.Errorf("%w (generation 42)", prometheus.ErrMetricsStopping) }
	req := httptest.NewRequest(http.MethodPost, "/netlox/v1/config/metrics", nil)
	response := ConfigPostPrometheus(operations.PostConfigMetricsParams{HTTPRequest: req}, nil)
	rec := httptest.NewRecorder()
	response.WriteResponse(rec, runtime.JSONProducer())
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(body, "still stopping") || !strings.Contains(body, "retry disable") || strings.Contains(body, "already enabled") {
		t.Fatalf("misreported stopping: %d %s", rec.Code, body)
	}
	if options.Opts.Prometheus {
		t.Fatal("failed POST enabled export")
	}
}

func TestMetricsDeleteRetriesStoppingGeneration(t *testing.T) {
	withMetricsState(t, true, false, false)
	saveMetricsLifecycleHooks(t)
	metricsCheckInit = func() error { return prometheus.ErrMetricsStopping }
	calls := 0
	metricsTurnOff = func() error {
		calls++
		if calls == 1 {
			return fmt.Errorf("%w: %w", prometheus.ErrMetricsStopping, context.DeadlineExceeded)
		}
		return nil
	}
	deleteReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/netlox/v1/config/metrics", nil)
		response := ConfigDeletePrometheus(operations.DeleteConfigMetricsParams{HTTPRequest: req}, nil)
		rec := httptest.NewRecorder()
		response.WriteResponse(rec, runtime.JSONProducer())
		return rec
	}
	first := deleteReq()
	if first.Code != http.StatusServiceUnavailable || options.Opts.Prometheus {
		t.Fatalf("timed-out disable exported metrics: %d enabled=%v", first.Code, options.Opts.Prometheus)
	}
	if code, _ := scrape(t, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("timed-out disable scrape got %d", code)
	}
	second := deleteReq()
	if second.Code != http.StatusOK || calls != 2 || !strings.Contains(second.Body.String(), "Success") {
		t.Fatalf("DELETE did not retry drain: calls=%d %d %s", calls, second.Code, second.Body.String())
	}
}
