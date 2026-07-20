/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loxilb-kv-agent -- Standalone KV Cache Pipeline Agent for BF2 DPU.
 *
 * Wraps the C pipeline library (loxilb_kv) with a Go REST API.
 * Probes DOCA hardware capabilities on startup, initializes the
 * compress/DMA/ComCh pipeline, and exposes health, capabilities,
 * session registration, and stats endpoints.
 *
 * Designed to run on the BF2 ARM cores as a separate process from
 * loxilb, providing failure isolation and independent DOCA state.
 */
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	capabilitiesPath = "/run/loxilb-kv/capabilities.json"
)

// sessionRequest is the JSON body for POST /kv/session.
type sessionRequest struct {
	SessionID     uint64 `json:"session_id"`
	GPUExportDesc string `json:"gpu_export_desc"` // base64-encoded PCI export descriptor
	Priority      uint32 `json:"priority"`
	KVStoreHost   string `json:"kv_store_host"`
	KVStorePort   uint16 `json:"kv_store_port"`
	TotalChunks   uint32 `json:"total_chunks"`
}

var (
	opts        KVAgentOptions
	pipelineCtx unsafe.Pointer
	caps        KVCapabilities
	capsJSON    []byte
	mgmtToken   string
	mu          sync.RWMutex
)

func main() {
	// Parse CLI flags
	parser := flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Configure logging
	setupLogging(opts.LogLevel)

	log.Info("loxilb-kv-agent starting")

	// Load management token if file exists
	loadMgmtToken(opts.MgmtToken)

	// Probe hardware capabilities
	caps = probeCapabilities()
	log.WithFields(log.Fields{
		"hw_deflate": caps.HWDeflate,
		"hw_dma":     caps.HWDMA,
		"comch":      caps.ComCh,
		"status":     caps.HealthStatus,
	}).Info("hardware capabilities probed")

	// Marshal capabilities JSON and write to runtime path
	var err error
	capsJSON, err = json.MarshalIndent(caps, "", "  ")
	if err != nil {
		log.WithError(err).Fatal("failed to marshal capabilities")
	}
	writeCapabilitiesFile(capabilitiesPath, capsJSON)

	// Initialize pipeline if hardware allows
	if caps.HealthStatus != "down" {
		pipelineCtx = pipelineInit(opts.StagingSize)
		if pipelineCtx == nil {
			log.Warn("pipeline init failed, running in degraded mode")
			caps.HealthStatus = "degraded"
			capsJSON, _ = json.MarshalIndent(caps, "", "  ")
		} else {
			log.Info("pipeline initialized successfully")
		}
	} else {
		log.Warn("hardware down, pipeline not initialized")
	}

	// Start pipeline event loop in background goroutine
	var pipelineWg sync.WaitGroup
	if pipelineCtx != nil {
		pipelineWg.Add(1)
		go func() {
			defer pipelineWg.Done()
			log.Info("pipeline event loop starting")
			pipelineRun(pipelineCtx)
			log.Info("pipeline event loop stopped")
		}()
	}

	// Register Prometheus metrics and start collector
	RegisterKVMetrics()
	metricsStopCh := make(chan struct{})
	if pipelineCtx != nil {
		StartMetricsCollector(pipelineCtx, metricsStopCh)
	}

	// Setup REST server
	mux := http.NewServeMux()
	mux.HandleFunc("/kv/health", handleHealth)
	mux.HandleFunc("/kv/capabilities", handleCapabilities)
	mux.HandleFunc("/kv/session", handleSession)
	mux.HandleFunc("/kv/stats", handleStats)
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:         opts.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start REST server
	go func() {
		log.WithField("addr", opts.Listen).Info("REST server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("REST server failed")
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.WithField("signal", sig.String()).Info("shutdown signal received")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Warn("REST server shutdown error")
	}

	// Stop metrics collector
	close(metricsStopCh)

	if pipelineCtx != nil {
		pipelineStop(pipelineCtx)
		pipelineWg.Wait()
		pipelineDestroy(pipelineCtx)
	}

	log.Info("loxilb-kv-agent stopped")
}

// setupLogging configures logrus to match loxilb logging style.
func setupLogging(level string) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	lvl, err := log.ParseLevel(level)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
}

// loadMgmtToken reads the management token from the specified file path.
func loadMgmtToken(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.WithField("path", path).Debug("no management token file, mutation endpoints are unprotected")
		return
	}
	mgmtToken = strings.TrimSpace(string(data))
	if mgmtToken != "" {
		log.Info("management token loaded, mutation endpoints require authorization")
	}
}

// writeCapabilitiesFile writes capabilities JSON to runtime path.
func writeCapabilitiesFile(path string, data []byte) {
	// Create parent directory if needed
	dir := path[:strings.LastIndex(path, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.WithError(err).WithField("path", dir).Warn("failed to create capabilities directory")
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.WithError(err).WithField("path", path).Warn("failed to write capabilities file")
	}
}

// checkAuth validates Bearer token for mutation endpoints.
func checkAuth(r *http.Request) bool {
	if mgmtToken == "" {
		return true // no token configured, allow all
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return strings.TrimSpace(auth[len(prefix):]) == mgmtToken
}

// handleHealth returns agent health status with HW capability summary.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.RLock()
	defer mu.RUnlock()

	resp := struct {
		Status    string `json:"status"`
		HWDeflate bool   `json:"hw_deflate"`
		HWDMA     bool   `json:"hw_dma"`
		ComCh     bool   `json:"comch"`
	}{
		Status:    caps.HealthStatus,
		HWDeflate: caps.HWDeflate,
		HWDMA:     caps.HWDMA,
		ComCh:     caps.ComCh,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleCapabilities returns full capability matrix as JSON.
func handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(capsJSON)
}

// handleSession registers a GPU mmap for a session (pre-registration before ComCh fetch).
func handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check authorization for mutation endpoint
	if !checkAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req sessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.SessionID == 0 {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	if pipelineCtx == nil {
		http.Error(w, "pipeline not initialized", http.StatusServiceUnavailable)
		return
	}

	// Register GPU mmap from base64-encoded export descriptor
	rc := 0
	if req.GPUExportDesc != "" {
		rc = pipelineRegisterGPUMmap(pipelineCtx, req.SessionID, req.GPUExportDesc)
		if rc != 0 {
			http.Error(w, fmt.Sprintf("gpu mmap registration failed: %d", rc), http.StatusInternalServerError)
			return
		}
	}

	log.WithFields(log.Fields{
		"session_id":    req.SessionID,
		"priority":      req.Priority,
		"kv_store_host": req.KVStoreHost,
		"kv_store_port": req.KVStorePort,
		"total_chunks":  req.TotalChunks,
		"has_gpu_desc":  req.GPUExportDesc != "",
	}).Info("session registered")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "registered",
		"session_id": req.SessionID,
	})
}

// handleStats returns pipeline statistics for Prometheus scraping.
func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stats := pipelineGetStats(pipelineCtx)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
