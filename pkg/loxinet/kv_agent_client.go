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
 * kv_agent_client.go -- REST client for loxilb -> kv-agent communication.
 *
 * Discovers and monitors the loxilb-kv-agent process via its REST API.
 * Polls /kv/health every 10 seconds and registers KVTransport capability
 * in the AI gateway when the agent is healthy. Auto-discovers at [::1]:9099
 * with --kv-agent-addr CLI override.
 *
 * NOTE: This file does NOT modify ai_kv_subscriber.go. The KV subscriber
 * handles ZMQ BlockStored/BlockRemoved events for L4 routing decisions.
 * KV_FETCH_REQ comes from vLLM directly via ComCh (PCIe, BF2 ARM side).
 */
package loxinet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// kvAgentUpGauge is the loxilb-side health gauge for the kv-agent.
// Updated from /kv/health poll results. No CGO or libloxilb_kv.a dependency.
// Registered only when a client is actually created: the family is outside
// the default package profile (kv-agent-health class), so a gateway that
// never talks to a kv-agent must not expose the series at all.
var (
	kvAgentUpGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "loxilb_kv_agent_up",
		Help: "KV agent health: 1.0=ok, 0.5=degraded, 0.0=down",
	})
	kvAgentUpRegisterOnce sync.Once
)

const (
	// kvAgentDefaultAddr is the default kv-agent REST address (IPv6 loopback).
	kvAgentDefaultAddr = "[::1]:9099"

	// kvAgentPollInterval is the health check polling interval.
	kvAgentPollInterval = 10 * time.Second

	// kvAgentHTTPTimeout is the HTTP client timeout for kv-agent requests.
	kvAgentHTTPTimeout = 2 * time.Second
)

// KVAgentHealth represents the response from GET /kv/health.
type KVAgentHealth struct {
	Status    string `json:"status"` // "ok", "degraded", "down"
	HWDeflate bool   `json:"hw_deflate"`
	HWDMA     bool   `json:"hw_dma"`
	ComCh     bool   `json:"comch"`
}

// KVSessionRequest is the request body for POST /kv/session.
type KVSessionRequest struct {
	SessionID     uint64 `json:"session_id"`
	GPUExportDesc string `json:"gpu_export_desc"` // base64-encoded PCI export descriptor
	Priority      uint32 `json:"priority"`
	KVStoreHost   string `json:"kv_store_host"`
	KVStorePort   uint16 `json:"kv_store_port"`
	TotalChunks   uint32 `json:"total_chunks"`
}

// KVAgentClient is a REST client for communicating with loxilb-kv-agent.
type KVAgentClient struct {
	addr       string
	httpClient *http.Client
	healthy    bool
	lastCheck  time.Time
	mu         sync.RWMutex
	stopCh     chan struct{}
}

// NewKVAgentClient creates a new KV agent client with the given address.
// If addr is empty, defaults to [::1]:9099.
func NewKVAgentClient(addr string) *KVAgentClient {
	kvAgentUpRegisterOnce.Do(func() { prometheus.MustRegister(kvAgentUpGauge) })
	if addr == "" {
		addr = kvAgentDefaultAddr
	}
	return &KVAgentClient{
		addr: addr,
		httpClient: &http.Client{
			Timeout: kvAgentHTTPTimeout,
		},
		stopCh: make(chan struct{}),
	}
}

// PollHealth sends GET /kv/health and returns the parsed response.
func (c *KVAgentClient) PollHealth() (*KVAgentHealth, error) {
	url := fmt.Sprintf("http://%s/kv/health", c.addr)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		c.mu.Lock()
		c.healthy = false
		c.lastCheck = time.Now()
		c.mu.Unlock()
		kvAgentUpGauge.Set(0.0)
		return nil, fmt.Errorf("kv-agent health poll failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.mu.Lock()
		c.healthy = false
		c.lastCheck = time.Now()
		c.mu.Unlock()
		kvAgentUpGauge.Set(0.0)
		return nil, fmt.Errorf("kv-agent health returned status %d", resp.StatusCode)
	}

	var health KVAgentHealth
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		c.mu.Lock()
		c.healthy = false
		c.lastCheck = time.Now()
		c.mu.Unlock()
		kvAgentUpGauge.Set(0.0)
		return nil, fmt.Errorf("kv-agent health decode failed: %w", err)
	}

	c.mu.Lock()
	c.healthy = health.Status == "ok" || health.Status == "degraded"
	c.lastCheck = time.Now()
	c.mu.Unlock()

	// Update loxilb-side Prometheus gauge from health poll result
	switch health.Status {
	case "ok":
		kvAgentUpGauge.Set(1.0)
	case "degraded":
		kvAgentUpGauge.Set(0.5)
	default:
		kvAgentUpGauge.Set(0.0)
	}

	return &health, nil
}

// IsKVTransportReady returns true if the last health check reported "ok" or "degraded".
func (c *KVAgentClient) IsKVTransportReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

// TriggerSession sends POST /kv/session to pre-register a GPU mmap for a session.
func (c *KVAgentClient) TriggerSession(req *KVSessionRequest) error {
	url := fmt.Sprintf("http://%s/kv/session", c.addr)
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal session request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create session request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("kv-agent session request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kv-agent session returned status %d", resp.StatusCode)
	}

	return nil
}

// StartHealthPoller starts a background goroutine that polls kv-agent health
// every 10 seconds. Call Stop to terminate the poller.
func (c *KVAgentClient) StartHealthPoller() {
	go func() {
		ticker := time.NewTicker(kvAgentPollInterval)
		defer ticker.Stop()

		// Initial poll immediately
		health, err := c.PollHealth()
		if err != nil {
			log.WithError(err).Debug("initial kv-agent health poll failed")
		} else {
			log.WithFields(log.Fields{
				"status":     health.Status,
				"hw_deflate": health.HWDeflate,
				"hw_dma":     health.HWDMA,
				"comch":      health.ComCh,
			}).Info("kv-agent health: initial poll")
		}

		for {
			select {
			case <-ticker.C:
				health, err := c.PollHealth()
				if err != nil {
					log.WithError(err).Debug("kv-agent health poll failed")
				} else {
					log.WithFields(log.Fields{
						"status":    health.Status,
						"transport": c.IsKVTransportReady(),
					}).Debug("kv-agent health poll")
				}
			case <-c.stopCh:
				return
			}
		}
	}()
}

// Stop terminates the health poller goroutine.
func (c *KVAgentClient) Stop() {
	close(c.stopCh)
}
