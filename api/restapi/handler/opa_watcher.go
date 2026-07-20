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

package handler

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/pkg/opa"
)

// opaWatcherManager holds the singleton watcher instance.
var (
	opaWatcher   *opa.Watcher
	opaWatcherMu sync.Mutex
)

// OPAWatcherConfigRequest matches the REST body for POST /config/opa/watcher
type OPAWatcherConfigRequest struct {
	OPAURL          string `json:"opa_url"`
	PolicyPath      string `json:"policy_path,omitempty"`
	PollIntervalSec int    `json:"poll_interval_sec,omitempty"`
	FailOpen        bool   `json:"fail_open,omitempty"`
}

// OPAWatcherStatusResponse is GET response
type OPAWatcherStatusResponse struct {
	OPAURL              string `json:"opa_url"`
	PolicyPath          string `json:"policy_path"`
	PollIntervalSec     int    `json:"poll_interval_sec"`
	FailOpen            bool   `json:"fail_open"`
	Status              string `json:"status"`
	LastSyncAt          string `json:"last_sync_at,omitempty"`
	RulesCount          int    `json:"rules_count"`
	CircuitBreakerState int    `json:"circuit_breaker_state"`
	LastError           string `json:"last_error,omitempty"`
}

// RegisterOPAWatcherRoutes adds OPA watcher endpoints to the mux.
func RegisterOPAWatcherRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/netlox/v1/config/opa/watcher", HandleOPAWatcher)
}

// HandleOPAWatcher dispatches OPA watcher requests by HTTP method.
func HandleOPAWatcher(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		configPostOPAWatcher(w, r)
	case http.MethodGet:
		configGetOPAWatcher(w, r)
	case http.MethodDelete:
		configDeleteOPAWatcher(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func configPostOPAWatcher(w http.ResponseWriter, r *http.Request) {
	tk.LogIt(tk.LogTrace, "api: OPA Watcher POST called by IP: %s\n", r.RemoteAddr)

	var req OPAWatcherConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if req.OPAURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "opa_url is required"})
		return
	}
	if err := validateSSRFGuard(req.OPAURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	opaWatcherMu.Lock()
	defer opaWatcherMu.Unlock()

	// Stop existing watcher if running
	if opaWatcher != nil {
		opaWatcher.Stop()
	}

	pollInterval := 30
	if req.PollIntervalSec > 0 {
		pollInterval = req.PollIntervalSec
	}
	policyPath := "loxilb/l4"
	if req.PolicyPath != "" {
		policyPath = req.PolicyPath
	}

	config := opa.WatcherConfig{
		OPAURL:       req.OPAURL,
		PolicyPath:   policyPath,
		PollInterval: time.Duration(pollInterval) * time.Second,
		FailOpen:     req.FailOpen,
	}

	opaWatcher = opa.NewWatcher(config)
	opaWatcher.Start()

	tk.LogIt(tk.LogInfo, "[OPA-L4] watcher configured via REST API: opa_url=%s policy=%s\n", req.OPAURL, policyPath)
	writeJSON(w, http.StatusOK, map[string]string{"result": "Success"})
}

func configGetOPAWatcher(w http.ResponseWriter, r *http.Request) {
	tk.LogIt(tk.LogTrace, "api: OPA Watcher GET called by IP: %s\n", r.RemoteAddr)

	opaWatcherMu.Lock()
	defer opaWatcherMu.Unlock()

	if opaWatcher == nil {
		writeJSON(w, http.StatusOK, OPAWatcherStatusResponse{Status: "not_configured"})
		return
	}

	status := opaWatcher.GetStatus()
	resp := OPAWatcherStatusResponse{
		OPAURL:              status.Config.OPAURL,
		PolicyPath:          status.Config.PolicyPath,
		PollIntervalSec:     int(status.Config.PollInterval.Seconds()),
		FailOpen:            status.Config.FailOpen,
		RulesCount:          status.RulesCount,
		CircuitBreakerState: int(status.CircuitBreakerState),
		LastError:           status.LastError,
	}
	if status.Running {
		resp.Status = "running"
	} else {
		resp.Status = "stopped"
	}
	if !status.LastSyncAt.IsZero() {
		resp.LastSyncAt = status.LastSyncAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func configDeleteOPAWatcher(w http.ResponseWriter, r *http.Request) {
	tk.LogIt(tk.LogTrace, "api: OPA Watcher DELETE called by IP: %s\n", r.RemoteAddr)

	opaWatcherMu.Lock()
	defer opaWatcherMu.Unlock()

	if opaWatcher == nil {
		writeJSON(w, http.StatusOK, map[string]string{"result": "Success"})
		return
	}

	opaWatcher.Stop()
	opaWatcher = nil
	tk.LogIt(tk.LogInfo, "[OPA-L4] watcher stopped and removed via REST API\n")
	writeJSON(w, http.StatusOK, map[string]string{"result": "Success"})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ssrfBlockedCIDRs is the list of private/reserved IP ranges blocked for SSRF protection.
var ssrfBlockedCIDRs = []struct {
	label   string
	network *net.IPNet
}{
	{"link-local/AWS-metadata", mustParseCIDR("169.254.0.0/16")},
	{"loopback", mustParseCIDR("127.0.0.0/8")},
	{"RFC1918-10", mustParseCIDR("10.0.0.0/8")},
	{"RFC1918-172", mustParseCIDR("172.16.0.0/12")},
	{"RFC1918-192", mustParseCIDR("192.168.0.0/16")},
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic("invalid CIDR: " + s)
	}
	return network
}

// validateSSRFGuard rejects URLs that resolve to private/reserved IP addresses.
func validateSSRFGuard(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid opa_url: %v", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("opa_url must contain a hostname")
	}

	// Resolve hostname to IPs (handles both direct IPs and DNS names).
	ips, err := net.LookupHost(host)
	if err != nil {
		// If host is an IP literal, net.LookupHost still returns it. If DNS
		// fails for a real hostname, treat as unparseable IP and try directly.
		ips = []string{host}
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, entry := range ssrfBlockedCIDRs {
			if entry.network.Contains(ip) {
				return fmt.Errorf("opa_url resolves to a private/reserved IP address (SSRF protection)")
			}
		}
	}
	return nil
}
