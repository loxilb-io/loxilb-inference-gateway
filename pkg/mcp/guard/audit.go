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

package guard

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/loxilb-io/loxilb/pkg/logrotate"
)

// Event kinds recorded in the audit log.
const (
	EventToolCall     = "tool_call"
	EventAuthReject   = "auth_reject"
	EventOriginReject = "origin_reject"
	EventRateLimit    = "rate_limit"
	// EventAutopilot records a destructive tool executing without the
	// confirm-token step because it is on the autopilot list (§3.7).
	EventAutopilot = "autopilot_exec"
)

// Event is one audit log line.
type Event struct {
	Time      string         `json:"ts"`
	Kind      string         `json:"kind"`
	Client    string         `json:"client,omitempty"`
	Target    string         `json:"target,omitempty"`
	Tool      string         `json:"tool,omitempty"`
	Args      map[string]any `json:"args,omitempty"`
	OK        bool           `json:"ok"`
	Err       string         `json:"err,omitempty"`
	LatencyMs int64          `json:"latency_ms,omitempty"`
	Remote    string         `json:"remote,omitempty"`
}

// Auditor appends JSONL events to <dir>/audit.jsonl (0600).
// A nil *Auditor is valid and discards events.
type Auditor struct {
	mu sync.Mutex
	f  io.WriteCloser
}

// OpenAuditor creates dir (0700) if needed and opens the append-only log.
// The log is size-rotated (20 MB, 8 gzipped backups, 90-day retention) so
// an audit trail can never starve the disk while still covering a long
// forensic window.
func OpenAuditor(dir string) (*Auditor, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := logrotate.New(filepath.Join(dir, "audit.jsonl"),
		logrotate.Config{MaxSizeMB: 20, MaxBackups: 8, MaxAgeDays: 90, Compress: true})
	if err != nil {
		return nil, err
	}
	return &Auditor{f: f}, nil
}

// Log writes one event; failures are silent (auditing must not break serving,
// but see docs/MCP-DESIGN.md §2.2 for the off-host syslog tee option).
func (a *Auditor) Log(e Event) {
	if a == nil {
		return
	}
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.f.Write(append(b, '\n'))
}

// Close closes the underlying file.
func (a *Auditor) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}

var secretKeyHints = []string{"token", "password", "secret", "apikey", "api_key", "key"}

func secretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, hint := range secretKeyHints {
		if strings.Contains(lk, hint) {
			return true
		}
	}
	return false
}

// Redact returns a copy of args with secret-shaped values masked.
func Redact(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		if secretKey(k) {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

// RedactDeep walks a decoded JSON value and masks every value stored under a
// secret-shaped key at any depth (config_export masking, threat T5).
func RedactDeep(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretKey(k) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = RedactDeep(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = RedactDeep(val)
		}
		return out
	default:
		return v
	}
}
