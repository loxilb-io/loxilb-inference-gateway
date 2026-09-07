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

package common

// TracingConfig is the persisted OTLP trace-export product configuration
// (the snapshot "tracing" domain payload): collector endpoint, protocol
// and TLS posture. A nil *TracingConfig means "never explicitly
// configured" — the compiled/environment default is node-local boot
// config, not desired state, and is not captured.
//
// Auth headers are split by design: only the header NAMES ride the
// snapshot document; the VALUES are secret material and live in a
// node-local 0600 file next to the snapshot (never in the document, which
// travels over the wire and into evidence archives). Restore re-joins
// names with locally stored values and warns loudly about names it cannot
// resolve — a document restored onto a different node needs the secrets
// re-provisioned there.
type TracingConfig struct {
	// Endpoint - OTLP collector endpoint, host:port.
	Endpoint string `json:"endpoint"`
	// Protocol - "grpc" or "http".
	Protocol string `json:"protocol"`
	// UseTLS - TLS toward the collector.
	UseTLS bool `json:"use_tls"`
	// TLSSkipVerify - skip certificate verification (insecure, dev only).
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`
	// HeaderNames - names of the configured auth headers, sorted. Values
	// are NEVER part of this structure.
	HeaderNames []string `json:"header_names,omitempty"`
}
