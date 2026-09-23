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

package audit

import (
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"
)

// tsLayout is RFC 3339 with millisecond precision. Times are always
// converted to UTC before formatting, so the suffix is always "Z".
const tsLayout = "2006-01-02T15:04:05.000Z"

// stamp carries the writer-owned envelope fields.
type stamp struct {
	instanceID  string
	bootID      string
	segmentUUID string
	seq         uint64
}

// encoder appends one JSON line per record into a reusable buffer. The
// envelope, actor, outcome and the data detail are written by hand so the
// data path allocates nothing after warm-up; the management and system
// details are cold and go through encoding/json from their typed structs.
// Either way the field set is exactly the struct: there is no generic
// marshal-then-redact step.
type encoder struct {
	buf []byte
}

func newEncoder() *encoder {
	return &encoder{buf: make([]byte, 0, 2048)}
}

// encode returns the record as one JSON object followed by a newline. The
// returned slice aliases the encoder's buffer and is valid until the next
// call.
func (e *encoder) encode(r *Record, st stamp) ([]byte, error) {
	b := e.buf[:0]
	b = append(b, `{"schema_version":`...)
	b = strconv.AppendInt(b, SchemaVersion, 10)
	b = appendField(b, "event_id", r.EventID)
	b = append(b, `,"ts":"`...)
	b = r.TS.UTC().AppendFormat(b, tsLayout)
	b = append(b, '"')
	b = appendField(b, "instance_id", st.instanceID)
	b = appendField(b, "boot_id", st.bootID)
	b = appendField(b, "segment_uuid", st.segmentUUID)
	b = append(b, `,"seq":`...)
	b = strconv.AppendUint(b, st.seq, 10)
	if r.producerID != "" {
		b = appendField(b, "producer_id", r.producerID)
		b = append(b, `,"pseq":`...)
		b = strconv.AppendUint(b, r.pseq, 10)
	}
	b = appendField(b, "stream", string(r.Stream))
	b = appendField(b, "event_type", r.EventType)
	b = appendOptField(b, "class", string(r.Class))
	b = appendOptField(b, "phase", string(r.Phase))
	b = appendOptField(b, "result_of", r.ResultOf)
	b = appendOptField(b, "request_id", r.RequestID)
	b = appendOptField(b, "trace_id", r.TraceID)
	b = appendOptField(b, "span_id", r.SpanID)

	b = append(b, `,"actor":{`...)
	b = appendFirstField(b, "auth", string(r.Actor.Auth))
	b = appendOptField(b, "key_id", r.Actor.KeyID)
	b = appendOptField(b, "subject", r.Actor.Subject)
	b = appendOptField(b, "user", r.Actor.User)
	b = appendOptField(b, "role", r.Actor.Role)
	b = appendOptField(b, "tenant", r.Actor.Tenant)
	b = appendOptField(b, "remote", r.Actor.Remote)
	b = appendOptField(b, "delegated", r.Actor.Delegated)
	if r.Actor.Delegated != "" {
		b = appendBool(b, "delegation_trusted", r.Actor.DelegationTrusted)
	}
	if r.Actor.Provisional {
		b = appendBool(b, "provisional", true)
	}
	b = appendOptField(b, "username_claimed", r.Actor.UsernameClaimed)
	if r.Actor.Bootstrap {
		b = appendBool(b, "bootstrap", true)
	}
	b = appendOptField(b, "mechanism", r.Actor.Mechanism)
	b = append(b, '}')

	b = append(b, `,"outcome":{"status":`...)
	b = strconv.AppendInt(b, int64(r.Outcome.Status), 10)
	b = appendBool(b, "ok", r.Outcome.OK)
	b = appendField(b, "reason", string(r.Outcome.Reason))
	b = append(b, '}')

	b = append(b, `,"detail":`...)
	var err error
	switch {
	case r.Data != nil:
		b = appendDataDetail(b, r.Data)
	case r.Mgmt != nil:
		b, err = appendJSON(b, mgmtJSON(*r.Mgmt))
	case r.Sys != nil:
		b, err = appendJSON(b, r.Sys)
	default:
		b = append(b, `{}`...)
	}
	if err != nil {
		return nil, err
	}
	b = append(b, '}', '\n')
	e.buf = b
	return b, nil
}

func appendJSON(b []byte, v any) ([]byte, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return b, err
	}
	return append(b, j...), nil
}

func appendDataDetail(b []byte, d *DataDetail) []byte {
	b = append(b, '{')
	b = appendFirstField(b, "service", d.Service)
	b = appendOptField(b, "rule", d.Rule)
	b = appendOptField(b, "model", d.Model)
	b = appendOptField(b, "model_version", d.ModelVersion)
	b = appendOptField(b, "engine", d.Engine)
	b = appendOptField(b, "tier", d.Tier)
	b = appendOptField(b, "endpoint", d.Endpoint)
	b = append(b, `,"tokens_in":`...)
	b = strconv.AppendInt(b, d.TokensIn, 10)
	b = append(b, `,"tokens_out":`...)
	b = strconv.AppendInt(b, d.TokensOut, 10)
	b = append(b, `,"latency_ms":`...)
	b = strconv.AppendInt(b, d.LatencyMs, 10)
	b = appendOptField(b, "finish_reason", d.FinishReason)
	b = appendBool(b, "retried", d.Retried)
	b = appendBool(b, "stream", d.Stream)
	b = appendOptField(b, "session_id", d.SessionID)
	b = appendBool(b, "prompt_captured", d.PromptCaptured)
	b = appendOptField(b, "stage", d.Stage)
	b = appendOptField(b, "scanner", d.Scanner)
	b = appendOptField(b, "decision", d.Decision)
	return append(b, '}')
}

// mgmtJSON is the wire shape of MgmtDetail. Keeping the tags on a
// separate type keeps the public struct free of serialisation concerns
// while the field set stays one-to-one.
type mgmtJSON struct {
	Method                string   `json:"method,omitempty"`
	Path                  string   `json:"path,omitempty"`
	RouteClass            string   `json:"route_class,omitempty"`
	Raw                   bool     `json:"raw,omitempty"`
	Resource              string   `json:"resource,omitempty"`
	Action                string   `json:"action,omitempty"`
	ChangedFields         []string `json:"changed_fields,omitempty"`
	McpTool               string   `json:"mcp_tool,omitempty"`
	Username              string   `json:"username,omitempty"`
	Role                  string   `json:"role,omitempty"`
	RoleFrom              string   `json:"role_from,omitempty"`
	RoleTo                string   `json:"role_to,omitempty"`
	Bootstrap             bool     `json:"bootstrap,omitempty"`
	Provider              string   `json:"provider,omitempty"`
	StateTokenFingerprint string   `json:"state_token_fingerprint,omitempty"`
	TokenFingerprint      string   `json:"token_fingerprint_sha256,omitempty"`
	ActiveFrom            string   `json:"active_from,omitempty"`
	ActiveTo              string   `json:"active_to,omitempty"`
	RestorePhase          string   `json:"restore_phase,omitempty"`
	EntriesApplied        int      `json:"entries_applied,omitempty"`
	EntriesFailed         int      `json:"entries_failed,omitempty"`
	Bytes                 int64    `json:"bytes,omitempty"`
	Checksum              string   `json:"checksum,omitempty"`
	ContentDisposition    string   `json:"content_disposition,omitempty"`
	Format                string   `json:"format,omitempty"`
	SecretsIncluded       bool     `json:"secrets_included,omitempty"`
	Filename              string   `json:"filename,omitempty"`
	Count                 int      `json:"count,omitempty"`
	Tenant                string   `json:"tenant,omitempty"`
	ConfigGeneration      uint64   `json:"config_generation,omitempty"`
	AuthMode              string   `json:"auth_mode,omitempty"`
	Mechanism             string   `json:"mechanism,omitempty"`
	X509Error             string   `json:"x509_error,omitempty"`
}

func appendField(b []byte, key, val string) []byte {
	b = append(b, ',', '"')
	b = append(b, key...)
	b = append(b, '"', ':')
	return appendString(b, val)
}

func appendFirstField(b []byte, key, val string) []byte {
	b = append(b, '"')
	b = append(b, key...)
	b = append(b, '"', ':')
	return appendString(b, val)
}

func appendOptField(b []byte, key, val string) []byte {
	if val == "" {
		return b
	}
	return appendField(b, key, val)
}

func appendBool(b []byte, key string, v bool) []byte {
	b = append(b, ',', '"')
	b = append(b, key...)
	b = append(b, '"', ':')
	if v {
		return append(b, "true"...)
	}
	return append(b, "false"...)
}

const hexDigits = "0123456789abcdef"

// appendString appends s as a JSON string. Control characters, the quote
// and the backslash are escaped; invalid UTF-8 is replaced so the line
// always parses.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// formatTS is the shared timestamp format for header, footer and detail
// fields that carry a time.
func formatTS(t time.Time) string {
	return t.UTC().Format(tsLayout)
}
