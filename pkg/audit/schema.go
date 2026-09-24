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
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the envelope version written into every record. The
// schema is add-only: a field is never renamed, retyped or removed.
const SchemaVersion = 1

// Stream discriminates the three record families that share the envelope.
type Stream string

const (
	// StreamMgmt is the management plane: configuration mutations,
	// authentication and account lifecycle, sensitive reads and the
	// management-plane security refusals.
	StreamMgmt Stream = "mgmt"
	// StreamData is the inference path: one record per admitted request
	// plus the data-path security decisions.
	StreamData Stream = "data"
	// StreamSystem is the audit subsystem explaining itself: writer
	// lifecycle, heartbeat, segment lifecycle, retention and gaps. It is
	// never sampled or filtered.
	StreamSystem Stream = "audit_system"
)

func (s Stream) valid() bool {
	switch s {
	case StreamMgmt, StreamData, StreamSystem:
		return true
	}
	return false
}

// Phase marks the two halves of a fail-closed management pair. The intent
// is written durably before the handler runs; the result is appended after
// it returns. Both share one EventID.
type Phase string

const (
	PhaseIntent Phase = "intent"
	PhaseResult Phase = "result"
)

// Class tags a record whose contract differs from its stream's default:
// a security decision (generation mandatory, never sampled) or a sensitive
// read. The empty class is the stream's ordinary contract.
type Class string

const (
	ClassSecurity Class = "security"
	ClassRead     Class = "read"
)

// AuthMode is how the actor authenticated.
type AuthMode string

const (
	AuthAPIKey  AuthMode = "apikey"
	AuthMTLS    AuthMode = "mtls"
	AuthSession AuthMode = "session"
	AuthNone    AuthMode = "none"
)

// Reason is the closed vocabulary of outcome.reason. It is the only
// free-text-shaped field in the envelope and it is not free text: a SIEM
// rule written against a value here must not break when a log line is
// reworded.
type Reason string

const (
	ReasonOK               Reason = "ok"
	ReasonAuth             Reason = "auth"
	ReasonAuthz            Reason = "authz"
	ReasonLoginFailed      Reason = "login_failed"
	ReasonAdmission        Reason = "admission"
	ReasonRateLimit        Reason = "ratelimit"
	ReasonQuota            Reason = "quota"
	ReasonCircuitBreaker   Reason = "circuit_breaker"
	ReasonBackendTLS       Reason = "backend_tls"
	ReasonBackendConn      Reason = "backend_conn"
	ReasonTimeout          Reason = "timeout"
	ReasonClientAbort      Reason = "client_abort"
	ReasonUpstreamError    Reason = "upstream_error"
	ReasonAuditUnavailable Reason = "audit_unavailable"
)

var reasons = map[Reason]struct{}{
	ReasonOK: {}, ReasonAuth: {}, ReasonAuthz: {}, ReasonLoginFailed: {},
	ReasonAdmission: {}, ReasonRateLimit: {}, ReasonQuota: {},
	ReasonCircuitBreaker: {}, ReasonBackendTLS: {}, ReasonBackendConn: {},
	ReasonTimeout: {}, ReasonClientAbort: {}, ReasonUpstreamError: {},
	ReasonAuditUnavailable: {},
}

// ValidReason reports whether r is in the closed vocabulary. The empty
// reason is not valid: a record always says why.
func ValidReason(r Reason) bool {
	_, ok := reasons[r]
	return ok
}

// Actor is who did it. Every field is an identifier; none is a credential.
type Actor struct {
	Auth AuthMode
	// KeyID is the API key identifier, never the key.
	KeyID string
	// Subject is the certificate subject when Auth is mtls.
	Subject string
	// User is the authenticated principal. It is never populated from a
	// caller-supplied header; a delegated originator goes in Delegated.
	User   string
	Role   string
	Tenant string
	// Remote is the direct peer address.
	Remote string
	// Delegated is the originator a delegating caller claimed through the
	// originator header, recorded verbatim and never promoted to User.
	Delegated string
	// DelegationTrusted is true only when the authenticated principal is
	// allowed to delegate; otherwise the claim is evidence, not attribution.
	DelegationTrusted bool
	// Provisional marks the pre-authentication view carried by an intent
	// written before the handler established the real actor.
	Provisional bool
	// UsernameClaimed is the login name a request asserted before it was
	// validated. Never the password.
	UsernameClaimed string
	// Bootstrap marks the loopback first-user bootstrap branch.
	Bootstrap bool
	// AuthMode of the route, for refusals recorded before any principal
	// exists (token, password, none).
	Mechanism string
}

// Outcome is what happened.
type Outcome struct {
	Status int
	OK     bool
	Reason Reason
}

// MgmtDetail is the detail object of a mgmt record. Path is the route
// template (or URL.Path where no template applies); the URL as received,
// its query string and any query value are never stored, because at least
// one route carries credentials in the query string. ChangedFields carries
// field names only, never values.
type MgmtDetail struct {
	Method     string
	Path       string
	RouteClass string
	Raw        bool
	Resource   string
	Action     string
	// ChangedFields is a list of field names, never values.
	ChangedFields []string
	McpTool       string
	Username      string
	Role          string
	RoleFrom      string
	RoleTo        string
	Bootstrap     bool
	Provider      string
	// Fingerprints identify a token or state value without carrying it.
	StateTokenFingerprint string
	TokenFingerprint      string
	ActiveFrom            string
	ActiveTo              string
	// Snapshot restore lifecycle.
	RestorePhase   string
	EntriesApplied int
	EntriesFailed  int
	// Export-class reads report what was served, never the content.
	Bytes              int64
	Checksum           string
	ContentDisposition string
	Format             string
	// SecretsIncluded is a pointer so that an export can state false
	// explicitly: the field is a claim about the document served, and an
	// omitted claim is not the same as a negative one.
	SecretsIncluded  *bool
	Filename         string
	Count            int
	Tenant           string
	ConfigGeneration uint64
	AuthMode         string
	Mechanism        string
	X509Error        string
}

// DataDetail is the detail object of a data record. It has no body field,
// so a prompt or a response has nowhere to go.
type DataDetail struct {
	Service        string
	Rule           string
	Model          string
	ModelVersion   string
	Engine         string
	Tier           string
	Endpoint       string
	TokensIn       int64
	TokensOut      int64
	LatencyMs      int64
	FinishReason   string
	Retried        bool
	Stream         bool
	SessionID      string
	PromptCaptured bool
	Stage          string
	Scanner        string
	Decision       string
}

// SysDetail is the detail object of an audit_system record. Fields are
// grouped by the event families that use them; unused fields are omitted.
type SysDetail struct {
	Resource string `json:"resource,omitempty"`

	// Writer lifecycle.
	BootID        string `json:"boot_id,omitempty"`
	MatrixDigest  string `json:"matrix_digest,omitempty"`
	LastSeqBefore uint64 `json:"last_seq_before,omitempty"`
	RestartCount  uint64 `json:"restart_count,omitempty"`
	PanicMsg      string `json:"panic_msg,omitempty"`

	// Write failures, reported retroactively once writing resumes.
	ErrnoClass string `json:"errno_class,omitempty"`
	FirstTS    string `json:"first_ts,omitempty"`
	LastTS     string `json:"last_ts,omitempty"`
	Count      uint64 `json:"count,omitempty"`

	// Disk reserve.
	FreeBytes     int64 `json:"free_bytes,omitempty"`
	ReservedBytes int64 `json:"reserved_bytes,omitempty"`

	// Heartbeat.
	Heartbeat *Heartbeat `json:"heartbeat,omitempty"`

	// Segment lifecycle.
	PrevSegmentUUID   string `json:"prev_segment_uuid,omitempty"`
	PrevSeal          string `json:"prev_seal,omitempty"`
	FirstSeq          uint64 `json:"first_seq,omitempty"`
	LastSeq           uint64 `json:"last_seq,omitempty"`
	RecordCount       uint64 `json:"record_count,omitempty"`
	RecordsRecovered  uint64 `json:"records_recovered,omitempty"`
	TruncatedTailByte int64  `json:"truncated_tail_bytes,omitempty"`
	AgeDays           int    `json:"age_days,omitempty"`
	Bytes             int64  `json:"bytes,omitempty"`
	Hold              bool   `json:"hold"`
	Recovered         bool   `json:"recovered,omitempty"`

	// Orphaned intents.
	IntentEventID          string `json:"intent_event_id,omitempty"`
	ConfigGenerationAtBoot uint64 `json:"config_generation_at_boot,omitempty"`

	// Producer gaps.
	ProducerID   string `json:"producer_id,omitempty"`
	Stream       Stream `json:"stream,omitempty"`
	PseqFrom     uint64 `json:"pseq_from,omitempty"`
	PseqTo       uint64 `json:"pseq_to,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Exact        *bool  `json:"exact,omitempty"`
	CounterDelta uint64 `json:"counter_delta,omitempty"`
}

// Heartbeat is the fixed-interval liveness record's payload. Every counter
// is since boot; a consumer differences successive heartbeats.
type Heartbeat struct {
	SeqHigh           uint64            `json:"seq_high"`
	Accepted          map[Stream]uint64 `json:"accepted"`
	Dropped           []DropCount       `json:"dropped_by_reason"`
	QueueDepth        map[string]uint64 `json:"queue_depth"`
	QueueHWM          map[string]uint64 `json:"queue_hwm"`
	PseqHigh          []ProducerSeq     `json:"pseq_high,omitempty"`
	DropRingOverflows []ProducerCount   `json:"drop_ring_overflows,omitempty"`
	UnattributedTotal uint64            `json:"unattributed_total"`
	WriteFailures     uint64            `json:"write_failures_total"`
}

// DropCount is one cell of the dropped_by_reason matrix.
type DropCount struct {
	ProducerID string `json:"producer_id,omitempty"`
	Stream     Stream `json:"stream"`
	Reason     string `json:"reason"`
	Count      uint64 `json:"count"`
}

// ProducerSeq is a producer's highest sequence so far.
type ProducerSeq struct {
	ProducerID string `json:"producer_id"`
	Stream     Stream `json:"stream"`
	Pseq       uint64 `json:"pseq"`
}

// ProducerCount is a per-producer counter.
type ProducerCount struct {
	ProducerID string `json:"producer_id"`
	Count      uint64 `json:"count"`
}

// Record is the envelope. Exactly one of Mgmt, Data and Sys is set and it
// must match Stream. The writer assigns EventID (when empty), TS (when
// zero), instance and boot identity, the segment UUID and seq at write
// time; a producer assigns its own identity and pseq at emit time.
type Record struct {
	EventID   string
	TS        time.Time
	Stream    Stream
	EventType string
	Class     Class
	Phase     Phase
	// ResultOf names the event type of the intent this result answers when
	// the two differ (a gated route whose result is a security refusal).
	ResultOf  string
	RequestID string
	TraceID   string
	SpanID    string
	Actor     Actor
	Outcome   Outcome

	Mgmt *MgmtDetail
	Data *DataDetail
	Sys  *SysDetail

	producerID string
	pseq       uint64
	pooled     bool
}

// Reset clears a record for reuse.
func (r *Record) Reset() {
	pooled := r.pooled
	*r = Record{}
	r.pooled = pooled
}

var (
	errNoStream    = errors.New("audit: record has no stream")
	errDetail      = errors.New("audit: record detail does not match its stream")
	errNoEventType = errors.New("audit: record has no event_type")
	errReason      = errors.New("audit: outcome.reason is not in the vocabulary")
	errPhase       = errors.New("audit: phase is only valid on the mgmt stream")
)

// Validate checks the structural rules a record must satisfy before it is
// written. It does not stamp anything.
func (r *Record) Validate() error {
	if !r.Stream.valid() {
		return errNoStream
	}
	if r.EventType == "" {
		return errNoEventType
	}
	if !ValidReason(r.Outcome.Reason) {
		return fmt.Errorf("%w: %q", errReason, r.Outcome.Reason)
	}
	switch r.Stream {
	case StreamMgmt:
		if r.Mgmt == nil || r.Data != nil || r.Sys != nil {
			return errDetail
		}
		if r.Phase != "" && r.Phase != PhaseIntent && r.Phase != PhaseResult {
			return fmt.Errorf("audit: unknown phase %q", r.Phase)
		}
	case StreamData:
		if r.Data == nil || r.Mgmt != nil || r.Sys != nil {
			return errDetail
		}
		if r.Phase != "" {
			return errPhase
		}
	case StreamSystem:
		if r.Sys == nil || r.Mgmt != nil || r.Data != nil {
			return errDetail
		}
		if r.Phase != "" {
			return errPhase
		}
	}
	return nil
}

// sanitize enforces the rules that are applied rather than rejected: the
// management path is cut at the first query or fragment delimiter so a
// URL as received can never be stored. It reports whether anything was
// changed so the writer can count it.
func (r *Record) sanitize() bool {
	if r.Mgmt == nil {
		return false
	}
	if i := strings.IndexAny(r.Mgmt.Path, "?#"); i >= 0 {
		r.Mgmt.Path = r.Mgmt.Path[:i]
		return true
	}
	return false
}
