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

package loxinet

import (
	"strconv"
	"sync"
	"sync/atomic"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

// This file is the data plane's half of the audit trail. The CGO exports
// next door convert C strings and hand the values here as Go types, so
// every rule about what a record may carry is decided in plain Go and can
// be tested without a C caller.
//
// Three records come from this path. A request that completed produces
// data.ai.complete. The token charge that settles its reservation produces
// data.ai.settle, joined to the first by request_id rather than by time. A
// request the admission gate refused produces sec.ai.deny, which is a
// security-class record and so leaves on the dedicated security queue.
//
// None of the three may block, and none may fail a request. A record that
// cannot be emitted is counted by the producer's own drop ring and turns
// into a sys.producer.gap at the next heartbeat; the response is served
// either way.

const (
	eventAIComplete = "data.ai.complete"
	eventAISettle   = "data.ai.settle"
	eventAIDeny     = "sec.ai.deny"
)

// ctlProducerID is the producer identity for records emitted off a thread
// that is not a sockproxy relay worker.
//
// The C side sets its per-thread worker id once at worker start, outside
// every build-time feature guard, so a negative id does not mean a worker
// whose identity was lost — it means the caller is not a relay worker at
// all. On these paths that caller is the proxy's own teardown and reaper
// side, releasing the reservations a dying connection still held. That is
// a known producer, so it gets a name.
//
// The unattributed identity stays reserved for a genuine loss of
// attribution, which is why the writer counts it separately. Spending it
// on a caller we can name would leave the counter permanently non-zero and
// blind to the case it exists to show.
const ctlProducerID = "ctl"

// aiAuditProducers caches one producer per emitting thread. Producer
// lookup on the writer takes a lock and walks a slice, which is fine once
// per worker and wrong once per request, so the mapping is resolved here
// and kept until the writer itself is replaced.
type aiAuditProducers struct {
	w        *audit.Writer
	byWorker []*audit.Producer
	ctl      *audit.Producer
}

var (
	aiAuditProdCache atomic.Pointer[aiAuditProducers]
	aiAuditProdMu    sync.Mutex
)

// aiDataProducer returns the data-stream producer for the emitting thread,
// creating it on first use. workerID is the C side's per-thread worker
// identity; negative means the caller is not a relay worker.
func aiDataProducer(w *audit.Writer, workerID int) *audit.Producer {
	if w == nil {
		return nil
	}
	if c := aiAuditProdCache.Load(); c != nil && c.w == w {
		if workerID < 0 {
			return c.ctl
		}
		if workerID < len(c.byWorker) {
			if p := c.byWorker[workerID]; p != nil {
				return p
			}
		}
	}
	return aiDataProducerSlow(w, workerID)
}

// aiDataProducerSlow installs the producer for an id seen for the first
// time, and rebuilds the cache from scratch when the writer has changed.
// The cache is copy-on-write so the fast path above never takes a lock.
func aiDataProducerSlow(w *audit.Writer, workerID int) *audit.Producer {
	aiAuditProdMu.Lock()
	defer aiAuditProdMu.Unlock()

	cur := aiAuditProdCache.Load()
	next := &aiAuditProducers{w: w}
	if cur != nil && cur.w == w {
		next.byWorker = append(next.byWorker, cur.byWorker...)
		next.ctl = cur.ctl
	}
	if next.ctl == nil {
		next.ctl = w.Producer(ctlProducerID, audit.StreamData)
	}
	if workerID < 0 {
		aiAuditProdCache.Store(next)
		return next.ctl
	}
	for len(next.byWorker) <= workerID {
		next.byWorker = append(next.byWorker, nil)
	}
	if next.byWorker[workerID] == nil {
		next.byWorker[workerID] = w.Producer(aiWorkerProducerID(workerID), audit.StreamData)
	}
	aiAuditProdCache.Store(next)
	return next.byWorker[workerID]
}

// aiWorkerProducerID names a relay worker's producer.
func aiWorkerProducerID(workerID int) string {
	return "w" + strconv.Itoa(workerID)
}

// aiAuditRecord starts a data-stream record on the producer for the
// emitting thread. It returns nil when there is no trail to write to,
// which every caller treats as "carry on".
func aiAuditRecord(workerID int) (*audit.Producer, *audit.Record) {
	w := audit.Global()
	if w == nil {
		return nil, nil
	}
	p := aiDataProducer(w, workerID)
	if p == nil {
		return nil, nil
	}
	return p, w.AcquireRecord()
}

// aiCompleteRecord describes one completed request for the trail.
type aiCompleteRecord struct {
	RequestID  string
	TenantID   string
	UserID     string
	KeyID      string
	SvcIdent   string
	ModelName  string
	StatusCode int
	LatencyMs  int64
	TokensIn   int64
	TokensOut  int64
	IsStream   bool
	ErrorCode  string
	WorkerID   int
	// ClientIP, OriginIP and TrustedHops are where the request came from,
	// with the meanings aiAttribute documents.
	ClientIP    string
	OriginIP    string
	TrustedHops int
	// AuthSrc and NetIdentity are what decided the tenant and the
	// network-identity binding that matched, with the meanings aiNetActor
	// documents.
	AuthSrc     int
	NetIdentity string
	// Priority, ClassInfo and Objective are the class the admission gate
	// gave the request: ClassInfo is the data plane's AI_GW_CLASSF_* bits
	// and is 0 when the class stage did not run.
	Priority  int
	ClassInfo int
	Objective string
	// TraceID, ParentSpanID and SessionID are the request's correlation as
	// the datapath captured it (aiCorr): each "" when absent, and then not
	// written. Never identity.
	TraceID      string
	ParentSpanID string
	SessionID    string
}

// The class bits a completion carries, mirroring AI_GW_CLASSF_* in
// sockproxy_ai_gw.h; the low two are the class (AI_GW_CLASS_*).
const (
	aiClassInfoMask       = 0x03
	aiClassInfoSet        = 0x04
	aiClassInfoDenied     = 0x08
	aiClassInfoHintUnread = 0x10
)

// aiClassDetail writes the request's class into a data record. It writes
// nothing for a request the class stage did not run for, so such a record
// reads as it did before classes existed.
func aiClassDetail(d *audit.DataDetail, priority, classInfo int, objective string) {
	if classInfo&aiClassInfoSet == 0 {
		return
	}
	d.PriorityClass = aiClassName(classInfo & aiClassInfoMask)
	d.Priority = int64(priority)
	d.Objective = objective
	d.ObjectiveDenied = classInfo&aiClassInfoDenied != 0
	d.HintNotApplied = classInfo&aiClassInfoHintUnread != 0
}

// emitAIComplete writes the data.ai.complete record for a request whose
// response finished, however it finished. The status and the error code
// the datapath reports decide the outcome; a request that ended badly is
// still a completed request with a bad outcome, not a missing record.
func emitAIComplete(c aiCompleteRecord) bool {
	p, r := aiAuditRecord(c.WorkerID)
	if p == nil {
		return false
	}
	r.Stream = audit.StreamData
	r.EventType = eventAIComplete
	r.RequestID = c.RequestID
	r.Actor = aiAttribute(aiNetActor(aiDataActor(c.TenantID, c.UserID, c.KeyID), c.AuthSrc, c.NetIdentity),
		c.ClientIP, c.OriginIP, c.TrustedHops)
	r.Outcome = audit.Outcome{
		Status: c.StatusCode,
		OK:     c.StatusCode > 0 && c.StatusCode < 400 && prom.AIEndCause(c.ErrorCode) == "",
		Reason: aiCompleteReason(c.StatusCode, c.ErrorCode),
	}
	r.Data = &audit.DataDetail{
		Service:   c.SvcIdent,
		Model:     c.ModelName,
		TokensIn:  c.TokensIn,
		TokensOut: c.TokensOut,
		LatencyMs: c.LatencyMs,
		Stream:    c.IsStream,
	}
	aiClassDetail(r.Data, c.Priority, c.ClassInfo, c.Objective)
	aiCorrDetail(r, c.TraceID, c.ParentSpanID, c.SessionID)
	return p.Emit(r)
}

// aiSettleRecord describes one token charge for the trail.
type aiSettleRecord struct {
	RequestID string
	TenantID  string
	UserID    string
	KeyID     string
	SvcIdent  string
	ModelName string
	TokensIn  int64
	TokensOut int64
	Reserved  int64
	ResEpoch  int64
	Allowed   bool
	WorkerID  int
	// AuthSrc and NetIdentity: as on a completion, so the three records of
	// one request name one actor.
	AuthSrc     int
	NetIdentity string
	// TraceID, ParentSpanID and SessionID are the request's correlation as
	// the datapath captured it (aiCorr): each "" when absent, and then not
	// written. Never identity.
	TraceID      string
	ParentSpanID string
	SessionID    string
}

// emitAISettle writes the data.ai.settle record for a token charge. A
// settle that charges nothing is still recorded: releasing an unspent
// reservation is the event a reader needs to explain why a tenant's
// headroom came back, and leaving it out would make the release look like
// a lost record.
func emitAISettle(s aiSettleRecord) bool {
	p, r := aiAuditRecord(s.WorkerID)
	if p == nil {
		return false
	}
	reason := audit.ReasonOK
	if !s.Allowed {
		reason = audit.ReasonQuota
	}
	r.Stream = audit.StreamData
	r.EventType = eventAISettle
	r.RequestID = s.RequestID
	r.Actor = aiNetActor(aiDataActor(s.TenantID, s.UserID, s.KeyID), s.AuthSrc, s.NetIdentity)
	r.Outcome = audit.Outcome{OK: s.Allowed, Reason: reason}
	r.Data = &audit.DataDetail{
		Service:   s.SvcIdent,
		Model:     s.ModelName,
		TokensIn:  s.TokensIn,
		TokensOut: s.TokensOut,
		Reserved:  s.Reserved,
		ResEpoch:  s.ResEpoch,
	}
	aiCorrDetail(r, s.TraceID, s.ParentSpanID, s.SessionID)
	return p.Emit(r)
}

// aiDenyRecord describes one admission refusal for the trail.
type aiDenyRecord struct {
	RequestID  string
	TenantID   string
	UserID     string
	KeyID      string
	SvcIdent   string
	ModelName  string
	Stage      int
	HTTPStatus int
	ErrorCode  string
	WorkerID   int
	// ClientIP, OriginIP and TrustedHops carry the same attribution a
	// completion does: a refusal is the record most likely to be read as
	// "who did this".
	ClientIP    string
	OriginIP    string
	TrustedHops int
	// AuthSrc and NetIdentity: as on a completion. A refusal a binding
	// caused names the binding with the credential's own auth mode.
	AuthSrc     int
	NetIdentity string
	// Priority, ClassInfo and Objective: as on a completion. ClassInfo is 0
	// for a refusal made before the class stage ran.
	Priority  int
	ClassInfo int
	Objective string
	// TraceID, ParentSpanID and SessionID are the request's correlation as
	// the datapath captured it (aiCorr): each "" when absent, and then not
	// written. Never identity.
	TraceID      string
	ParentSpanID string
	SessionID    string
}

// emitAIDeny writes the sec.ai.deny record for a request the admission
// gate refused. It is security-class, so the writer routes it to the
// dedicated security queue where a flood of ordinary data records cannot
// crowd it out.
//
// The identity fields carry whatever the refusing arm had resolved before
// it refused: a rejected model names its tenant, an unrecognised
// credential names nobody. The credential itself never reaches here.
func emitAIDeny(d aiDenyRecord) bool {
	p, r := aiAuditRecord(d.WorkerID)
	if p == nil {
		return false
	}
	r.Stream = audit.StreamData
	r.Class = audit.ClassSecurity
	r.EventType = eventAIDeny
	r.RequestID = d.RequestID
	r.Actor = aiAttribute(aiNetActor(aiDataActor(d.TenantID, d.UserID, d.KeyID), d.AuthSrc, d.NetIdentity),
		d.ClientIP, d.OriginIP, d.TrustedHops)
	r.Outcome = audit.Outcome{
		Status: d.HTTPStatus,
		OK:     false,
		Reason: aiDenyReason(d.Stage, d.ErrorCode),
	}
	r.Data = &audit.DataDetail{
		Service:  d.SvcIdent,
		Model:    d.ModelName,
		Stage:    aiDenyStage(d.Stage),
		Decision: d.ErrorCode,
	}
	aiClassDetail(r.Data, d.Priority, d.ClassInfo, d.Objective)
	aiCorrDetail(r, d.TraceID, d.ParentSpanID, d.SessionID)
	return p.Emit(r)
}

// aiCorrDetail writes a request's trace and session correlation into its
// record: trace_id and parent_span_id on the envelope, session_id in the
// data detail. Each is written only when present, and as given; the
// datapath has already decided validity (sockproxy_corr.h). It touches
// neither the actor nor span_id.
func aiCorrDetail(r *audit.Record, traceID, parentSpanID, sessionID string) {
	r.TraceID = traceID
	r.ParentSpanID = parentSpanID
	if r.Data != nil {
		r.Data.SessionID = sessionID
	}
}

// aiDataActor builds the actor for a data-path record. The data path
// authenticates with an API key, so a request that named one is apikey and
// a request that named none is not silently promoted to anything else.
func aiDataActor(tenantID, userID, keyID string) audit.Actor {
	a := audit.Actor{Auth: audit.AuthNone, Tenant: tenantID, User: userID, KeyID: keyID}
	if keyID != "" {
		a.Auth = audit.AuthAPIKey
	}
	return a
}

// What decided a request's tenant, mirroring AI_GW_AUTH_SRC_*.
const (
	aiAuthSrcCredential = 0
	aiAuthSrcNetwork    = 1
	aiAuthSrcBearer     = 2
)

// aiNetActor records, on a data-path actor, what the gate said decided the
// tenant and the network-identity binding that matched the source.
//
// A bearer token the gateway validated reads as bearer: the token mints no
// key id, so without this the actor would read as unauthenticated.
//
// netIdentity is the binding that matched the request's source and is
// recorded whenever one did. authSrc says whether it decided the tenant:
// only then does the actor read as network-authenticated. A binding that
// matched beside a credential leaves the credential's own mode in place, so
// "who vouched for this tenant" always has one answer. The network mode is
// not written without a binding to name: a mode nothing can be traced to
// would be a claim, not a record.
func aiNetActor(a audit.Actor, authSrc int, netIdentity string) audit.Actor {
	if authSrc == aiAuthSrcBearer {
		a.Auth = audit.AuthBearer
	}
	if netIdentity == "" {
		return a
	}
	a.NetIdentity = netIdentity
	if authSrc == aiAuthSrcNetwork {
		a.Auth = audit.AuthNetwork
	}
	return a
}

// aiAttribute records where a request came from on a data-path actor.
//
// clientIP is the socket peer, which nothing a client sends can change.
// originIP is the address the datapath ATTRIBUTED the request to, and is
// empty when no attribution ran -- which is not the same statement as "the
// origin is the peer", so it is left empty rather than defaulted to the
// peer. trustedHops is how many hops of ours the walk stepped past, and is
// dropped where no origin was derived: a hop count on a record that
// decided nothing would read as a measurement.
func aiAttribute(a audit.Actor, clientIP, originIP string, trustedHops int) audit.Actor {
	a.Remote = clientIP
	if originIP == "" {
		return a
	}
	a.Origin = originIP
	a.TrustedHops = trustedHops
	return a
}

// Gate stages, mirroring ai_gw_admit_stage_t. The names are the record's
// wire values, so they are spelled here once and not derived from the
// numbers anywhere else.
const (
	aiStageNone = iota
	aiStageAuth
	aiStageConflict
	aiStageRateLimit
	aiStageReserve
	// aiStageCapacity is the service/endpoint capacity gate, which refuses
	// after policy admitted the request and reports through its own frame.
	aiStageCapacity
	// aiStageObjective is the class stage on a rule that is strict about
	// objectives: the request named one it may not use.
	aiStageObjective
	// aiStageRoute and aiStageFraming refuse outside the gate's verdict
	// frame, before any backend is chosen: no pool serves the named model,
	// no rule matches, or an L7 policy rejects (route); the request cannot
	// be admitted as framed, an oversized body or a model out of reach
	// (framing).
	aiStageRoute
	aiStageFraming
	// aiStageSecurity is a content-security scanner's block (LlamaFirewall),
	// also outside the verdict frame.
	aiStageSecurity
)

// aiDenyStage names the gate stage that refused the request.
func aiDenyStage(stage int) string {
	switch stage {
	case aiStageAuth:
		return "auth"
	case aiStageConflict:
		return "conflict"
	case aiStageRateLimit:
		return "ratelimit"
	case aiStageReserve:
		return "reserve"
	case aiStageCapacity:
		return "capacity"
	case aiStageObjective:
		return "objective"
	case aiStageRoute:
		return "route"
	case aiStageFraming:
		return "framing"
	case aiStageSecurity:
		return "security"
	}
	return "keyless"
}

// aiDenyReason maps a refusal onto the envelope's closed reason vocabulary.
//
// Two stages bundle refusals that a reader has to be able to tell apart,
// so within those the error code decides.
//
// The auth stage covers a credential that did not validate, a valid
// credential asking for a model it may not have, and a policy store that
// could not answer at all. Filing a store outage as an authentication
// failure would put an infrastructure fault in front of the on-call
// engineer as a break-in attempt.
//
// It also covers the two refusals a network-identity binding adds. A valid
// credential used from a network bound to another tenant is the caller
// being somewhere it may not be, not a credential that failed: authz. A
// binding that could not be resolved on a service that fails closed is the
// gateway's own fault, filed where the policy-store outage is.
//
// The rate-limit stage covers both a request-rate refusal and a token
// quota that is already spent. They are different resources with different
// remedies — one is throttling, the other is a budget — and the stage
// cannot distinguish them.
func aiDenyReason(stage int, errorCode string) audit.Reason {
	switch stage {
	case aiStageAuth:
		switch errorCode {
		case "model_not_allowed", "network_tenant_mismatch":
			return audit.ReasonAuthz
		case "policy_store_unavailable", "netid_unavailable":
			return audit.ReasonAdmission
		}
		return audit.ReasonAuth
	case aiStageConflict:
		return audit.ReasonAdmission
	case aiStageRateLimit:
		if aiTokenQuotaCode(errorCode) {
			return audit.ReasonQuota
		}
		return audit.ReasonRateLimit
	case aiStageReserve:
		return audit.ReasonQuota
	case aiStageCapacity:
		// Backend saturation, not the caller's budget and not throttling:
		// an admission decision, and the decision field names which
		// ceiling refused (admission_capacity, admission_no_capacity).
		return audit.ReasonAdmission
	case aiStageObjective:
		// A caller asking for something it is not entitled to.
		return audit.ReasonAuthz
	case aiStageRoute, aiStageFraming, aiStageSecurity:
		// Nothing serves the request as asked, or a scanner refused its
		// content: an admission decision, and the decision field names
		// which (model_unavailable, no_route, request_body_too_large,
		// llamafirewall_block, ...).
		return audit.ReasonAdmission
	}
	return audit.ReasonAdmission
}

// aiTokenQuotaCode reports whether a refusal code names a token budget
// rather than a request rate.
func aiTokenQuotaCode(errorCode string) bool {
	switch errorCode {
	case "token_quota_exceeded", "token_quota_would_exceed":
		return true
	}
	return false
}

// aiCompleteReason maps a finished response onto the reason vocabulary.
// The datapath's error code is preferred where it names a transport
// outcome, because the status alone cannot tell a backend that refused
// from a client that walked away. Every end code (prom.AIEndCodes, the
// codes of an answer the client did not get whole) has its reason here:
// the client's three are client_abort, a cut by a cap or a reaper is a
// timeout, the engine dying ended the backend connection under the answer,
// and the rule's listener going away is the gateway's own doing,
// gateway_shutdown (the metric reads cause="gateway"; no backend failed).
func aiCompleteReason(status int, errorCode string) audit.Reason {
	switch errorCode {
	case "client_abort", "client_stall", "client_abort_before_answer":
		return audit.ReasonClientAbort
	case "timeout", "max_stream_duration_exceeded", "pd_decode_stream_timeout", "pd_idle_timeout":
		return audit.ReasonTimeout
	case "backend_conn", "backend_died":
		return audit.ReasonBackendConn
	case "listener_closed":
		return audit.ReasonGatewayShutdown
	case "backend_tls":
		return audit.ReasonBackendTLS
	case "upstream_error":
		return audit.ReasonUpstreamError
	}
	if status >= 400 {
		return audit.ReasonUpstreamError
	}
	return audit.ReasonOK
}
