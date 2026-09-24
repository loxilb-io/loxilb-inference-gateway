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
	r.Actor = aiDataActor(c.TenantID, c.UserID, c.KeyID)
	r.Outcome = audit.Outcome{
		Status: c.StatusCode,
		OK:     c.StatusCode > 0 && c.StatusCode < 400,
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
	r.Actor = aiDataActor(s.TenantID, s.UserID, s.KeyID)
	r.Outcome = audit.Outcome{OK: s.Allowed, Reason: reason}
	r.Data = &audit.DataDetail{
		Service:   s.SvcIdent,
		Model:     s.ModelName,
		TokensIn:  s.TokensIn,
		TokensOut: s.TokensOut,
		Reserved:  s.Reserved,
		ResEpoch:  s.ResEpoch,
	}
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
	r.Actor = aiDataActor(d.TenantID, d.UserID, d.KeyID)
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
	return p.Emit(r)
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

// Gate stages, mirroring ai_gw_admit_stage_t. The names are the record's
// wire values, so they are spelled here once and not derived from the
// numbers anywhere else.
const (
	aiStageNone = iota
	aiStageAuth
	aiStageConflict
	aiStageRateLimit
	aiStageReserve
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
	}
	return "keyless"
}

// aiDenyReason maps a refusal onto the envelope's closed reason vocabulary.
//
// The stage alone is not enough for the auth stage, which bundles three
// genuinely different refusals: a credential that did not validate, a
// valid credential asking for a model it may not have, and a policy store
// that could not answer at all. Filing a store outage as an authentication
// failure would put an infrastructure fault in front of the on-call
// engineer as a break-in attempt, so the error code decides within that
// stage. Every other stage means exactly one thing.
func aiDenyReason(stage int, errorCode string) audit.Reason {
	switch stage {
	case aiStageAuth:
		switch errorCode {
		case "model_not_allowed":
			return audit.ReasonAuthz
		case "policy_store_unavailable":
			return audit.ReasonAdmission
		}
		return audit.ReasonAuth
	case aiStageConflict:
		return audit.ReasonAdmission
	case aiStageRateLimit:
		return audit.ReasonRateLimit
	case aiStageReserve:
		return audit.ReasonQuota
	}
	return audit.ReasonAdmission
}

// aiCompleteReason maps a finished response onto the reason vocabulary.
// The datapath's error code is preferred where it names a transport
// outcome, because the status alone cannot tell a backend that refused
// from a client that walked away.
func aiCompleteReason(status int, errorCode string) audit.Reason {
	switch errorCode {
	case "client_abort":
		return audit.ReasonClientAbort
	case "timeout":
		return audit.ReasonTimeout
	case "backend_conn":
		return audit.ReasonBackendConn
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
