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
package handler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	auditops "github.com/loxilb-io/loxilb/api/restapi/operations/audit"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/audit/syslog"
)

// auditPolicyFloor is the deployment profile's floor. It is startup-only:
// the profile that sets it is the thing the operator is being held to, so
// it is not reachable from the management API that the floor constrains.
var auditPolicyFloor atomic.Pointer[audit.PolicyFloor]

// SetAuditPolicyFloor installs the profile's floor. The zero floor, which
// is what an unset profile leaves, constrains nothing.
func SetAuditPolicyFloor(f audit.PolicyFloor) { auditPolicyFloor.Store(&f) }

// AuditPolicyFloor returns the floor in force.
func AuditPolicyFloor() audit.PolicyFloor {
	if p := auditPolicyFloor.Load(); p != nil {
		return *p
	}
	return audit.PolicyFloor{}
}

// auditSink holds the configured sink, the settings it was built from and
// the tailer that feeds it from the trail. The sink is replaced wholesale
// on a change: a half-reconfigured connection to a receiver is worse than
// a closed one.
var auditSink struct {
	mu     sync.Mutex
	cfg    syslog.Config
	sink   *syslog.Sink
	tailer *audit.SinkTailer
	// named are the secondary sinks of /audit/sinks/{name}.
	named map[string]*auditNamedSink
}

// AuditSink returns the configured sink, or nil when none is configured.
func AuditSink() *syslog.Sink {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	return auditSink.sink
}

// AuditGetPolicy answers GET /audit/policy. Like the status read it is not
// audited: it is a read of configuration the trail already records every
// change to, and a record per poll would bury the records that matter.
func AuditGetPolicy(params auditops.GetAuditPolicyParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit policy %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	w := AuditWriter()
	if w == nil {
		return auditops.NewGetAuditPolicyOK().WithPayload(&models.AuditPolicy{})
	}
	return auditops.NewGetAuditPolicyOK().WithPayload(auditPolicyModel(w.Policy()))
}

// AuditPostPolicy answers POST /audit/policy. The gate ahead of it has
// already written the durable intent, so by the time this runs the
// intention to change the policy is on disk whether or not the change
// succeeds.
func AuditPostPolicy(params auditops.PostAuditPolicyParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit policy %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	w := AuditWriter()
	if w == nil {
		return auditops.NewPostAuditPolicyServiceUnavailable()
	}
	if params.Attr == nil {
		return auditops.NewPostAuditPolicyBadRequest()
	}
	next := auditPolicyFrom(params.Attr, w.Policy())
	changed, err := w.SetPolicy(params.HTTPRequest.Context(), next, AuditPolicyFloor())
	var fe *audit.ErrPolicyFloor
	switch {
	case err == nil:
		no := false
		AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
			d.ChangedFields = changed
			d.FloorRejected = &no
		})
		return auditops.NewPostAuditPolicyNoContent()
	case errors.As(err, &fe):
		// A floor violation answers 400, not 403. The caller was
		// authorized; the profile refused the values. The gate re-types
		// every 403 as an authorization denial, so answering 403 here
		// would file a refused policy change as a failed login-adjacent
		// security event and lose the mgmt.audit.policy result that says
		// which knob was refused. The fields travel into that result, so
		// the trail names the knob rather than merely recording that
		// something was refused.
		yes := true
		AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
			d.ChangedFields = fe.Fields
			d.FloorRejected = &yes
		})
		return auditops.NewPostAuditPolicyBadRequest()
	default:
		tk.LogIt(tk.LogError, "api: audit policy refused: %v\n", err)
		return auditops.NewPostAuditPolicyBadRequest()
	}
}

// AuditGetSink answers GET /audit/sink with the configuration and what is
// known about the session. Certificate material is named by path and never
// served.
func AuditGetSink(params auditops.GetAuditSinkParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit sink %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	auditSink.mu.Lock()
	cfg, s := auditSink.cfg, auditSink.sink
	auditSink.mu.Unlock()
	return auditops.NewGetAuditSinkOK().WithPayload(auditSinkModel(cfg, s))
}

// AuditPostSink answers POST /audit/sink. A configuration that cannot be
// built — no CA bundle, an unreadable one, half a client keypair — is
// refused here rather than accepted and left failing at connect time,
// because a sink that is configured but cannot verify its receiver reads
// as working until the day it matters.
func AuditPostSink(params auditops.PostAuditSinkParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit sink %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	if params.Attr == nil {
		return auditops.NewPostAuditSinkBadRequest()
	}
	// Without a writer there is no trail to follow; the sink is held as
	// configured and sends nothing.
	changed, cfg, err := setAuditComplianceSink(params.HTTPRequest.Context(), params.Attr, false)
	switch {
	case err == nil:
	case errors.Is(err, errAuditSinkRefused):
		tk.LogIt(tk.LogError, "api: audit sink %v\n", err)
		return auditops.NewPostAuditSinkBadRequest()
	default:
		tk.LogIt(tk.LogError, "api: audit sink: %v\n", err)
		return auditops.NewPostAuditSinkServiceUnavailable()
	}
	AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
		d.ChangedFields = changed
		// The endpoint and the trust anchor are named, never their
		// contents: the record says where the trail is being sent and
		// what vouches for the receiver.
		d.Endpoint = cfg.Address
		d.TLSCAID = cfg.CABundlePath
	})
	return auditops.NewPostAuditSinkNoContent()
}

// setAuditComplianceSink configures the compliance sink from a, or ends it
// when a is not enabled, and says what the change altered. The sink is
// replaced wholesale. needTrail refuses a sink there is no trail to feed,
// where the default is to hold it as configured. ctx bounds the wait for
// the replaced sink to end.
func setAuditComplianceSink(ctx context.Context, a *models.AuditSink, needTrail bool) ([]string, syslog.Config, error) {
	none := syslog.Config{}
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	changed := auditSinkChangedFields(auditSink.cfg, a)

	// The tailer finishes the submission it is in before it ends, so the
	// wait is bounded by the sink's own timeouts and by the caller's.
	stopCtx, cancel := context.WithTimeout(ctx, auditSinkStopTimeout)
	defer cancel()

	if !a.Enabled {
		if err := stopAuditSinkLocked(stopCtx); err != nil {
			return nil, none, fmt.Errorf("%w: the tailer did not stop: %v", errAuditSinkUnavailable, err)
		}
		auditSink.sink, auditSink.cfg = nil, none
		return changed, none, nil
	}

	// The two numbers are checked here, on the value as it arrived, and not
	// after the conversion below: int(x) does not fail on a value too large
	// for an int, it yields a different number, so a check afterwards would
	// be checking something the caller never sent.
	if a.Facility < 0 || a.Facility > syslog.MaxFacility {
		return nil, none, fmt.Errorf("%w: facility %d outside 0..%d", errAuditSinkRefused,
			a.Facility, syslog.MaxFacility)
	}
	if a.MaxFrameBytes < 0 || a.MaxFrameBytes > syslog.MaxFrameBytesLimit {
		return nil, none, fmt.Errorf("%w: max_frame_bytes %d outside 0..%d", errAuditSinkRefused,
			a.MaxFrameBytes, syslog.MaxFrameBytesLimit)
	}
	w := AuditWriter()
	if w == nil && needTrail {
		return nil, none, errAuditTrailNotRunning
	}

	cfg := syslog.Config{
		Address:        a.Address,
		CABundlePath:   a.CaBundlePath,
		ServerName:     a.ServerName,
		ClientCertPath: a.ClientCertPath,
		ClientKeyPath:  a.ClientKeyPath,
		MaxFrameBytes:  int(a.MaxFrameBytes),
		Facility:       int(a.Facility),
		Logf:           func(f string, v ...any) { tk.LogIt(tk.LogInfo, "audit sink: "+f+"\n", v...) },
	}
	s, err := syslog.New(cfg)
	if err != nil {
		return nil, none, fmt.Errorf("%w: %v", errAuditSinkRefused, err)
	}
	// The old tailer has ended, and saved its cursor, before the new one
	// reads it. One that has not ended leaves the change refused: the
	// configuration reported stays the one in force.
	if err := stopAuditSinkLocked(stopCtx); err != nil {
		return nil, none, fmt.Errorf("%w: the tailer did not stop: %v", errAuditSinkUnavailable, err)
	}
	auditSink.sink, auditSink.cfg = s, cfg
	if w != nil {
		t, err := newAuditSinkTailer(w, auditComplianceSink, s, true, audit.SinkFilter{})
		if err != nil {
			auditSink.sink, auditSink.cfg = nil, none
			return nil, none, fmt.Errorf("%w: %v", errAuditSinkUnavailable, err)
		}
		t.Start()
		auditSink.tailer = t
		publishAuditSinksLocked()
	}
	return changed, cfg, nil
}

// AuditPostRotate answers POST /audit/rotate: seal the active segment and
// open the next.
func AuditPostRotate(params auditops.PostAuditRotateParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit rotate %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	w := AuditWriter()
	if w == nil {
		return auditops.NewPostAuditRotateServiceUnavailable()
	}
	sealed, opened, err := w.RotateNow(params.HTTPRequest.Context())
	if err != nil {
		tk.LogIt(tk.LogError, "api: audit rotate: %v\n", err)
		return auditops.NewPostAuditRotateServiceUnavailable()
	}
	AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
		d.SealedSegmentUUID = sealed
		d.NewSegmentUUID = opened
	})
	return auditops.NewPostAuditRotateOK().WithPayload(&models.AuditRotateResult{
		SealedSegmentUUID: sealed,
		NewSegmentUUID:    opened,
	})
}

// ── model mapping ─────────────────────────────────────────────────────────

func auditPolicyModel(p audit.Policy) *models.AuditPolicy {
	return &models.AuditPolicy{
		MaxSegmentBytes:          p.MaxSegmentBytes,
		MaxSegmentAgeSeconds:     int64(p.MaxSegmentAge / time.Second),
		RetentionMaxAgeSeconds:   int64(p.Retention.MaxAge / time.Second),
		RetentionMaxBytes:        p.Retention.MaxBytes,
		RetentionReserveBytes:    p.Retention.ReserveBytes,
		RetentionMaxPrunePerPass: int64(p.Retention.MaxPrunePerPass),
	}
}

// auditPolicyFrom builds the policy the body asks for. The body is a
// replacement, not a patch: every field is carried, so a caller cannot
// change one knob by omission of the rest.
func auditPolicyFrom(a *models.AuditPolicy, _ audit.Policy) audit.Policy {
	return audit.Policy{
		MaxSegmentBytes: a.MaxSegmentBytes,
		MaxSegmentAge:   time.Duration(a.MaxSegmentAgeSeconds) * time.Second,
		Retention: audit.Retention{
			MaxAge:          time.Duration(a.RetentionMaxAgeSeconds) * time.Second,
			MaxBytes:        a.RetentionMaxBytes,
			ReserveBytes:    a.RetentionReserveBytes,
			MaxPrunePerPass: int(a.RetentionMaxPrunePerPass),
		},
	}
}

func auditSinkModel(cfg syslog.Config, s *syslog.Sink) *models.AuditSink {
	out := &models.AuditSink{
		Address:        cfg.Address,
		CaBundlePath:   cfg.CABundlePath,
		ServerName:     cfg.ServerName,
		ClientCertPath: cfg.ClientCertPath,
		ClientKeyPath:  cfg.ClientKeyPath,
		MaxFrameBytes:  int64(cfg.MaxFrameBytes),
		Facility:       int64(cfg.Facility),
	}
	if s == nil {
		return out
	}
	st := s.Stats()
	out.Enabled = true
	out.Connected = st.Connected
	out.Submitted = int64(st.Submitted)
	out.Truncated = int64(st.Truncated)
	out.WriteErrors = int64(st.WriteErrors)
	out.LastError = st.LastError
	return out
}

// auditSinkChangedFields names what a sink change actually alters, for the
// record's changed_fields.
func auditSinkChangedFields(old syslog.Config, next *models.AuditSink) []string {
	var out []string
	add := func(name string, changed bool) {
		if changed {
			out = append(out, name)
		}
	}
	enabledBefore := old.Address != ""
	add("enabled", enabledBefore != next.Enabled)
	add("address", old.Address != next.Address)
	add("ca_bundle_path", old.CABundlePath != next.CaBundlePath)
	add("server_name", old.ServerName != next.ServerName)
	add("client_cert_path", old.ClientCertPath != next.ClientCertPath)
	add("client_key_path", old.ClientKeyPath != next.ClientKeyPath)
	add("max_frame_bytes", int64(old.MaxFrameBytes) != next.MaxFrameBytes)
	add("facility", int64(old.Facility) != next.Facility)
	return out
}
