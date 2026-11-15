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
	"math"
	"net/http"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	auditops "github.com/loxilb-io/loxilb/api/restapi/operations/audit"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/audit/syslog"
)

// auditComplianceSink names the sink /audit/sink configures: the one that
// receives every record. Its cursor is kept under this name whatever the
// receiver's address is, so pointing the sink at another receiver continues
// where the trail was left and does not send it again from the start.
const auditComplianceSink = "compliance"

// auditSinkStopTimeout bounds the wait for a tailer to end. A tailer that
// is asked to stop finishes the submission it is in first, and that is at
// most one dial and one write.
const auditSinkStopTimeout = syslog.DefaultDialTimeout + syslog.DefaultWriteTimeout + 5*time.Second

// auditSinkCloseShare is how much of a shutdown's time the tailer may take
// before the writer is closed regardless. A tailer cut off here has not
// saved its cursor, which costs a re-send of at most one batch at the next
// start; a writer cut off loses records.
const auditSinkCloseShare = 2 * time.Second

// syslogSubmitter puts a syslog sink behind the tailer's Submitter, and
// says in the tailer's terms how a submission failed.
type syslogSubmitter struct{ s *syslog.Sink }

func (a syslogSubmitter) Submit(line []byte, xseq, epoch uint64) error {
	var err error
	if xseq == 0 {
		err = a.s.Submit(line)
	} else {
		err = a.s.SubmitExport(line, xseq, epoch)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syslog.ErrRejected):
		return fmt.Errorf("%w: %w", audit.ErrSubmitRejected, err)
	case errors.Is(err, syslog.ErrNotAttempted), errors.Is(err, syslog.ErrNoEnterpriseNumber):
		// A sink with no enterprise number refuses before it frames
		// anything. That is a fault of the configuration and not of the
		// record, so the record is kept and tried again rather than
		// skipped.
		return fmt.Errorf("%w: %w", audit.ErrSubmitNotAttempted, err)
	}
	return err
}

func (a syslogSubmitter) Peer() (string, time.Time, bool) { return a.s.Peer() }

func (a syslogSubmitter) Unconfirmed() (int, bool) { return a.s.Unconfirmed() }

func (a syslogSubmitter) Broken() bool { return a.s.Broken() }

// newAuditSinkTailer builds the tailer that feeds s from w's trail. It is
// not started: building it is what checks the name and the filter, and a
// caller replacing a sink wants that answer before it stops the old one.
func newAuditSinkTailer(w *audit.Writer, name string, s *syslog.Sink, compliance bool, filter audit.SinkFilter) (*audit.SinkTailer, error) {
	return audit.NewSinkTailer(audit.SinkTailerConfig{
		Name:       name,
		Dir:        w.Dir(),
		Submitter:  syslogSubmitter{s},
		Compliance: compliance,
		Filter:     filter,
		Emit:       w.EmitSystem,
		Logf:       func(f string, v ...any) { tk.LogIt(tk.LogInfo, f+"\n", v...) },
		Fault:      audit.FaultArmed,
	})
}

// auditSinkTailers is every running tailer, for the reader that must not
// take auditSink.mu: the writer's pruner asks where the sinks are from the
// writer goroutine, and a handler holding that lock may be waiting for a
// tailer which is itself waiting for the writer.
var auditSinkTailers atomic.Pointer[[]*audit.SinkTailer]

// publishAuditSinksLocked refreshes auditSinkTailers after the set of
// tailers changed. The caller holds auditSink.mu.
func publishAuditSinksLocked() {
	var ts []*audit.SinkTailer
	if auditSink.tailer != nil {
		ts = append(ts, auditSink.tailer)
	}
	for _, ns := range auditSink.named {
		ts = append(ts, ns.tailer)
	}
	auditSinkTailers.Store(&ts)
}

// auditSinkProgress tells the writer where each sink is.
func auditSinkProgress() []audit.SinkProgress {
	p := auditSinkTailers.Load()
	if p == nil {
		return nil
	}
	out := make([]audit.SinkProgress, 0, len(*p))
	for _, t := range *p {
		out = append(out, t.Progress())
	}
	return out
}

// stopAuditSinkLocked ends the tailer, waits for it and drops the sink's
// connection. The tailer is forgotten only once it has ended: two tailers
// over one cursor would each send what the other already sent. The caller
// holds auditSink.mu.
func stopAuditSinkLocked(ctx context.Context) error {
	if auditSink.tailer != nil {
		if err := auditSink.tailer.Stop(ctx); err != nil {
			return err
		}
		auditSink.tailer = nil
		publishAuditSinksLocked()
	}
	if auditSink.sink != nil {
		_ = auditSink.sink.Close()
	}
	return nil
}

// auditNamedSink is one secondary sink: a receiver, what it selects from
// the trail, and the tailer that feeds it.
type auditNamedSink struct {
	cfg    syslog.Config
	filter audit.SinkFilter
	sink   *syslog.Sink
	tailer *audit.SinkTailer
}

// stop ends the sink's tailer, waits for it and drops the connection.
func (ns *auditNamedSink) stop(ctx context.Context) error {
	if err := ns.tailer.Stop(ctx); err != nil {
		return err
	}
	_ = ns.sink.Close()
	return nil
}

// MaxEnterpriseNumber is the largest private enterprise number a sink
// takes: the number is carried as 32 bits.
const MaxEnterpriseNumber = math.MaxUint32

// AuditGetNamedSink answers GET /audit/sinks/{name}.
func AuditGetNamedSink(params auditops.GetAuditSinksNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit sink %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	auditSink.mu.Lock()
	ns := auditSink.named[params.Name]
	auditSink.mu.Unlock()
	if ns == nil {
		return auditops.NewGetAuditSinksNameNotFound().WithPayload(&models.Error{
			Code: http.StatusNotFound, Message: "no audit sink of that name"})
	}
	return auditops.NewGetAuditSinksNameOK().WithPayload(auditNamedSinkModel(params.Name, ns))
}

// errAuditSinkRefused and errAuditSinkUnavailable say why a sink was not
// configured: the configuration cannot be taken, or it could be and the
// gateway cannot act on it now.
var (
	errAuditSinkRefused     = errors.New("refused")
	errAuditSinkUnavailable = errors.New("unavailable")
)

// errAuditTrailNotRunning is the unavailable a sink meets when there is no
// trail for it to follow.
var errAuditTrailNotRunning = fmt.Errorf("%w: audit trail not running", errAuditSinkUnavailable)

// AuditPutNamedSink answers PUT /audit/sinks/{name}.
func AuditPutNamedSink(params auditops.PutAuditSinksNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit sink %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	name := params.Name
	if params.Attr == nil {
		return auditops.NewPutAuditSinksNameBadRequest()
	}
	changed, cfg, err := setAuditNamedSink(params.HTTPRequest.Context(), name, params.Attr)
	switch {
	case err == nil:
	case errors.Is(err, errAuditSinkRefused):
		tk.LogIt(tk.LogError, "api: audit sink %s %v\n", name, err)
		return auditops.NewPutAuditSinksNameBadRequest()
	default:
		if !errors.Is(err, errAuditTrailNotRunning) {
			tk.LogIt(tk.LogError, "api: audit sink %s: %v\n", name, err)
		}
		return auditops.NewPutAuditSinksNameServiceUnavailable()
	}
	AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
		d.ChangedFields = changed
		d.Endpoint = cfg.Address
		d.TLSCAID = cfg.CABundlePath
	})
	return auditops.NewPutAuditSinksNameNoContent()
}

// setAuditNamedSink configures the secondary sink name from a, replacing
// one of that name, and says what the change altered. Everything that can
// refuse the configuration is checked before the sink it replaces is
// touched, so a refused change leaves that sink running as it was. ctx
// bounds the wait for the replaced sink to end.
func setAuditNamedSink(ctx context.Context, name string, a *models.AuditNamedSink) ([]string, syslog.Config, error) {
	refuse := func(format string, v ...any) ([]string, syslog.Config, error) {
		return nil, syslog.Config{}, fmt.Errorf("%w: "+format, append([]any{errAuditSinkRefused}, v...)...)
	}
	// The name compliance belongs to the sink of /audit/sink: a secondary
	// under it would share that sink's cursor.
	if !audit.ValidSinkName(name) || name == auditComplianceSink {
		return refuse("the name is reserved or not 1 to 64 of a-z, 0-9, '-' and '_'")
	}
	w := AuditWriter()
	if w == nil {
		return nil, syslog.Config{}, errAuditTrailNotRunning
	}
	// The numbers are checked as they arrived, before any conversion.
	if a.Facility < 0 || a.Facility > syslog.MaxFacility {
		return refuse("facility %d outside 0..%d", a.Facility, syslog.MaxFacility)
	}
	if a.MaxFrameBytes < 0 || a.MaxFrameBytes > syslog.MaxFrameBytesLimit {
		return refuse("max_frame_bytes %d outside 0..%d", a.MaxFrameBytes, syslog.MaxFrameBytesLimit)
	}
	// A secondary sink numbers what it sends, and the number travels in an
	// element that only a private enterprise number can qualify.
	if a.EnterpriseNumber < 1 || a.EnterpriseNumber > MaxEnterpriseNumber {
		return refuse("enterprise_number %d outside 1..%d", a.EnterpriseNumber, int64(MaxEnterpriseNumber))
	}
	var filter audit.SinkFilter
	if f := a.Filter; f != nil {
		if f.DataSample < 0 {
			return refuse("filter.data_sample %d is negative", f.DataSample)
		}
		for _, s := range f.Streams {
			filter.Streams = append(filter.Streams, audit.Stream(s))
		}
		filter.Services = f.Services
		filter.Outcome = f.Outcome
		filter.DataSample = uint64(f.DataSample)
	}
	cfg := syslog.Config{
		Address:          a.Address,
		CABundlePath:     a.CaBundlePath,
		ServerName:       a.ServerName,
		ClientCertPath:   a.ClientCertPath,
		ClientKeyPath:    a.ClientKeyPath,
		MaxFrameBytes:    int(a.MaxFrameBytes),
		Facility:         int(a.Facility),
		EnterpriseNumber: uint32(a.EnterpriseNumber),
		Logf:             func(f string, v ...any) { tk.LogIt(tk.LogInfo, "audit sink "+name+": "+f+"\n", v...) },
	}
	s, err := syslog.New(cfg)
	if err != nil {
		return refuse("%v", err)
	}
	t, err := newAuditSinkTailer(w, name, s, false, filter)
	if err != nil {
		return refuse("%v", err)
	}

	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	old := auditSink.named[name]
	changed := auditNamedSinkChangedFields(old, cfg, filter)
	if old != nil {
		stopCtx, cancel := context.WithTimeout(ctx, auditSinkStopTimeout)
		defer cancel()
		if err := old.stop(stopCtx); err != nil {
			return nil, syslog.Config{}, fmt.Errorf("%w: the tailer did not stop: %v", errAuditSinkUnavailable, err)
		}
	}
	if auditSink.named == nil {
		auditSink.named = map[string]*auditNamedSink{}
	}
	t.Start()
	auditSink.named[name] = &auditNamedSink{cfg: cfg, filter: filter, sink: s, tailer: t}
	publishAuditSinksLocked()
	return changed, cfg, nil
}

// AuditDeleteNamedSink answers DELETE /audit/sinks/{name}. The sink ends;
// its place in the trail and its export sequence stay on disk, as they do
// for the compliance sink when it is disabled. A sink configured under the
// same name later continues both, which is what keeps a number from being
// used twice under one epoch: an epoch is taken from the clock, and a sink
// removed and made again within one tick of it would otherwise start the
// same epoch over.
func AuditDeleteNamedSink(params auditops.DeleteAuditSinksNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit sink %s API called. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.URL)
	name := params.Name
	address, found, err := removeAuditNamedSink(params.HTTPRequest.Context(), name)
	if err != nil {
		tk.LogIt(tk.LogError, "api: audit sink %s: %v\n", name, err)
		return auditops.NewDeleteAuditSinksNameServiceUnavailable()
	}
	if !found {
		return auditops.NewDeleteAuditSinksNameNotFound().WithPayload(&models.Error{
			Code: http.StatusNotFound, Message: "no audit sink of that name"})
	}
	AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
		d.ChangedFields = []string{"enabled"}
		d.Endpoint = address
	})
	return auditops.NewDeleteAuditSinksNameNoContent()
}

// removeAuditNamedSink ends the secondary sink name and says where it was
// sending. ctx bounds the wait for it to end.
func removeAuditNamedSink(ctx context.Context, name string) (address string, found bool, err error) {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	ns := auditSink.named[name]
	if ns == nil {
		return "", false, nil
	}
	stopCtx, cancel := context.WithTimeout(ctx, auditSinkStopTimeout)
	defer cancel()
	if err := ns.stop(stopCtx); err != nil {
		return "", true, fmt.Errorf("%w: the tailer did not stop: %v", errAuditSinkUnavailable, err)
	}
	delete(auditSink.named, name)
	publishAuditSinksLocked()
	return ns.cfg.Address, true, nil
}

func auditSinkCursorModel(p audit.Position) *models.AuditSinkCursor {
	return &models.AuditSinkCursor{SegmentUUID: p.SegmentUUID, Seq: int64(p.Seq)}
}

func auditNamedSinkModel(name string, ns *auditNamedSink) *models.AuditNamedSink {
	st, ts := ns.sink.Stats(), ns.tailer.Stats()
	out := &models.AuditNamedSink{
		Name:             name,
		Address:          ns.cfg.Address,
		CaBundlePath:     ns.cfg.CABundlePath,
		ServerName:       ns.cfg.ServerName,
		ClientCertPath:   ns.cfg.ClientCertPath,
		ClientKeyPath:    ns.cfg.ClientKeyPath,
		MaxFrameBytes:    int64(ns.cfg.MaxFrameBytes),
		Facility:         int64(ns.cfg.Facility),
		EnterpriseNumber: int64(ns.cfg.EnterpriseNumber),
		State:            ts.State,
		Cursor:           auditSinkCursorModel(ts.Cursor.Position),
		XseqHigh:         int64(ts.Cursor.XseqHigh),
		XseqEpoch:        int64(ts.Cursor.XseqEpoch),
		Submitted:        int64(ts.Submitted),
		Filtered:         int64(ts.Filtered),
		Resent:           int64(ts.Resent),
		Poison:           int64(ts.Poison),
		Truncated:        int64(st.Truncated),
		WriteErrors:      int64(ts.SubmitErrors),
		LagDrops:         int64(ts.LagDrops),
		LastError:        ts.LastError,
	}
	f := ns.filter
	if len(f.Streams) > 0 || len(f.Services) > 0 || f.Outcome != "" || f.DataSample > 1 {
		mf := &models.AuditSinkFilter{Services: f.Services, Outcome: f.Outcome, DataSample: int64(f.DataSample)}
		for _, s := range f.Streams {
			mf.Streams = append(mf.Streams, string(s))
		}
		out.Filter = mf
	}
	return out
}

// auditNamedSinkChangedFields names what a secondary sink change alters.
func auditNamedSinkChangedFields(old *auditNamedSink, cfg syslog.Config, filter audit.SinkFilter) []string {
	if old == nil {
		return []string{"enabled"}
	}
	var out []string
	add := func(name string, changed bool) {
		if changed {
			out = append(out, name)
		}
	}
	o := old.cfg
	add("address", o.Address != cfg.Address)
	add("ca_bundle_path", o.CABundlePath != cfg.CABundlePath)
	add("server_name", o.ServerName != cfg.ServerName)
	add("client_cert_path", o.ClientCertPath != cfg.ClientCertPath)
	add("client_key_path", o.ClientKeyPath != cfg.ClientKeyPath)
	add("max_frame_bytes", o.MaxFrameBytes != cfg.MaxFrameBytes)
	add("facility", o.Facility != cfg.Facility)
	add("enterprise_number", o.EnterpriseNumber != cfg.EnterpriseNumber)
	add("filter", !reflect.DeepEqual(old.filter, filter))
	return out
}

// auditSinkStatuses reports every sink that follows the trail, the
// compliance sink first and the others by name. segment and seqHigh are
// the writer's active segment and the highest sequence number written.
func auditSinkStatuses(segment string, seqHigh uint64) (compliance bool, out []*models.AuditSinkStatus) {
	auditSink.mu.Lock()
	defer auditSink.mu.Unlock()
	add := func(ts audit.SinkTailerStats) {
		s := &models.AuditSinkStatus{
			Name:       ts.Name,
			Compliance: ts.Compliance,
			State:      ts.State,
			Cursor:     auditSinkCursorModel(ts.Cursor.Position),
			LagDrops:   int64(ts.LagDrops),
		}
		// seq counts within a boot, so the distance to the newest record
		// is a number only once the sink reads the segment being written.
		if segment != "" && ts.Cursor.SegmentUUID == segment {
			s.InActiveSegment = true
			if seqHigh > ts.Cursor.Seq {
				s.LagRecords = int64(seqHigh - ts.Cursor.Seq)
			}
		}
		out = append(out, s)
	}
	if auditSink.tailer != nil {
		compliance = true
		add(auditSink.tailer.Stats())
	}
	names := make([]string, 0, len(auditSink.named))
	for name := range auditSink.named {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add(auditSink.named[name].tailer.Stats())
	}
	return compliance, out
}
