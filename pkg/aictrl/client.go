/*
 * Copyright (c) 2026 LoxiLB Authors
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

// Stream session (+): loxilb DIALS OUT
// to the controller, consumes the WatchSnapshots SotW stream, validates every
// snapshot (V5), ACKs applied / NACKs invalid epochs, and runs the ONE
// continuous α(t) mechanism — a 1 Hz rewrite of effective weights with mode
// as a derived label. All cgo is behind the injected Sink; this
// file is pure Go (bufconn fake-controller testable, darwin CGO_ENABLED=0).
package aictrl

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// maxReconnectBackoff caps the exponential reconnect backoff. The controller
// lives on a private, low-latency bus and (in production) auto-restarts within
// seconds; a large cap needlessly keeps loxilb in Autonomous long after the
// controller is back. live validation measured ~105s reconvergence
// with a 30s cap after a kill+restart — a 5s cap bounds the post-recovery
// Autonomous window without risking a reconnect storm against a private peer.
const maxReconnectBackoff = 5 * time.Second

// Sink receives the applier's C-side writes. The production implementation
// (pkg/loxinet/ai_ctrl_applier.go) bridges to llb_ai_ctrl_update_ep /
// llb_ai_ctrl_set_mode via cgo; tests inject a recorder.
type Sink interface {
	// UpdateEp stores the packed instruction word (state<<24|weight) for one
	// EP of one service.
	UpdateEp(serviceKey string, epIdx int, packed uint32)
	// SetMode stores the per-service controller mode scalar (0 = autonomous /
	// controller absent — the C hot path does ZERO controller work at 0).
	SetMode(serviceKey string, mode uint8)
}

// Config parameterizes a Session. Zero-value fields take production defaults
// in NewSession; Now/Dial/Sleep/Rand/TickCh are injectable for fake-clock and
// bufconn fake-controller tests.
type Config struct {
	// Addr is the controller dial target (from LOXILB_AI_CTRL_ADDR).
	Addr string
	// GatewayID identifies this loxilb instance (WatchRequest/Ack echo).
	GatewayID string

	// DecayWindow is the Stale linear-decay span (default 30s).
	DecayWindow time.Duration
	// Hysteresis is the mode-transition damping window (default 5s).
	Hysteresis time.Duration
	// AckTimeout bounds each AckSnapshot unary call (default 10s).
	AckTimeout time.Duration
	// JitterPct delays each snapshot application by uniform
	// [0, JitterPct% of the epoch period] (P3 anti-herding, default set by
	// the applier from LOXILB_AI_CTRL_APPLY_JITTER_PCT).
	JitterPct int

	// Now is the clock (default time.Now; fake-clock in tests).
	Now func() time.Time
	// Dial opens the client connection (default insecure lazy dial-out;
	// bufconn dialer in tests). mTLS is deferred to —
	// documented accepted interim risk (operator-set address on the
	// private bus; loxilb opens NO new inbound listener).
	Dial func(ctx context.Context, addr string) (*grpc.ClientConn, error)
	// Sleep is the interruptible sleep used for jitter + reconnect backoff.
	Sleep func(ctx context.Context, d time.Duration)
	// Rand yields uniform [0,1) for jitter (default math/rand).
	Rand func() float64
	// TickCh overrides the internal 1 Hz rewrite ticker (tests drive
	// tickOnce directly and pass a never-firing channel).
	TickCh <-chan time.Time

	// Known returns the locally-known (service_key → ep indices) set for V5
	// validation. Dynamic — re-queried per snapshot (rules can change).
	Known func() map[string][]uint32
	// Healthy reports LOCAL health for one EP (probe up, not admin-removed).
	// nil ⇒ always healthy. Local health always wins (P4/G4).
	Healthy func(serviceKey string, epIdx int) bool

	// Observability hooks (all optional) — wired to Prometheus by the applier.
	OnApplied    func(epoch uint64, serviceKeys []string)
	OnRejected   func(epoch uint64, errorDetail string)
	OnOverride   func(serviceKey string, epIdx int)
	OnModeChange func(m Mode)
	OnTick       func(alpha float64, m Mode)
	Logf         func(format string, args ...interface{})
}

// Session owns one controller stream lifecycle: dial-out with backoff
// reconnect, per-snapshot validate→jitter→merge→apply→ACK, and the 1 Hz
// α(t) rewrite loop.
type Session struct {
	cfg  Config
	sink Sink

	mu                sync.Mutex
	haveSnapshot      bool
	lastBootID        string
	lastEpoch         uint64
	deadline          time.Time
	directives        map[string][]EpDirective
	autonomousLatched bool // ONE SetMode(0) written; rewrites stop until a fresh snapshot

	// Mode-transition hysteresis (WR-03 CAS template, sockproxy_sync.go:562).
	lastHysteresisAt atomic.Int64
	lastAcceptedMode atomic.Int64

	// AckSnapshot capability (cleared on codes.Unimplemented — the
	// sockproxy_sync.go sendOnce degrade idiom).
	ackCapable atomic.Bool
	warnOnce   sync.Once
}

// NewSession builds a Session, filling production defaults for any zero
// Config fields.
func NewSession(cfg Config, sink Sink) *Session {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Dial == nil {
		cfg.Dial = defaultDial
	}
	if cfg.Sleep == nil {
		cfg.Sleep = defaultSleep
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	if cfg.DecayWindow <= 0 {
		cfg.DecayWindow = 30 * time.Second //
	}
	if cfg.Hysteresis <= 0 {
		cfg.Hysteresis = 5 * time.Second
	}
	if cfg.AckTimeout <= 0 {
		cfg.AckTimeout = 10 * time.Second
	}
	s := &Session{cfg: cfg, sink: sink}
	s.ackCapable.Store(true)
	s.lastAcceptedMode.Store(int64(ModeAutonomous))
	return s
}

// Run blocks consuming the controller stream until ctx is cancelled,
// reconnecting with capped exponential backoff on stream death. The 1 Hz
// rewrite loop runs alongside for the whole session lifetime — decay
// continues regardless of stream state (a dead stream simply stops
// refreshing the deadline; α(t) does the rest).
func (s *Session) Run(ctx context.Context) error {
	tickCh := s.cfg.TickCh
	if tickCh == nil {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		tickCh = t.C
	}
	go s.rewriteLoop(ctx, tickCh)

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		received, err := s.runStream(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if received {
			backoff = time.Second // stream was live — reset backoff
		}
		s.logf("stream session ended: %v; reconnecting in %s", err, backoff)
		s.cfg.Sleep(ctx, backoff)
		backoff *= 2
		if backoff > maxReconnectBackoff {
			backoff = maxReconnectBackoff
		}
	}
}

// runStream performs one dial+subscribe+consume cycle. received reports
// whether at least one snapshot arrived (used to reset backoff).
func (s *Session) runStream(ctx context.Context) (received bool, err error) {
	conn, err := s.cfg.Dial(ctx, s.cfg.Addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := NewAiCtrlClient(conn)
	stream, err := client.WatchSnapshots(ctx, &WatchRequest{
		GatewayId:      s.cfg.GatewayID,
		ApplierVersion: ApplierVersion,
	})
	if err != nil {
		return false, err
	}
	s.logf("subscribed addr=%s gateway_id=%s applier_version=%d",
		s.cfg.Addr, s.cfg.GatewayID, ApplierVersion)

	for {
		snap, rerr := stream.Recv()
		if rerr != nil {
			return received, rerr
		}
		received = true
		s.handleSnapshot(ctx, client, snap)
	}
}

// handleSnapshot validates, jitters, merges and applies ONE snapshot, then
// ACKs/NACKs. A rejected snapshot keeps last-good state applied and the
// staleness clock running — a bad snapshot is equivalent to an absent
// controller (V5/13).
func (s *Session) handleSnapshot(ctx context.Context, client AiCtrlClient, snap *Snapshot) {
	now := s.cfg.Now()
	s.mu.Lock()
	lastBoot, lastEpoch := s.lastBootID, s.lastEpoch
	s.mu.Unlock()

	known := map[string][]uint32{}
	if s.cfg.Known != nil {
		known = s.cfg.Known()
	}

	if verr := ValidateSnapshot(snap, known, lastBoot, lastEpoch, now, s.cfg.DecayWindow); verr != nil {
		if s.cfg.OnRejected != nil {
			s.cfg.OnRejected(snap.GetEpoch(), verr.Error())
		}
		s.logf("NACK epoch=%d: %v", snap.GetEpoch(), verr)
		s.ackSnapshot(ctx, client, snap, AckStatus_ACK_STATUS_REJECTED, verr.Error())
		return
	}

	// P3 anti-herding: delay application by uniform [0, JitterPct% of the
	// epoch period]; period inferred from deadline spacing (: staleness
	// deadline = 3× the epoch period).
	deadline := time.UnixMilli(int64(snap.GetStalenessDeadlineUnixMs()))
	if s.cfg.JitterPct > 0 {
		if period := deadline.Sub(now) / 3; period > 0 {
			d := time.Duration(s.cfg.Rand() * float64(s.cfg.JitterPct) / 100.0 * float64(period))
			s.cfg.Sleep(ctx, d)
		}
	}
	if ctx.Err() != nil {
		return
	}

	s.mu.Lock()
	dirs := make(map[string][]EpDirective, len(snap.GetServices()))
	for _, svc := range snap.GetServices() {
		for _, ep := range svc.GetEps() {
			dirs[svc.GetServiceKey()] = append(dirs[svc.GetServiceKey()], EpDirective{
				ServiceKey: svc.GetServiceKey(),
				EpIdx:      int(ep.GetEpIdx()),
				Weight:     ep.GetWeight(),
				State:      ep.GetState(),
			})
		}
	}
	s.lastBootID = snap.GetBootId()
	s.lastEpoch = snap.GetEpoch()
	s.deadline = deadline
	s.directives = dirs
	s.haveSnapshot = true
	s.autonomousLatched = false // fresh snapshot re-arms the ladder

	applyNow := s.cfg.Now()
	alpha := Alpha(applyNow, deadline, s.cfg.DecayWindow)
	if s.modeGate(ModeFromAlpha(alpha), applyNow) {
		s.announceMode(ModeFromAlpha(alpha))
	}
	s.writeAllLocked(alpha)
	for key := range dirs {
		s.sink.SetMode(key, 1) // controller instructions live
	}
	s.mu.Unlock()

	if s.cfg.OnApplied != nil {
		keys := make([]string, 0, len(dirs))
		for k := range dirs {
			keys = append(keys, k)
		}
		s.cfg.OnApplied(snap.GetEpoch(), keys)
	}
	s.ackSnapshot(ctx, client, snap, AckStatus_ACK_STATUS_APPLIED, "")
}

// rewriteLoop drives the 1 Hz decayed rewrite.
func (s *Session) rewriteLoop(ctx context.Context, tickCh <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tickCh:
			s.tickOnce()
		}
	}
}

// tickOnce recomputes α(t) and rewrites every directive EP's effective
// weight. When α reaches 0: ONE SetMode(0) per service, then rewrites stop
// until a fresh snapshot arrives (Autonomous ≡ automatically).
func (s *Session) tickOnce() {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	var alpha float64 // no snapshot ever ⇒ α=0 ⇒ Autonomous
	if s.haveSnapshot {
		alpha = Alpha(now, s.deadline, s.cfg.DecayWindow)
	}
	m := ModeFromAlpha(alpha)
	if s.modeGate(m, now) {
		s.announceMode(m)
	}
	if s.cfg.OnTick != nil {
		s.cfg.OnTick(alpha, m)
	}
	if !s.haveSnapshot {
		return
	}
	if alpha <= 0 {
		if !s.autonomousLatched {
			// Autonomous: ONE mode=0 write per service — after this the C
			// hot path does ZERO controller work (G3); no repeated writes.
			for key := range s.directives {
				s.sink.SetMode(key, 0)
			}
			s.autonomousLatched = true
		}
		return
	}
	s.writeAllLocked(alpha)
}

// writeAllLocked rewrites effective_weight = 100 + α·(w−100) for every
// directive EP through the pure-intersection merge. Caller holds s.mu.
func (s *Session) writeAllLocked(alpha float64) {
	for key, ds := range s.directives {
		for _, d := range ds {
			eff := d
			eff.Weight = EffectiveWeight(d.Weight, alpha)
			healthy := true
			if s.cfg.Healthy != nil {
				healthy = s.cfg.Healthy(key, d.EpIdx)
			}
			apply, overridden := MergeVerdict(eff, healthy)
			if overridden {
				// G4: packed write SUPPRESSED — local health wins; every
				// veto is counted (override_events_total).
				if s.cfg.OnOverride != nil {
					s.cfg.OnOverride(key, d.EpIdx)
				}
				continue
			}
			s.sink.UpdateEp(key, apply.EpIdx, apply.Packed())
		}
	}
}

// modeGate is the mode-transition hysteresis (template: sockproxy_sync.go
// OnStateChange WR-03 CAS block). Returns true when the transition to m
// should be announced/processed.
//
// L-9 lesson (encoded verbatim from the template's defect history): the
// hysteresis window collapses rapid SAME-STATE flapping only. A
// DIFFERENT-state transition inside the window is a legitimate role change
// and MUST pass — e.g. Stale→Smart recovery 2s after Smart→Stale (controller
// came right back) must not be wedged. Blanket suppression previously
// suppressed legitimate BACKUP→MASTER transitions in xSync (Defect #5,
// 3-03).
func (s *Session) modeGate(m Mode, now time.Time) bool {
	nowNs := now.UnixNano()
	// WR-03: CAS-loop the hysteresis window so two near-simultaneous
	// transitions cannot both pass the gate and double-announce.
	for {
		last := s.lastHysteresisAt.Load()
		if last != 0 && nowNs-last < int64(s.cfg.Hysteresis) {
			if Mode(s.lastAcceptedMode.Load()) == m {
				return false // same-state repeat within window — suppressed
			}
			// Different state within window — legitimate transition (L-9);
			// fall through to the CAS.
		} else if Mode(s.lastAcceptedMode.Load()) == m {
			return false // steady state — no transition to announce
		}
		if s.lastHysteresisAt.CompareAndSwap(last, nowNs) {
			s.lastAcceptedMode.Store(int64(m))
			return true
		}
		// Another goroutine advanced the timestamp under us — re-check.
	}
}

func (s *Session) announceMode(m Mode) {
	s.logf("mode change -> %s", m)
	if s.cfg.OnModeChange != nil {
		s.cfg.OnModeChange(m)
	}
}

// ackSnapshot reports the apply outcome within AckTimeout. codes.Unimplemented
// from the controller clears the ack capability with a single warning and all
// subsequent acks are skipped (capability-degrade, sockproxy_sync sendOnce
// idiom) — apply/decay behavior is unaffected.
func (s *Session) ackSnapshot(ctx context.Context, client AiCtrlClient,
	snap *Snapshot, st AckStatus, detail string) {

	if !s.ackCapable.Load() {
		return // capability cleared — pretend success, no retry storm
	}
	actx, cancel := context.WithTimeout(ctx, s.cfg.AckTimeout)
	defer cancel()
	_, err := client.AckSnapshot(actx, &Ack{
		Epoch:       snap.GetEpoch(),
		Nonce:       snap.GetNonce(),
		Status:      st,
		ErrorDetail: detail,
		GatewayId:   s.cfg.GatewayID,
	})
	if err == nil {
		return
	}
	if status.Code(err) == codes.Unimplemented {
		// Clear capability + WARN once (degrade gracefully).
		s.ackCapable.Store(false)
		s.warnOnce.Do(func() {
			s.logf("controller returned Unimplemented for AckSnapshot; clearing capability and degrading gracefully")
		})
		return
	}
	s.logf("AckSnapshot epoch=%d failed: %v", snap.GetEpoch(), err)
}

func (s *Session) logf(format string, args ...interface{}) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// defaultDial is the production dial-out: lazy connect, NO grpc.WithBlock —
// the Run retry loop owns reconnection. Plaintext on the private bus for the
// MVP; mTLS deferred to (accepted interim risk).
func defaultDial(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// defaultSleep is an interruptible timer sleep.
func defaultSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
