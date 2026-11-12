package loxinet

import (
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
)

func TestBGPDaemonRecoveryGatePreservesRoles(t *testing.T) {
	for _, role := range []int{cmn.CIStateMaster, cmn.CIStateBackup, cmn.CIStateNotDefined} {
		h := GoBgpH{}
		ci := &goCI{hastate: role, vip: net.IPv4zero}
		h.daemonConfigPending.Store(true)
		if h.roleAllowsAdvertisement(ci) {
			t.Fatal("daemon replay gate leaked a VIP", role)
		}
		h.daemonConfigPending.Store(false)
		if !h.roleAllowsAdvertisement(ci) {
			t.Fatal("settled unmanaged role blocked", role)
		}
		h.requireRole.Store(true)
		if role == cmn.CIStateNotDefined && h.roleAllowsAdvertisement(ci) {
			t.Fatal("recovery bypassed HA role gate")
		}
	}
}

func TestBGPObsoleteSessionCannotDisconnectReplacement(t *testing.T) {
	h := GoBgpH{state: BGPConnected}
	h.session.Store(3)
	h.processBgpEvent(goBgpEvent{EventType: bgpDisconnected, session: 2})
	if h.state != BGPConnected {
		t.Fatal("old watch disconnected replacement session")
	}
}

type eofBGPWatch struct{ grpc.ClientStream }

func (*eofBGPWatch) Recv() (*api.WatchEventResponse, error) { return nil, io.EOF }

type eofBGPClient struct{ api.GobgpApiClient }

func (*eofBGPClient) WatchEvent(_ context.Context, _ *api.WatchEventRequest, _ ...grpc.CallOption) (api.GobgpApi_WatchEventClient, error) {
	return &eofBGPWatch{}, nil
}

func TestBGPWatchEOFTriggersBoundedReconnect(t *testing.T) {
	h := GoBgpH{eventCh: make(chan goBgpEvent, 1)}
	done := make(chan struct{})
	go func() { h.watchRoutes(context.Background(), &eofBGPClient{}, 7); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EOF watch spun instead of reconnecting")
	}
	event := <-h.eventCh
	if event.EventType != bgpDisconnected || event.session != 7 {
		t.Fatal(event)
	}
}

func TestBGPWithdrawUnavailableFiftyPrefixes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	conn, err := newBGPClientConn(address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	refs := map[string]int{}
	ips := []string{}
	for i := 1; i <= 50; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		refs[ip] = 1
		ips = append(ips, ip)
	}
	h := GoBgpH{client: api.NewGobgpApiClient(conn), state: BGPConnected, ciMap: map[string]*goCI{cmn.CIDefault: {vip: net.IPv4zero, rules: refs}}}
	began := time.Now()
	h.DelBGPRule(cmn.CIDefault, ips)
	elapsed := time.Since(began)
	if elapsed >= time.Second {
		t.Fatalf("50 unavailable withdrawals held lock for %s", elapsed)
	}
	if len(refs) != 0 {
		t.Fatal("deletions retained stale routes")
	}
	t.Logf("50 unavailable withdrawals: %s", elapsed)
}

func daemonGateMetric(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "loxilb_bgp_daemon_config_pending" {
			return f.Metric[0].GetGauge().GetValue()
		}
	}
	t.Fatal("missing daemon recovery metric")
	return -1
}

func TestBGPPrepareFailureRetriesAndReopensGate(t *testing.T) {
	h := GoBgpH{}
	h.setDaemonConfigPending(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	first, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		h.retryDaemonRecovery(ctx, func(context.Context) (bool, error) {
			if attempts.Add(1) == 1 {
				close(first)
				return true, errors.New("injected prepare failure")
			}
			return false, nil
		})
	}()
	<-first
	if !h.daemonConfigPending.Load() || daemonGateMetric(t) != 1 {
		t.Fatal("preparation failure opened gate or hid metric")
	}
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("prepare retry did not recover")
	}
	if attempts.Load() != 2 || h.daemonConfigPending.Load() || daemonGateMetric(t) != 0 {
		t.Fatal("successful prepare did not clear gate")
	}
}

func TestBGPInteractiveCompletionCancelsPrepareErrorWithoutPendingGroup(t *testing.T) {
	old := mh.bgp
	h := &GoBgpH{pMode: true}
	mh.bgp = h
	defer func() { mh.bgp = old; h.cancelDaemonRecovery() }()
	h.setDaemonConfigPending(true)
	first := make(chan struct{})
	var once sync.Once
	h.startDaemonRecovery(context.Background(), func(context.Context) (bool, error) {
		once.Do(func() { close(first) })
		return true, errors.New("persistent prepare error")
	})
	<-first
	(&NetAPIStruct{}).NetBGPRecoveryComplete()
	if h.daemonConfigPending.Load() || daemonGateMetric(t) != 0 {
		t.Fatal("interactive completion left an error gate closed")
	}
}

type reviewPathStream struct{ grpc.ClientStream }

func (*reviewPathStream) Recv() (*api.ListPathResponse, error) { return nil, io.EOF }

type reviewWatchStream struct {
	grpc.ClientStream
	ctx    context.Context
	active *atomic.Int32
	once   sync.Once
}

func (s *reviewWatchStream) Recv() (*api.WatchEventResponse, error) {
	<-s.ctx.Done()
	s.once.Do(func() { s.active.Add(-1) })
	return nil, s.ctx.Err()
}

type reviewSessionClient struct {
	api.GobgpApiClient
	active   atomic.Int32
	starts   atomic.Int32
	contexts chan context.Context
}

func (c *reviewSessionClient) GetBgp(context.Context, *api.GetBgpRequest, ...grpc.CallOption) (*api.GetBgpResponse, error) {
	return &api.GetBgpResponse{Global: &api.Global{Asn: 65122}}, nil
}
func (c *reviewSessionClient) ListPath(context.Context, *api.ListPathRequest, ...grpc.CallOption) (api.GobgpApi_ListPathClient, error) {
	return &reviewPathStream{}, nil
}
func (c *reviewSessionClient) WatchEvent(ctx context.Context, _ *api.WatchEventRequest, _ ...grpc.CallOption) (api.GobgpApi_WatchEventClient, error) {
	c.active.Add(1)
	c.starts.Add(1)
	c.contexts <- ctx
	return &reviewWatchStream{ctx: ctx, active: &c.active}, nil
}
func TestBGPDuplicateDisconnectStartsOneInitAndCancellableWatch(t *testing.T) {
	c := &reviewSessionClient{contexts: make(chan context.Context, 4)}
	h := GoBgpH{client: c, state: BGPConnected, eventCh: make(chan goBgpEvent, 16), ciMap: map[string]*goCI{}}
	h.session.Store(10)
	h.processBgpEvent(goBgpEvent{EventType: bgpDisconnected, session: 10})
	h.processBgpEvent(goBgpEvent{EventType: bgpDisconnected, session: 10})
	var connected goBgpEvent
	select {
	case connected = <-h.eventCh:
	case <-time.After(time.Second):
		t.Fatal("no replacement connect")
	}
	if connected.EventType != bgpConnected || connected.session != 11 {
		t.Fatal(connected)
	}
	h.processBgpEvent(connected)
	var oldWatch context.Context
	select {
	case oldWatch = <-c.contexts:
	case <-time.After(time.Second):
		t.Fatal("watch not initialized")
	}
	h.processBgpEvent(connected)
	h.processBgpEvent(goBgpEvent{EventType: bgpRtRecvd, session: 10}) // nil route would panic if not filtered
	if c.starts.Load() != 1 || c.active.Load() != 1 {
		t.Fatal("duplicate init opened extra watch")
	}
	h.processBgpEvent(goBgpEvent{EventType: bgpDisconnected, session: 11})
	if oldWatch.Err() == nil {
		t.Fatal("old watch context was not cancelled")
	}
	deadline := time.Now().Add(time.Second)
	for c.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.active.Load() != 0 {
		t.Fatal("old watch stream remained live")
	}
	for {
		select {
		case e := <-h.eventCh:
			if e.EventType == bgpConnected && e.session == 12 {
				h.processBgpEvent(e)
				goto ready
			}
		case <-time.After(time.Second):
			t.Fatal("second generation did not connect")
		}
	}
ready:
	select {
	case <-c.contexts:
	case <-time.After(time.Second):
		t.Fatal("replacement watch absent")
	}
	h.processBgpEvent(goBgpEvent{EventType: bgpDisconnected, session: 10})
	if h.session.Load() != 12 || c.starts.Load() != 2 || c.active.Load() != 1 {
		t.Fatal("stale event affected live session")
	}
	h.mtx.Lock()
	h.watchCancel()
	h.mtx.Unlock()
}
