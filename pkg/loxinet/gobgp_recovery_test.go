package loxinet

import (
	"context"
	"io"
	"net"
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
	go func() { h.watchRoutes(&eofBGPClient{}, 7); close(done) }()
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
