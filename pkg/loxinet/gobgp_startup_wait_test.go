package loxinet

import (
	"context"
	"errors"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"net"
	"testing"
	"time"
)

type startupReviewClient struct {
	api.GobgpApiClient
	failures, probes, mutations int
	accept                      bool
}

func (c *startupReviewClient) GetBgp(context.Context, *api.GetBgpRequest, ...grpc.CallOption) (*api.GetBgpResponse, error) {
	c.probes++
	if c.probes <= c.failures {
		return nil, errRefused
	}
	return &api.GetBgpResponse{}, nil
}
func (c *startupReviewClient) AddPeer(context.Context, *api.AddPeerRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	c.mutations++
	if c.accept {
		return &emptypb.Empty{}, nil
	}
	return nil, errRefused
}
func TestBGPStartupWaitUsesInjectedClockAndLatchesTransportReadiness(t *testing.T) {
	c := &startupReviewClient{failures: 3}
	h := GoBgpH{client: c}
	now := time.Unix(0, 0)
	slept := time.Duration(0)
	wait := func(ctx context.Context, d time.Duration) error {
		// Neither the subsystem lock nor recovery-op lock belongs to this wait.
		if !h.mtx.TryLock() {
			t.Fatal("startup waited under BGP mutex")
		}
		h.mtx.Unlock()
		now = now.Add(d)
		slept += d
		return nil
	}
	if err := h.waitForStartup(context.Background(), func() time.Time { return now }, wait); err != nil {
		t.Fatal(err)
	}
	if c.probes != 4 || slept != 1750*time.Millisecond || !h.startupReady.Load() {
		t.Fatal(c.probes, slept)
	}
	c.accept = true
	if _, err := h.BGPNeighMod(true, net.ParseIP("192.0.2.5"), 65123, 0, false); err != nil {
		t.Fatal("startup mutation did not succeed", err)
	}
	c.accept = false
	probes := c.probes
	if err := h.waitForStartup(context.Background(), func() time.Time { return now }, func(context.Context, time.Duration) error { t.Fatal("post-readiness wait"); return nil }); err != nil {
		t.Fatal(err)
	}
	if c.probes != probes {
		t.Fatal("latched readiness probed again")
	}
	if _, err := h.BGPNeighMod(true, net.ParseIP("192.0.2.5"), 65123, 0, false); err != errRefused || c.mutations != 2 {
		t.Fatal("post-readiness Unavailable retried", err)
	}
}
func TestBGPStartupWaitBudgetAndCancellation(t *testing.T) {
	c := &startupReviewClient{failures: 1000}
	h := GoBgpH{client: c}
	now := time.Unix(0, 0)
	slept := time.Duration(0)
	err := h.waitForStartup(context.Background(), func() time.Time { return now }, func(_ context.Context, d time.Duration) error { now = now.Add(d); slept += d; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || slept != 30*time.Second || h.startupReady.Load() {
		t.Fatal(err, slept)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probes := c.probes
	if err := h.waitForStartup(ctx, time.Now, waitBGPStartupDelay); !errors.Is(err, context.Canceled) || c.probes != probes {
		t.Fatal("cancelled startup probed", err)
	}
}
