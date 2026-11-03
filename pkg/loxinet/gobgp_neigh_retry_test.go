package loxinet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type peerBGPClient struct {
	api.GobgpApiClient
	errs  []error
	calls int
}

func (c *peerBGPClient) next() error {
	c.calls++
	if len(c.errs) == 0 {
		return nil
	}
	err := c.errs[0]
	c.errs = c.errs[1:]
	return err
}

func (c *peerBGPClient) AddPeer(_ context.Context, _ *api.AddPeerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.next()
}

func (c *peerBGPClient) DeletePeer(_ context.Context, _ *api.DeletePeerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.next()
}

func fakeBGPSleep(t *testing.T) *time.Duration {
	t.Helper()
	slept := new(time.Duration)
	old := bgpRetrySleep
	bgpRetrySleep = func(d time.Duration) { *slept += d }
	t.Cleanup(func() { bgpRetrySleep = old })
	return slept
}

var errRefused = status.Error(codes.Unavailable, `connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:50052: connect: connection refused"`)

// A neighbor change made while gobgpd is still starting succeeds once it answers.
func TestBGPNeighModWaitsForGobgpd(t *testing.T) {
	for _, add := range []bool{true, false} {
		slept := fakeBGPSleep(t)
		c := &peerBGPClient{errs: []error{errRefused, errRefused, errRefused}}
		h := GoBgpH{client: c}
		if rc, err := h.BGPNeighMod(add, net.ParseIP("10.10.10.254"), 65001, 0, false); rc != 0 || err != nil {
			t.Fatalf("add=%v: rc=%d err=%v", add, rc, err)
		}
		if c.calls != 4 {
			t.Fatalf("add=%v: expected 4 calls, got %d", add, c.calls)
		}
		if *slept != 1750*time.Millisecond {
			t.Fatalf("add=%v: expected 1.75s of backoff, got %v", add, *slept)
		}
	}
}

// Any other error is returned at once.
func TestBGPNeighModOtherErrorNotRetried(t *testing.T) {
	slept := fakeBGPSleep(t)
	exists := status.Error(codes.AlreadyExists, "can't overwrite the existing peer")
	for _, e := range []error{exists, errors.New("plain error")} {
		c := &peerBGPClient{errs: []error{e}}
		h := GoBgpH{client: c}
		if rc, err := h.BGPNeighMod(true, net.ParseIP("10.10.10.254"), 65001, 0, false); rc != -1 || err != e {
			t.Fatalf("rc=%d err=%v, want -1 and %v", rc, err, e)
		}
		if c.calls != 1 {
			t.Fatalf("expected 1 call, got %d", c.calls)
		}
	}
	if *slept != 0 {
		t.Fatalf("slept %v on a non-retryable error", *slept)
	}
}

// gobgpd that never comes up fails after the bounded wait with its own error.
func TestBGPNeighModGivesUpAfterWait(t *testing.T) {
	slept := fakeBGPSleep(t)
	errs := make([]error, 100)
	for i := range errs {
		errs[i] = errRefused
	}
	c := &peerBGPClient{errs: errs}
	h := GoBgpH{client: c}
	rc, err := h.BGPNeighMod(true, net.ParseIP("10.10.10.254"), 65001, 0, false)
	if rc != -1 || status.Code(err) != codes.Unavailable {
		t.Fatalf("rc=%d err=%v, want -1 and Unavailable", rc, err)
	}
	if *slept != bgpRetryWait {
		t.Fatalf("waited %v, want exactly %v", *slept, bgpRetryWait)
	}
	if c.calls > 15 {
		t.Fatalf("too many attempts: %d", c.calls)
	}
}
