package loxinet

import (
	"context"
	"errors"
	"net"
	"testing"

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

var errRefused = status.Error(codes.Unavailable, "connection refused")

// Add and delete both fail fast. Supervisor/coordinator retries are separate.
func TestBGPNeighModUnavailableNotRetried(t *testing.T) {
	for _, add := range []bool{true, false} {
		c := &peerBGPClient{errs: []error{errRefused}}
		h := GoBgpH{client: c}
		if rc, err := h.BGPNeighMod(add, net.ParseIP("10.10.10.254"), 65001, 0, false); rc != -1 || err != errRefused {
			t.Fatalf("add=%v: rc=%d err=%v", add, rc, err)
		}
		if c.calls != 1 {
			t.Fatalf("add=%v: expected one call, got %d", add, c.calls)
		}
	}
}

func TestBGPNeighModOtherErrorNotRetried(t *testing.T) {
	exists := status.Error(codes.AlreadyExists, "can't overwrite the existing peer")
	for _, e := range []error{exists, errors.New("plain error")} {
		c := &peerBGPClient{errs: []error{e}}
		h := GoBgpH{client: c}
		if rc, err := h.BGPNeighMod(true, net.ParseIP("10.10.10.254"), 65001, 0, false); rc != -1 || err != e {
			t.Fatalf("rc=%d err=%v, want -1 and %v", rc, err, e)
		}
		if c.calls != 1 {
			t.Fatalf("expected one call, got %d", c.calls)
		}
	}
}
