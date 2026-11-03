package loxinet

import (
	"context"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
)

type addPathBGPClient struct {
	api.GobgpApiClient
	paths []*api.Path
}

func (c *addPathBGPClient) AddPath(_ context.Context, r *api.AddPathRequest, _ ...grpc.CallOption) (*api.AddPathResponse, error) {
	c.paths = append(c.paths, r.Path)
	return &api.AddPathResponse{}, nil
}

// An originated path must not carry our own AS: goBGP adds it towards eBGP peers,
// and iBGP peers must receive an empty AS_PATH.
func TestAdvertiseRouteOriginatesWithoutASPath(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		plen   int
		nh     string
		ipv4   bool
	}{
		{"ipv4", "20.20.20.1", 32, "0.0.0.0", true},
		{"ipv6", "2001:db8::1", 128, "::", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &addPathBGPClient{}
			h := GoBgpH{client: c, localAs: 64512}
			if rc := h.AdvertiseRoute(tc.prefix, tc.plen, tc.nh, 5000, 7, tc.ipv4); rc != 0 {
				t.Fatalf("AdvertiseRoute rc=%d", rc)
			}
			if len(c.paths) != 1 {
				t.Fatalf("expected one AddPath, got %d", len(c.paths))
			}
			var origin, nextHop, localPref, med bool
			for _, a := range c.paths[0].Pattrs {
				m, err := a.UnmarshalNew()
				if err != nil {
					t.Fatal(err)
				}
				switch v := m.(type) {
				case *api.AsPathAttribute:
					t.Fatalf("originated path carries AS_PATH: %v", v.Segments)
				case *api.OriginAttribute:
					origin = v.Origin == 0
				case *api.NextHopAttribute:
					nextHop = v.NextHop == tc.nh
				case *api.LocalPrefAttribute:
					localPref = v.LocalPref == 5000
				case *api.MultiExitDiscAttribute:
					med = v.Med == 7
				}
			}
			if !origin || !nextHop || !localPref || !med {
				t.Fatalf("attributes lost: origin=%v nexthop=%v localpref=%v med=%v", origin, nextHop, localPref, med)
			}
		})
	}
}
