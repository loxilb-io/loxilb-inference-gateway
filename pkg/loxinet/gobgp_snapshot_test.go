package loxinet

import (
	"context"
	"errors"
	cmn "github.com/loxilb-io/loxilb/common"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"io"
	"net"
	"testing"
)

type assignmentStream struct {
	grpc.ClientStream
	items []*api.PolicyAssignment
}

func (s *assignmentStream) Recv() (*api.ListPolicyAssignmentResponse, error) {
	if len(s.items) == 0 {
		return nil, io.EOF
	}
	a := s.items[0]
	s.items = s.items[1:]
	return &api.ListPolicyAssignmentResponse{Assignment: a}, nil
}

type snapshotBGPClient struct {
	api.GobgpApiClient
	assignments   []*api.PolicyAssignment
	assignmentErr error
	starts        int
	resets        []*api.SetPolicyAssignmentRequest
}

func (c *snapshotBGPClient) GetBgp(context.Context, *api.GetBgpRequest, ...grpc.CallOption) (*api.GetBgpResponse, error) {
	return &api.GetBgpResponse{Global: &api.Global{Asn: 65118, RouterId: "192.0.2.18", ListenPort: 1179}}, nil
}
func (c *snapshotBGPClient) ListPolicyAssignment(_ context.Context, r *api.ListPolicyAssignmentRequest, _ ...grpc.CallOption) (api.GobgpApi_ListPolicyAssignmentClient, error) {
	if c.assignmentErr != nil {
		return nil, c.assignmentErr
	}
	var a []*api.PolicyAssignment
	for _, v := range c.assignments {
		if (r.Name == "" || r.Name == v.Name) && (r.Direction == api.PolicyDirection_UNKNOWN || r.Direction == v.Direction) {
			a = append(a, v)
		}
	}
	return &assignmentStream{items: a}, nil
}
func (c *snapshotBGPClient) SetPolicyAssignment(_ context.Context, r *api.SetPolicyAssignmentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.resets = append(c.resets, r)
	return &emptypb.Empty{}, nil
}
func TestSnapshotBGPGlobalReplayDoesNotRecreateActions(t *testing.T) {
	c := &snapshotBGPClient{assignments: []*api.PolicyAssignment{{Name: "global", Direction: api.PolicyDirection_EXPORT, Policies: []*api.Policy{{Name: "set-next-hop-self-gpolicy"}}}}}
	h := GoBgpH{client: c}
	// Unimplemented mutating methods on the embedded interface panic: an
	// identical replay must reach zero Start/AddStatement/AddPolicy calls.
	for i := 0; i < 3; i++ {
		if _, err := h.BGPGlobalConfigAdd(cmn.GoBGPGlobalConfig{LocalAs: 65118, RouterID: "192.0.2.18", ListenPort: 1179, SetNHSelf: true}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestSnapshotBGPAssignmentGetterKeepsOrderAndExcludesManaged(t *testing.T) {
	c := &snapshotBGPClient{assignments: []*api.PolicyAssignment{{Name: "global", Direction: api.PolicyDirection_IMPORT, Policies: []*api.Policy{{Name: "second"}, {Name: "set-llb-export-gpolicy"}, {Name: "first"}}, DefaultAction: api.RouteAction_REJECT}}}
	h := GoBgpH{client: c}
	got, err := h.GetPolicyAssignments()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Polices[0] != "second" || got[0].Polices[1] != "first" || got[0].RouteAction != "reject" {
		t.Fatalf("lost desired binding: %+v", got)
	}
	if _, err = h.ResetOperatorPolicyAssignment(&got[0]); err != nil {
		t.Fatal(err)
	}
	if len(c.resets) != 1 || len(c.resets[0].Assignment.Policies) != 1 || c.resets[0].Assignment.Policies[0].Name != "set-llb-export-gpolicy" || c.resets[0].Assignment.DefaultAction != api.RouteAction_ACCEPT {
		t.Fatalf("managed binding lost: %+v", c.resets)
	}
}

func TestSnapshotBFDConfigurationVisibleBeforeAddReturns(t *testing.T) {
	ch := CIStateH{Bs: bfd.StructNew(0), ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: {}}}
	item := cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP("127.0.0.2"), SourceIP: net.ParseIP("127.0.0.1"), Interval: 1000000, RetryCount: 5}
	if _, err := ch.CIBFDSessionAdd(item); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := ch.CIBFDSessionDel(item); err != nil {
			t.Errorf("join snapshot BFD fixture: %v", err)
		}
	})
	got, err := ch.CIBFDSessionGet()
	if err != nil || len(got) != 1 {
		t.Fatalf("acknowledged BFD configuration missing: %+v %v", got, err)
	}
	if _, err := ch.CIBFDSessionAdd(item); err != nil {
		t.Fatalf("identical boot retry rejected: %v", err)
	}
}

func TestSnapshotBGPGlobalReadFailureCannotClaimNHSelfDisabled(t *testing.T) {
	failure := errors.New("policy assignment store unavailable")
	h := GoBgpH{client: &snapshotBGPClient{assignmentErr: failure}}
	if _, err := h.BGPGlobalConfigGet(); !errors.Is(err, failure) {
		t.Fatalf("read failure hidden: %v", err)
	}
	if _, err := h.BGPGlobalConfigAdd(cmn.GoBGPGlobalConfig{LocalAs: 65118, RouterID: "192.0.2.18", ListenPort: 1179}); !errors.Is(err, failure) {
		t.Fatalf("replay accepted without actual flag readback: %v", err)
	}
}
