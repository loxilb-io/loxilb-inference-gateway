package loxinet

import (
	api "github.com/osrg/gobgp/v3/api"
	"strings"
	"testing"
)

func defaultReviewPeer() *api.Peer {
	return &api.Peer{Conf: &api.PeerConf{NeighborAddress: "192.0.2.5"}, Timers: &api.Timers{Config: &api.TimersConfig{ConnectRetry: 120, HoldTime: 90, KeepaliveInterval: 30, IdleHoldTimeAfterReset: 30}}, AfiSafis: []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Enabled: true}}}}
}
func TestBGPAdoptionDetectsOnlyNonDefaultConfigWithoutSecretValues(t *testing.T) {
	p := defaultReviewPeer()
	if names := bgpDroppedPeerAttributes(p); len(names) != 0 {
		t.Fatal("default peer warned", names)
	}
	p.Conf.AuthPassword = "test-only-sensitive-value"
	p.Timers.Config.HoldTime = 27
	p.Timers.Config.KeepaliveInterval = 9
	p.GracefulRestart = &api.GracefulRestart{Enabled: true}
	p.AfiSafis = append(p.AfiSafis, &api.AfiSafi{Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, Enabled: true}})
	names := strings.Join(bgpDroppedPeerAttributes(p), ",")
	for _, want := range []string{"auth_password", "timers.hold_time", "timers.keepalive_interval", "graceful_restart", "afi_safis"} {
		if !strings.Contains(names, want) {
			t.Fatal("missing warning", want, names)
		}
	}
	if strings.Contains(names, p.Conf.AuthPassword) {
		t.Fatal("secret value escaped")
	}
}

func TestBGPAdoptionAPIDefaultMRAIAndPeerAssignmentsAreSupported(t *testing.T) {
	p := defaultReviewPeer()
	// Recorded default/static profile peers have MRAI omitted (protobuf zero).
	p.Timers.Config.MinimumAdvertisementInterval = 0
	p.ApplyPolicy = &api.ApplyPolicy{
		ImportPolicy: &api.PolicyAssignment{Name: "192.0.2.5", Direction: api.PolicyDirection_IMPORT, Policies: []*api.Policy{{Name: "operator-import"}}, DefaultAction: api.RouteAction_REJECT},
		ExportPolicy: &api.PolicyAssignment{Name: "192.0.2.5", Direction: api.PolicyDirection_EXPORT, Policies: []*api.Policy{{Name: "operator-export"}}, DefaultAction: api.RouteAction_ACCEPT},
	}
	if names := bgpDroppedPeerAttributes(p); len(names) != 0 {
		t.Fatal("in-model peer assignments or default MRAI reported", names)
	}
	// Family-scoped policy is a different, unsupported attribute; retain that
	// diagnostic rather than suppressing every apply_policy field.
	p.AfiSafis[0].ApplyPolicy = &api.ApplyPolicy{ImportPolicy: &api.PolicyAssignment{Policies: []*api.Policy{{Name: "family-only"}}}}
	names := strings.Join(bgpDroppedPeerAttributes(p), ",")
	if names != "afi_safis.apply_policy" {
		t.Fatal("family-only policy warning lost", names)
	}
}
