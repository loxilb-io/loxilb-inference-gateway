package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// Reproduce the idle-persist CI oracle: an acknowledged API write retains a
// live peer read, then captures alternate between retained and healthy state.
func TestBGPCompletedIntentRuntimeFieldsDoNotChangeIdlePersist(t *testing.T) {
	for _, outage := range []string{"unhealthy", "read-failure"} {
		t.Run(outage, func(t *testing.T) {
			h, d, e := intentFixture(t)
			h.bgpGC = d.Domains.BGP.GlobalConfig
			live := &healthyBGPFixture{mockHooks: h, healthy: true}
			peer := &cmn.GoBGPNeighMod{Addr: net.ParseIP("192.0.2.23"), RemoteAS: 65123, RemotePort: 1790, MultiHop: true}
			if _, err := ChangeBGPIntent(live, peer, true, func() (int, error) {
				n, err := h.NetGoBGPNeighAdd(peer)
				h.bgpNeighbors[0].State, h.bgpNeighbors[0].Uptime = "ACTIVE", "never"
				return n, err
			}); err != nil {
				t.Fatal(err)
			}
			if outage == "unhealthy" {
				live.healthy = false
			} else {
				h.failOn["NetGoBGPGCGet"] = errors.New("speaker temporarily unavailable")
			}
			_, first, err := WriteThrough(live, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
			if err != nil {
				t.Fatal(err)
			}
			firstRaw, err := LoadPersisted(e.PreRestoreDir)
			if err != nil {
				t.Fatal(err)
			}
			live.healthy = true
			delete(h.failOn, "NetGoBGPGCGet")
			_, second, err := WriteThrough(live, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
			if err != nil {
				t.Fatal(err)
			}
			a, err := json.Marshal(first.Domains)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(second.Domains)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatalf("idle domains changed: retained peer runtime=%q/%q; healthy peer runtime=%q/%q", first.Domains.BGP.Neighbors[0].State, first.Domains.BGP.Neighbors[0].Uptime, second.Domains.BGP.Neighbors[0].State, second.Domains.BGP.Neighbors[0].Uptime)
			}
			saved, err := Decode(bytes.NewReader(firstRaw))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyChecksum(saved); err != nil {
				t.Fatal(err)
			}
			got := saved.Domains.BGP.Neighbors
			if len(got) != 1 || got[0].State != "" || got[0].Uptime != "" || got[0].Addr != peer.Addr.String() || got[0].RemoteAS != peer.RemoteAS || got[0].RemotePort != 1790 || !got[0].MultiHop {
				t.Fatalf("persisted desired peer changed or contains runtime: %+v", got)
			}
			if h.bgpNeighbors[0].State != "ACTIVE" || h.bgpNeighbors[0].Uptime != "never" {
				t.Fatal("capture changed the speaker's runtime state")
			}
		})
	}
}

func TestBGPCompletedIntentDropsRawRuntimeWithoutReordering(t *testing.T) {
	h, d, e := intentFixture(t)
	d.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{
		{Addr: "192.0.2.99", RemoteAS: 65199, State: "ACTIVE", Uptime: "never"},
		{Addr: "192.0.2.23", RemoteAS: 65123, RemotePort: 1790, MultiHop: true, State: "ESTABLISHED", Uptime: "00:01:00"},
	}
	d.Domains.BGP.DefinedSets = []cmn.GoBGPPolicyDefinedSetMod{{Name: "z", DefinedTypeString: "prefix"}, {Name: "a", DefinedTypeString: "prefix"}}
	d.Domains.BGPPolicyAssignment = []cmn.GoBGPPolicyApply{
		{NeighIPAddress: "global", PolicyType: "import", Polices: []string{"z-policy", "a-policy"}, RouteAction: "reject"},
		{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"z-policy", "a-policy"}, RouteAction: "accept"},
	}
	bgpRaw, err := json.Marshal(d.Domains.BGP)
	if err != nil {
		t.Fatal(err)
	}
	assignmentRaw, err := json.Marshal(d.Domains.BGPPolicyAssignment)
	if err != nil {
		t.Fatal(err)
	}
	d.pendingBGPRaw = map[string]json.RawMessage{DomainBGP: bgpRaw, DomainBGPPolicyAssignment: assignmentRaw}
	expected := cloneBGPDocument(d)
	for i := range expected.Domains.BGP.Neighbors {
		expected.Domains.BGP.Neighbors[i].State, expected.Domains.BGP.Neighbors[i].Uptime = "", ""
	}
	RememberBGPIntent(d)
	live := &healthyBGPFixture{mockHooks: h, healthy: false}
	_, saved, err := WriteThrough(live, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := LoadPersisted(e.PreRestoreDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(disk))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum(got); err != nil {
		t.Fatal(err)
	}
	for _, actual := range []*Document{saved, got} {
		if !reflect.DeepEqual(actual.Domains.BGP, expected.Domains.BGP) || !reflect.DeepEqual(actual.Domains.BGPPolicyAssignment, expected.Domains.BGPPolicyAssignment) {
			t.Fatalf("completed intent changed order/config or retained runtime: peers=%+v assignments=%+v", actual.Domains.BGP.Neighbors, actual.Domains.BGPPolicyAssignment)
		}
	}
	if len(saved.pendingBGPRaw) != 0 {
		t.Fatal("completed intent still carries raw boot bytes")
	}
	if !bytes.Equal(d.pendingBGPRaw[DomainBGP], bgpRaw) || !bytes.Equal(d.pendingBGPRaw[DomainBGPPolicyAssignment], assignmentRaw) || d.Domains.BGP.Neighbors[0].State != "ACTIVE" {
		t.Fatal("retention mutated its source document")
	}
}
