package loxinet

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	bfd "github.com/loxilb-io/loxilb/pkg/proto"
)

// bfdPeer listens where a session to remote sends its control packets.
func bfdPeer(t *testing.T, remote string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(remote), Port: int(cmn.BFDPort)})
	if err != nil {
		t.Fatalf("listen %s:%d: %v", remote, cmn.BFDPort, err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

// bfdTestRun numbers the runs of the test below, so that each run talks to
// loopback addresses no earlier run's sessions still send to.
var bfdTestRun atomic.Int32

// sent reports whether a BFD control packet arrives within d.
func sent(pc *net.UDPConn, d time.Duration) bool {
	buf := make([]byte, 128)
	pc.SetReadDeadline(time.Now().Add(d))
	_, _, err := pc.ReadFromUDP(buf)
	return err == nil
}

// A session added while the initial HA sync is pending stays silent until it
// is done, also when --ka has already set SpawnKa (the boot replay of a saved
// configuration); a session added after it starts at once.
//
// Both sessions are left in place: deleting a session whose ticker is sending
// races that ticker inside pkg/proto, a teardown defect this test is not
// about. With no peer answering they stay Down and never notify, and the next
// run uses other addresses.
func TestBFDSessionWaitsForInitialHASync(t *testing.T) {
	run := bfdTestRun.Add(1)
	if run > 250 {
		t.Fatal("out of per-run loopback addresses")
	}
	bootIP, runtimeIP := fmt.Sprintf("127.0.10.%d", run), fmt.Sprintf("127.0.11.%d", run)
	ch := &CIStateH{Bs: bfd.StructNew(0), ClusterMap: map[string]*ClusterInstance{cmn.CIDefault: {}},
		SpawnKa: true, initSync: make(chan struct{})}
	interval := uint64(bfd.BFDMinSysTXIntervalUs)

	boot := cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP(bootIP), SourceIP: net.ParseIP("127.0.0.1"), Interval: interval, RetryCount: 3}
	bootPeer := bfdPeer(t, bootIP)
	if _, err := ch.CIBFDSessionAdd(boot); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ch.Bs.BFDDeleteRemote(bfd.ConfigArgs{RemoteIP: boot.RemoteIP.String()}); err != nil {
			t.Errorf("stop test-owned BFD session: %v", err)
		}
	})
	if sent(bootPeer, 5*time.Duration(interval)*time.Microsecond) {
		t.Fatal("boot session sent BFD before the initial HA sync was done")
	}

	close(ch.initSync)
	if !sent(bootPeer, 2*time.Second) {
		t.Fatal("boot session silent after the initial HA sync was done")
	}

	runtime := cmn.BFDMod{Instance: cmn.CIDefault, RemoteIP: net.ParseIP(runtimeIP), SourceIP: net.ParseIP("127.0.0.1"), Interval: interval, RetryCount: 3}
	runtimePeer := bfdPeer(t, runtimeIP)
	if _, err := ch.CIBFDSessionAdd(runtime); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ch.Bs.BFDDeleteRemote(bfd.ConfigArgs{RemoteIP: runtime.RemoteIP.String()}); err != nil {
			t.Errorf("stop test-owned BFD session: %v", err)
		}
	})
	if !sent(runtimePeer, 2*time.Second) {
		t.Fatal("session added after the initial HA sync did not start")
	}
}
