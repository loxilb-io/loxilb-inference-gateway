package prometheus

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const netstatFixture = `TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops
TcpExt: %d 0 0 4 0 0 0 0 0 0 1200 0 0 0 0 100 0 0 %d %d
IpExt: InNoRoutes InTruncatedPkts
IpExt: 0 0
`

func writeNetstat(t *testing.T, dir string, cookies, overflows, drops uint64) {
	t.Helper()
	body := []byte(fmtNetstat(cookies, overflows, drops))
	if err := os.WriteFile(filepath.Join(dir, "netstat"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fmtNetstat(cookies, overflows, drops uint64) string {
	return fmt.Sprintf(netstatFixture, cookies, overflows, drops)
}

func TestReadTcpExt(t *testing.T) {
	dir := t.TempDir()
	writeNetstat(t, dir, 7, 23902, 23910)

	ext, err := readTcpExt(filepath.Join(dir, "netstat"))
	if err != nil {
		t.Fatal(err)
	}
	if ext["ListenOverflows"] != 23902 || ext["ListenDrops"] != 23910 || ext["SyncookiesSent"] != 7 {
		t.Fatalf("unexpected counters: %+v", ext)
	}

	if _, err := readTcpExt(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must be an error")
	}
	if err := os.WriteFile(filepath.Join(dir, "short"), []byte("TcpExt: A B\nTcpExt: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTcpExt(filepath.Join(dir, "short")); err == nil {
		t.Fatal("a value line shorter than its header must be an error")
	}
}

func TestSampleListenBacklogExportsDeltas(t *testing.T) {
	dir := t.TempDir()
	origPath := netstatPath
	netstatPath = filepath.Join(dir, "netstat")
	prevListenOverflows, prevListenDrops, listenBacklogInited = 0, 0, false
	t.Cleanup(func() {
		netstatPath = origPath
		prevListenOverflows, prevListenDrops, listenBacklogInited = 0, 0, false
	})

	before := testutil.ToFloat64(proxyListenOverflowsTotal)
	beforeDrops := testutil.ToFloat64(proxyListenDropsTotal)

	// The first sample is the baseline: the kernel's boot-cumulative value
	// must not be exported as if it happened on loxilb's watch.
	writeNetstat(t, dir, 0, 1000, 1005)
	if err := sampleListenBacklog(); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(proxyListenOverflowsTotal); got != before {
		t.Fatalf("baseline sample exported %v overflows, want 0", got-before)
	}

	writeNetstat(t, dir, 0, 1030, 1042)
	if err := sampleListenBacklog(); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(proxyListenOverflowsTotal) - before; got != 30 {
		t.Fatalf("overflows delta = %v, want 30", got)
	}
	if got := testutil.ToFloat64(proxyListenDropsTotal) - beforeDrops; got != 37 {
		t.Fatalf("drops delta = %v, want 37", got)
	}

	// A counter that went backwards (namespace restart) adds nothing and
	// re-baselines.
	writeNetstat(t, dir, 0, 5, 5)
	if err := sampleListenBacklog(); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(proxyListenOverflowsTotal) - before; got != 30 {
		t.Fatalf("a reset must add nothing, got %v", got)
	}
	writeNetstat(t, dir, 0, 6, 5)
	if err := sampleListenBacklog(); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(proxyListenOverflowsTotal) - before; got != 31 {
		t.Fatalf("after a reset the delta must resume, got %v", got)
	}

	// An unreadable file is an error, and the counters stay put.
	netstatPath = filepath.Join(dir, "absent")
	if err := sampleListenBacklog(); err == nil {
		t.Fatal("unreadable netstat must be an error")
	}
	if got := testutil.ToFloat64(proxyListenOverflowsTotal) - before; got != 31 {
		t.Fatalf("an error must not move the counter, got %v", got)
	}
}
