package prometheus

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestQosVipString(t *testing.T) {
	// xip is network byte order: the least significant byte is the first
	// octet (matches loxilib IPtonl / NltoIP, which the config path uses).
	cases := []struct {
		xip  uint32
		want string
	}{
		{0x0100007f, "127.0.0.1"},
		{0x0a01a8c0, "192.168.1.10"},
		{0x00000000, "0.0.0.0"},
		{0xffffffff, "255.255.255.255"},
	}
	for _, c := range cases {
		if got := qosVipString(c.xip); got != c.want {
			t.Errorf("qosVipString(%#x) = %q, want %q", c.xip, got, c.want)
		}
	}
}

func TestQosProtoString(t *testing.T) {
	cases := map[uint8]string{6: "tcp", 17: "udp", 132: "sctp", 47: "47"}
	for proto, want := range cases {
		if got := qosProtoString(proto); got != want {
			t.Errorf("qosProtoString(%d) = %q, want %q", proto, got, want)
		}
	}
}

func TestSortQosSamplesIsDeterministic(t *testing.T) {
	samples := []qosShaperSample{
		{vip: "10.0.0.2", port: "9000", direction: "upload"},
		{vip: "10.0.0.1", port: "9100", direction: "download"},
		{vip: "10.0.0.1", port: "9000", direction: "upload"},
		{vip: "10.0.0.1", port: "9000", direction: "download"},
	}
	sortQosSamples(samples)

	want := []string{
		"10.0.0.1/9000/download",
		"10.0.0.1/9000/upload",
		"10.0.0.1/9100/download",
		"10.0.0.2/9000/upload",
	}
	for i, w := range want {
		got := samples[i].vip + "/" + samples[i].port + "/" + samples[i].direction
		if got != w {
			t.Errorf("sorted[%d] = %q, want %q", i, got, w)
		}
	}
}

// The collector must emit nothing at all when no service is shaped - an empty
// store means "the shaper is not in use", not "zero throughput".
func TestQosShaperCollectorEmptyStore(t *testing.T) {
	qosShaperStoreMutex.Lock()
	saved := qosShaperStore
	qosShaperStore = nil
	qosShaperStoreMutex.Unlock()
	defer func() {
		qosShaperStoreMutex.Lock()
		qosShaperStore = saved
		qosShaperStoreMutex.Unlock()
	}()

	if n := testutil.CollectAndCount(qosShaperCollector{}); n != 0 {
		t.Errorf("empty store emitted %d metrics, want 0", n)
	}
}

func TestQosShaperCollectorEmitsLabelledSeries(t *testing.T) {
	qosShaperStoreMutex.Lock()
	saved := qosShaperStore
	qosShaperStore = []qosShaperSample{{
		vip:            "192.168.1.10",
		port:           "9000",
		proto:          "tcp",
		direction:      "download",
		bytesPassed:    4096,
		bytesDelayed:   1024,
		parks:          3,
		parkSeconds:    1.5,
		parkedConns:    2,
		tokens:         512,
		cirBytesPerSec: 1000000,
		cbsBytes:       100000,
	}}
	qosShaperStoreMutex.Unlock()
	defer func() {
		qosShaperStoreMutex.Lock()
		qosShaperStore = saved
		qosShaperStoreMutex.Unlock()
	}()

	want := `
# HELP loxilb_proxy_qos_parks_total Times the shaper parked a reader because its bucket was empty.
# TYPE loxilb_proxy_qos_parks_total counter
loxilb_proxy_qos_parks_total{direction="download",port="9000",proto="tcp",vip="192.168.1.10"} 3
`
	if err := testutil.CollectAndCompare(qosShaperCollector{}, strings.NewReader(want),
		"loxilb_proxy_qos_parks_total"); err != nil {
		t.Errorf("parks series mismatch: %v", err)
	}

	// 8 series per shaped direction: 4 counters + 4 gauges.
	if n := testutil.CollectAndCount(qosShaperCollector{}); n != 8 {
		t.Errorf("collected %d metrics for one shaped direction, want 8", n)
	}
}
