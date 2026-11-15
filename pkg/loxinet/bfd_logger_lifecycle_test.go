package loxinet

import (
	"io"
	"runtime"
	"testing"
	"time"

	bfd "github.com/loxilb-io/loxilb/pkg/proto"
	tk "github.com/loxilb-io/loxilib"
)

// Exercise real ticker LogIt readers while the next fixture publishes/restores
// loggers. Deletion must join that ticker before its peer socket is released.
func TestBFDLoggerReplacementAndTeardown(t *testing.T) {
	peer := bfdPeer(t, "127.0.12.1")
	table := bfd.StructNew(0)
	config := bfd.ConfigArgs{RemoteIP: "127.0.12.1", SourceIP: "127.0.0.1", Port: 3784, Interval: uint32(bfd.BFDMinSysTXIntervalUs), Multi: 3}
	if err := table.BFDAddRemote(config, nil); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			if err := table.BFDDeleteRemote(config); err != nil {
				t.Errorf("join BFD fixture: %v", err)
			}
		}
	})
	logger, err := tk.NewLogger(io.Discard, tk.LogTrace, false)
	if err != nil {
		t.Fatal(err)
	}
	previous := tk.SwapDefaultLogger(logger)
	// Registered after the session cleanup, so a live ticker must tolerate restore.
	t.Cleanup(func() { tk.SwapDefaultLogger(previous) })
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			tk.SwapDefaultLogger(nil)
			tk.SwapDefaultLogger(logger)
			runtime.Gosched()
		}
	}()
	for i := 0; i < 2; i++ {
		if !sent(peer, 2*time.Second) {
			t.Error("BFD ticker did not send")
		}
	}
	close(stop)
	<-done
	if err := table.BFDDeleteRemote(config); err != nil {
		t.Fatal(err)
	}
	stopped = true
	// Drain queued control packets including the final AdminDown. A fresh packet
	// after a quiet interval would mean the worker survived successful deletion.
	quiet := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if !sent(peer, 3*time.Duration(config.Interval)*time.Microsecond) {
			quiet = true
			break
		}
	}
	if !quiet {
		t.Fatal("BFD never became quiet after stop/join")
	}
	if sent(peer, 3*time.Duration(config.Interval)*time.Microsecond) {
		t.Fatal("BFD sent after stop/join")
	}
}
