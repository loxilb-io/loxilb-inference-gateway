//go:build linux

package loxinet

import (
	"testing"
	"time"
)

// A constructor-started ticker must observe its own stop channel even before
// its returned datapath instance is published in the process-wide holder.
func TestDpTickerStopsBeforeGlobalPublication(t *testing.T) {
	dp := &DpEbpfH{stop: make(chan struct{}), ticker: time.NewTicker(time.Hour)}
	defer dp.ticker.Stop()
	close(dp.stop)
	done := make(chan struct{})
	go func() { dpEbpfTicker(dp); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unpublished datapath ticker did not stop")
	}
}
