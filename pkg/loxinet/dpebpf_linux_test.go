// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"testing"
	"time"
)

func TestMapNotifierReturnsOnShutdown(t *testing.T) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		dpMapNotifierWorker(stop, nil)
	}()
	close(stop)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("map notifier did not return after shutdown")
	}
}
