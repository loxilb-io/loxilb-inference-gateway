package loxinet

import (
	"context"
	api "github.com/osrg/gobgp/v3/api"
	"time"
)

// Transport readiness includes an unconfigured speaker: the first global POST
// must be able to StartBgp. This process-lifetime latch never resets on a crash.
// No subsystem/recovery mutex is held while probing or backing off.
func (h *GoBgpH) waitForStartup(parent context.Context, now func() time.Time, wait func(context.Context, time.Duration) error) error {
	if h.startupReady.Load() {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	deadline := now().Add(30 * time.Second)
	delay := 250 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if h.startupReady.Load() {
			return nil
		}
		probe, stop := context.WithTimeout(ctx, 5*time.Second)
		_, err := h.client.GetBgp(probe, &api.GetBgpRequest{})
		stop()
		if err == nil {
			h.startupReady.Store(true)
			return nil
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return err
		}
		pause := delay
		if pause > remaining {
			pause = remaining
		}
		if err := wait(ctx, pause); err != nil {
			return err
		}
		if !now().Before(deadline) {
			return context.DeadlineExceeded
		}
		if delay < 4*time.Second {
			delay *= 2
			if delay > 4*time.Second {
				delay = 4 * time.Second
			}
		}
	}
}
func waitBGPStartupDelay(ctx context.Context, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
