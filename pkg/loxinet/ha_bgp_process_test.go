package loxinet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHABGPDaemonReceivesTermOnCancel(t *testing.T) {
	d := t.TempDir()
	marker := filepath.Join(d, "term")
	ready := filepath.Join(d, "ready")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newBGPDaemonCommand(ctx, `trap 'echo term > "$MARKER"; exit 0' TERM; echo ready > "$READY"; while :; do sleep 0.02; done`)
	cmd.Env = append(os.Environ(), "MARKER="+marker, "READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("child not ready")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	_ = cmd.Wait()
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("SIGTERM trap did not run", err)
	}
	if cmd.WaitDelay != 5*time.Second {
		t.Fatal("shutdown fallback bound changed")
	}
}

func TestHABGPDaemonKillFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := newBGPDaemonCommand(ctx, `trap '' TERM; echo ready; exec sleep 60`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// sleep inherits ignored SIGTERM; cancellation must reach the fallback.
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	cancel()
	_ = cmd.Wait()
	elapsed := time.Since(start)
	if elapsed < 4*time.Second || elapsed > 7*time.Second {
		t.Fatal("unbounded or missing kill fallback", elapsed)
	}
}
