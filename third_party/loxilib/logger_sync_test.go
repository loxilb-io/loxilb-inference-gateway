// SPDX-License-Identifier: Apache 2.0
// Copyright (c) 2026 LoxiLB Authors
package loxilib

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger(t *testing.T, output io.Writer, level LogLevelT) *Logger {
	t.Helper()
	l, err := NewLogger(output, level, false)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestDefaultLoggerConcurrentSwapAndLogging(t *testing.T) {
	l := testLogger(t, io.Discard, LogTrace)
	previous := SwapDefaultLogger(l)
	defer SwapDefaultLogger(previous)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				LogIt(LogInfo, "live %d", j)
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		SwapDefaultLogger(nil)
		SwapDefaultLogger(l)
	}
	wg.Wait()
	out := &bytes.Buffer{}
	SwapDefaultLogger(testLogger(t, out, LogInfo))
	LogIt(LogInfo, "after replacement")
	SwapDefaultLogger(nil)
	LogIt(LogInfo, "must be silent")
	if !strings.Contains(out.String(), "after replacement") || strings.Contains(out.String(), "must be silent") {
		t.Fatal(out.String())
	}
}

type blockedLogWriter struct {
	entered chan struct{}
	release chan struct{}
}

func (w *blockedLogWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}

func TestDefaultLoggerSwapJoinsInflightCall(t *testing.T) {
	w := &blockedLogWriter{make(chan struct{}), make(chan struct{})}
	previous := SwapDefaultLogger(testLogger(t, w, LogInfo))
	defer SwapDefaultLogger(previous)
	var once sync.Once
	release := func() { once.Do(func() { close(w.release) }) }
	defer release()
	logged := make(chan struct{})
	go func() { LogIt(LogInfo, "blocked"); close(logged) }()
	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("log did not reach writer")
	}
	swapped := make(chan struct{})
	go func() { SwapDefaultLogger(nil); close(swapped) }()
	select {
	case <-swapped:
		t.Fatal("replacement returned while old output was in use")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not join")
	}
	<-logged
}

func TestLoggerConcurrentConfiguration(t *testing.T) {
	l := testLogger(t, io.Discard, LogTrace)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				l.Log(LogDebug, "message")
				l.LogItGetLevel()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		l.LogItSetLevel(LogInfo)
		l.LogItSetTTY(false)
		l.LogItSetLevel(LogTrace)
	}
	wg.Wait()
	if err := l.LogItSetLevel(LogTrace + 1); err == nil || l.LogItGetLevel() != LogTrace {
		t.Fatal("invalid level changed configuration")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	for level := LogEmerg; level <= LogTrace; level++ {
		out := &bytes.Buffer{}
		l := testLogger(t, out, level)
		for message := LogEmerg; message <= LogTrace; message++ {
			l.Log(message, "message-level-%d", message)
		}
		if got := strings.Count(out.String(), "message-level-"); got != int(level)+1 {
			t.Fatalf("level %d: got %d lines", level, got)
		}
	}
	if _, err := NewLogger(nil, LogInfo, false); err == nil {
		t.Fatal("nil output accepted")
	}
	if _, err := NewLogger(io.Discard, -1, false); err == nil {
		t.Fatal("invalid level accepted")
	}
}

func TestLogItInitConcurrentFirstPublication(t *testing.T) {
	previous := SwapDefaultLogger(nil)
	defer SwapDefaultLogger(previous)
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			LogItInit(filepath.Join(dir, "init.log"), LogInfo, false)
			LogIt(LogInfo, "initialized")
		}()
	}
	wg.Wait()
	if SwapDefaultLogger(nil) == nil {
		t.Fatal("initialization did not publish a logger")
	}
}
