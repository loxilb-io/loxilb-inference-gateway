// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package operlog

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type formatter func() string

func (f formatter) String() string { return f() }

func testLogger(t testing.TB, out io.Writer, level Level) *Logger {
	t.Helper()
	l, err := New(out, level, false)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestFilteredLogDoesNotFormat(t *testing.T) {
	var out bytes.Buffer
	l := testLogger(t, &out, Info)
	previous := SwapDefault(l)
	t.Cleanup(func() { SwapDefault(previous) })
	calls := 0
	message := formatter(func() string { calls++; return "message" })
	Logf(Debug, "%s", message)
	Logf(-1, "%s", message)
	if calls != 0 || out.Len() != 0 {
		t.Fatal("filtered messages formatted or written")
	}
	if err := l.SetLevel(Debug); err != nil {
		t.Fatal(err)
	}
	Logf(Debug, "%s", message)
	if calls != 1 || !strings.Contains(out.String(), "message") {
		t.Fatalf("enabled message: calls=%d log=%q", calls, out.String())
	}
}

func TestSwapDrainsOldPublicationWhileFormatterLogs(t *testing.T) {
	var oldOutput, newOutput bytes.Buffer
	old := testLogger(t, &oldOutput, Info)
	next := testLogger(t, &newOutput, Info)
	previous := SwapDefault(old)
	t.Cleanup(func() { SwapDefault(previous) })

	formatting, resume := make(chan struct{}), make(chan struct{})
	var release sync.Once
	continueFormatting := func() { release.Do(func() { close(resume) }) }
	defer continueFormatting()
	logged := make(chan struct{})
	go func() {
		defer close(logged)
		Logf(Info, "%s", formatter(func() string {
			close(formatting)
			<-resume
			Logf(Info, "nested message")
			return "outer message"
		}))
	}()
	select {
	case <-formatting:
	case <-time.After(5 * time.Second):
		t.Fatal("outer log did not reach its formatter")
	}

	swapped := make(chan *Logger, 1)
	go func() { swapped <- SwapDefault(next) }()
	deadline := time.Now().Add(5 * time.Second)
	for current.Load().logger != next {
		if time.Now().After(deadline) {
			t.Fatal("replacement was not published while the outer call was active")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-swapped:
		t.Fatal("swap returned while an old caller was active")
	default:
	}
	continueFormatting()
	select {
	case <-logged:
	case <-time.After(5 * time.Second):
		t.Fatal("nested Logf blocked")
	}
	select {
	case got := <-swapped:
		if got != old {
			t.Fatal("swap did not return the previous logger")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("swap did not return after the old call completed")
	}
	if !strings.Contains(oldOutput.String(), "outer message") || !strings.Contains(newOutput.String(), "nested message") {
		t.Fatalf("outer and nested messages reached the wrong sinks: old=%q new=%q", oldOutput.String(), newOutput.String())
	}
}

// writeRecorder keeps each Write call apart, so a test can see whether a
// line reached the sink in one piece.
type writeRecorder struct {
	mu     sync.Mutex
	writes []string
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

// The terminal mirror shares stdout with go test and other goroutines. Each
// line must be one write: a timestamp written apart from its message let a
// "--- PASS" line land between them and fail the EPP datapath gate.
func TestTTYMirrorWritesEachLineOnce(t *testing.T) {
	l, err := New(io.Discard, Info, true)
	if err != nil {
		t.Fatal(err)
	}
	var tty writeRecorder
	l.ttyOut = &tty
	previous := SwapDefault(l)
	t.Cleanup(func() { SwapDefault(previous) })

	Logf(Info, "ends with a newline %d\n", 1)
	Logf(Info, "ends without one %d", 2)
	Logf(Debug, "filtered")

	stamp := regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} `)
	want := []string{"ends with a newline 1\n", "ends without one 2\n"}
	if len(tty.writes) != len(want) {
		t.Fatalf("terminal writes = %q, want one per line", tty.writes)
	}
	for i, got := range tty.writes {
		loc := stamp.FindStringIndex(got)
		if loc == nil || got[loc[1]:] != want[i] {
			t.Errorf("write %d = %q, want a timestamp then %q", i, got, want[i])
		}
	}
}

func BenchmarkFilteredParallel(b *testing.B) {
	l := testLogger(b, io.Discard, Info)
	previous := SwapDefault(l)
	b.Cleanup(func() { SwapDefault(previous) })
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			Logf(Debug, "filtered request log")
		}
	})
}
