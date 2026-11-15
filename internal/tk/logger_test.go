// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package tk

import (
	"bytes"
	"io"
	"log"
	"path/filepath"
	"testing"

	"github.com/loxilb-io/loxilib"
)

func TestLogItMatchesPinnedLoxilib(t *testing.T) {
	var got, want bytes.Buffer
	l, err := NewLogger(&got, LogTrace, false)
	if err != nil {
		t.Fatal(err)
	}
	previous := SwapDefaultLogger(l)
	t.Cleanup(func() { SwapDefaultLogger(previous) })

	reference := loxilib.LogItInit(filepath.Join(t.TempDir(), "reference.log"), loxilib.LogTrace, false)
	referenceFile := reference.LogItEmer.Writer().(io.Closer)
	t.Cleanup(func() { referenceFile.Close() })
	writers := [...]*log.Logger{l.LogItEmer, l.LogItAlert, l.LogItCrit, l.LogItErr, l.LogItWarn,
		l.LogItNotice, l.LogItInfo, l.LogItDebug, l.LogItTrace}
	referenceWriters := [...]*log.Logger{reference.LogItEmer, reference.LogItAlert, reference.LogItCrit,
		reference.LogItErr, reference.LogItWarn, reference.LogItNotice, reference.LogItInfo,
		reference.LogItDebug, reference.LogItTrace}
	levels := [...]LogLevelT{LogEmerg, LogAlert, LogCritical, LogError, LogWarning, LogNotice, LogInfo, LogDebug, LogTrace}
	referenceLevels := [...]loxilib.LogLevelT{loxilib.LogEmerg, loxilib.LogAlert, loxilib.LogCritical,
		loxilib.LogError, loxilib.LogWarning, loxilib.LogNotice, loxilib.LogInfo, loxilib.LogDebug, loxilib.LogTrace}
	for i, writer := range writers {
		ref := referenceWriters[i]
		if int(levels[i]) != int(referenceLevels[i]) || writer.Flags() != ref.Flags() {
			t.Fatalf("severity %d: level/flags = %d/%d, want %d/%d", i,
				levels[i], writer.Flags(), referenceLevels[i], ref.Flags())
		}
		// Compare the complete formatted message with the clock disabled.
		writer.SetFlags(0)
		ref.SetFlags(0)
		ref.SetOutput(&want)
		LogIt(levels[i], "message %d", i)
		reference.Log(referenceLevels[i], "message %d", i)
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("log output = %q, want %q", got.Bytes(), want.Bytes())
	}
}

type benchmarkSink struct{}

// A writer distinct from io.Discard keeps formatting and Write active.
func (benchmarkSink) Write(p []byte) (int, error) { return len(p), nil }

func installBenchmarkLogger(b *testing.B, out io.Writer, level LogLevelT) {
	b.Helper()
	l, err := NewLogger(out, level, false)
	if err != nil {
		b.Fatal(err)
	}
	previous := SwapDefaultLogger(l)
	b.Cleanup(func() { SwapDefaultLogger(previous) })
	b.ReportAllocs()
	b.ResetTimer()
}

func BenchmarkLogItFilteredParallel(b *testing.B) {
	installBenchmarkLogger(b, io.Discard, LogInfo)
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			LogIt(LogDebug, "filtered request log")
		}
	})
}

func BenchmarkLogItEnabledParallel(b *testing.B) {
	installBenchmarkLogger(b, benchmarkSink{}, LogDebug)
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			LogIt(LogDebug, "enabled request log")
		}
	})
}
