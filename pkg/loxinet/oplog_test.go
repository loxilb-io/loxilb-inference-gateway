package loxinet

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tk "github.com/loxilb-io/loxilib"
	logrus "github.com/sirupsen/logrus"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/aikey"
)

type oplogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *oplogBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *oplogBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// oplogTestLogger makes a gateway logger at level and installs it as the
// default one for the test.
func oplogTestLogger(t *testing.T, level tk.LogLevelT, tty bool) *tk.Logger {
	t.Helper()
	lg, err := tk.NewLogger(io.Discard, level, tty)
	if err != nil {
		t.Fatal(err)
	}
	previousRing := opLog
	prev := tk.SwapDefaultLogger(lg)
	previousOutput := logrus.StandardLogger().Out
	t.Cleanup(func() {
		tk.SwapDefaultLogger(prev)
		logrus.SetOutput(previousOutput)
		if opLog != nil && opLog != previousRing {
			opLog.Stop(opLogShutdownWait)
		}
		opLog = previousRing
	})
	return lg
}

// The key-validation callback runs on a data-plane worker for every keyed
// request. At the default level it writes no log line, whatever it
// decides; at debug it says what it decided.
func TestRequestPathLogsNothingAtTheDefaultLevel(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	valid := &cmn.ApiKeyEntry{KeyID: "abc123", TenantID: "tenant-1", Enabled: true}
	calls := func() {
		validateAPIKeyInternal(&mockAPIKeyValidator{entry: valid}, "", "m")
		validateAPIKeyInternal(&mockAPIKeyValidator{entry: valid}, "raw", "m")
		validateAPIKeyInternal(&mockAPIKeyValidator{err: aikey.ErrInvalidKey}, "raw", "m")
		validateAPIKeyInternal(&mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{KeyID: "old", TenantID: "t", Enabled: true, ExpiresAt: &past}}, "raw", "m")
		validateAPIKeyInternal(&mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{KeyID: "k", TenantID: "t", Enabled: true, AllowedModels: []string{"other"}}}, "raw", "m")
	}
	for _, tc := range []struct {
		level tk.LogLevelT
		lines int
	}{{tk.LogInfo, 0}, {tk.LogDebug, 5}} {
		lg := oplogTestLogger(t, tc.level, false)
		out := &oplogBuf{}
		opLogInstall(lg, out)
		calls()
		got := strings.Count(out.String(), "llb_ai_validate_key")
		if got != tc.lines {
			t.Fatalf("level %d: %d log lines for five keyed requests, want %d:\n%s", tc.level, got, tc.lines, out.String())
		}
	}
}

// opLogInstall puts the queue in front of every level and takes the
// terminal copy over from the logger, which made it with two writes of
// its own on the calling thread.
func TestOpLogInstallRoutesEveryLevelThroughTheQueue(t *testing.T) {
	lg := oplogTestLogger(t, tk.LogTrace, true)
	out := &oplogBuf{}

	opLogInstall(lg, out)
	if lg.LogTTY {
		t.Fatal("the logger still writes its own terminal copy")
	}
	for l := tk.LogEmerg; l <= tk.LogTrace; l++ {
		tk.LogIt(l, "level %d\n", int(l))
	}
	for l := tk.LogEmerg; l <= tk.LogTrace; l++ {
		if !strings.Contains(out.String(), "level "+string(rune('0'+int(l)))+"\n") {
			t.Fatalf("level %d did not reach the file:\n%s", l, out.String())
		}
	}
	opLogStart()
	tk.LogIt(tk.LogInfo, "queued\n")
	if !opLog.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if !strings.Contains(out.String(), "queued\n") {
		t.Fatal("a line logged after opLogStart was not written by the writer")
	}
	got := opLogDropped()
	for _, level := range []string{"error", "warn", "notice", "info", "debug", "trace"} {
		if v, ok := got[level]; !ok || v != 0 {
			t.Fatalf("dropped[%s] = %d, %v; want 0, present", level, v, ok)
		}
	}
	if len(got) != 6 {
		t.Fatalf("%d levels reported, want 6: %v", len(got), got)
	}
	opLog.Stop(time.Second)
}
