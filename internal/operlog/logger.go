// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

// Package operlog writes the gateway's operational text logs.
package operlog

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Level is the severity used by the gateway and the native logging bridge.
type Level int

const (
	Emerg Level = iota
	Alert
	Critical
	Error
	Warning
	Notice
	Info
	Debug
	Trace
)

var prefixes = [Trace + 1]string{
	Emerg: "EMER: ", Alert: "ALRT: ", Critical: "CRIT: ",
	Error: "ERR:  ", Warning: "WARN: ", Notice: "NOTI: ",
	Info: "INFO: ", Debug: "DBG:  ", Trace: "TRACE:  ",
}

// Logger holds a writable sink for each severity and concurrent log settings.
// Construct it with New and keep the output open until its callers finish.
type Logger struct {
	level   atomic.Int32
	tty     atomic.Bool
	writers [Trace + 1]*log.Logger
	// ttyOut receives the terminal mirror; nil means os.Stdout at write
	// time. Only tests set it, before the logger is used.
	ttyOut io.Writer

	// These writer fields are read-only after New. Reassigning a field does
	// not change the writer used by Logf. Use SetOutput on the writer to
	// change its output.
	LogItEmer, LogItAlert, LogItCrit  *log.Logger
	LogItErr, LogItWarn, LogItNotice  *log.Logger
	LogItInfo, LogItDebug, LogItTrace *log.Logger
}

func New(output io.Writer, level Level, tty bool) (*Logger, error) {
	if output == nil || level < Emerg || level > Trace {
		return nil, fmt.Errorf("operlog: invalid output or level %d", level)
	}
	l := &Logger{}
	l.level.Store(int32(level))
	l.tty.Store(tty)
	for n, prefix := range prefixes {
		l.writers[n] = log.New(output, prefix, log.Ldate|log.Ltime)
	}
	l.LogItEmer, l.LogItAlert, l.LogItCrit = l.writers[Emerg], l.writers[Alert], l.writers[Critical]
	l.LogItErr, l.LogItWarn, l.LogItNotice = l.writers[Error], l.writers[Warning], l.writers[Notice]
	l.LogItInfo, l.LogItDebug, l.LogItTrace = l.writers[Info], l.writers[Debug], l.writers[Trace]
	return l, nil
}

func (l *Logger) Level() Level { return Level(l.level.Load()) }

func (l *Logger) SetLevel(level Level) error {
	if level < Emerg || level > Trace {
		return fmt.Errorf("operlog: invalid level %d", level)
	}
	l.level.Store(int32(level))
	return nil
}

// SetTTY enables terminal mirroring and returns its previous setting.
func (l *Logger) SetTTY(enabled bool) bool {
	return l.tty.Swap(enabled)
}

// TTY reports whether terminal mirroring is enabled.
func (l *Logger) TTY() bool { return l.tty.Load() }

func (l *Logger) enabled(level Level) bool {
	return level >= Emerg && level <= l.Level()
}

func (l *Logger) logf(level Level, format string, args ...any) {
	l.writers[level].Printf(format, args...)
	if l.tty.Load() {
		l.mirror(format, args...)
	}
}

// mirror copies a log line to the terminal in a single write. A timestamp
// written apart from its message lets other output on the same stdout, such
// as go test's "--- PASS" lines or another goroutine's log, land between
// the two. Like the file writer, it ends the line with a newline if the
// message has none, so the next output starts on a line of its own.
func (l *Logger) mirror(format string, args ...any) {
	line := fmt.Appendf(time.Now().AppendFormat(nil, "2006-01-02 15:04:05 "), format, args...)
	if line[len(line)-1] != '\n' {
		line = append(line, '\n')
	}
	out := l.ttyOut
	if out == nil {
		out = os.Stdout
	}
	_, _ = out.Write(line)
}

type publication struct {
	logger *Logger
	users  sync.WaitGroup
}

var (
	current atomic.Pointer[publication]
	// The lock serializes joining a publication with detaching it. Output
	// and draining both happen after releasing the lock.
	publicationMu sync.Mutex
)

// InstallDefault publishes logger only if no default is installed.
func InstallDefault(logger *Logger) {
	current.CompareAndSwap(nil, &publication{logger: logger})
}

// SwapDefault installs a logger (nil disables logging) and waits for calls
// through the previous publication. A formatter or output writer must avoid
// calling SwapDefault because a swap could wait for that same call to finish.
func SwapDefault(logger *Logger) *Logger {
	var next *publication
	if logger != nil {
		next = &publication{logger: logger}
	}
	publicationMu.Lock()
	previous := current.Swap(next)
	publicationMu.Unlock()
	if previous == nil {
		return nil
	}
	previous.users.Wait()
	return previous.logger
}

// Logf formats a line if the current logger accepts the severity. Filtered
// calls do not acquire a lock or format arguments.
func Logf(level Level, format string, args ...any) {
	p := current.Load()
	if p == nil || !p.logger.enabled(level) {
		return
	}
	publicationMu.Lock()
	p = current.Load()
	if p == nil || !p.logger.enabled(level) {
		publicationMu.Unlock()
		return
	}
	p.users.Add(1)
	publicationMu.Unlock()
	defer p.users.Done()
	p.logger.logf(level, format, args...)
}
