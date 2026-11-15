// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

// Package operlog writes the gateway's operational text logs.
package operlog

import (
	"fmt"
	"io"
	"log"
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
	ttyMu   sync.Mutex
	writers [Trace + 1]*log.Logger

	// LogTTY is the compatibility view for callers with exclusive access.
	// Concurrent logging uses tty, which is updated by SetTTY.
	LogTTY bool

	// The compatibility writers are the same sinks used by Logf. Their
	// pointers are fixed by New. Call SetOutput to configure a sink.
	LogItEmer, LogItAlert, LogItCrit  *log.Logger
	LogItErr, LogItWarn, LogItNotice  *log.Logger
	LogItInfo, LogItDebug, LogItTrace *log.Logger
}

func New(output io.Writer, level Level, tty bool) (*Logger, error) {
	if output == nil || level < Emerg || level > Trace {
		return nil, fmt.Errorf("operlog: invalid output or level %d", level)
	}
	l := &Logger{LogTTY: tty}
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
	l.ttyMu.Lock()
	defer l.ttyMu.Unlock()
	l.LogTTY = enabled
	return l.tty.Swap(enabled)
}

func (l *Logger) enabled(level Level) bool {
	return level >= Emerg && level <= l.Level()
}

func (l *Logger) logf(level Level, format string, args ...any) {
	l.writers[level].Printf(format, args...)
	if l.tty.Load() {
		fmt.Printf("%s ", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Printf(format, args...)
	}
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
