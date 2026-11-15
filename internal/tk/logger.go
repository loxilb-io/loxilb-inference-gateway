// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

// Package tk provides the gateway's toolkit API. Operational logging is
// implemented in operlog; utilities come directly from the pinned loxilib.
package tk

import (
	"io"
	"log"
	"os"

	"github.com/loxilb-io/loxilb/internal/operlog"
)

type LogLevelT = operlog.Level

const (
	LogEmerg    = operlog.Emerg
	LogAlert    = operlog.Alert
	LogCritical = operlog.Critical
	LogError    = operlog.Error
	LogWarning  = operlog.Warning
	LogNotice   = operlog.Notice
	LogInfo     = operlog.Info
	LogDebug    = operlog.Debug
	LogTrace    = operlog.Trace
)

// Logger exposes the legacy level writers for log-ring configuration.
// Read LogTTY only with exclusive access. Use the methods to update settings.
type Logger operlog.Logger

func (l *Logger) LogItSetLevel(level LogLevelT) error { return (*operlog.Logger)(l).SetLevel(level) }
func (l *Logger) LogItGetLevel() LogLevelT            { return (*operlog.Logger)(l).Level() }
func (l *Logger) LogItSetTTY(enabled bool) bool       { return (*operlog.Logger)(l).SetTTY(enabled) }

func NewLogger(output io.Writer, level LogLevelT, tty bool) (*Logger, error) {
	l, err := operlog.New(output, level, tty)
	return (*Logger)(l), err
}

func LogItInit(path string, level LogLevelT, tty bool) *Logger {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		log.Fatal(err)
	}
	l, err := NewLogger(file, level, tty)
	if err != nil {
		file.Close()
		log.Fatal(err)
	}
	operlog.InstallDefault((*operlog.Logger)(l))
	return l
}

func SwapDefaultLogger(logger *Logger) *Logger {
	return (*Logger)(operlog.SwapDefault((*operlog.Logger)(logger)))
}

func LogIt(level LogLevelT, format string, args ...any) {
	operlog.Logf(level, format, args...)
}
