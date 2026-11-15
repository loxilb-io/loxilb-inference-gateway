// SPDX-License-Identifier: Apache 2.0
// Copyright (c) 2022 NetLOX Inc

package loxilib

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogLevelT - Current log-level
type LogLevelT int

// Log levels
const (
	LogEmerg LogLevelT = iota
	LogAlert
	LogCritical
	LogError
	LogWarning
	LogNotice
	LogInfo
	LogDebug
	LogTrace
)

// Logger configuration fields are for construction only. Use the synchronized
// methods after publication; log.Logger.SetOutput is safe for destination changes.
type Logger struct {
	mu           sync.RWMutex
	LogTTY       bool
	CurrLogLevel LogLevelT
	LogItEmer    *log.Logger
	LogItAlert   *log.Logger
	LogItCrit    *log.Logger
	LogItErr     *log.Logger
	LogItWarn    *log.Logger
	LogItNotice  *log.Logger
	LogItInfo    *log.Logger
	LogItDebug   *log.Logger
	LogItTrace   *log.Logger
}

var (
	// DefaultLogger is retained for source compatibility. Do not read or assign it
	// directly while logging; use SwapDefaultLogger to replace it.
	DefaultLogger   *Logger
	defaultLoggerMu sync.RWMutex
)

// LogItInit - Initialize the logger
// logFile - name of the logfile
// logLevel - specify current loglevel
// toTTY - specify if logs need to be redirected to TTY as well or not
func LogItInit(logFile string, logLevel LogLevelT, toTTY bool) *Logger {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	logger, err := NewLogger(file, logLevel, toTTY)
	if err != nil {
		file.Close()
		log.Fatal(err)
	}
	defaultLoggerMu.Lock()
	if DefaultLogger == nil {
		DefaultLogger = logger
	}
	defaultLoggerMu.Unlock()
	return logger
}

// NewLogger constructs a complete logger without publishing it. The caller owns
// output and must keep it open until all uses (including default uses) finish.
func NewLogger(output io.Writer, logLevel LogLevelT, toTTY bool) (*Logger, error) {
	if output == nil || logLevel < LogEmerg || logLevel > LogTrace {
		return nil, errors.New("invalid logger output or level")
	}
	logger := new(Logger)

	logger.CurrLogLevel = logLevel
	logger.LogTTY = toTTY
	logger.LogItEmer = log.New(output, "EMER: ", log.Ldate|log.Ltime)
	logger.LogItAlert = log.New(output, "ALRT: ", log.Ldate|log.Ltime)
	logger.LogItCrit = log.New(output, "CRIT: ", log.Ldate|log.Ltime)
	logger.LogItErr = log.New(output, "ERR:  ", log.Ldate|log.Ltime)
	logger.LogItWarn = log.New(output, "WARN: ", log.Ldate|log.Ltime)
	logger.LogItNotice = log.New(output, "NOTI: ", log.Ldate|log.Ltime)
	logger.LogItInfo = log.New(output, "INFO: ", log.Ldate|log.Ltime)
	logger.LogItDebug = log.New(output, "DBG:  ", log.Ldate|log.Ltime)
	logger.LogItTrace = log.New(output, "TRACE:  ", log.Ldate|log.Ltime)

	return logger, nil
}

// SwapDefaultLogger publishes a fully configured logger (nil disables logging).
// It waits for in-flight LogIt calls to finish, so the old output may be closed
// after it returns. A log output must not call SwapDefaultLogger recursively.
func SwapDefaultLogger(logger *Logger) *Logger {
	defaultLoggerMu.Lock()
	defer defaultLoggerMu.Unlock()
	previous := DefaultLogger
	DefaultLogger = logger
	return previous
}

// Log uses Printf format internally
// Arguments are considered in-line with fmt.Printf.
func (logger *Logger) Log(l LogLevelT, format string, v ...interface{}) {
	logger.mu.RLock()
	defer logger.mu.RUnlock()
	if l < 0 || l > logger.CurrLogLevel {
		return
	}
	switch l {
	case LogEmerg:
		logger.LogItEmer.Printf(format, v...)
	case LogAlert:
		logger.LogItAlert.Printf(format, v...)
	case LogCritical:
		logger.LogItCrit.Printf(format, v...)
	case LogError:
		logger.LogItErr.Printf(format, v...)
	case LogWarning:
		logger.LogItWarn.Printf(format, v...)
	case LogNotice:
		logger.LogItNotice.Printf(format, v...)
	case LogInfo:
		logger.LogItInfo.Printf(format, v...)
	case LogDebug:
		logger.LogItDebug.Printf(format, v...)
	case LogTrace:
		logger.LogItTrace.Printf(format, v...)
	default:
		break
	}

	if logger.LogTTY {
		fmt.Printf("%s ", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Printf(format, v...)
	}
}

// LogIt uses Printf format internally
func LogIt(l LogLevelT, format string, v ...interface{}) {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	if DefaultLogger == nil {
		return
	}

	DefaultLogger.Log(l, format, v...)
}

// LogItSetLevel - Set level of the logger
func (logger *Logger) LogItSetLevel(logLevel LogLevelT) error {

	if logLevel < LogEmerg || logLevel > LogTrace {
		return errors.New("LogLevel is out of bounds")
	}

	logger.mu.Lock()
	defer logger.mu.Unlock()
	logger.CurrLogLevel = logLevel
	return nil
}

// LogItGetLevel reads the configured level while other goroutines log or update it.
func (logger *Logger) LogItGetLevel() LogLevelT {
	logger.mu.RLock()
	defer logger.mu.RUnlock()
	return logger.CurrLogLevel
}

// LogItSetTTY changes terminal mirroring and returns its previous setting.
func (logger *Logger) LogItSetTTY(enabled bool) bool {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	previous := logger.LogTTY
	logger.LogTTY = enabled
	return previous
}
