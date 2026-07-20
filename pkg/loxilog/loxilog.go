package loxilog

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"

	"github.com/loxilb-io/loxilb/pkg/logrotate"
)

// Config holds the configuration for initializing the loxilog package.
type Config struct {
	LogDir    string // Directory for log files. Default: "/var/log/loxilb/"
	LogFormat string // Output format: "json", "text", or "both". Default: "both"
	LogLevel  string // Initial global log level. Default: "debug"
	// Rotate controls size-based rotation of the log files. The zero
	// value falls back to logrotate.Defaults(); set MaxSizeMB negative
	// to explicitly disable rotation.
	Rotate logrotate.Config
}

// Package-level loggers and state.
var (
	cpLogger zerolog.Logger
	dpLogger zerolog.Logger

	cpDiodeWriter diode.Writer
	dpDiodeWriter diode.Writer

	cpJSONFile io.WriteCloser
	cpTxtFile  io.WriteCloser
	dpJSONFile io.WriteCloser
	dpTxtFile  io.WriteCloser

	initialized atomic.Bool

	// Drop counters — incremented from diode alerter callbacks.
	cpDrops atomic.Int64
	dpDrops atomic.Int64
)

// Init initializes the loxilog package with dual-output logging.
// It creates JSON (ECS) and plaintext (ConsoleWriter) log files for both
// the control plane (CP) and data plane (DP), each wrapped in an async
// diode ring buffer.
//
// Init must be called once during process startup. Subsequent calls are no-ops.
func Init(cfg Config) error {
	if !initialized.CompareAndSwap(false, true) {
		return nil // Already initialized.
	}

	if cfg.LogDir == "" {
		cfg.LogDir = "/var/log/loxilb/"
	}
	if cfg.LogFormat == "" {
		cfg.LogFormat = "both"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "debug"
	}

	// Ensure trailing slash.
	if cfg.LogDir[len(cfg.LogDir)-1] != '/' {
		cfg.LogDir += "/"
	}

	// Create log directory if it doesn't exist, then verify it's writable.
	logDir := cfg.LogDir
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logDir = "/tmp/"
	} else {
		testPath := logDir + ".loxilog_write_test"
		if f, err := os.OpenFile(testPath, os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			f.Close()
			os.Remove(testPath)
		} else {
			logDir = "/tmp/"
		}
	}

	hostname := os.Getenv("HOSTNAME")

	// Parse log level.
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)

	// Rotation: zero value means "not configured" → production defaults;
	// a negative MaxSizeMB explicitly disables rotation.
	rot := cfg.Rotate
	if rot == (logrotate.Config{}) {
		rot = logrotate.Defaults()
	}

	// --- Control Plane Logger ---
	var cpErr error
	cpLogger, cpDiodeWriter, cpJSONFile, cpTxtFile, cpErr = createLogger(
		logDir, "loxilb-audit.json.log", fmt.Sprintf("loxilb%s.log", hostname),
		cfg.LogFormat, 8192, &cpDrops, rot,
	)
	if cpErr != nil {
		initialized.Store(false)
		return fmt.Errorf("loxilog: CP logger init failed: %w", cpErr)
	}

	// --- Data Plane Logger ---
	var dpErr error
	dpLogger, dpDiodeWriter, dpJSONFile, dpTxtFile, dpErr = createLogger(
		logDir, "loxilb-dp-audit.json.log", fmt.Sprintf("loxilb-dp%s.log", hostname),
		cfg.LogFormat, 16384, &dpDrops, rot,
	)
	if dpErr != nil {
		// Clean up CP resources on DP failure.
		cpDiodeWriter.Close()
		closeFiles(cpJSONFile, cpTxtFile)
		initialized.Store(false)
		return fmt.Errorf("loxilog: DP logger init failed: %w", dpErr)
	}

	return nil
}

// createLogger creates a zerolog.Logger with diode-wrapped dual output.
// Files are opened through logrotate.Writer so they rotate by size instead
// of growing unbounded.
func createLogger(dir, jsonName, txtName, format string, diodeSize int, drops *atomic.Int64, rot logrotate.Config) (
	zerolog.Logger, diode.Writer, io.WriteCloser, io.WriteCloser, error,
) {
	var jsonFile, txtFile io.WriteCloser
	var err error

	jsonPath := dir + jsonName
	txtPath := dir + txtName

	// Open files based on format.
	needJSON := format == "json" || format == "both"
	needText := format == "text" || format == "both"

	if needJSON {
		jsonFile, err = logrotate.New(jsonPath, rot)
		if err != nil {
			return zerolog.Logger{}, diode.Writer{}, nil, nil,
				fmt.Errorf("open %s: %w", jsonPath, err)
		}
	}

	if needText {
		txtFile, err = logrotate.New(txtPath, rot)
		if err != nil {
			if jsonFile != nil {
				jsonFile.Close()
			}
			return zerolog.Logger{}, diode.Writer{}, nil, nil,
				fmt.Errorf("open %s: %w", txtPath, err)
		}
	}

	// Build the writer based on format.
	var writer zerolog.LevelWriter
	switch format {
	case "json":
		writer = zerolog.MultiLevelWriter(jsonFile)
	case "text":
		cw := zerolog.ConsoleWriter{
			Out:        txtFile,
			TimeFormat: time.RFC3339,
			NoColor:    true,
		}
		writer = zerolog.MultiLevelWriter(cw)
	default: // "both"
		cw := zerolog.ConsoleWriter{
			Out:        txtFile,
			TimeFormat: time.RFC3339,
			NoColor:    true,
		}
		writer = zerolog.MultiLevelWriter(jsonFile, cw)
	}

	// Wrap in async diode.
	dw := diode.NewWriter(writer, diodeSize, 10*time.Millisecond, func(missed int) {
		drops.Add(int64(missed))
	})

	logger := zerolog.New(dw).With().
		Timestamp().
		Str(FieldECSVersion, ECSVersion).
		Logger()

	return logger, dw, jsonFile, txtFile, nil
}

// closeFiles closes non-nil file handles.
func closeFiles(files ...io.WriteCloser) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}

// Close flushes all diode buffers and closes log files.
// It should be called during process shutdown to ensure all buffered
// events are written.
func Close() {
	if !initialized.Load() {
		return
	}
	cpDiodeWriter.Close()
	dpDiodeWriter.Close()
	closeFiles(cpJSONFile, cpTxtFile, dpJSONFile, dpTxtFile)
	initialized.Store(false)
}

// Event returns a new EventBuilder targeting the control plane logger.
// The default level is InfoLevel.
func Event(ctx context.Context) *EventBuilder {
	return &EventBuilder{
		ctx:    ctx,
		logger: &cpLogger,
		level:  zerolog.InfoLevel,
	}
}

// DPEvent returns a new EventBuilder targeting the data plane logger.
// The default level is InfoLevel.
func DPEvent(ctx context.Context) *EventBuilder {
	return &EventBuilder{
		ctx:    ctx,
		logger: &dpLogger,
		level:  zerolog.InfoLevel,
	}
}

// Context key for trace ID propagation.
type ctxKey int

const (
	// CtxKeyTraceID is the context key for storing trace IDs.
	CtxKeyTraceID ctxKey = iota
)

// WithTraceID returns a new context with the given trace ID.
func WithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, CtxKeyTraceID, id)
}

// TraceIDFromCtx extracts the trace ID from context, or returns "".
func TraceIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(CtxKeyTraceID).(string); ok {
		return id
	}
	return ""
}

// CPDrops returns the total number of dropped CP log events.
func CPDrops() int64 {
	return cpDrops.Load()
}

// DPDrops returns the total number of dropped DP log events.
func DPDrops() int64 {
	return dpDrops.Load()
}
