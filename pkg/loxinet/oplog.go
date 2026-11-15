/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package loxinet

import (
	"io"
	"log"
	"os"
	"time"

	tk "github.com/loxilb-io/loxilib"
	logrus "github.com/sirupsen/logrus"

	"github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/pkg/logring"
)

// opLog is the queue between the gateway's log calls and its log file and
// terminal. A log call on the request path (a cgo callback on a data-plane
// worker) copies its line into it and returns; one goroutine writes.
var opLog *logring.Ring

// opLogShutdownWait bounds how long shutdown waits for queued lines.
const opLogShutdownWait = 2 * time.Second

// opLogInstall points every level of the gateway's logger, and logrus, at
// a queue in front of file. Lines are written by their callers until
// opLogStart. The logger's own terminal copy is turned off: it was two
// writes to stdout on the calling thread, and the queue's writer makes the
// same copy.
func opLogInstall(lg *tk.Logger, file io.Writer) {
	var tty io.Writer
	if lg.LogItSetTTY(false) {
		tty = os.Stdout
	}
	r := logring.New(file, tty, os.Stderr, logring.DefaultSize)
	for _, l := range []struct {
		lg    *log.Logger
		level logring.Level
	}{
		{lg.LogItEmer, logring.Fatal}, {lg.LogItAlert, logring.Fatal}, {lg.LogItCrit, logring.Fatal},
		{lg.LogItErr, logring.Error}, {lg.LogItWarn, logring.Warn}, {lg.LogItNotice, logring.Notice},
		{lg.LogItInfo, logring.Info}, {lg.LogItDebug, logring.Debug}, {lg.LogItTrace, logring.Trace},
	} {
		l.lg.SetOutput(r.Leveled(l.level, len(l.lg.Prefix())))
	}
	// The AI subsystems (KV attest/subscriber, adapters) log through
	// sirupsen/logrus, which writes to stderr only. Under any launcher
	// that discards the process's stderr (docker exec -dt, detached
	// supervisors) those lines vanish entirely. Send them to the same
	// rotated file the level writers use so /var/log/loxilb<host>.log
	// carries the whole story regardless of how stderr is wired.
	logrus.SetOutput(r.Raw())
	opLog = r
	prometheus.SetLogLinesDroppedSource(opLogDropped)
}

// opLogStart ends start-up: from here on no log call writes.
func opLogStart() {
	if opLog != nil {
		opLog.Start()
	}
}

// opLogStop writes what both logs hold, the gateway's and the data
// plane's, and gives the writing back to the callers. Shutdown calls it
// before the process leaves.
func opLogStop() {
	if opLog != nil {
		opLog.Stop(opLogShutdownWait)
	}
	dpLogStop()
}

// opLogDropped is what loxilb_log_lines_dropped_total reports: by level,
// the gateway's dropped lines and the data plane's together.
func opLogDropped() map[string]uint64 {
	out := make(map[string]uint64, 6)
	if opLog != nil {
		for _, l := range logring.Levels() {
			out[l.String()] = opLog.Dropped(l)
		}
	}
	out["trace"] += dpLogDropped(dpLogTrace)
	out["debug"] += dpLogDropped(dpLogDebug)
	out["info"] += dpLogDropped(dpLogInfo)
	out["warn"] += dpLogDropped(dpLogWarn)
	out["error"] += dpLogDropped(dpLogError)
	return out
}
