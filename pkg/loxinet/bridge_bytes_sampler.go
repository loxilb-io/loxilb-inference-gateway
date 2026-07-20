/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 *
 * P49-R3: sample kernel-bridge RX+TX bytes from /sys/class/net/<br>/statistics
 * and publish as a Prometheus gauge. Stays flat when DOCA ASIC carries traffic —
 * proves HW offload engagement (ground truth independent of DOCA counter quirks,
 * including the BF2 silicon caveat where FWD_PORT counters may stay at 0 even
 * though packets are offloaded; see 49-RESEARCH.md §BF2 silicon caveat).
 */

package loxinet

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// sysfsNetBase is the root of per-interface sysfs statistics.
// Exported as a package-level var (not const) so tests can override with t.TempDir.
// Production code MUST NOT mutate this from anywhere except a test.
var sysfsNetBase = "/sys/class/net"

// missingBridges tracks bridges that have reported ENOENT — we log once per
// bridge per process lifetime to avoid log spam on permanently-missing entries.
// Cleared (per-name) when a bridge reappears (bridge recreate / rename churn).
var missingBridges = map[string]bool{}

// SampleKernelBridgeBytes reads rx_bytes + tx_bytes from /sys/class/net/<name>/statistics
// for every bridge tracked bridgeByName registry, and sets the
// kernelBridgeBytes gauge to rx+tx per bridge.
//
// Security (threat: sysfs path injection):
//   - bridge name comes from kernel netlink (bridgeByName is populated by nlp),
//     so it is NOT user-controlled today. Defense-in-depth: filepath.Clean +
//     reject names containing '/' or '..' before Sprintf into the sysfs path.
//
// Robustness:
//   - ENOENT (bridge just deleted): log Info once, drop the stale gauge
//     child, continue. Do NOT fail the whole sample cycle.
//   - Parse error (sysfs contents non-numeric): log Debug, skip this bridge
//     this tick. Retry next tick. Do NOT Set gauge with a bad value.
func SampleKernelBridgeBytes() {
	for _, name := range ListBridges() {
		cleaned := filepath.Clean(name)
		if cleaned == "" || cleaned == "." || strings.Contains(cleaned, "/") || strings.Contains(cleaned, "..") {
			logrus.WithField("bridge", name).Warn("bridge-bytes-sampler: rejecting suspicious bridge name (defense)")
			continue
		}

		rxPath := fmt.Sprintf("%s/%s/statistics/rx_bytes", sysfsNetBase, cleaned)
		txPath := fmt.Sprintf("%s/%s/statistics/tx_bytes", sysfsNetBase, cleaned)

		rx, errRx := readSysfsUint64(rxPath)
		tx, errTx := readSysfsUint64(txPath)

		if errRx != nil || errTx != nil {
			if os.IsNotExist(errRx) || os.IsNotExist(errTx) {
				if !missingBridges[cleaned] {
					logrus.WithFields(logrus.Fields{
						"bridge":  cleaned,
						"rx_path": rxPath,
						"tx_path": txPath,
					}).Info("bridge-bytes-sampler: bridge sysfs not present -- dropping gauge child")
					missingBridges[cleaned] = true
				}
				kernelBridgeBytes.DeleteLabelValues(cleaned)
				continue
			}
			// Parse error or other I/O error: Debug-level, keep retrying.
			logrus.WithFields(logrus.Fields{
				"bridge": cleaned,
				"errRx":  errRx,
				"errTx":  errTx,
			}).Debug("bridge-bytes-sampler: read error, skipping this tick")
			continue
		}

		// Bridge reappeared after being missing -- clear the once-flag so a future
		// disappearance logs again.
		if missingBridges[cleaned] {
			delete(missingBridges, cleaned)
		}

		kernelBridgeBytes.WithLabelValues(cleaned).Set(float64(rx + tx))
	}
}

// readSysfsUint64 reads a decimal ASCII uint64 from a sysfs file, tolerating
// trailing whitespace/newline. Returns the wrapped PathError on os.ReadFile
// failure so callers can test with os.IsNotExist.
func readSysfsUint64(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	return strconv.ParseUint(s, 10, 64)
}
