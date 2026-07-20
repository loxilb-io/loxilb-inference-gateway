/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

package loxinet

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// CleanupStaleRingFiles removes ring buffer files from dead/crashed processes
//
// This function should be called at startup BEFORE DpEbpfInit to prevent
// SIGBUS crashes from attempting to reuse corrupted shared memory files.
//
// Safety checks:
// - Only removes files matching pattern: /dev/shm/loxilb-trace-ring-<pid>-<worker>
// - Verifies PID doesn't exist (kill(pid, 0) returns ESRCH)
// - Skips current process PID
// - Logs all cleanup operations for debugging
//
// Returns number of files cleaned up and any error encountered.
func CleanupStaleRingFiles() (int, error) {
	currentPID := os.Getpid()
	pattern := "/dev/shm/loxilb-trace-ring-*"

	files, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("failed to glob ring files: %w", err)
	}

	if len(files) == 0 {
		tk.LogIt(tk.LogDebug, "[RingCleanup] No stale ring files found\n")
		return 0, nil
	}

	// Regex to extract PID from filename: loxilb-trace-ring-<pid>-<worker>
	// Example: /dev/shm/loxilb-trace-ring-12345-0
	pidRegex := regexp.MustCompile(`loxilb-trace-ring-(\d+)-\d+$`)

	cleaned := 0
	for _, path := range files {
		basename := filepath.Base(path)
		matches := pidRegex.FindStringSubmatch(basename)
		if len(matches) < 2 {
			tk.LogIt(tk.LogWarning, "[RingCleanup] Skipping malformed filename: %s\n", path)
			continue
		}

		pid, err := strconv.Atoi(matches[1])
		if err != nil {
			tk.LogIt(tk.LogWarning, "[RingCleanup] Failed to parse PID from %s: %v\n", path, err)
			continue
		}

		// Skip current process
		if pid == currentPID {
			tk.LogIt(tk.LogDebug, "[RingCleanup] Skipping current process ring: %s\n", path)
			continue
		}

		// Check if process exists
		// kill(pid, 0) returns ESRCH if process doesn't exist
		process, err := os.FindProcess(pid)
		if err != nil {
			// Process doesn't exist, safe to delete
			if err := os.Remove(path); err != nil {
				tk.LogIt(tk.LogWarning, "[RingCleanup] Failed to remove %s: %v\n", path, err)
			} else {
				tk.LogIt(tk.LogInfo, "[RingCleanup] Removed stale ring file: %s (PID %d not found)\n", path, pid)
				cleaned++
			}
			continue
		}

		// Process handle exists, check if it's actually running
		// In containers/namespaces, we may get EPERM for cross-namespace signals
		// Check /proc/<pid>/stat as a more reliable method
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			// Process doesn't exist (ESRCH) or permission denied (EPERM)
			// For ESRCH, definitely safe to delete
			if err == syscall.ESRCH {
				if err := os.Remove(path); err != nil {
					tk.LogIt(tk.LogWarning, "[RingCleanup] Failed to remove %s: %v\n", path, err)
				} else {
					tk.LogIt(tk.LogInfo, "[RingCleanup] Removed stale ring file: %s (PID %d dead)\n", path, pid)
					cleaned++
				}
				continue
			}

			// EPERM or other errors - check /proc to verify if PID exists
			// In containers, kill(pid, 0) may return EPERM even for dead PIDs
			procPath := fmt.Sprintf("/proc/%d/stat", pid)
			if _, statErr := os.Stat(procPath); os.IsNotExist(statErr) {
				// /proc/<pid>/stat doesn't exist - process is definitely dead
				if err := os.Remove(path); err != nil {
					tk.LogIt(tk.LogWarning, "[RingCleanup] Failed to remove %s: %v\n", path, err)
				} else {
					tk.LogIt(tk.LogInfo, "[RingCleanup] Removed stale ring file: %s (PID %d dead, /proc check)\n", path, pid)
					cleaned++
				}
			} else if statErr == nil {
				// /proc/<pid>/stat exists - process is running (but may be in different namespace)
				tk.LogIt(tk.LogInfo, "[RingCleanup] Keeping ring file %s (PID %d exists in /proc)\n", path, pid)
			} else {
				// Stat error (permission issue?) - be conservative
				tk.LogIt(tk.LogWarning, "[RingCleanup] Keeping ring file %s (PID %d status unknown: %v)\n", path, pid, statErr)
			}
		} else {
			// Process exists and responding to signal
			tk.LogIt(tk.LogInfo, "[RingCleanup] Keeping ring file %s (PID %d is alive)\n", path, pid)
		}
	}

	if cleaned > 0 {
		tk.LogIt(tk.LogInfo, "[RingCleanup] Cleaned up %d stale ring file(s)\n", cleaned)
	}

	return cleaned, nil
}

// CleanupStaleBodyFiles removes old body files from /dev/shm
//
// Body files are created by C code when HTTP bodies exceed 280 bytes:
// Pattern: /dev/shm/lxb-body-<span_id>.json or /dev/shm/lxb-body-<span_id>-<random>.json
//
// These files should be cleaned up immediately after reading in EnrichSpanWithPayload,
// but some may remain if:
// - loxilb crashed before processing
// - Events still in ring buffer at shutdown
//
// This function uses file modification time for cleanup:
// - Files older than 5 minutes are considered stale
// - Safe to call at startup before tracing initialization
//
// Returns number of files cleaned up and any error encountered.
func CleanupStaleBodyFiles() (int, error) {
	pattern := "/dev/shm/lxb-body-*.json"

	files, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("failed to glob body files: %w", err)
	}

	if len(files) == 0 {
		tk.LogIt(tk.LogDebug, "[BodyCleanup] No stale body files found\n")
		return 0, nil
	}

	cleaned := 0
	staleThreshold := 5 * 60 // 5 minutes in seconds

	for _, path := range files {
		// Check file modification time
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// File already deleted, skip
				continue
			}
			tk.LogIt(tk.LogWarning, "[BodyCleanup] Failed to stat %s: %v\n", path, err)
			continue
		}

		// Calculate file age
		age := int(time.Now().Sub(info.ModTime()).Seconds())
		if age > staleThreshold {
			// File is stale, safe to delete
			if err := os.Remove(path); err != nil {
				tk.LogIt(tk.LogWarning, "[BodyCleanup] Failed to remove %s: %v\n", path, err)
			} else {
				tk.LogIt(tk.LogInfo, "[BodyCleanup] Removed stale body file: %s (age=%ds)\n", path, age)
				cleaned++
			}
		} else {
			tk.LogIt(tk.LogDebug, "[BodyCleanup] Keeping recent body file: %s (age=%ds)\n", path, age)
		}
	}

	if cleaned > 0 {
		tk.LogIt(tk.LogInfo, "[BodyCleanup] Cleaned up %d stale body file(s)\n", cleaned)
	}

	return cleaned, nil
}

// CleanupAllBodyFiles removes ALL body files from /dev/shm
//
// This function is called during shutdown to ensure no body files are left behind.
// Unlike CleanupStaleBodyFiles, this removes ALL body files regardless of age.
//
// Should be called after stopping ring consumers to ensure no new files are created.
//
// Returns number of files cleaned up and any error encountered.
func CleanupAllBodyFiles() (int, error) {
	pattern := "/dev/shm/lxb-body-*.json"

	files, err := filepath.Glob(pattern)
	if err != nil {
		return 0, fmt.Errorf("failed to glob body files: %w", err)
	}

	if len(files) == 0 {
		tk.LogIt(tk.LogDebug, "[BodyCleanup] No body files to clean up\n")
		return 0, nil
	}

	cleaned := 0
	for _, path := range files {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				// File already deleted, skip
				continue
			}
			tk.LogIt(tk.LogWarning, "[BodyCleanup] Failed to remove %s: %v\n", path, err)
		} else {
			tk.LogIt(tk.LogDebug, "[BodyCleanup] Removed body file: %s\n", path)
			cleaned++
		}
	}

	if cleaned > 0 {
		tk.LogIt(tk.LogInfo, "[BodyCleanup] Cleaned up %d body file(s) on shutdown\n", cleaned)
	}

	return cleaned, nil
}
