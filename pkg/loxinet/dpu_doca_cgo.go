//go:build doca

/*
 * Copyright (c) 2022 NetLOX Inc
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

/*
#include <stdlib.h>
#include "../../loxilb-ebpf/doca/loxilb_doca_flow.h"
#cgo CFLAGS: -I./../../loxilb-ebpf/doca/
#cgo LDFLAGS: -L./../../loxilb-ebpf/doca/ -l:libloxilb_doca_flow.a
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// docaWorkItem represents a unit of work to be executed on the DOCA worker goroutine.
type docaWorkItem struct {
	fn     func() error
	result chan<- error
}

// DocaBridge manages the lifecycle of the DOCA bridge and ensures all DOCA
// C calls are serialized on a single OS thread via runtime.LockOSThread.
type DocaBridge struct {
	workCh     chan docaWorkItem
	initDone   bool
	shutdownCh chan struct{}
	// workerDone is closed by the worker goroutine on its way out (after the
	// `case <-d.shutdownCh:` branch fires). Lets `Shutdown(ctx)` block
	// until the worker has truly drained, with a ctx-bounded deadline.
	//
	workerDone chan struct{}
	// shutdownOnce guards `close(d.shutdownCh)` so the new graceful
	// `Shutdown(ctx)` and the legacy fire-and-forget `DocaShutdown` can
	// both signal the worker without panicking on double-close.
	shutdownOnce sync.Once
	mu           sync.Mutex
	pciAddr      string
	numRepr      uint32     // number of VF representors (default: 2)
	bf2          *DpDocaBf2 // back-pointer for aged entry processing
}

// docaBridgeInstance is the process-wide singleton.
var docaBridgeInstance *DocaBridge

// NewDocaBridge creates and initializes a DocaBridge.
// If pciAddr is empty, it falls back to BF2_PCI_ADDR env var or default "0000:03:00.0".
// Returns (nil, nil) on graceful degradation (DOCA init fails but not fatal).
func NewDocaBridge(pciAddr string, numRepr uint32) (*DocaBridge, error) {
	if pciAddr == "" {
		pciAddr = os.Getenv("BF2_PCI_ADDR")
		if pciAddr == "" {
			pciAddr = "0000:03:00.0"
		}
	}
	if numRepr == 0 {
		numRepr = 2
	}

	d := &DocaBridge{
		workCh:     make(chan docaWorkItem, 64),
		shutdownCh: make(chan struct{}),
		workerDone: make(chan struct{}),
		pciAddr:    pciAddr,
		numRepr:    numRepr,
	}

	// Start the dedicated DOCA worker goroutine (pinned to one OS thread).
	go d.worker()

	// Submit the DOCA init call to run on the worker thread.
	cPci := C.CString(pciAddr)
	initErr := d.submit(func() error {
		var cfg C.llb_doca_config
		cfg.ct_pipe_capacity = 8192     // C init doubles this → 16384 actual entries
		cfg.udp_ct_pipe_capacity = 8192 // same default as TCP CT pipe
		cfg.snat_pipe_capacity = 2048
		cfg.num_repr = C.uint32_t(d.numRepr)
		rc := C.llb_doca_init(cPci, C.int(1), &cfg)
		C.free(unsafe.Pointer(cPci))
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_init(%s) failed: rc=%d", pciAddr, int(rc))
		}
		return nil
	})

	if initErr != nil {
		logrus.WithField("pci", pciAddr).Warn("DOCA init failed -- running without DPU offload: ", initErr)
		// use shutdownOnce so the legacy
		// fire-and-forget DocaShutdown and the new graceful
		// Shutdown(ctx) can both signal the worker without panicking
		// on a double-close.
		d.shutdownOnce.Do(func() { close(d.shutdownCh) })
		return nil, nil
	}

	// Log port info.
	portID := int(C.llb_doca_get_port_id())
	var macBuf [6]C.uint8_t
	macRC := C.llb_doca_get_port_mac(&macBuf[0])
	if macRC == C.LLB_DOCA_OK {
		hwAddr := net.HardwareAddr{byte(macBuf[0]), byte(macBuf[1]), byte(macBuf[2]),
			byte(macBuf[3]), byte(macBuf[4]), byte(macBuf[5])}
		logrus.WithFields(logrus.Fields{
			"pci":    pciAddr,
			"portID": portID,
			"mac":    hwAddr.String(),
		}).Info("DOCA bridge initialized")
	} else {
		logrus.WithFields(logrus.Fields{
			"pci":    pciAddr,
			"portID": portID,
		}).Info("DOCA bridge initialized (MAC unavailable)")
	}

	d.mu.Lock()
	d.initDone = true
	d.mu.Unlock()

	docaBridgeInstance = d
	return d, nil
}

// worker is the dedicated goroutine pinned to a single OS thread.
// All DOCA C calls are funneled through this goroutine to satisfy
// DPDK's thread-local storage requirements.
func (d *DocaBridge) worker() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// workerDone is the rendezvous channel that
	// the new graceful Shutdown(ctx) blocks on. Closing here covers BOTH
	// the legacy DocaShutdown path (close(shutdownCh) → this case
	// fires → workerDone closes) AND the init-failure path (same shape).
	defer close(d.workerDone)

	// aging poll ticker (10 second interval)
	agingTicker := time.NewTicker(10 * time.Second)
	defer agingTicker.Stop()

	for {
		select {
		case item := <-d.workCh:
			item.result <- item.fn()
		case <-agingTicker.C:
			d.agingPollCycle()
		case <-d.shutdownCh:
			return
		}
	}
}

// agingPollCycle runs on the DOCA worker thread: polls HW aging tables,
// drains the C-side ring buffer, and dispatches aged entries to bf2 handler.
func (d *DocaBridge) agingPollCycle() {
	d.mu.Lock()
	if !d.initDone {
		d.mu.Unlock()
		return
	}
	bf2 := d.bf2
	d.mu.Unlock()

	if bf2 == nil {
		return
	}

	// -03: Process retry queue as a separate goroutine.
	// processRetries calls LBFlowOffload → submit, which would self-deadlock
	// if called directly from the worker thread. Spawning as a goroutine lets
	// submit serialize the work items through the worker after agingPollCycle returns.
	go bf2.processRetries()

	// B23-02: deferred-retry sweep on a separate
	// goroutine for the same S4 reason — pairedLBFlowOffload routes through
	// submit, which would self-deadlock if invoked from the worker thread.
	// The egress-steer pipe (and its active-entry accounting) was deleted in
	// TX-1, so activeEntries is always 0 and the capacity gate never trips;
	// the queue survives as a generic transient-DOCA-error retry queue.
	capacity := GetEgressSteerCapacity()
	go bf2.sweepDeferred(0, capacity)

	// Measure aging cycle duration
	cycleStart := time.Now()

	// Poll DOCA aging: walks HW aging tables and fires entry callbacks
	DocaAgingPoll(0, 100000, 256)

	// SPIKE-001 DIAG: dump root-pipe per-entry counters every aging cycle so
	// we can correlate reverse-traffic entry counters with port_meta dispatch
	// hits. Stays here permanently while the spike is open; remove with the
	// rest of the spike code if/when this branch is reverted.
	C.llb_doca_diag_dump_root_entries()

	// Drain aged entries from C-side ring buffer
	aged := DocaGetAgedEntries(C.LLB_DOCA_AGED_RING_SIZE)
	for _, userCtx := range aged {
		bf2.handleAgedEntry(userCtx)
	}

	docaAgingCycleDuration.Observe(time.Since(cycleStart).Seconds())

	// Update pipe utilization gauges
	// A1: read-only snapshot uses statsRWMu.RLock for scrape parallelism.
	bf2.statsRWMu.RLock()
	tcpCount := countEntriesForPipe(bf2.entries, "ct")
	udpCount := countEntriesForPipe(bf2.entries, "udp_ct")
	bf2.statsRWMu.RUnlock()

	// Option A: aggregate denominator covers BOTH g_ct_pipe
	// (forward) and g_ct_rev_pipe (reply). countEntriesForPipe(bf2.entries,
	// "ct") already aggregates forward+reply because keeps
	// pipeKey="ct" for both directions; only the denominator changes.
	tcpUtil := float64(tcpCount) / float64(docaDefaultTCPPipeCapacityAggregate)
	udpUtil := float64(udpCount) / float64(docaDefaultUDPPipeCapacity)
	docaCtPipeUtilization.WithLabelValues("tcp").Set(tcpUtil)
	docaCtPipeUtilization.WithLabelValues("udp").Set(udpUtil)

	// High-water mark warning at 80% utilization
	if tcpUtil > docaHighWaterMark {
		logrus.WithFields(logrus.Fields{
			"pipe":        "tcp",
			"utilization": fmt.Sprintf("%.1f%%", tcpUtil*100),
			"entries":     tcpCount,
			"capacity":    docaDefaultTCPPipeCapacityAggregate,
		}).Warn("doca-bf2: TCP CT pipe utilization above 80% — consider accelerated eviction")
	}
	if udpUtil > docaHighWaterMark {
		logrus.WithFields(logrus.Fields{
			"pipe":        "udp",
			"utilization": fmt.Sprintf("%.1f%%", udpUtil*100),
			"entries":     udpCount,
			"capacity":    docaDefaultUDPPipeCapacity,
		}).Warn("doca-bf2: UDP CT pipe utilization above 80% — consider accelerated eviction")
	}

	// sweep stale pending-pair half-arrivals every cycle (10s tick).
	// Half-arrived entries older than 30s are GC'd silently — eBPF still handles
	// the unpaired flow naturally.
	bf2.gcPendingPairs(30 * time.Second)

	// trace: dump per-entry hw_pkts each aging cycle so we can correlate
	// fwd vs reply HW activity over the lifetime of a connection. Note: BF2 BASIC
	// pipe FWD_PORT counters can return 0 even with active traffic (silicon
	// limitation, see AllFlowStats comment) — this trace is best-effort.
	if traceBidirEnabled() {
		// A1: read-only trace snapshot uses statsRWMu.RLock for scrape parallelism.
		bf2.statsRWMu.RLock()
		entriesSnapshot := make([]struct {
			flowKey   string
			direction string
			pipeKey   string
			entry     unsafe.Pointer
			fwdPortID uint16
		}, 0, len(bf2.entries))
		for k, oe := range bf2.entries {
			if oe == nil {
				continue
			}
			entriesSnapshot = append(entriesSnapshot, struct {
				flowKey   string
				direction string
				pipeKey   string
				entry     unsafe.Pointer
				fwdPortID uint16
			}{k, oe.Direction, oe.pipeKey, oe.entry, oe.fwdPortID})
		}
		bf2.statsRWMu.RUnlock()
		for _, e := range entriesSnapshot {
			bytes, pkts, qerr := DocaEntryQuery(e.entry)
			fields := logrus.Fields{
				"flowKey":   e.flowKey,
				"direction": e.direction,
				"pipeKey":   e.pipeKey,
				"fwd_port":  e.fwdPortID,
				"hw_pkts":   pkts,
				"hw_bytes":  bytes,
			}
			if qerr != nil {
				fields["query_err"] = qerr.Error()
			}
			logrus.WithFields(fields).Info("[bf2-trace] agingTick entry stat")
		}
	}
}

// submit sends a work item to the DOCA worker goroutine and waits for the result.
func (d *DocaBridge) submit(fn func() error) error {
	ch := make(chan error, 1)
	d.workCh <- docaWorkItem{fn: fn, result: ch}
	return <-ch
}

// submitWithTimeout sends a work item with a deadline. Used by heartbeat watchdog
// to detect worker deadlock without blocking indefinitely.
func (d *DocaBridge) submitWithTimeout(fn func() error, timeout time.Duration) error {
	ch := make(chan error, 1)
	d.workCh <- docaWorkItem{fn: fn, result: ch}
	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("doca worker timeout after %v", timeout)
	}
}

// checkInit verifies the bridge is initialized.
func (d *DocaBridge) checkInit() error {
	d.mu.Lock()
	ok := d.initDone
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	return nil
}

// Shutdown closes the worker goroutine and blocks until it has truly
// drained, OR the supplied ctx expires (whichever comes first).
// this is the graceful path called from the layered
// shutdown sequencer's `shutdownDoca` stage.
//
// Idempotent: multiple callers race the shutdownOnce; only the first
// `close(d.shutdownCh)` runs. Subsequent callers still wait on the same
// `workerDone` channel.
//
// Returns:
//   - nil if the worker exited within the deadline.
//   - wrapped ctx.Err if the deadline expired first (worker may still
//     be alive; the second-SIGINT escalation path is the safety net).
func (d *DocaBridge) Shutdown(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	initDone := d.initDone
	d.mu.Unlock()
	if !initDone {
		// Worker started but init never finished. Closing shutdownCh
		// still terminates the worker; wait for workerDone.
		d.shutdownOnce.Do(func() { close(d.shutdownCh) })
		select {
		case <-d.workerDone:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("DocaBridge shutdown timed out (init never completed): %w", ctx.Err())
		}
	}
	d.shutdownOnce.Do(func() { close(d.shutdownCh) })
	select {
	case <-d.workerDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("DocaBridge shutdown timed out: %w", ctx.Err())
	}
}

// ---- Public API functions ----

// DocaInit initializes the DOCA bridge singleton. Safe to call multiple times;
// subsequent calls are no-ops if the bridge is already up.
// numRepr specifies the number of VF representors to probe in DPDK.
func DocaInit(pciAddr string, numRepr uint32) error {
	if docaBridgeInstance != nil {
		return nil
	}
	_, err := NewDocaBridge(pciAddr, numRepr)
	return err
}

// DocaShutdown tears down the DOCA bridge.
func DocaShutdown() {
	if docaBridgeInstance == nil {
		return
	}
	d := docaBridgeInstance
	_ = d.submit(func() error {
		C.llb_doca_shutdown()
		return nil
	})
	// shutdownOnce-guarded close so the new
	// graceful Shutdown(ctx) and this legacy fire-and-forget path are
	// idempotent against each other.
	d.shutdownOnce.Do(func() { close(d.shutdownCh) })
	docaBridgeInstance = nil
}

// DocaIsInitialized returns true if the DOCA bridge is up and running.
func DocaIsInitialized() bool {
	if docaBridgeInstance == nil {
		return false
	}
	return C.llb_doca_is_initialized() != 0
}

// DocaGetRootPipe returns the root pipe handle for the DOCA switch port.
// The root pipe dispatches incoming traffic via FWD_PIPE to the LB pipe.
func DocaGetRootPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	var result unsafe.Pointer
	docaBridgeInstance.submit(func() error {
		result = unsafe.Pointer(C.llb_doca_get_root_pipe())
		return nil
	})
	return result
}

// DocaGetCTFwdPipe returns the forward CT pipe handle (g_ct_fwd_pipe) for
// per-flow entry addition. -04 renamed the unified CT pipe to
// g_ct_fwd_pipe and chained it to g_ct_rev_pipe via the BASIC DEFAULT
// miss-chain pattern. All forward-direction CT offload entries (NAT and
// non-NAT, TCP and UDP — protocol-agnostic TRANSPORT match) install here;
// reply-direction entries fall through via the miss-chain to g_ct_rev_pipe.
//
// (TX-2) completes the lockstep rename from the legacy
// DocaGetCTPipe accessor: the transitional `#define llb_doca_get_ct_pipe
// llb_doca_get_ct_fwd_pipe` header alias is gone, and this wrapper now
// calls C.llb_doca_get_ct_fwd_pipe directly.
func DocaGetCTFwdPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	var result unsafe.Pointer
	docaBridgeInstance.submit(func() error {
		result = unsafe.Pointer(C.llb_doca_get_ct_fwd_pipe())
		return nil
	})
	return result
}

// DocaGetCTRevPipe returns the CT-REV (per-direction reply) pipe handle.
// reply CT entries from VF-rep ingress are added to this
// pipe; forward CT entries continue to use DocaGetCTFwdPipe (renamed in
// -06 from DocaGetCTPipe). -04: the two pipes are
// now miss-chained — g_ct_fwd_pipe miss → g_ct_rev_pipe, so reply traffic
// reaches g_ct_rev_pipe via the BASIC DEFAULT miss-chain rather than via
// direct VF-rep root dispatch.
func DocaGetCTRevPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	var result unsafe.Pointer
	docaBridgeInstance.submit(func() error {
		result = unsafe.Pointer(C.llb_doca_get_ct_rev_pipe())
		return nil
	})
	return result
}

// DocaGetUDPCTPipe returns the UDP CT pipe handle for UDP flow entry addition.
// dedicated UDP conntrack pipe for hardware-accelerated UDP flows.
func DocaGetUDPCTPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	var result unsafe.Pointer
	docaBridgeInstance.submit(func() error {
		result = unsafe.Pointer(C.llb_doca_get_udp_ct_pipe())
		return nil
	})
	return result
}

// -06 (TX-1): DocaGetEgressSteerPipe + docaGetSteerPipeDirect removed.
// The g_egress_steer C-side pipe and accessor were deleted
// (validated DOCA samples prove the EGRESS-domain steer pipe is wrong on BF2
// 2.9.4); the per-flow paired-steer entry pattern is replaced by
// g_egress_dispatch (DEFAULT-domain BASIC pipe with static per-port FWD_PORT
// entries installed at init time —). This plan removes the
// last two Go-side callers' transitional CGO link break.
//
// GetEgressSteerCapacity is retained as a pure-Go const because deferred_offload.go
// still consumes it as the sweep capacity gate constant — that infrastructure
// (markDeferred / sweepDeferred / deferredOffload) is orthogonal to the
// per-flow paired-steer entry pattern and stays in place for the deferred-retry
// queue (which now only fires from the agingPollCycle's existing sweepDeferred
// call site at line ~208; the rollback-path markDeferred calls in
// pairedLBFlowOffload were also cleaned up of this plan).

// GetEgressSteerCapacity returns the legacy g_egress_steer pipe capacity
// constant. Retained as a pure-Go const (no CGO dependency) because the
// deferred-retry sweep's capacity-gate ratio still needs a denominator.
// Removable when deferred_offload.go is rewritten in a follow-up phase.
func GetEgressSteerCapacity() int {
	return 1024
}

// DocaPipeCreateBasic creates a BASIC match pipe on the DOCA flow engine.
func DocaPipeCreateBasic(name string, matchDstIPMask uint32, matchDstPortMask uint16,
	matchSrcIPMask uint32, matchSrcPortMask uint16,
	matchProto uint8, fwdType int, fwdPortID uint16,
	nrEntries uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return nil, err
	}

	var result unsafe.Pointer
	cName := C.CString(name)
	err := d.submit(func() error {
		defer C.free(unsafe.Pointer(cName))
		h := C.llb_doca_pipe_create_basic(
			cName,
			C.uint32_t(matchDstIPMask),
			C.uint16_t(matchDstPortMask),
			C.uint32_t(matchSrcIPMask),
			C.uint16_t(matchSrcPortMask),
			C.uint8_t(matchProto),
			C.int(fwdType),
			C.uint16_t(fwdPortID),
			C.uint32_t(nrEntries),
		)
		if h == nil {
			return fmt.Errorf("llb_doca_pipe_create_basic(%s) returned NULL", name)
		}
		result = unsafe.Pointer(h)
		return nil
	})
	return result, err
}

// DocaPipeDestroy destroys a pipe handle.
func DocaPipeDestroy(pipe unsafe.Pointer) error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}

	return d.submit(func() error {
		rc := C.llb_doca_pipe_destroy(C.llb_doca_pipe_handle_t(pipe))
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_pipe_destroy failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaEntryAddBasic adds a BASIC pipe flow entry with full NAT rewrite support.
// agingSec and userCtx enable per-entry DOCA hardware aging.
// meterID attaches a shared meter (LLB_DOCA_METER_NONE = no meter).
//
// -06: signature reduced to (entry, err). The trailing
// steerEntry return is gone along with the paired g_egress_steer entry
// pattern — replaced the per-flow paired install with a
// DEFAULT-domain g_egress_dispatch pipe that installs static per-port
// FWD_PORT entries at init time, and deleted g_egress_steer_pipe.
// CT entries now drive the downstream dispatch via meta.pkt_meta =
// target_port_id; no paired install is needed at flow time.
func DocaEntryAddBasic(pipe unsafe.Pointer,
	dstIP uint32, dstPort uint16,
	srcIP uint32, srcPort uint16,
	newDstIP uint32, newDstPort uint16,
	newSrcIP uint32, newSrcPort uint16,
	newDstMAC [6]byte, newSrcMAC [6]byte,
	timeoutMs uint32, matchProto uint8,
	fwdPortID uint16, agingSec uint32,
	userCtx uint64, meterID uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return nil, err
	}

	var ctResult unsafe.Pointer
	err := d.submit(func() error {
		h := C.llb_doca_entry_add_basic(
			C.llb_doca_pipe_handle_t(pipe),
			C.uint32_t(dstIP),
			C.uint16_t(dstPort),
			C.uint32_t(srcIP),
			C.uint16_t(srcPort),
			C.uint32_t(newDstIP),
			C.uint16_t(newDstPort),
			C.uint32_t(newSrcIP),
			C.uint16_t(newSrcPort),
			(*C.uint8_t)(&newDstMAC[0]),
			(*C.uint8_t)(&newSrcMAC[0]),
			C.uint32_t(timeoutMs),
			C.uint8_t(matchProto),
			C.uint16_t(fwdPortID),
			C.uint32_t(agingSec),
			C.uint64_t(userCtx),
			C.uint32_t(meterID),
		)
		if h == nil {
			return fmt.Errorf("llb_doca_entry_add_basic failed: returned NULL")
		}
		ctResult = unsafe.Pointer(h)
		return nil
	})
	return ctResult, err
}

// DocaAgingPoll polls DOCA hardware aging tables and fires callbacks for aged entries.
// Must be called from the DOCA worker thread (LockOSThread).
func DocaAgingPoll(quotaTime uint64, timeoutUs, maxEntries uint32) int {
	return int(C.llb_doca_aging_poll(C.uint64_t(quotaTime), C.uint32_t(timeoutUs), C.uint32_t(maxEntries)))
}

// DocaEntriesDrain drains the DOCA per-pipe-queue NO_WAIT pending buffer (Plan
// 64-06). Pairs with ACL debouncer which enqueues entries
// via doca_flow_pipe_add_entry(..., DOCA_FLOW_NO_WAIT, ...) and relies on the
// caller to drain. Without this drain the queue saturates at the DOCA
// per-queue depth (~128 with set_pipe_queues(1) on BF2 DOCA 2.9.4) and every
// subsequent add_entry returns INVALID_VALUE. Routes through d.submit so the
// drain runs on the DOCA worker thread (same lock-graph as add/del entries).
func DocaEntriesDrain(timeoutUs, maxEntries uint32) error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}
	return d.submit(func() error {
		rc := C.llb_doca_entries_drain(C.uint32_t(timeoutUs), C.uint32_t(maxEntries))
		if rc != 0 {
			return fmt.Errorf("llb_doca_entries_drain failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaGetAgedEntries drains the C-side aged entry ring buffer and returns user_ctx values.
func DocaGetAgedEntries(maxOut int) []uint64 {
	if maxOut <= 0 {
		return nil
	}
	outBuf := (*C.uint64_t)(C.malloc(C.size_t(maxOut) * C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
	if outBuf == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(outBuf))

	n := int(C.llb_doca_get_aged_entries(outBuf, C.int(maxOut)))
	if n <= 0 {
		return nil
	}

	result := make([]uint64, n)
	cSlice := unsafe.Slice(outBuf, n)
	for i := 0; i < n; i++ {
		result[i] = uint64(cSlice[i])
	}
	return result
}

// DocaEntryRemove removes a flow entry from its pipe.
func DocaEntryRemove(pipe, entry unsafe.Pointer) error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}

	return d.submit(func() error {
		rc := C.llb_doca_entry_remove(
			C.llb_doca_pipe_handle_t(pipe),
			C.llb_doca_entry_handle_t(entry),
			C.uint32_t(5000),
		)
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_entry_remove failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaEntryRemoveDirect removes a flow entry without going through submit.
// MUST only be called from the DOCA worker thread (e.g., from agingPollCycle).
// Using submit from the worker thread would self-deadlock.
func DocaEntryRemoveDirect(pipe, entry unsafe.Pointer) error {
	rc := C.llb_doca_entry_remove(
		C.llb_doca_pipe_handle_t(pipe),
		C.llb_doca_entry_handle_t(entry),
		C.uint32_t(5000),
	)
	if rc != C.LLB_DOCA_OK {
		return fmt.Errorf("llb_doca_entry_remove failed: rc=%d", int(rc))
	}
	return nil
}

// DocaGetPortCount returns the number of DPDK ports (PF + VF representors).
func DocaGetPortCount() int {
	return int(C.llb_doca_get_port_count())
}

// DocaGetPortMacByID retrieves the MAC address for a DPDK port by its port ID.
func DocaGetPortMacByID(portID uint16) ([6]byte, error) {
	var mac [6]C.uint8_t
	ret := C.llb_doca_get_port_mac_by_id(C.uint16_t(portID), &mac[0])
	if ret != C.LLB_DOCA_OK {
		return [6]byte{}, fmt.Errorf("llb_doca_get_port_mac_by_id(%d) failed: rc=%d", portID, int(ret))
	}
	var result [6]byte
	for i := 0; i < 6; i++ {
		result[i] = byte(mac[i])
	}
	return result, nil
}

// DocaGetPortIfindex retrieves the Linux interface index bound to a DPDK port.
// Returns 0 if the port has no bound interface (e.g., the PF uplink in some configs).
func DocaGetPortIfindex(portID uint16) (int, error) {
	var ifindex C.uint
	ret := C.llb_doca_get_port_ifindex(C.uint16_t(portID), &ifindex)
	if ret != C.LLB_DOCA_OK {
		return 0, fmt.Errorf("llb_doca_get_port_ifindex(%d) failed: rc=%d", portID, int(ret))
	}
	return int(ifindex), nil
}

// DocaGetFdbPipe returns the FDB L2 pipe handle.
func DocaGetFdbPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	var result unsafe.Pointer
	_ = docaBridgeInstance.submit(func() error {
		result = unsafe.Pointer(C.llb_doca_get_fdb_pipe())
		return nil
	})
	return result
}

// DocaFdbEntryAdd adds a MAC forwarding entry to the FDB pipe.
func DocaFdbEntryAdd(pipe unsafe.Pointer, dstMAC [6]byte, fwdPortID uint16, agingSec uint32, userCtx uint64, timeoutMs uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if e := d.checkInit(); e != nil {
		return nil, e
	}

	var mac [6]C.uint8_t
	for i := 0; i < 6; i++ {
		mac[i] = C.uint8_t(dstMAC[i])
	}

	var result unsafe.Pointer
	err := d.submit(func() error {
		entry := C.llb_doca_fdb_entry_add(
			C.llb_doca_pipe_handle_t(pipe),
			&mac[0],
			C.uint16_t(fwdPortID),
			C.uint32_t(agingSec),
			C.uint64_t(userCtx),
			C.uint32_t(timeoutMs),
		)
		if entry == nil {
			return fmt.Errorf("llb_doca_fdb_entry_add failed")
		}
		result = unsafe.Pointer(entry)
		return nil
	})
	return result, err
}

// DocaRebuildRootPipe rebuilds the eswitch root pipe to match the current ACL
// lazy state. When DocaGetDenyPipe returns NULL (no
// HwOffload=true rules currently installed — lazy CLOSED state), IPv4 L4
// dispatch targets the CT_FWD chain directly (baseline; ROOT →
// CT_FWD direct). When the C-side g_deny_pipe handle is non-NULL (lazy OPEN
// state), IPv4 L4 dispatch targets DENY_PIPE which fan-misses to ALLOW_PIPE
// then to CT_FWD (dispatch chain).
//
// The CLOSED-vs-OPEN gate is the C-side `g_deny_pipe` handle, NOT the
// Go-side `DpDocaBf2.aclPipesUp` bool — `aclPipesUp` exists strictly for
// state-machine bookkeeping inside `DpDocaBf2` (Step A); the rebuild
// path consults the canonical C-side handle so the two sides of the lazy
// state machine cannot disagree.
//
// Both branches set num_dispatch=2 so the V2 ABI validator's exact-2 contract
// (fix) is preserved. The nested-submit
// avoidance also still applies: DocaGetFdbPipe MUST NOT be called from
// inside submit — read C.llb_doca_get_fdb_pipe directly.
//
// (minimal repoint) → (this evolution): the
// log line marks each rebuild with the aclPipesUp branch so the operator
// runbook can correlate with the lazy-state Info lines
// Open-Q-2 actionable-log discipline).
func DocaRebuildRootPipe() error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}

	return d.submit(func() error {
		// read the canonical C-side DENY pipe handle. NULL =
		// lazy CLOSED, non-NULL = lazy OPEN. This is the SINGLE source of
		// truth for the rebuild branch selection.
		denyPipe := C.llb_doca_get_deny_pipe()

		// read FDB pipe handle INSIDE submit to avoid
		// nested-submit deadlock. DocaGetFdbPipe wraps its own submit and
		// MUST NOT be called here. If FDB pipe is not yet created (handle==0),
		// the C-side validator treats miss_pipe_override==0 as "fall back to
		// to_kernel", preserving V1 semantics.
		fdbPipe := C.llb_doca_get_fdb_pipe()

		// pick the L4 dispatch target. When DENY pipe is up
		// (lazy OPEN), root dispatches IPv4 → DENY → ALLOW → CT_FWD. When
		// DENY pipe is NULL (lazy CLOSED, no HwOffload=true rules installed),
		// bypass the ACL layer and dispatch ROOT → CT_FWD directly so the CT
		// pipeline continues to work without ACL HW offload.
		ctFwdPipe := C.llb_doca_get_ct_fwd_pipe()
		l4Target := denyPipe
		closed := false
		if l4Target == nil {
			l4Target = ctFwdPipe
			closed = true
		}

		var cfg C.llb_doca_root_pipe_cfg
		cfg.version = C.LLB_DOCA_ROOT_PIPE_CFG_V2
		cfg.nr_entries = 4
		cfg.num_dispatch = 2 // V2 contract: exactly 2 dispatch entries.

		// TCP -> L4 target (DOCA_FLOW_L4_META_TCP = 1)
		cfg.dispatch[0].l4_type = 1
		cfg.dispatch[0].target = C.llb_doca_pipe_handle_t(l4Target)
		// UDP -> L4 target (DOCA_FLOW_L4_META_UDP = 2)
		cfg.dispatch[1].l4_type = 2
		cfg.dispatch[1].target = C.llb_doca_pipe_handle_t(l4Target)
		// unmatched unicast -> FDB pipe (L2 offload).
		// Zero handle = fall back to to_kernel (V1-equivalent).
		cfg.miss_pipe_override = C.llb_doca_pipe_handle_t(fdbPipe)

		rc := C.llb_doca_rebuild_root_pipe(&cfg)
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_rebuild_root_pipe failed: rc=%d", int(rc))
		}
		// Open-Q-2: operator-correlatable log line. `aclPipesUp`
		// here is the C-side handle state (NOT the Go-side bool — they always
		// agree in steady state, but the C-side is the canonical truth).
		logrus.WithField("aclPipesUp", !closed).Info("acl-root-rebuild")
		return nil
	})
}

// ---- ACL HW offload wrappers ----
//
// These bind to the 8 new C-side ABI signatures added to
// loxilb-ebpf/doca/loxilb_doca_flow.h (lines 239-270). The lazy DENY+ALLOW
// pipe pair replaces single-pipe surface (retired in pairs with
// their stubs). Match-struct opacity: the public header
// references `struct doca_flow_match *` without including DOCA headers; the
// type is incomplete in the CGO preamble — pointer-only usage is legal C and
// CGO emits the appropriate cast. The caller owns the
// alloc/fill/free lifetime of the `em` and `em_mask` byte buffers; this
// wrapper layer only forwards opaque pointers under DocaBridge serialization.

// DocaAclPipesCreate creates BOTH the DENY and ALLOW BASIC pipes atomically
// (lazy OPENING). Idempotent — a second call when both pipes are up
// returns nil. ALLOW is created first because DENY's fwd_miss points at it.
func DocaAclPipesCreate() error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}
	return d.submit(func() error {
		rc := C.llb_doca_acl_pipes_create()
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_acl_pipes_create failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaAclPipesDestroy destroys BOTH the DENY and ALLOW pipes (lazy
// CLOSING). The caller MUST first re-dispatch the root pipe AWAY from
// g_deny_pipe (via DocaRebuildRootPipe when the lazy state goes CLOSED).
func DocaAclPipesDestroy() error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}
	return d.submit(func() error {
		C.llb_doca_acl_pipes_destroy()
		return nil
	})
}

// DocaAclDenyEntryAdd installs a DENY (FWD_DROP) entry on the DENY pipe.
// `em` points to a caller-owned `struct doca_flow_match` buffer with exact-IP
// 5-tuple TRANSPORT values (corrected: DOCA 2.9.4 `doca_flow_pipe_add_entry`
// is 9-arg and BASIC pipes use the pipe-level template mask set at create time;
// per-entry CIDR masks are not supported. `validateHwOffloadExpressible` rejects
// non-/32 source/destination prefixes). When timeoutMs > 0 the C side blocks on
// wait_entry_offload; when 0 the call returns immediately after the
// DOCA_FLOW_NO_WAIT enqueue (debouncer drives flush).
// Returns the entry handle (opaque) and error.
func DocaAclDenyEntryAdd(em unsafe.Pointer, timeoutMs uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return nil, err
	}
	var result unsafe.Pointer
	err := d.submit(func() error {
		// Pass em as opaque (C signature is `const void *em` per the header's
		// no-DOCA-include contract; the C impl casts back to `doca_flow_match *`).
		ret := C.llb_doca_acl_deny_entry_add(
			em,
			C.uint32_t(timeoutMs),
		)
		if ret == nil {
			return fmt.Errorf("llb_doca_acl_deny_entry_add failed: returned NULL")
		}
		result = unsafe.Pointer(ret)
		return nil
	})
	return result, err
}

// DocaAclAllowEntryAdd installs an ALLOW (counter-only audit, FWD_PIPE→CT_FWD)
// entry on the ALLOW pipe. Same em semantics as DocaAclDenyEntryAdd (exact-IP).
// Returns the entry handle (opaque) and error.
func DocaAclAllowEntryAdd(em unsafe.Pointer, timeoutMs uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return nil, err
	}
	var result unsafe.Pointer
	err := d.submit(func() error {
		ret := C.llb_doca_acl_allow_entry_add(
			em,
			C.uint32_t(timeoutMs),
		)
		if ret == nil {
			return fmt.Errorf("llb_doca_acl_allow_entry_add failed: returned NULL")
		}
		result = unsafe.Pointer(ret)
		return nil
	})
	return result, err
}

// DocaAclDenyEntryDel removes a DENY entry by opaque handle.
func DocaAclDenyEntryDel(entry unsafe.Pointer) error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}
	return d.submit(func() error {
		rc := C.llb_doca_acl_deny_entry_del(C.llb_doca_entry_handle_t(entry))
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_acl_deny_entry_del failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaAclAllowEntryDel removes an ALLOW entry by opaque handle.
func DocaAclAllowEntryDel(entry unsafe.Pointer) error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if err := d.checkInit(); err != nil {
		return err
	}
	return d.submit(func() error {
		rc := C.llb_doca_acl_allow_entry_del(C.llb_doca_entry_handle_t(entry))
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_acl_allow_entry_del failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaGetDenyPipe returns the DENY pipe handle, or nil when the lazy lifecycle
// is in the CLOSED state (no HwOffload rules installed). Pure read — no
// submit needed (mirrors DocaGetFdbPipe).
func DocaGetDenyPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	return unsafe.Pointer(C.llb_doca_get_deny_pipe())
}

// DocaGetAllowPipe returns the ALLOW pipe handle, or nil when the lazy
// lifecycle is in the CLOSED state. Pure read — no submit needed.
func DocaGetAllowPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	return unsafe.Pointer(C.llb_doca_get_allow_pipe())
}

// DocaAclMatchAllocIP4 allocates an opaque match buffer filled with the given
// IPv4/TRANSPORT 5-tuple values. Caller must free via DocaAclMatchFree after
// the matching entry-add call returns (the C-side copies the match contents
// before returning under DOCA_FLOW_NO_WAIT). All multi-byte fields are in
// network byte order; mask of 0 = wildcard, 0xFFFF = exact.
//
// ext: bridges the opaque-header constraint
// (loxilb_doca_flow.h:21 — no DOCA includes in the bridge header) by routing
// the match-buffer alloc/fill through a C helper that owns the struct layout.
func DocaAclMatchAllocIP4(srcIP, srcMask, dstIP, dstMask uint32, srcPort, srcPortMask, dstPort, dstPortMask uint16) unsafe.Pointer {
	return unsafe.Pointer(C.llb_doca_acl_match_alloc_ip4(
		C.uint32_t(srcIP), C.uint32_t(srcMask),
		C.uint32_t(dstIP), C.uint32_t(dstMask),
		C.uint16_t(srcPort), C.uint16_t(srcPortMask),
		C.uint16_t(dstPort), C.uint16_t(dstPortMask)))
}

// DocaAclMatchAllocMaskIP4 allocates the companion mask buffer.
func DocaAclMatchAllocMaskIP4(srcMask, dstMask uint32, srcPortMask, dstPortMask uint16) unsafe.Pointer {
	return unsafe.Pointer(C.llb_doca_acl_match_alloc_mask_ip4(
		C.uint32_t(srcMask), C.uint32_t(dstMask),
		C.uint16_t(srcPortMask), C.uint16_t(dstPortMask)))
}

// DocaAclMatchFree releases an opaque match buffer allocated by either of the
// match alloc helpers above. Safe to call with nil.
func DocaAclMatchFree(p unsafe.Pointer) {
	if p == nil {
		return
	}
	C.llb_doca_acl_match_free(p)
}

// DocaMeterAdd configures and binds a DOCA shared meter.
func DocaMeterAdd(meterID uint32, cirBps uint64, cbs uint64, ebs uint64) int {
	if docaBridgeInstance == nil {
		return -1
	}
	var result int
	_ = docaBridgeInstance.submit(func() error {
		result = int(C.llb_doca_meter_add(C.uint32_t(meterID), C.uint64_t(cirBps), C.uint64_t(cbs), C.uint64_t(ebs)))
		return nil
	})
	return result
}

// DocaMeterDel unbinds and releases a DOCA shared meter.
func DocaMeterDel(meterID uint32) int {
	if docaBridgeInstance == nil {
		return -1
	}
	var result int
	_ = docaBridgeInstance.submit(func() error {
		result = int(C.llb_doca_meter_del(C.uint32_t(meterID)))
		return nil
	})
	return result
}

// DocaMeterQuery retrieves aggregate stats for a DOCA shared meter.
// BF2 returns aggregate (total_pkts, total_bytes) -- not per-color.
func DocaMeterQuery(meterID uint32) (totalPkts, totalBytes uint64, err error) {
	if docaBridgeInstance == nil {
		return 0, 0, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if e := d.checkInit(); e != nil {
		return 0, 0, e
	}

	var stats C.struct_llb_doca_meter_stats
	err = d.submit(func() error {
		rc := C.llb_doca_meter_query(C.uint32_t(meterID), &stats)
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_meter_query(%d) failed: rc=%d", meterID, int(rc))
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return uint64(stats.total_pkts), uint64(stats.total_bytes), nil
}

// DocaEntryUpdateMeter attaches or updates a shared meter on an existing CT entry.
func DocaEntryUpdateMeter(pipeHandle unsafe.Pointer, entryHandle unsafe.Pointer, meterID uint32) int {
	if docaBridgeInstance == nil {
		return -1
	}
	var result int
	_ = docaBridgeInstance.submit(func() error {
		result = int(C.llb_doca_entry_update_meter(C.llb_doca_pipe_handle_t(pipeHandle), entryHandle, C.uint32_t(meterID)))
		return nil
	})
	return result
}

// DocaGetL4DispatchPipe + DocaAclQueryAll retired.
// The `llb_doca_get_l4_dispatch_pipe` header decl is gone (the C body
// is kept as a vestigial NULL-returning accessor pending retiring
// the bf2.go caller). `llb_doca_acl_query_all` is fully retired (C body gone).
// The lazy DENY+ALLOW pair exposes counters via the per-entry
// NON_SHARED monitor; pipe-level audit goes through DocaEntryQuery on the
// new handles instead.

// DocaGetMeterPipe returns the meter classification pipe handle.
func DocaGetMeterPipe() unsafe.Pointer {
	if docaBridgeInstance == nil {
		return nil
	}
	var result unsafe.Pointer
	_ = docaBridgeInstance.submit(func() error {
		result = unsafe.Pointer(C.llb_doca_get_meter_pipe())
		return nil
	})
	return result
}

// DocaSetMeterPipe sets the global meter pipe pointer.
func DocaSetMeterPipe(pipe unsafe.Pointer) {
	if docaBridgeInstance == nil {
		return
	}
	_ = docaBridgeInstance.submit(func() error {
		C.llb_doca_set_meter_pipe(C.llb_doca_pipe_handle_t(pipe))
		return nil
	})
}

// DocaMeterPipeCreate creates a per-meter classification pipe with fixed meter_id.
func DocaMeterPipeCreate(missTarget unsafe.Pointer, meterID uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	var pipe unsafe.Pointer
	err := docaBridgeInstance.submit(func() error {
		pipe = unsafe.Pointer(C.llb_doca_meter_pipe_create(
			C.llb_doca_pipe_handle_t(missTarget),
			C.uint32_t(meterID),
			C.uint32_t(LLB_DOCA_METER_PIPE_CAPACITY)))
		if pipe == nil {
			return fmt.Errorf("llb_doca_meter_pipe_create failed for meter_id=%d", meterID)
		}
		return nil
	})
	return pipe, err
}

const LLB_DOCA_METER_PIPE_CAPACITY = 16

// DocaMeterPipeEntryAdd adds a dst-IP match entry to a meter pipe.
func DocaMeterPipeEntryAdd(pipe unsafe.Pointer, dstIP uint32) (unsafe.Pointer, error) {
	if docaBridgeInstance == nil {
		return nil, fmt.Errorf("DOCA bridge not initialized")
	}
	var entry unsafe.Pointer
	err := docaBridgeInstance.submit(func() error {
		entry = unsafe.Pointer(C.llb_doca_meter_pipe_entry_add(
			C.llb_doca_pipe_handle_t(pipe),
			C.uint32_t(dstIP), C.uint32_t(5000)))
		if entry == nil {
			return fmt.Errorf("llb_doca_meter_pipe_entry_add failed")
		}
		return nil
	})
	return entry, err
}

// DocaGetAclPipe retired alongside the C-side
// llb_doca_get_acl_pipe symbol. Callers should use
// DocaGetDenyPipe / DocaGetAllowPipe instead — lazy DENY+ALLOW
// pair replaces the single-pipe surface.

// DocaDiagDumpRootEntries (SPIKE-001) prints per-entry root-pipe counters to
// stderr. Used to diagnose whether reply traffic reaches the root pipe and
// which port_meta dispatch entry it hits. No-op if DOCA isn't initialized.
func DocaDiagDumpRootEntries() {
	if docaBridgeInstance == nil {
		return
	}
	_ = docaBridgeInstance.submit(func() error {
		C.llb_doca_diag_dump_root_entries()
		return nil
	})
}

// DocaCtRevTestDropAll rebuilds CT_REV_5TUPLE_PIPE with miss=DROP so that any
// [TCP + port_meta=N/VF] packet that reaches the pipe but has no 5-tuple entry
// is dropped instead of forwarded to the kernel. Call DocaRebuildRootPipe
// immediately after to re-wire root dispatch entries to the new pipe handle.
// TEST-ONLY: remove after diagnosis is complete.
func DocaCtRevTestDropAll() error {
	if docaBridgeInstance == nil {
		return fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if e := d.checkInit(); e != nil {
		return e
	}
	return d.submit(func() error {
		rc := C.llb_doca_ct_rev_test_drop_all()
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_ct_rev_test_drop_all failed: rc=%d", int(rc))
		}
		return nil
	})
}

// DocaEntryQuery retrieves byte and packet counters for a flow entry.
func DocaEntryQuery(entry unsafe.Pointer) (bytes uint64, pkts uint64, err error) {
	if docaBridgeInstance == nil {
		return 0, 0, fmt.Errorf("DOCA bridge not initialized")
	}
	d := docaBridgeInstance
	if e := d.checkInit(); e != nil {
		return 0, 0, e
	}

	var b, p C.uint64_t
	err = d.submit(func() error {
		rc := C.llb_doca_entry_query(
			C.llb_doca_entry_handle_t(entry),
			&b,
			&p,
		)
		if rc != C.LLB_DOCA_OK {
			return fmt.Errorf("llb_doca_entry_query failed: rc=%d", int(rc))
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return uint64(b), uint64(p), nil
}

// docaErrorReason maps a DOCA error returned by the CGO bridge to one of the
// 6 closed-enum reason values consumed by docaOffloadInstallErrorsTotal
// (A2). The mapping is intentionally string-based because the C
// bridge surfaces DOCA error codes via the wrapped error string (e.g.
// "rc=LLB_DOCA_INSUFFICIENT_RESOURCES"); a sentinel-error redesign would
// require touching every CGO failure surface and is deferred.
//
// "null_return" is the catchall — keeps cardinality bounded; future PRs add
// specific cases as new sentinels appear in the C bridge.
//
// "paired_steer_failed" is reserved for the P2 atomic-rollback path; callers
// pass the explicit reason at those sites rather than calling this helper.
func docaErrorReason(err error) string {
	if err == nil {
		return "null_return"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "INVALID_VALUE"), strings.Contains(s, "INVALID_INPUT"), strings.Contains(s, "Invalid input"):
		return "invalid_input"
	case strings.Contains(s, "INSUFFICIENT_RESOURCES"), strings.Contains(s, "FULL"), strings.Contains(s, "capacity"):
		return "capacity_full"
	case strings.Contains(s, "TIME_OUT"), strings.Contains(s, "timeout"):
		return "timeout"
	case strings.Contains(s, "DOCA_FLOW") && strings.Contains(s, "BUSY"):
		return "hw_busy"
	case strings.Contains(s, "paired_steer_failed"), strings.Contains(s, "egress_steer"):
		return "paired_steer_failed"
	default:
		return "null_return"
	}
}
