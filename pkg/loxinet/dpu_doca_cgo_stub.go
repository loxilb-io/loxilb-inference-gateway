//go:build !doca

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

import (
	"context"
	"fmt"
	"time"
	"unsafe"
)

// errDocaNotAvailable is returned by all stub functions.
var errDocaNotAvailable = fmt.Errorf("DOCA not available")

// Mirror of DOCA-build-only constants so the !doca test file compiles.
// These have no runtime meaning under !doca (no pipes are created); they
// exist solely so dpu_doca_bf2_test.go can reference the same identifiers
// as the real build. unblock — pre-existing build break in the
// test file (docaLBPipeCapacity was never defined under !doca).
const (
	docaFwdPort        = 1
	docaLBPipeCapacity = 4096
)

// DocaBridge is a stub for non-DOCA builds. The real implementation is in dpu_doca_cgo.go.
type DocaBridge struct{}

// submitWithTimeout is a stub -- never called on non-DOCA builds.
func (d *DocaBridge) submitWithTimeout(_ func() error, _ time.Duration) error {
	return errDocaNotAvailable
}

// Shutdown is a stub -- DOCA bridge does not exist on non-DOCA builds.
// kept symmetric with the real impl in
// dpu_doca_cgo.go so the layered shutdown sequencer compiles under
// the default `!doca` build tag (no DOCA toolchain available).
func (d *DocaBridge) Shutdown(_ context.Context) error {
	return nil
}

// DocaInit is a no-op when built without the doca tag.
func DocaInit(pciAddr string, numRepr uint32) error {
	return nil
}

// DocaShutdown is a no-op when built without the doca tag.
func DocaShutdown() {
}

// DocaIsInitialized always returns false when built without the doca tag.
func DocaIsInitialized() bool {
	return false
}

// DocaGetRootPipe returns nil -- DOCA not available.
func DocaGetRootPipe() unsafe.Pointer {
	return nil
}

// DocaGetCTFwdPipe returns nil -- DOCA not available.
// -06 (TX-2) rename: was DocaGetCTPipe, renamed in lockstep with the
// C-side llb_doca_get_ct_pipe → llb_doca_get_ct_fwd_pipe rename.
func DocaGetCTFwdPipe() unsafe.Pointer {
	return nil
}

// DocaGetCTRevPipe returns nil -- DOCA not available (stub).
func DocaGetCTRevPipe() unsafe.Pointer {
	return nil
}

// -06 (TX-1): DocaGetEgressSteerPipe + docaGetSteerPipeDirect stub
// mirrors removed. The DOCA-build accessors are gone (deleted the
// C-side pipe + symbol; this plan removes the Go-side CGO wrappers and their
// callers). The !doca build no longer needs to mirror them because the
// pairedSteerEntry release paths in dpu_doca_bf2.go were stripped.

// GetEgressSteerCapacity returns a legacy capacity constant. Retained as
// pure Go (no CGO dependency) because deferred_offload.go's sweepDeferred
// still consumes it as the capacity-gate denominator. Mirrors the
// production const in dpu_doca_cgo.go.
func GetEgressSteerCapacity() int {
	return 1024
}

// DocaPipeCreateBasic returns an error -- DOCA not available.
func DocaPipeCreateBasic(name string, matchDstIPMask uint32, matchDstPortMask uint16,
	matchSrcIPMask uint32, matchSrcPortMask uint16,
	matchProto uint8, fwdType int, fwdPortID uint16,
	nrEntries uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}

// DocaPipeDestroy returns an error -- DOCA not available.
func DocaPipeDestroy(pipe unsafe.Pointer) error {
	return errDocaNotAvailable
}

// DocaEntryAddBasic returns an error -- DOCA not available.
// meterID parameter added (ignored in stub).
// -06: signature reduced to (ctEntry, error) — the
// paired-steer steerEntry return was dropped along with g_egress_steer_pipe.
func DocaEntryAddBasic(pipe unsafe.Pointer,
	dstIP uint32, dstPort uint16,
	srcIP uint32, srcPort uint16,
	newDstIP uint32, newDstPort uint16,
	newSrcIP uint32, newSrcPort uint16,
	newDstMAC [6]byte, newSrcMAC [6]byte,
	timeoutMs uint32, matchProto uint8,
	fwdPortID uint16, agingSec uint32,
	userCtx uint64, meterID uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}

// DocaEntryRemove returns an error -- DOCA not available.
func DocaEntryRemove(pipe, entry unsafe.Pointer) error {
	return errDocaNotAvailable
}

// DocaEntryRemoveDirect returns an error -- DOCA not available.
// stubbed so the !doca build can reference the symbol from the
// paired-offload rollback path's injectable fn-var seam.
func DocaEntryRemoveDirect(pipe, entry unsafe.Pointer) error {
	return errDocaNotAvailable
}

// DocaGetPortCount returns 0 -- DOCA not available.
func DocaGetPortCount() int {
	return 0
}

// DocaGetPortMacByID returns error -- DOCA not available.
func DocaGetPortMacByID(portID uint16) ([6]byte, error) {
	return [6]byte{}, errDocaNotAvailable
}

// DocaGetPortIfindex returns error -- DOCA not available.
func DocaGetPortIfindex(portID uint16) (int, error) {
	return 0, errDocaNotAvailable
}

// DocaEntryQuery returns an error -- DOCA not available.
func DocaEntryQuery(entry unsafe.Pointer) (bytes uint64, pkts uint64, err error) {
	return 0, 0, errDocaNotAvailable
}

// DocaDiagDumpRootEntries is a no-op -- DOCA not available (SPIKE-001).
func DocaDiagDumpRootEntries() {}

// DocaCtRevTestDropAll returns an error -- DOCA not available (TEST-ONLY diagnostic).
func DocaCtRevTestDropAll() error {
	return errDocaNotAvailable
}

// DocaRebuildRootPipe is a no-op -- DOCA not available.
func DocaRebuildRootPipe() error {
	return errDocaNotAvailable
}

// ---- ACL HW offload stubs ----
//
// These mirror the eight new wrappers in dpu_doca_cgo.go. Build-tag symmetry
// is enforced: every Doca* symbol exported under `//go:build doca` has a
// same-name stub here under `//go:build !doca` so the project links on
// macOS / Linux dev hosts without the DOCA SDK. The single-pipe
// stubs (DocaAclPipeCreate / DocaAclEntryAdd / DocaAclPipeDestroy /
// DocaSetAclPipe / DocaGetAclPipe / DocaAclQueryAll / DocaGetL4DispatchPipe)
// are retired in the same commit pair.

// DocaAclPipesCreate is stub -- DOCA not available.
func DocaAclPipesCreate() error { return errDocaNotAvailable }

// DocaAclPipesDestroy is stub -- DOCA not available.
func DocaAclPipesDestroy() error { return errDocaNotAvailable }

// DocaAclDenyEntryAdd is stub -- DOCA not available.
func DocaAclDenyEntryAdd(em unsafe.Pointer, timeoutMs uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}

// DocaAclAllowEntryAdd is stub -- DOCA not available.
func DocaAclAllowEntryAdd(em unsafe.Pointer, timeoutMs uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}

// DocaAclDenyEntryDel is stub -- DOCA not available.
func DocaAclDenyEntryDel(entry unsafe.Pointer) error { return errDocaNotAvailable }

// DocaAclAllowEntryDel is stub -- DOCA not available.
func DocaAclAllowEntryDel(entry unsafe.Pointer) error { return errDocaNotAvailable }

// DocaGetDenyPipe is stub -- DOCA not available.
func DocaGetDenyPipe() unsafe.Pointer { return nil }

// DocaGetAllowPipe is stub -- DOCA not available.
func DocaGetAllowPipe() unsafe.Pointer { return nil }

// DocaAclMatchAllocIP4 is stub. Returns a non-nil sentinel so that
// !doca-build tests can exercise the FwRuleAdd / FwRuleDel state-machine
// (the buffer is opaque to Go anyway — only ACL CGO call sites dereference it,
// and those are no-ops under !doca via the matching entry-add stubs).
func DocaAclMatchAllocIP4(srcIP, srcMask, dstIP, dstMask uint32, srcPort, srcPortMask, dstPort, dstPortMask uint16) unsafe.Pointer {
	// Allocate a small Go-owned buffer so its address is non-nil and stable.
	b := make([]byte, 1)
	return unsafe.Pointer(&b[0])
}

// DocaAclMatchAllocMaskIP4 is stub.
func DocaAclMatchAllocMaskIP4(srcMask, dstMask uint32, srcPortMask, dstPortMask uint16) unsafe.Pointer {
	b := make([]byte, 1)
	return unsafe.Pointer(&b[0])
}

// DocaAclMatchFree is stub no-op (the Go-owned buffer is freed by GC).
func DocaAclMatchFree(p unsafe.Pointer) {}

// DocaGetUDPCTPipe returns nil -- DOCA not available.
func DocaGetUDPCTPipe() unsafe.Pointer {
	return nil
}

// DocaMeterAdd is a no-op -- DOCA not available.
func DocaMeterAdd(meterID uint32, cirBps uint64, cbs uint64, ebs uint64) int {
	return -1
}

// DocaMeterDel is a no-op -- DOCA not available.
func DocaMeterDel(meterID uint32) int {
	return -1
}

// DocaMeterQuery returns error -- DOCA not available.
func DocaMeterQuery(meterID uint32) (totalPkts, totalBytes uint64, err error) {
	return 0, 0, errDocaNotAvailable
}

// DocaEntryUpdateMeter is a no-op -- DOCA not available.
func DocaEntryUpdateMeter(pipeHandle unsafe.Pointer, entryHandle unsafe.Pointer, meterID uint32) int {
	return -1
}

// DocaGetMeterPipe returns nil -- DOCA not available.
func DocaGetMeterPipe() unsafe.Pointer {
	return nil
}

// DocaSetMeterPipe is a no-op -- DOCA not available.
func DocaSetMeterPipe(pipe unsafe.Pointer) {}

// DocaMeterPipeCreate returns error -- DOCA not available.
func DocaMeterPipeCreate(missTarget unsafe.Pointer, meterID uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}

// DocaMeterPipeEntryAdd returns error -- DOCA not available.
func DocaMeterPipeEntryAdd(pipe unsafe.Pointer, dstIP uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}

// DocaAgingPoll is a no-op -- DOCA not available.
func DocaAgingPoll(quotaTime uint64, timeoutUs, maxEntries uint32) int {
	return 0
}

// DocaEntriesDrain is a no-op -- DOCA not available.
func DocaEntriesDrain(timeoutUs, maxEntries uint32) error {
	return nil
}

// DocaGetAgedEntries returns nil -- DOCA not available.
func DocaGetAgedEntries(maxOut int) []uint64 {
	return nil
}

// DocaGetFdbPipe returns nil -- DOCA not available.
func DocaGetFdbPipe() unsafe.Pointer {
	return nil
}

// DocaFdbEntryAdd returns nil -- DOCA not available.
func DocaFdbEntryAdd(pipe unsafe.Pointer, dstMAC [6]byte, fwdPortID uint16, agingSec uint32, userCtx uint64, timeoutMs uint32) (unsafe.Pointer, error) {
	return nil, errDocaNotAvailable
}
