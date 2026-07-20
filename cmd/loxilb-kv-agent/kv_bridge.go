/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../loxilb-ebpf/doca/kv
#cgo LDFLAGS: -L${SRCDIR}/../../loxilb-ebpf/doca/kv -lloxilb_kv -lz
#include "loxilb_kv.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/base64"
	"unsafe"
)

// KVCapabilities represents hardware capabilities detected by the C pipeline.
type KVCapabilities struct {
	HWDeflate        bool   `json:"hw_deflate"`
	HWDMA            bool   `json:"hw_dma"`
	ComCh            bool   `json:"comch"`
	PCIExportHW      bool   `json:"pci_export_hw"`
	ComChMaxMsgBytes uint32 `json:"comch_max_msg_bytes"`
	HealthStatus     string `json:"health_status"`
}

// KVPipelineStats holds pipeline statistics for Prometheus scraping.
type KVPipelineStats struct {
	Fetches   uint64 `json:"fetches"`
	Errors    uint64 `json:"errors"`
	Evictions uint64 `json:"evictions"`
	Bytes     uint64 `json:"bytes"`
}

// probeCapabilities calls the C library to detect DOCA hardware capabilities.
func probeCapabilities() KVCapabilities {
	var caps C.llb_kv_capabilities_t
	C.llb_kv_capability_probe(&caps)
	return KVCapabilities{
		HWDeflate:        bool(caps.hw_deflate),
		HWDMA:            bool(caps.hw_dma),
		ComCh:            bool(caps.comch),
		PCIExportHW:      bool(caps.pci_export_hw),
		ComChMaxMsgBytes: uint32(caps.comch_max_msg_bytes),
		HealthStatus:     C.GoString(&caps.health_status[0]),
	}
}

// pipelineInit initializes the C pipeline with transport, compress, and DMA.
// dev is NULL for stub builds. Returns an opaque pipeline context.
func pipelineInit(stagingSize uint64) unsafe.Pointer {
	compress := C.llb_kv_compress_init(nil, C.size_t(stagingSize))
	if compress == nil {
		return nil
	}
	dma := C.llb_kv_dma_init(nil, C.size_t(stagingSize))
	if dma == nil {
		C.llb_kv_compress_destroy(compress)
		return nil
	}
	pipeline := C.llb_kv_pipeline_init(&C.llb_kv_tcp_ops, compress, dma)
	if pipeline == nil {
		C.llb_kv_dma_destroy(dma)
		C.llb_kv_compress_destroy(compress)
		return nil
	}
	return unsafe.Pointer(pipeline)
}

// pipelineRun starts the pipeline main event loop (blocks until stopped).
func pipelineRun(ctx unsafe.Pointer) {
	if ctx != nil {
		C.llb_kv_pipeline_run((*C.llb_kv_pipeline_ctx_t)(ctx))
	}
}

// pipelineStop signals the pipeline to stop its event loop.
func pipelineStop(ctx unsafe.Pointer) {
	if ctx != nil {
		C.llb_kv_pipeline_stop((*C.llb_kv_pipeline_ctx_t)(ctx))
	}
}

// pipelineDestroy frees all pipeline resources.
func pipelineDestroy(ctx unsafe.Pointer) {
	if ctx != nil {
		C.llb_kv_pipeline_destroy((*C.llb_kv_pipeline_ctx_t)(ctx))
	}
}

// pipelineGetStats retrieves pipeline statistics for monitoring.
func pipelineGetStats(ctx unsafe.Pointer) KVPipelineStats {
	if ctx == nil {
		return KVPipelineStats{}
	}
	var fetches, errors, evictions, bytes C.uint64_t
	C.llb_kv_pipeline_get_stats(
		(*C.llb_kv_pipeline_ctx_t)(ctx),
		&fetches, &errors, &evictions, &bytes,
	)
	return KVPipelineStats{
		Fetches:   uint64(fetches),
		Errors:    uint64(errors),
		Evictions: uint64(evictions),
		Bytes:     uint64(bytes),
	}
}

// pipelineRegisterGPUMmap imports a GPU mmap for a session from a base64-encoded
// PCI export descriptor. Called from POST /kv/session before ComCh KV_FETCH_REQ.
func pipelineRegisterGPUMmap(ctx unsafe.Pointer, sessionID uint64, gpuExportDescB64 string) int {
	if ctx == nil {
		return -1
	}
	descBytes, err := base64.StdEncoding.DecodeString(gpuExportDescB64)
	if err != nil {
		return -1
	}
	if len(descBytes) == 0 {
		return -1
	}
	rc := C.llb_kv_pipeline_register_gpu_mmap(
		(*C.llb_kv_pipeline_ctx_t)(ctx),
		C.uint64_t(sessionID),
		unsafe.Pointer(&descBytes[0]),
		C.size_t(len(descBytes)),
	)
	return int(rc)
}
