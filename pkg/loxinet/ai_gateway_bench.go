/*
 * Copyright (c) 2026 NetLOX Inc
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
#include <stdint.h>

// Mirrors llb_sp_audit_bench_t in loxilb-ebpf/common/sockproxy_ai_bench.h.
typedef struct {
    uint64_t iters;
    double   p50_ns;
    double   p95_ns;
    double   p99_ns;
    double   max_ns;
} llb_sp_audit_bench_t;

int llb_sp_audit_bench(uint64_t iters, llb_sp_audit_bench_t *out);
*/
import "C"

import (
	"fmt"
	"syscall"
)

// AuditProducerCost is the cost a relay worker pays to record one completed
// request: the C call, the CGO crossing and the producer's non-blocking
// hand-off, as seen from the C side.
type AuditProducerCost struct {
	Iters uint64
	P50Ns float64
	P95Ns float64
	P99Ns float64
	MaxNs float64
}

// RunAuditProducerBench times llb_ai_audit_emit_only from a worker-shaped C
// thread and returns the distribution.
//
// It is measured from C on purpose. The cost that matters is the one paid on
// the sockproxy thread, and a Go-side benchmark can only see the Go half of
// the crossing — it would report the cheaper number and call it the answer.
// The harness carries a worker identity, so every record it emits is
// attributed exactly as a relay worker's would be.
//
// It times the trail on its own rather than the completion export, whose
// other half raises the Prometheus counters. The number wanted is what
// recording costs, and it is read directly instead of subtracted out of a
// larger one: differences of percentiles are not percentiles of
// differences, and an export timed with no trail behind it still carries
// the same garbage collection and scheduling that dominates the tail.
//
// The trail must be running: the calls emit real records, and a measurement
// taken with no writer behind them is timing the drop path.
func RunAuditProducerBench(iters uint64) (AuditProducerCost, error) {
	var out C.llb_sp_audit_bench_t

	if iters == 0 {
		return AuditProducerCost{}, fmt.Errorf("audit producer bench: iterations must be positive")
	}
	if rc := C.llb_sp_audit_bench(C.uint64_t(iters), &out); rc != 0 {
		return AuditProducerCost{}, fmt.Errorf("audit producer bench: %w", syscall.Errno(-rc))
	}
	return AuditProducerCost{
		Iters: uint64(out.iters),
		P50Ns: float64(out.p50_ns),
		P95Ns: float64(out.p95_ns),
		P99Ns: float64(out.p99_ns),
		MaxNs: float64(out.max_ns),
	}, nil
}

// llb_ai_audit_emit_only writes one completed request to the audit trail and
// raises no counters.
//
// It exists so the trail's cost can be timed on its own. llb_ai_record_request
// does this and the Prometheus work, and no measurement of the two together
// can be turned into a measurement of one: subtracting an arm with the trail
// closed subtracts the same garbage collection and scheduling that dominates
// either arm's tail, and percentiles do not subtract in the first place.
//
// The only caller is the harness in sockproxy_ai_bench.c. The datapath wants
// the counters as well as the record, so it calls llb_ai_record_request; a
// second path into the trail on the request's own thread would be a way to
// record a request that the dashboards never see.
//
//export llb_ai_audit_emit_only
func llb_ai_audit_emit_only(tenantID *C.char, modelName *C.char, statusCode C.int, latencyMs C.int64_t, promptTokens C.int, completTokens C.int, errorCode *C.char, requestID *C.char, userID *C.char, keyID *C.char, svcIdent *C.char, isStream C.int, producerID C.int) {
	defer cgoRecover("llb_ai_audit_emit_only")

	emitAIComplete(aiCompleteRecord{
		RequestID:  C.GoString(requestID),
		TenantID:   C.GoString(tenantID),
		UserID:     C.GoString(userID),
		KeyID:      C.GoString(keyID),
		SvcIdent:   C.GoString(svcIdent),
		ModelName:  C.GoString(modelName),
		StatusCode: int(statusCode),
		LatencyMs:  int64(latencyMs),
		TokensIn:   int64(promptTokens),
		TokensOut:  int64(completTokens),
		IsStream:   isStream != 0,
		ErrorCode:  C.GoString(errorCode),
		WorkerID:   int(producerID),
	})
}
