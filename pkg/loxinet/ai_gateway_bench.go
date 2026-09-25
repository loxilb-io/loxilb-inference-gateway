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
// request: the call into the export, the CGO crossing and the producer's
// non-blocking hand-off, as seen from the C side.
type AuditProducerCost struct {
	Iters uint64
	P50Ns float64
	P95Ns float64
	P99Ns float64
	MaxNs float64
}

// RunAuditProducerBench times the completion export from a worker-shaped C
// thread and returns the distribution.
//
// It is measured from C on purpose. The cost that matters is the one paid on
// the sockproxy thread, and a Go-side benchmark can only see the Go half of
// the crossing — it would report the cheaper number and call it the answer.
// The harness carries a worker identity, so every record it emits is
// attributed exactly as a relay worker's would be.
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
