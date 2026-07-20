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

/*
 * dpu_doca_collector_registry.go -- DOCA collector callback registry
 * (amendment iter 2: callback invocation from the existing per-tick path,
 * NO goroutine spawn, NO ticker).
 *
 * Build-tag free on purpose: the registry is pure Go with no SDK or CGO
 * dependency, so both the doca build and the !doca build share one
 * implementation (and the !doca unit tests exercise the real panic-isolation
 * semantics instead of a stub no-op). Only noteDocaCollectorPanic — which
 * touches the doca-build-only Prometheus error counter — keeps per-build-tag
 * implementations in dpu_doca_bf2_metrics.go / dpu_doca_bf2_stub_metrics.go.
 */

package loxinet

import "sync"

var (
	docaCollectorMu          sync.Mutex
	registeredDocaCollectors []func()
)

// RegisterDocaCollector appends fn to the in-process collector registry.
// The per-tick path ((*DpuManager).CollectHwOffloadStats) invokes the
// registry; fn MUST be safe to call from that collection goroutine — this
// registry does NOT spawn new goroutines.
func RegisterDocaCollector(fn func()) {
	if fn == nil {
		return
	}
	docaCollectorMu.Lock()
	registeredDocaCollectors = append(registeredDocaCollectors, fn)
	docaCollectorMu.Unlock()
}

// InvokeRegisteredDocaCollectors invokes every collector previously
// registered via RegisterDocaCollector. Each invocation runs inside its own
// `defer recover` block so a panicking collector cannot poison the per-tick
// path or sibling collectors.
//
// Lock discipline: snapshot the slice under docaCollectorMu, release the
// lock, then iterate — a panicking collector never holds the registry lock
// during recover handling.
func InvokeRegisteredDocaCollectors() {
	docaCollectorMu.Lock()
	if len(registeredDocaCollectors) == 0 {
		docaCollectorMu.Unlock()
		return
	}
	snapshot := make([]func(), len(registeredDocaCollectors))
	copy(snapshot, registeredDocaCollectors)
	docaCollectorMu.Unlock()

	for _, fn := range snapshot {
		func(cb func()) {
			defer func() {
				if r := recover(); r != nil {
					noteDocaCollectorPanic(r)
				}
			}()
			cb()
		}(fn)
	}
}
