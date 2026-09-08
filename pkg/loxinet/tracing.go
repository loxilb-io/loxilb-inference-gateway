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

// tracing.go — NetHookInterface surface over the OTLP trace-export
// configuration store (api/restapi/handler/configure_trace.go; this
// package already imports handler for the exporter/callback wiring), so
// the config snapshot/restore engine captures and replays it like any
// other domain. Header values never cross this surface — they stay in the
// node-local secret store the handler package manages. No BgpPeerMode
// guard: trace export runs in every mode.

package loxinet

import (
	"github.com/loxilb-io/loxilb/api/restapi/handler"
	cmn "github.com/loxilb-io/loxilb/common"
)

// NetTracingGet - export the explicit OTLP configuration (header names
// only); nil while only the boot default is in effect.
func (na *NetAPIStruct) NetTracingGet() (*cmn.TracingConfig, error) {
	return handler.OtlpExportConfig(), nil
}

// NetTracingSet - apply a restored OTLP configuration (overwrite
// semantics), re-joining header values from the node-local secret store.
func (na *NetAPIStruct) NetTracingSet(cfg *cmn.TracingConfig) (int, error) {
	if err := handler.OtlpApplyConfig(cfg); err != nil {
		return RuleErrBase, err
	}
	return 0, nil
}

// NetTracingReset - back to the node's boot default.
func (na *NetAPIStruct) NetTracingReset() (int, error) {
	handler.OtlpResetConfig()
	return 0, nil
}
