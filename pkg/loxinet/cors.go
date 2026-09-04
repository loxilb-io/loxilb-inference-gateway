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

// cors.go — NetHookInterface surface over the CORS allowlist manager
// (common/cors.go), so the config snapshot/restore engine captures and
// replays the API server's CORS desired state like any other domain. No
// BgpPeerMode guard: the REST API (and with it CORS policy) runs in every
// mode.

package loxinet

import (
	cmn "github.com/loxilb-io/loxilb/common"
)

// NetCORSGet - export the explicit CORS configuration; nil while the
// gateway is unconfigured (factory default).
func (na *NetAPIStruct) NetCORSGet() (*cmn.CORSConfig, error) {
	return cmn.GetCORSManager().ExportConfig(), nil
}

// NetCORSSet - replace the whole CORS configuration (overwrite semantics).
func (na *NetAPIStruct) NetCORSSet(cfg *cmn.CORSConfig) (int, error) {
	if err := cmn.GetCORSManager().SetConfig(cfg); err != nil {
		return RuleErrBase, err
	}
	return 0, nil
}

// NetCORSReset - back to the unconfigured factory default.
func (na *NetAPIStruct) NetCORSReset() (int, error) {
	cmn.GetCORSManager().ResetConfig()
	return 0, nil
}
