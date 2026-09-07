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

// cert.go — NetHookInterface surface over the certId TLS-material
// registry (api/restapi/handler/cert.go), so the config snapshot/restore
// engine captures and replays certificate desired state as {id, digest}
// metadata. PEM material never crosses this surface — it stays in the
// node-local managed directory. BgpPeerMode guard: the sockproxy (and
// with it the SNI registry) does not run on a BGP-only node, so the
// domain reads as empty there (capture treats it as an unavailable
// subsystem).

package loxinet

import (
	"errors"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
	cmn "github.com/loxilb-io/loxilb/common"
)

// NetCertGet - export registered certificates as desired-state metadata.
func (na *NetAPIStruct) NetCertGet() ([]cmn.CertMeta, error) {
	if na.BgpPeerMode {
		return nil, errors.New("running in bgp only mode")
	}
	return handler.CertExportMetas()
}

// NetCertAdd - re-register one certificate from the node-local managed
// material after digest verification.
func (na *NetAPIStruct) NetCertAdd(meta *cmn.CertMeta) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	if err := handler.CertApplyMeta(meta); err != nil {
		return RuleErrBase, err
	}
	return 0, nil
}

// NetCertDel - unregister one certificate (SNI store + metadata), keeping
// the managed on-disk material.
func (na *NetAPIStruct) NetCertDel(id string) (int, error) {
	if na.BgpPeerMode {
		return RuleErrBase, errors.New("running in bgp only mode")
	}
	if err := handler.CertWipeRegistration(id); err != nil {
		return RuleErrBase, err
	}
	return 0, nil
}
