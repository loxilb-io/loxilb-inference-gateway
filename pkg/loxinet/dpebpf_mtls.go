//go:build mtls
// +build mtls

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
#include <string.h>
*/
import "C"
import (
	"unsafe"

	opts "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
)

// DpLBRuleSetMTLS sets mTLS fields directly in the dp_proxy_tacts struct (dat)
// so that llb_conv_nat2proxy can read them when creating the proxy entry.
// This is called in the DpCreate path before llb_add_map_elem.
func DpLBRuleSetMTLS(dat *proxyActs, w *LBDpWorkQ) error {
	if w.NatType != DpFullProxy {
		return nil
	}

	// The backend leg's request rides every push, with or without a frontend
	// client-certificate configuration.
	if w.MTLSBackend != nil && w.MTLSBackend.VerifyServerCert {
		dat.mtls_backend_verify = 1
	}
	if w.BackendTLSServerName != "" {
		cName := C.CString(w.BackendTLSServerName)
		C.strncpy(&dat.mtls_backend_server_name[0], cName, 255)
		C.free(unsafe.Pointer(cName))
	}

	if w.MTLSFrontend == nil {
		return nil
	}

	switch w.MTLSFrontend.ClientCertMode {
	case "required":
		dat.mtls_frontend_mode = 2
	case "optional":
		dat.mtls_frontend_mode = 1
	default:
		dat.mtls_frontend_mode = 0
	}

	if w.MTLSFrontend.RequireClientCN {
		dat.mtls_require_client_cn = 1
	}

	caPath := ""
	if dat.mtls_frontend_mode != 0 {
		var err error
		caPath, err = frontendClientCAPath(opts.Opts.ConfigPath, w.MTLSFrontend)
		if err != nil {
			return err
		}
		cPath := C.CString(caPath)
		C.strncpy(&dat.mtls_client_ca_path[0], cPath, 255)
		C.free(unsafe.Pointer(cPath))
	}

	if w.MTLSFrontend.ClientCNPattern != "" {
		cPattern := C.CString(w.MTLSFrontend.ClientCNPattern)
		C.strncpy(&dat.mtls_client_cn_pattern[0], cPattern, 255)
		C.free(unsafe.Pointer(cPattern))
	}

	// explicit client-cert CRL path. Empty ⇒ the 77-04 sibling-crl
	// convention (mtls_derive_crl_path) in the data plane (additive/default-off).
	if w.MTLSFrontend.ClientCRLPath != "" {
		cCRL := C.CString(w.MTLSFrontend.ClientCRLPath)
		C.strncpy(&dat.mtls_client_crl_path[0], cCRL, 255)
		C.free(unsafe.Pointer(cCRL))
	}

	tk.LogIt(tk.LogInfo, "[DP] mTLS frontend set in dat: mode=%s ca_path=%s require_cn=%v crl=%s\n",
		w.MTLSFrontend.ClientCertMode, caPath, w.MTLSFrontend.RequireClientCN,
		w.MTLSFrontend.ClientCRLPath)
	return nil
}
