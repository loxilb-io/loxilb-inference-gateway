//go:build !mtls
// +build !mtls

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

package common

import "fmt"

// ===========================================================================
// mTLS Stub Implementations (When HAVE_MTLS is disabled)
// Note: Types are defined in common.go, not here
// ===========================================================================

// Validate stub - always returns error indicating mTLS is not compiled
func (m *MTLSFrontendConfig) Validate() error {
	if m != nil {
		return fmt.Errorf("mTLS support not compiled (rebuild with HAVE_MTLS=1)")
	}
	return nil
}

// Validate stub - always returns error indicating mTLS is not compiled
func (m *MTLSBackendConfig) Validate() error {
	if m != nil {
		return fmt.Errorf("mTLS support not compiled (rebuild with HAVE_MTLS=1)")
	}
	return nil
}

// ValidateMTLSConfig stub - returns error if mTLS config is provided
func ValidateMTLSConfig(serv *LbServiceArg) error {
	if serv == nil {
		return nil
	}
	if serv.MTLSFrontend != nil || serv.MTLSBackend != nil {
		return fmt.Errorf("mTLS support not compiled (rebuild with HAVE_MTLS=1)")
	}
	return nil
}

// ToC stub - returns zeros
func (m *MTLSFrontendConfig) ToC() (mode uint8, requireCN uint8) {
	return 0, 0
}

// ToC stub - returns zero
func (m *MTLSBackendConfig) ToC() (verifyCert uint8) {
	return 0
}
