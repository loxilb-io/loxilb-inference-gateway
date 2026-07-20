//go:build mtls

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

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ============================================================================
// mTLS Validation Helper Functions
// ============================================================================

// fileExists - Check if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// validatePEMFile - Validate PEM file format
func validatePEMFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	return validatePEMData(string(data))
}

// validatePEMData - Validate PEM data format
func validatePEMData(data string) error {
	if data == "" {
		return fmt.Errorf("empty PEM data")
	}

	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}

	// Try to parse as X.509 certificate
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid X.509 certificate: %w", err)
	}

	return nil
}

// isValidHostnamePattern - Validate hostname pattern for CN matching
func isValidHostnamePattern(pattern string) bool {
	if pattern == "" {
		return false
	}

	// Basic validation: alphanumeric, dots, wildcards, hyphens
	for _, ch := range pattern {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '*' || ch == '?' || ch == '-') {
			return false
		}
	}
	return true
}

// ============================================================================
// mTLS Validation Methods
// ============================================================================

// Validate validates MTLSFrontendConfig
func (m *MTLSFrontendConfig) Validate() error {
	if m == nil {
		return nil // nil config is valid (no mTLS)
	}

	// Validate client_cert_mode
	validModes := map[string]bool{
		"disabled": true,
		"optional": true,
		"required": true,
	}
	if m.ClientCertMode == "" {
		m.ClientCertMode = "disabled" // Default
	}
	if !validModes[m.ClientCertMode] {
		return fmt.Errorf("invalid client_cert_mode: %s (must be disabled/optional/required)",
			m.ClientCertMode)
	}

	// If mode is not disabled, require CA path or data
	if m.ClientCertMode != "disabled" {
		if m.ClientCAPath == "" && m.ClientCACertData == "" {
			return fmt.Errorf("client_ca_path or client_ca_cert_data required when client_cert_mode is %s",
				m.ClientCertMode)
		}

		// Validate CA path if provided
		if m.ClientCAPath != "" {
			// Check absolute path
			if !filepath.IsAbs(m.ClientCAPath) {
				return fmt.Errorf("client_ca_path must be absolute path: %s", m.ClientCAPath)
			}

			if !fileExists(m.ClientCAPath) {
				return fmt.Errorf("client CA file not found: %s", m.ClientCAPath)
			}

			// Validate PEM format
			if err := validatePEMFile(m.ClientCAPath); err != nil {
				return fmt.Errorf("invalid client CA file: %w", err)
			}
		}

		// Validate CA data if provided
		if m.ClientCACertData != "" {
			if err := validatePEMData(m.ClientCACertData); err != nil {
				return fmt.Errorf("invalid client CA certificate data: %w", err)
			}
		}
	}

	// Validate CN pattern if required
	if m.RequireClientCN {
		if m.ClientCNPattern == "" {
			return fmt.Errorf("client_cn_pattern required when require_client_cn is true")
		}

		if len(m.ClientCNPattern) > 255 {
			return fmt.Errorf("client_cn_pattern too long (max 255 characters)")
		}

		if !isValidHostnamePattern(m.ClientCNPattern) {
			return fmt.Errorf("invalid client_cn_pattern: %s", m.ClientCNPattern)
		}
	}

	return nil
}

// Validate validates MTLSBackendConfig
func (m *MTLSBackendConfig) Validate() error {
	if m == nil {
		return nil // nil config is valid (no mTLS)
	}

	// Validate cert/key consistency
	hasCertPath := m.ClientCertPath != ""
	hasKeyPath := m.ClientKeyPath != ""
	hasCertData := m.ClientCertData != ""
	hasKeyData := m.ClientKeyData != ""

	// Both path fields must be provided together
	if hasCertPath != hasKeyPath {
		return fmt.Errorf("both client_cert_path and client_key_path must be provided together")
	}

	// Both data fields must be provided together
	if hasCertData != hasKeyData {
		return fmt.Errorf("both client_cert_data and client_key_data must be provided together")
	}

	// Cannot mix path and data
	if (hasCertPath || hasKeyPath) && (hasCertData || hasKeyData) {
		return fmt.Errorf("cannot use both path-based and data-based configuration")
	}

	// Validate path-based configuration
	if hasCertPath {
		// Check absolute paths
		if !filepath.IsAbs(m.ClientCertPath) {
			return fmt.Errorf("client_cert_path must be absolute path: %s", m.ClientCertPath)
		}
		if !filepath.IsAbs(m.ClientKeyPath) {
			return fmt.Errorf("client_key_path must be absolute path: %s", m.ClientKeyPath)
		}

		// Check file existence
		if !fileExists(m.ClientCertPath) {
			return fmt.Errorf("client certificate file not found: %s", m.ClientCertPath)
		}
		if !fileExists(m.ClientKeyPath) {
			return fmt.Errorf("client key file not found: %s", m.ClientKeyPath)
		}

		// Validate PEM formats
		if err := validatePEMFile(m.ClientCertPath); err != nil {
			return fmt.Errorf("invalid client certificate: %w", err)
		}
		// Note: Key validation would require different parsing
	}

	// Validate data-based configuration
	if hasCertData {
		if err := validatePEMData(m.ClientCertData); err != nil {
			return fmt.Errorf("invalid client certificate data: %w", err)
		}
		// Note: Key validation would require different parsing
	}

	// Validate backend CA path if provided
	if m.BackendCAPath != "" {
		if !filepath.IsAbs(m.BackendCAPath) {
			return fmt.Errorf("backend_ca_path must be absolute path: %s", m.BackendCAPath)
		}

		if !fileExists(m.BackendCAPath) {
			return fmt.Errorf("backend CA file not found: %s", m.BackendCAPath)
		}

		if err := validatePEMFile(m.BackendCAPath); err != nil {
			return fmt.Errorf("invalid backend CA file: %w", err)
		}
	}

	return nil
}

// ValidateMTLSConfig validates mTLS configuration against service settings
// This enforces the critical requirement: mTLS only works with FullProxy mode
func ValidateMTLSConfig(mode LBMode, security LBSec, frontend *MTLSFrontendConfig, backend *MTLSBackendConfig) error {
	// mTLS requires FullProxy mode (critical requirement)
	if (frontend != nil || backend != nil) && mode != LBModeFullProxy {
		return fmt.Errorf("mTLS requires mode=fullproxy (current mode: %v)", mode)
	}

	// Frontend mTLS requires HTTPS or E2EHTTPS security mode
	if frontend != nil && frontend.ClientCertMode != "disabled" {
		if security != LBServHTTPS && security != LBServE2EHTTPS {
			return fmt.Errorf("frontend mTLS requires security=https or security=e2ehttps (current: %v)", security)
		}
	}

	// Backend mTLS requires E2EHTTPS security mode
	if backend != nil && (backend.VerifyServerCert || backend.ClientCertPath != "" || backend.ClientCertData != "") {
		if security != LBServE2EHTTPS {
			return fmt.Errorf("backend mTLS requires security=e2ehttps (current: %v)", security)
		}
	}

	// Validate individual configs
	if frontend != nil {
		if err := frontend.Validate(); err != nil {
			return fmt.Errorf("frontend mTLS validation failed: %w", err)
		}
	}

	if backend != nil {
		if err := backend.Validate(); err != nil {
			return fmt.Errorf("backend mTLS validation failed: %w", err)
		}
	}

	return nil
}

// ToC converts MTLSFrontendConfig to C-compatible values
func (m *MTLSFrontendConfig) ToC() (mode uint8, requireCN uint8) {
	if m == nil {
		return 0, 0 // Disabled
	}

	// Map mode to C constant
	switch strings.ToLower(m.ClientCertMode) {
	case "optional":
		mode = 1
	case "required":
		mode = 2
	default:
		mode = 0 // Disabled
	}

	// Require CN flag
	if m.RequireClientCN {
		requireCN = 1
	} else {
		requireCN = 0
	}

	return mode, requireCN
}

// ToC converts MTLSBackendConfig to C-compatible value
func (m *MTLSBackendConfig) ToC() (verifyCert uint8) {
	if m == nil {
		return 0 // Disabled
	}

	if m.VerifyServerCert {
		return 1
	}
	return 0
}
