package common

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
)

// DecodeFrontendClientCA parses all certificates in the inline trust bundle.
func DecodeFrontendClientCA(data string) ([]byte, error) {
	const header = "-----BEGIN CERTIFICATE-----"
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace([]byte(data))))
	if err != nil {
		return nil, errors.New("client_ca_cert_data must be base64-encoded PEM")
	}
	bundle := bytes.TrimSpace(decoded)
	if len(bundle) == 0 {
		return nil, errors.New("client_ca_cert_data is empty")
	}
	for rest := bundle; len(rest) > 0; {
		if !bytes.HasPrefix(rest, []byte(header)) {
			return nil, errors.New("client_ca_cert_data must contain only PEM certificates")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("client_ca_cert_data contains invalid PEM")
		}
		// pem.Decode can skip a malformed block and return a later certificate.
		if bytes.Count(rest[:len(rest)-len(next)], []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("client_ca_cert_data contains invalid PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.New("client_ca_cert_data contains an invalid X.509 certificate")
		}
		rest = bytes.TrimSpace(next)
	}
	return append(bundle, '\n'), nil
}

// FrontendClientCADir contains only IGW-managed inline CA files.
const FrontendClientCADir = "frontend-client-ca"

// FrontendClientCAFilename derives the filename from the validated PEM bundle.
func FrontendClientCAFilename(bundle []byte) string {
	return fmt.Sprintf("%x.pem", sha256.Sum256(bundle))
}

// FrontendClientCAFile resolves the managed bundle path.
func FrontendClientCAFile(configPath string, bundle []byte) (string, error) {
	return filepath.Abs(filepath.Join(configPath, FrontendClientCADir, FrontendClientCAFilename(bundle)))
}
