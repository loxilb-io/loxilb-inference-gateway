package loxinet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
)

func makeFrontendTestCA(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestFrontendClientCAPath(t *testing.T) {
	root := t.TempDir()
	oldCA := makeFrontendTestCA(t, 1)
	newCA := makeFrontendTestCA(t, 2)
	f := &cmn.MTLSFrontendConfig{ClientCACertData: base64.StdEncoding.EncodeToString(oldCA)}
	oldPath, err := frontendClientCAPath(root, f)
	if err != nil {
		t.Fatal(err)
	}
	samePath, err := frontendClientCAPath(root, f)
	if err != nil || samePath != oldPath {
		t.Fatalf("unchanged CA has a different path: %v", err)
	}
	f.ClientCACertData = base64.StdEncoding.EncodeToString(append(newCA, oldCA...))
	path, err := frontendClientCAPath(root, f)
	if err != nil || path == oldPath {
		t.Fatalf("CA rollover did not get its own file: %v", err)
	}
	if got, err := os.ReadFile(oldPath); err != nil || string(got) != string(oldCA) {
		t.Fatalf("CA rollover altered the previous bundle: %v", err)
	}
	f.ClientCACertData = base64.StdEncoding.EncodeToString(append(newCA, []byte("bad PEM")...))
	if _, err := frontendClientCAPath(root, f); err == nil {
		t.Fatal("accepted an invalid bundle after a valid certificate")
	}
	malformed := []byte("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n")
	f.ClientCACertData = base64.StdEncoding.EncodeToString(append(malformed, oldCA...))
	if _, err := frontendClientCAPath(root, f); err == nil {
		t.Fatal("skipped an invalid PEM block before a valid certificate")
	}
	f.ClientCAPath = oldPath
	if got, err := frontendClientCAPath(root, f); err != nil || got != oldPath {
		t.Fatalf("explicit CA path must take precedence: %v", err)
	}
}

func TestFrontendClientCARepairsCache(t *testing.T) {
	bundle := makeFrontendTestCA(t, 1)
	f := &cmn.MTLSFrontendConfig{ClientCACertData: base64.StdEncoding.EncodeToString(bundle)}
	for name, damaged := range map[string][]byte{
		"corrupt":   []byte(strings.Repeat("X", len(bundle))),
		"truncated": bundle[:len(bundle)/2],
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path, err := frontendClientCAPath(root, f)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, damaged, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := frontendClientCAPath(root, f); err != nil || got != path {
				t.Fatalf("repair failed: path=%q err=%v", got, err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != string(bundle) {
				t.Fatalf("repaired file has wrong content: %v", err)
			}
		})
	}
}

func TestFrontendClientCAUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires a non-root user")
	}
	root := t.TempDir()
	dir := filepath.Join(root, cmn.FrontendClientCADir)
	if err := os.Mkdir(dir, 0500); err != nil {
		t.Fatal(err)
	}
	f := &cmn.MTLSFrontendConfig{ClientCACertData: base64.StdEncoding.EncodeToString(makeFrontendTestCA(t, 1))}
	if _, err := frontendClientCAPath(root, f); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected permission error: %v", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("failed materialization left files: %v, %v", entries, err)
	}
}

func TestPrepareFrontendMTLS(t *testing.T) {
	oldPath := opts.Opts.ConfigPath
	t.Cleanup(func() { opts.Opts.ConfigPath = oldPath })
	opts.Opts.ConfigPath = t.TempDir()
	valid := base64.StdEncoding.EncodeToString(makeFrontendTestCA(t, 1))
	for _, tc := range []struct {
		name      string
		mode      cmn.LBMode
		security  cmn.LBSec
		frontend  *cmn.MTLSFrontendConfig
		wantError bool
	}{
		{"disabled", 0, 0, &cmn.MTLSFrontendConfig{ClientCertMode: "disabled", ClientCACertData: "malformed"}, false},
		{"valid inline", cmn.LBModeFullProxy, cmn.LBServHTTPS, &cmn.MTLSFrontendConfig{ClientCertMode: "required", ClientCACertData: valid}, !cmn.MTLSBuild},
		{"valid inline E2E", cmn.LBModeFullProxy, cmn.LBServE2EHTTPS, &cmn.MTLSFrontendConfig{ClientCertMode: "optional", ClientCACertData: valid}, !cmn.MTLSBuild},
		{"missing CA", cmn.LBModeFullProxy, cmn.LBServHTTPS, &cmn.MTLSFrontendConfig{ClientCertMode: "required"}, true},
		{"malformed CA", cmn.LBModeFullProxy, cmn.LBServHTTPS, &cmn.MTLSFrontendConfig{ClientCertMode: "required", ClientCACertData: "malformed"}, true},
		{"HTTP", cmn.LBModeFullProxy, 0, &cmn.MTLSFrontendConfig{ClientCertMode: "required", ClientCACertData: valid}, true},
		{"non proxy", 0, cmn.LBServHTTPS, &cmn.MTLSFrontendConfig{ClientCertMode: "required", ClientCACertData: valid}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := cmn.LbServiceArg{Mode: tc.mode, Security: tc.security, MTLSFrontend: tc.frontend}
			if err := prepareFrontendMTLS(&rule); (err != nil) != tc.wantError {
				t.Fatalf("prepare error = %v, want error=%t", err, tc.wantError)
			}
			if _, err := os.Stat(filepath.Join(opts.Opts.ConfigPath, cmn.FrontendClientCADir)); !os.IsNotExist(err) {
				t.Fatalf("admission wrote into the config directory: %v", err)
			}
		})
	}
}
