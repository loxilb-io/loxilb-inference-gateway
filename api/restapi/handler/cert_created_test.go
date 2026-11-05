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

package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

func testCABundlePEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cert-created-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A certificate that was created is answered with the ID it is stored under:
// the one the request named, and the one the server minted when it named none.
func TestCertCreateAnswersWithTheCertID(t *testing.T) {
	dir := t.TempDir()
	prevCmn, prevHandler := cmn.CertManagedDir, certManagedDir
	cmn.CertManagedDir, certManagedDir = dir, dir
	t.Cleanup(func() { cmn.CertManagedDir, certManagedDir = prevCmn, prevHandler })

	sp := func(v string) *string { return &v }
	bundle := testCABundlePEM(t)

	post := func(certID *string) string {
		t.Helper()
		resp := ConfigPostCert(operations.PostConfigCertParams{
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/netlox/v1/config/cert", nil),
			Attr:        &models.Cert{CertID: certID, Usage: sp("ca"), CertPem: sp(bundle), KeyPem: sp("")},
		}, nil)
		created, ok := resp.(*operations.PostConfigCertCreated)
		if !ok {
			if bad, isBad := resp.(*operations.PostConfigCertBadRequest); isBad && bad.Payload != nil {
				t.Fatalf("POST answered 400: %s", bad.Payload.Result)
			}
			t.Fatalf("POST answered %T, want a 201", resp)
		}
		if created.Payload == nil || created.Payload.CertID == nil {
			t.Fatal("the 201 carries no certId")
		}
		id := *created.Payload.CertID
		t.Cleanup(func() {
			certStoreMu.Lock()
			delete(certStore, id)
			certStoreMu.Unlock()
		})
		return id
	}

	if got := post(sp("created-named")); got != "created-named" {
		t.Errorf("a named certificate was answered with certId %q", got)
	}

	minted := post(nil)
	if minted == "" || minted == "created-named" {
		t.Fatalf("the minted certId is %q", minted)
	}
	if got := cmn.CertDiskUsage(minted); got != cmn.CertUsageCA {
		t.Errorf("the answered certId %q holds usage %q on disk, want %q", minted, got, cmn.CertUsageCA)
	}
	certStoreMu.Lock()
	_, stored := certStore[minted]
	certStoreMu.Unlock()
	if !stored {
		t.Errorf("the answered certId %q is not in the registry", minted)
	}
}

func TestCertCreateProtectsExistingAndConcurrentEntries(t *testing.T) {
	dir := t.TempDir()
	prevCmn, prevHandler := cmn.CertManagedDir, certManagedDir
	cmn.CertManagedDir, certManagedDir = dir, dir
	t.Cleanup(func() {
		cmn.CertManagedDir, certManagedDir = prevCmn, prevHandler
		certStoreMu.Lock()
		delete(certStore, "duplicate-race")
		certStoreMu.Unlock()
	})

	bundle := testCABundlePEM(t)
	post := func(id, usage string, keyPEM *string) int {
		res := ConfigPostCert(operations.PostConfigCertParams{
			HTTPRequest: httptest.NewRequest(http.MethodPost, "/netlox/v1/config/cert", nil),
			Attr:        &models.Cert{CertID: &id, Usage: &usage, CertPem: &bundle, KeyPem: keyPEM},
		}, nil)
		switch r := res.(type) {
		case *operations.PostConfigCertCreated:
			return http.StatusCreated
		case *operations.PostConfigCertConflict:
			return int(r.Payload.Code)
		default:
			return 0
		}
	}

	// An incomplete directory may still hold pre-existing private material.
	partial := filepath.Join(dir, "duplicate-partial")
	if err := os.Mkdir(partial, 0700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(partial, "server.key")
	if err := os.WriteFile(key, []byte("existing key"), 0600); err != nil {
		t.Fatal(err)
	}
	attemptedKey := "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
	if code := post("duplicate-partial", cmn.CertUsageServer, &attemptedKey); code != http.StatusConflict {
		t.Fatalf("existing partial directory returned %d, want 409", code)
	}
	if got, err := os.ReadFile(key); err != nil || string(got) != "existing key" {
		t.Fatalf("existing key changed: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan int, 8)
	start := make(chan struct{})
	for range cap(results) {
		wg.Go(func() {
			<-start
			results <- post("duplicate-race", cmn.CertUsageCA, nil)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	created := 0
	for code := range results {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
		default:
			t.Fatalf("unexpected POST result %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("created %d times, want 1", created)
	}
	got, err := os.ReadFile(filepath.Join(dir, "duplicate-race", "ca.crt"))
	if err != nil || string(got) != bundle {
		t.Fatalf("winning certificate changed: %v", err)
	}
}
