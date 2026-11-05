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

// cert.go — Plan 07 ( residual, -10..13/16): the certId TLS-material
// management surface. The CANONICAL store for all TLS material (frontend certs, backend
// client certs, CA bundles, CRLs) referenced by a short opaque certId.
//
//	POST   /config/cert            — upload inline PEM under a (server-minted-if-absent) certId
//	PUT    /config/cert/{certId}    — atomic zero-downtime rotation under a STABLE certId
//	DELETE /config/cert/{certId}    — remove the managed material + SNI registration
//	GET    /config/cert[/{certId}]  — round-trip the metadata (id + derived hostnames)
//
// The handler persists the inline PEM to PROXY_SSL_CERTID_DIR/<certId>/ with restrictive
// permissions (0700 dir, 0600 key — -KAR, the in-scope key-at-rest mitigation;
// encryption-at-rest is DEFERRED per CONTEXT), then drives the 77-02 C registry
// (proxy_register_cert / proxy_rotate_cert / proxy_delete_cert) which auto-derives the
// hostnames from the leaf SAN/CN and registers them into the proven hostname-keyed
// SNI store. Selection at handshake stays by hostname (the SNI callback is unchanged); certId
// is purely the management handle.
//
// validateCert / certFromModel / serializeCert are PURE (no CGO, no disk) so the 77-01
// cert_test.go RED scaffold turns GREEN WITHOUT the go-swagger regen (the same deferred-regen
// idiom l7policy.go uses): the generated operations.*/models.Cert types come from `make build`
// on the AWS runner, but the validation/convert invariants are provable independently.
package handler

/*
#cgo CFLAGS: -I./../../../loxilb-ebpf/libbpf/src/ -I./../../../loxilb-ebpf/common -I./../../../loxilb-ebpf/kernel
#cgo LDFLAGS: -L. -L/lib64 -L./../../../loxilb-ebpf/kernel -L./../../../loxilb-ebpf/libbpf/src/build/usr/lib64/ -Wl,-rpath=/lib64/ -l:libloxilbdp.a -l:libbpf.a -lelf -lz -lssl -lcrypto -lnghttp2
#include <stdlib.h>
#include "loxilb_libdp.h"
#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_ssl.h"
*/
import "C"
import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/go-openapi/runtime/middleware"
	"github.com/google/uuid"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// certManagedDir mirrors PROXY_SSL_CERTID_DIR (sockproxy_ssl.h) — the managed dir the C
// registry loads from. The handler persists PEM here BEFORE calling the registry.
var certManagedDir = cmn.CertManagedDir

// File/permission constants — : the private key is the secret-at-rest, so the dir
// is 0700 (owner-only) and the key file is 0600. The cert/chain are public material (0644).
const (
	certDirPerm  os.FileMode = 0o700
	certKeyPerm  os.FileMode = 0o600
	certFilePerm os.FileMode = 0o644
)

// certIDMax mirrors the C CERTID_MAX (sockproxy_ssl.h) — the opaque handle bound.
const certIDMax = cmn.CertIDMax

// certStore is the in-memory certId registry metadata mirror (id -> CertArg). The C registry
// holds the SNI-store binding + derived hostnames; this Go store carries the management-side
// metadata for GET round-trip. Guarded by certStoreMu (REST handlers run concurrently).
var (
	certStore   = map[string]*cmn.CertArg{}
	certStoreMu sync.RWMutex
	// Serialize certificate writers across the filesystem, C registry and metadata.
	certMutationMu sync.Mutex
)

// validateCert enforces upload contract (PURE — no disk, no CGO):
//   - certId is required (the management handle) and bounded (<= certIDMax-1).
//   - cert PEM and key PEM are required and non-empty.
//   - the cert PEM TRY-PARSES to a real X.509 certificate (malformed PEM / missing key ⇒ 400,
//     never a panic); only well-formed material is allowed to reach the managed dir + registry.
//
// It returns a non-nil error describing the FIRST violation (the handler maps that to a 400).
func validateCert(c *cmn.CertArg) error {
	if c == nil {
		return fmt.Errorf("cert: nil body")
	}
	if err := validateCertID(c.CertId); err != nil {
		return err
	}
	usage, err := certUsageOf(c)
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.CertPEM) == "" {
		return fmt.Errorf("cert: certPem is required")
	}
	// Structural PEM-armor validation: the cert PEM must carry a CERTIFICATE
	// armor and the key PEM a key armor (BEGIN/END markers). The deep X.509 /
	// key parse is OpenSSL's when the material is loaded.
	if !pemHasArmor(c.CertPEM, "CERTIFICATE") {
		return fmt.Errorf("cert: certPem is not a PEM CERTIFICATE (missing BEGIN/END CERTIFICATE armor)")
	}
	if usage == cmn.CertUsageCA {
		// A CA bundle is certificates only. A private key sent with one is a
		// mistake worth refusing: it would be a CA key at rest for no purpose.
		if strings.TrimSpace(c.KeyPEM) != "" {
			return fmt.Errorf("cert: keyPem must be empty for usage %q, a CA bundle holds no private key", usage)
		}
		return certBundleParses(c.CertPEM + "\n" + c.ChainPEM)
	}
	if strings.TrimSpace(c.KeyPEM) == "" {
		return fmt.Errorf("cert: keyPem is required")
	}
	if !pemHasArmor(c.KeyPEM, "PRIVATE KEY") && !pemHasArmor(c.KeyPEM, "RSA PRIVATE KEY") &&
		!pemHasArmor(c.KeyPEM, "EC PRIVATE KEY") {
		return fmt.Errorf("cert: keyPem is not a PEM private key (missing BEGIN/END *PRIVATE KEY armor)")
	}
	if usage == cmn.CertUsageClient {
		// Nothing else parses a client pair before a rule uses it, so a pair
		// that does not match is refused here and not at the first rule.
		if _, err := tls.X509KeyPair([]byte(certWithChain(c)), []byte(c.KeyPEM)); err != nil {
			return fmt.Errorf("cert: certPem and keyPem are not a usable pair: %v", err)
		}
	}
	return nil
}

// certRefusal is the body of a request this handler refuses for a reason the
// caller can act on: the material does not validate, the ID is taken or in
// use, a rotation was stored and not taken up. The sentence is written here
// for the caller, so it is the answer, whatever its wording.
func certRefusal(err error) *models.Error {
	return ResultErrorResponseError(&cmn.ValidationError{Err: err})
}

// certUsageOf returns the usage of an entry, "server" when none is given.
func certUsageOf(c *cmn.CertArg) (string, error) {
	switch c.Usage {
	case "", cmn.CertUsageServer:
		return cmn.CertUsageServer, nil
	case cmn.CertUsageCA, cmn.CertUsageClient:
		return c.Usage, nil
	}
	return "", fmt.Errorf("cert: usage must be one of %q, %q, %q", cmn.CertUsageServer, cmn.CertUsageCA, cmn.CertUsageClient)
}

// certBundleParses requires every PEM block of a CA bundle to be a
// certificate that parses, and at least one of them.
func certBundleParses(bundle string) error {
	rest := []byte(bundle)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("cert: a CA bundle holds certificates only, found a %q block", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("cert: certificate %d of the CA bundle does not parse: %v", n+1, err)
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("cert: the CA bundle holds no certificate")
	}
	return nil
}

func certWithChain(c *cmn.CertArg) string {
	crt := c.CertPEM
	if strings.TrimSpace(c.ChainPEM) != "" {
		if !strings.HasSuffix(crt, "\n") {
			crt += "\n"
		}
		crt += c.ChainPEM
	}
	return crt
}

// validateCertID enforces the certId contract everywhere an id reaches a
// filesystem path (upload, delete-reconcile, restore apply): required,
// bounded (< certIDMax, the C registry handle bound), and free of
// path-traversal / separator bytes so a crafted id cannot escape
// PROXY_SSL_CERTID_DIR.
func validateCertID(id string) error {
	return cmn.ValidateCertID(id)
}

// pemHasArmor reports whether s carries a "-----BEGIN <kind>-----" / "-----END <kind>-----"
// PEM armor pair (case-sensitive on the kind, which PEM mandates upper-case). Pure structural
// check — no base64/ASN.1 decode (the authoritative parse is OpenSSL's at load time).
func pemHasArmor(s, kind string) bool {
	return strings.Contains(s, "-----BEGIN "+kind+"-----") &&
		strings.Contains(s, "-----END "+kind+"-----")
}

// certPersist prepares the managed directory for rotation and replaces its material.
func certPersist(c *cmn.CertArg) error {
	dir := filepath.Join(certManagedDir, c.CertId)
	if err := os.MkdirAll(dir, certDirPerm); err != nil {
		return fmt.Errorf("cert: failed to create managed dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, certDirPerm); err != nil {
		return fmt.Errorf("cert: failed to chmod managed dir %s: %w", dir, err)
	}
	return certWriteMaterial(c, dir)
}

// certWriteMaterial writes the leaf and optional chain in the C loader's layout.
func certWriteMaterial(c *cmn.CertArg, dir string) error {
	usage, err := certUsageOf(c)
	if err != nil {
		return err
	}
	crtName, keyName := cmn.CertUsageFiles(usage)
	if err := certWriteFile(filepath.Join(dir, crtName), []byte(certWithChain(c)), certFilePerm); err != nil {
		return fmt.Errorf("cert: failed to write %s: %w", crtName, err)
	}
	if keyName != "" {
		if err := certWriteFile(filepath.Join(dir, keyName), []byte(c.KeyPEM), certKeyPerm); err != nil {
			return fmt.Errorf("cert: failed to write %s: %w", keyName, err)
		}
	}
	return nil
}

// certWriteFile replaces a file by writing a new one beside it and renaming
// it into place: a reader sees the old content or the new, never part of
// either, and the replaced file is a different file to whoever compares.
func certWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// certRegister drives the 77-02 C registry: proxy_register_cert reads server.crt/server.key
// from the managed dir, auto-derives the hostname(s) from the leaf SAN/CN, and
// registers each into the SNI store. Returns the number of hostnames registered (>=1) or a
// negative errno mapped to a Go error.
func certRegister(certId string) (int, error) {
	cID := C.CString(certId)
	defer C.free(unsafe.Pointer(cID))
	ret := int(C.proxy_register_cert(cID))
	if ret < 0 {
		return 0, fmt.Errorf("cert: proxy_register_cert(%s) failed: %w", certId, syscall.Errno(-ret))
	}
	return ret, nil
}

// certRotate drives proxy_rotate_cert — atomic zero-downtime swap of the (already re-persisted)
// material under the stable certId. In-flight connections keep the old SSL_CTX.
func certRotate(certId string) error {
	cID := C.CString(certId)
	defer C.free(unsafe.Pointer(cID))
	if ret := int(C.proxy_rotate_cert(cID)); ret != 0 {
		return fmt.Errorf("cert: proxy_rotate_cert(%s) failed: %d", certId, ret)
	}
	return nil
}

// certDelete drives proxy_delete_cert — unregister the derived hostnames from the SNI store
// and free the registry entry.
func certDelete(certId string) error {
	cID := C.CString(certId)
	defer C.free(unsafe.Pointer(cID))
	if ret := int(C.proxy_delete_cert(cID)); ret != 0 {
		return fmt.Errorf("cert: proxy_delete_cert(%s) failed: %d", certId, ret)
	}
	return nil
}

// certManagedDirRemove cleans the persisted material after a successful registry delete.
func certManagedDirRemove(certId string) {
	_ = os.RemoveAll(filepath.Join(certManagedDir, certId))
}

// --- model <-> cmn conversion (deferred-regen: models.* come from `make build`) ----------

// certFromModel converts the inbound generated model into the cmn CertArg (PURE).
func certFromModel(m *models.Cert) *cmn.CertArg {
	if m == nil {
		return &cmn.CertArg{}
	}
	return &cmn.CertArg{
		CertId:   l7Str(m.CertID),
		CertPEM:  l7Str(m.CertPem),
		KeyPEM:   l7Str(m.KeyPem),
		ChainPEM: m.ChainPem,
		Usage:    l7Str(m.Usage),
	}
}

// serializeCert converts a stored CertArg back to the generated model for GET (PURE). The
// private key is NEVER serialized back out (write-only secret); only the id + derived
// hostnames (and the public cert/chain) round-trip.
func serializeCert(c *cmn.CertArg) *models.Cert {
	if c == nil {
		return &models.Cert{}
	}
	return &models.Cert{
		CertID:    l7Ptr(c.CertId),
		CertPem:   l7Ptr(c.CertPEM),
		ChainPem:  c.ChainPEM,
		Usage:     l7Ptr(certUsageStored(c)),
		Hostnames: append([]string(nil), c.Hostnames...),
	}
}

// certUsageStored returns the usage of a stored entry; an entry stored before
// usages existed is a server certificate.
func certUsageStored(c *cmn.CertArg) string {
	if c == nil || c.Usage == "" {
		return cmn.CertUsageServer
	}
	return c.Usage
}

// certStoreBackend records a CA or client entry. The key is on disk only.
func certStoreBackend(cert *cmn.CertArg) {
	stored := *cert
	stored.KeyPEM = ""
	certStoreMu.Lock()
	certStore[cert.CertId] = &stored
	certStoreMu.Unlock()
}

// certInUse names the first load-balancer rule that refers to a certificate
// ID for its backend leg, or returns "". An instance that runs goBGP only has
// no rules, so nothing refers to the ID there; any other failure to read the
// rules is returned, because "no rule refers to it" is then not known.
func certInUse(certId string) (string, error) {
	if ApiHooks == nil {
		return "", nil
	}
	rules, err := ApiHooks.NetLbRuleGet()
	if errors.Is(err, cmn.ErrBgpOnlyMode) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for i := range rules {
		serv := &rules[i].Serv
		if serv.BackendCaCertId == certId || serv.BackendClientCertId == certId {
			return fmt.Sprintf("%s:%d/%s", serv.ServIP, serv.ServPort, serv.Proto), nil
		}
	}
	return "", nil
}

// certRefreshRules has the rules that refer to a certificate ID pushed again
// after its material was replaced. It returns how many were pushed and names
// the ones whose listener kept its previous context. An instance that runs
// goBGP only has no rules to push; any other failure is returned, because the
// rules may still be serving the replaced material.
func certRefreshRules(certId string) (int, []string, error) {
	if ApiHooks == nil {
		return 0, nil, nil
	}
	pushed, kept, err := ApiHooks.NetLbBackendCertRefresh(certId)
	if errors.Is(err, cmn.ErrBgpOnlyMode) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return pushed, kept, nil
}

// certHookFailure is the body of a certificate request that could not be
// completed because the load-balancer rules could not be consulted. The
// sentence is the handler's own; the cause goes to the log.
func certHookFailure(result string) *models.Error {
	return &models.Error{Code: 500, Message: "Internal service error", Result: result}
}

// --- CRUD handlers (deferred-regen: generated op types come from `make build`) -----------

// ConfigPostCert uploads inline PEM under a certId: validates (malformed PEM ⇒ 400), persists
// to the managed dir (0700/0600), and registers via the 77-02 C registry (auto-derive SAN/CN
// hostnames ⇒ SNI store). When certId is absent the server mints one.
func ConfigPostCert(params operations.PostConfigCertParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Cert %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	if params.Attr == nil {
		return operations.NewPostConfigCertBadRequest().WithPayload(certRefusal(fmt.Errorf("cert: empty body")))
	}
	cert := certFromModel(params.Attr)
	if cert.CertId == "" {
		// Server-minted stable id: a UUID, never a store-length counter
		// (len+1 collides with a surviving id after any deletion, and the
		// id doubles as the managed directory name).
		cert.CertId = uuid.NewString()
	}

	if err := validateCert(cert); err != nil {
		tk.LogIt(tk.LogDebug, "api: cert validation failed: %v\n", err)
		return operations.NewPostConfigCertBadRequest().WithPayload(certRefusal(err))
	}

	cert.Usage, _ = certUsageOf(cert)
	certMutationMu.Lock()
	defer certMutationMu.Unlock()

	certStoreMu.RLock()
	_, known := certStore[cert.CertId]
	certStoreMu.RUnlock()
	if known {
		return certCreateConflict(cert.CertId, "is registered; use PUT to rotate it")
	}

	dir := filepath.Join(certManagedDir, cert.CertId)
	if err := os.MkdirAll(certManagedDir, certDirPerm); err != nil {
		tk.LogIt(tk.LogError, "api: cert parent directory: %v\n", err)
		return operations.NewPostConfigCertInternalServerError().WithPayload(ResultErrorResponseError(err))
	}
	// Claim a fresh directory. Even a partial or unregistered entry belongs
	// to its existing owner and must survive a duplicate create.
	if err := os.Mkdir(dir, certDirPerm); err != nil {
		if errors.Is(err, os.ErrExist) {
			return certCreateConflict(cert.CertId, "has unregistered material on disk; restore a matching snapshot to re-register it, or DELETE the ID before uploading again")
		}
		tk.LogIt(tk.LogError, "api: cert directory: %v\n", err)
		return operations.NewPostConfigCertInternalServerError().WithPayload(ResultErrorResponseError(err))
	}
	if err := certWriteMaterial(cert, dir); err != nil {
		tk.LogIt(tk.LogError, "api: cert persist failed: %v\n", err)
		certManagedDirRemove(cert.CertId)
		return operations.NewPostConfigCertInternalServerError().WithPayload(ResultErrorResponseError(err))
	}

	if cert.Usage != cmn.CertUsageServer {
		// Backend material is not a listener certificate: it is never offered
		// by SNI, so it does not enter the SNI registry.
		certStoreBackend(cert)
		tk.LogIt(tk.LogInfo, "api: Cert %s uploaded (usage %s)\n", cert.CertId, cert.Usage)
		return operations.NewPostConfigCertCreated().WithPayload(&models.CertCreated{CertID: &cert.CertId})
	}

	n, err := certRegister(cert.CertId)
	if err != nil {
		tk.LogIt(tk.LogError, "api: cert register failed: %v\n", err)
		certManagedDirRemove(cert.CertId)
		if errors.Is(err, syscall.EEXIST) {
			return certCreateConflict(cert.CertId, "exists in the datapath registry without management metadata; restart the gateway to clear the stale registration before retrying")
		}
		return operations.NewPostConfigCertBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	cert.Hostnames = certListHostnames(cert.CertId)
	certStoreMu.Lock()
	certStore[cert.CertId] = cert
	certStoreMu.Unlock()

	tk.LogIt(tk.LogInfo, "api: Cert %s uploaded (%d hostname(s) registered)\n", cert.CertId, n)
	return operations.NewPostConfigCertCreated().WithPayload(&models.CertCreated{CertID: &cert.CertId})
}

func certCreateConflict(id, reason string) middleware.Responder {
	message := fmt.Sprintf("certId %q %s", id, reason)
	return operations.NewPostConfigCertConflict().WithPayload(&models.Error{
		Code:    http.StatusConflict,
		Message: message,
		Result:  message,
	})
}

// ConfigPutCert rotates the material under a STABLE certId (atomic swap). Unknown
// certId ⇒ 404; malformed material ⇒ 400.
func ConfigPutCert(params operations.PutConfigCertCertIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Cert %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	certMutationMu.Lock()
	defer certMutationMu.Unlock()

	certStoreMu.RLock()
	prev, known := certStore[params.CertID]
	certStoreMu.RUnlock()
	if !known {
		return operations.NewPutConfigCertCertIDNotFound()
	}
	if params.Attr == nil {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(certRefusal(fmt.Errorf("cert: empty body")))
	}

	cert := certFromModel(params.Attr)
	// The path certId is authoritative — rotation never re-keys (the handle is stable).
	cert.CertId = params.CertID
	// The usage of an ID is fixed when it is created: rules refer to it as a
	// CA or as a client certificate, and a rotation must not change which.
	if cert.Usage != "" && cert.Usage != certUsageStored(prev) {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(certRefusal(
			fmt.Errorf("cert: certId %q has usage %q, a rotation cannot change it", params.CertID, certUsageStored(prev))))
	}
	cert.Usage = certUsageStored(prev)
	if err := validateCert(cert); err != nil {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(certRefusal(err))
	}
	if err := certPersist(cert); err != nil {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}
	if cert.Usage != cmn.CertUsageServer {
		certStoreBackend(cert)
		// The rules that refer to the ID are pushed again: a listener
		// rebuilds its backend context when the files behind its certificate
		// IDs are no longer the ones the context was built from. One that
		// cannot load the new material keeps the context it has, and the
		// caller is told, because the material is stored either way.
		pushed, kept, err := certRefreshRules(cert.CertId)
		if err != nil {
			tk.LogIt(tk.LogError, "api: Cert %s rotated (usage %s), rule refresh failed: %v\n", cert.CertId, cert.Usage, err)
			return operations.NewPutConfigCertCertIDInternalServerError().WithPayload(certHookFailure(fmt.Sprintf(
				"cert: certId %q is stored, but the rules that refer to it could not be pushed again; "+
					"they keep the previous material until the certificate is written again", cert.CertId)))
		}
		tk.LogIt(tk.LogInfo, "api: Cert %s rotated (usage %s, %d rule(s) pushed, %d kept the previous context)\n",
			cert.CertId, cert.Usage, pushed, len(kept))
		if len(kept) != 0 {
			return operations.NewPutConfigCertCertIDBadRequest().WithPayload(certRefusal(fmt.Errorf(
				"cert: certId %q is stored, but the data plane could not load it for %s; "+
					"those rules keep the previous material until the certificate is written again",
				cert.CertId, strings.Join(kept, ", "))))
		}
		return operations.NewPutConfigCertCertIDOK()
	}
	if err := certRotate(cert.CertId); err != nil {
		tk.LogIt(tk.LogError, "api: cert rotate failed: %v\n", err)
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	cert.Hostnames = certListHostnames(cert.CertId)
	certStoreMu.Lock()
	certStore[cert.CertId] = cert
	certStoreMu.Unlock()

	tk.LogIt(tk.LogInfo, "api: Cert %s rotated (atomic zero-downtime swap)\n", cert.CertId)
	return operations.NewPutConfigCertCertIDOK()
}

// ConfigDeleteCert removes the managed material + SNI registration. The
// delete reconciles ALL three places a certId can live -- the in-memory
// store, the C SNI registry, and the managed on-disk directory -- so
// material orphaned by a crash or an un-reconciled boot is still
// deletable via the API instead of requiring shell access to the node
// (an on-disk private key the API can neither serve nor remove is the
// worst of both worlds). 404 only when NO trace of the id exists.
func ConfigDeleteCert(params operations.DeleteConfigCertCertIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Cert %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	// The certId reaches filesystem paths below -- hold it to the same
	// traversal rules as upload before touching anything.
	if err := validateCertID(params.CertID); err != nil {
		return operations.NewDeleteConfigCertCertIDBadRequest().WithPayload(certRefusal(err))
	}

	certMutationMu.Lock()
	defer certMutationMu.Unlock()

	certStoreMu.RLock()
	_, known := certStore[params.CertID]
	certStoreMu.RUnlock()
	dirExists := false
	if fi, err := os.Stat(filepath.Join(certManagedDir, params.CertID)); err == nil && fi.IsDir() {
		dirExists = true
	}
	if !known && !dirExists {
		return operations.NewDeleteConfigCertCertIDNotFound()
	}
	rule, err := certInUse(params.CertID)
	if err != nil {
		tk.LogIt(tk.LogError, "api: cert delete refused, rules unreadable: %v\n", err)
		return operations.NewDeleteConfigCertCertIDInternalServerError().WithPayload(certHookFailure(fmt.Sprintf(
			"cert: could not read the load-balancer rules to check whether certId %q is in use; nothing was deleted", params.CertID)))
	}
	if rule != "" {
		return operations.NewDeleteConfigCertCertIDBadRequest().WithPayload(certRefusal(
			fmt.Errorf("cert: certId %q is used by load-balancer rule %s for its backend leg; remove it from the rule first", params.CertID, rule)))
	}

	// Unregister from the SNI store; a registry that never heard of the
	// id (orphaned disk material after an unclean boot) is exactly the
	// state this delete reconciles, not an error.
	if err := certDelete(params.CertID); err != nil && !certErrIsNotFound(err) {
		tk.LogIt(tk.LogError, "api: cert delete failed: %v\n", err)
		return operations.NewDeleteConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}
	certManagedDirRemove(params.CertID)

	certStoreMu.Lock()
	delete(certStore, params.CertID)
	certStoreMu.Unlock()

	tk.LogIt(tk.LogInfo, "api: Cert %s deleted\n", params.CertID)
	return operations.NewDeleteConfigCertCertIDNoContent()
}

// ConfigGetCert returns a single certId's metadata (404 on miss). The private key is never
// returned (serializeCert omits it).
func ConfigGetCert(params operations.GetConfigCertCertIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Cert %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	certStoreMu.RLock()
	cert, ok := certStore[params.CertID]
	certStoreMu.RUnlock()
	if !ok || cert == nil {
		return operations.NewGetConfigCertCertIDNotFound()
	}
	return operations.NewGetConfigCertCertIDOK().WithPayload(serializeCert(cert))
}

// certListHostnames returns the hostnames the certId resolved to. The 77-02 registry derives
// them internally; the Go side re-reads them from the leaf cert it just persisted so the GET
// round-trip reflects what was registered (best-effort — a parse failure yields no hostnames,
// never a panic, since validateCert already proved the cert parses).
func certListHostnames(certId string) []string {
	certStoreMu.RLock()
	c := certStore[certId]
	certStoreMu.RUnlock()
	if c != nil && certUsageStored(c) != cmn.CertUsageServer {
		return nil
	}
	var pemBytes []byte
	if c != nil && c.CertPEM != "" {
		pemBytes = []byte(c.CertPEM)
	} else {
		pemBytes, _ = os.ReadFile(filepath.Join(certManagedDir, certId, "server.crt"))
	}
	if len(pemBytes) == 0 {
		return nil
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	if len(crt.DNSNames) > 0 {
		return append([]string(nil), crt.DNSNames...)
	}
	if cn := strings.TrimSpace(crt.Subject.CommonName); cn != "" {
		return []string{cn}
	}
	return nil
}

// ---------------------------------------------------------------------
// Config-persistence surface (the snapshot "cert" domain, reached via the
// NetCertGet/Add/Del hooks in pkg/loxinet) + the boot reconcile.
//
// Secret split: PEM material (above all the private key) never enters the
// snapshot document. The document carries {certId, digest} per
// certificate; the material itself lives ONLY in the managed directory
// (PROXY_SSL_CERTID_DIR/<certId>/). Restore verifies the on-disk material
// against the captured digest before re-registering -- a gateway must
// never come up silently serving DIFFERENT TLS material than its desired
// state declares, and a node missing the material fails the domain loudly
// (keys are re-provisioned, never invented).
// ---------------------------------------------------------------------

// certErrIsNotFound reports whether a C-registry error is the "certId not
// registered" errno (-ENOENT = -2) -- the state the delete/wipe reconcile
// paths tolerate.
func certErrIsNotFound(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), ": -2")
}

// certDiskDigest hashes the managed material exactly as persisted:
// sha256 over server.crt bytes followed by server.key bytes.
func certDiskDigest(certId string) (string, error) {
	dir := filepath.Join(certManagedDir, certId)
	usage := cmn.CertDiskUsage(certId)
	if usage == "" {
		usage = cmn.CertUsageServer
	}
	crtName, keyName := cmn.CertUsageFiles(usage)
	crt, err := os.ReadFile(filepath.Join(dir, crtName))
	if err != nil {
		return "", fmt.Errorf("cert %s: read %s: %w", certId, crtName, err)
	}
	h := sha256.New()
	h.Write(crt)
	if keyName != "" {
		key, err := os.ReadFile(filepath.Join(dir, keyName))
		if err != nil {
			return "", fmt.Errorf("cert %s: read %s: %w", certId, keyName, err)
		}
		h.Write(key)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// CertExportMetas returns every registered certificate as desired-state
// metadata (sorted by id), digesting the managed material from disk. A
// store entry whose material cannot be read is a loud capture error --
// it means the registry and the disk have diverged, which a snapshot
// must surface, not paper over.
func CertExportMetas() ([]cmn.CertMeta, error) {
	certStoreMu.RLock()
	ids := make([]string, 0, len(certStore))
	for id := range certStore {
		ids = append(ids, id)
	}
	certStoreMu.RUnlock()
	sort.Strings(ids)
	out := make([]cmn.CertMeta, 0, len(ids))
	for _, id := range ids {
		digest, err := certDiskDigest(id)
		if err != nil {
			return nil, err
		}
		out = append(out, cmn.CertMeta{CertId: id, Digest: digest})
	}
	return out, nil
}

// CertApplyMeta re-registers one certificate from the managed directory
// after verifying the on-disk material matches the captured digest.
// Identity semantics match the other restore intakes: a byte-identical
// re-apply is the idempotent "cert-exists error" no-op; the same id with
// divergent material is a fatal conflict.
func CertApplyMeta(meta *cmn.CertMeta) error {
	if meta == nil {
		return fmt.Errorf("cert: nil meta")
	}
	if err := validateCertID(meta.CertId); err != nil {
		return err
	}

	certMutationMu.Lock()
	defer certMutationMu.Unlock()

	digest, err := certDiskDigest(meta.CertId)
	if err != nil {
		return fmt.Errorf("cert %s: managed material missing on this node (re-provision it, key material never rides the snapshot): %w", meta.CertId, err)
	}
	if digest != meta.Digest {
		return fmt.Errorf("cert-exist error: cant apply %s -- managed material on disk diverges from the captured digest", meta.CertId)
	}

	certStoreMu.RLock()
	_, known := certStore[meta.CertId]
	certStoreMu.RUnlock()
	if known {
		// Digest already proven equal: identical re-apply (boot retry).
		return fmt.Errorf("cert-exists error")
	}

	if cmn.CertDiskUsage(meta.CertId) == cmn.CertUsageServer {
		if _, err := certRegister(meta.CertId); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("cert %s: register: %w", meta.CertId, err)
		}
	}
	certAdoptFromDisk(meta.CertId)
	tk.LogIt(tk.LogInfo, "api: Cert %s re-registered from managed material (restore)\n", meta.CertId)
	return nil
}

// CertWipeRegistration unregisters one certificate (SNI store + metadata)
// while KEEPING the managed on-disk material: a wipe removes desired
// state, not node secret material, and the apply that follows a wipe must
// still be able to re-register the material by digest. The API DELETE is
// the operation that removes material.
func CertWipeRegistration(id string) error {
	if err := validateCertID(id); err != nil {
		return err
	}
	certMutationMu.Lock()
	defer certMutationMu.Unlock()

	if err := certDelete(id); err != nil && !certErrIsNotFound(err) {
		return err
	}
	certStoreMu.Lock()
	delete(certStore, id)
	certStoreMu.Unlock()
	return nil
}

// certAdoptFromDisk rebuilds the in-memory metadata entry for a certId
// from the managed directory (server.crt; the key is never held in
// memory on this path -- it is write-only secret material).
func certAdoptFromDisk(certId string) {
	usage := cmn.CertDiskUsage(certId)
	crtName, _ := cmn.CertUsageFiles(usage)
	if crtName == "" {
		return
	}
	crt, err := os.ReadFile(filepath.Join(certManagedDir, certId, crtName))
	if err != nil {
		return
	}
	entry := &cmn.CertArg{CertId: certId, CertPEM: string(crt), Usage: usage}
	certStoreMu.Lock()
	certStore[certId] = entry
	certStoreMu.Unlock()
	entry.Hostnames = certListHostnames(certId)
}

// CertBootReconcile re-registers every certificate found in the managed
// directory at boot. Before this existed, a reboot orphaned all managed
// material: the SNI store came up empty (every TLS handshake dead until
// each cert was re-POSTed) while the material sat on disk invisible to
// the API. Runs before the boot snapshot replay, so a replay that
// declares certs finds them already registered and skips them as
// idempotent. Per-entry failures are logged and skipped -- one corrupt
// directory must not keep every other certificate down.
func CertBootReconcile() int {
	certMutationMu.Lock()
	defer certMutationMu.Unlock()

	entries, err := os.ReadDir(certManagedDir)
	if err != nil {
		if !os.IsNotExist(err) {
			tk.LogIt(tk.LogWarning, "api: cert boot reconcile: read %s: %v\n", certManagedDir, err)
		}
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if err := validateCertID(id); err != nil {
			tk.LogIt(tk.LogWarning, "api: cert boot reconcile: skip %q: %v\n", id, err)
			continue
		}
		usage := cmn.CertDiskUsage(id)
		if usage == "" {
			continue
		}
		if usage == cmn.CertUsageServer {
			if _, err := certRegister(id); err != nil && !errors.Is(err, syscall.EEXIST) {
				tk.LogIt(tk.LogError, "api: cert boot reconcile: register %s failed: %v\n", id, err)
				continue
			}
		}
		certAdoptFromDisk(id)
		n++
	}
	if n > 0 {
		tk.LogIt(tk.LogInfo, "api: cert boot reconcile: %d certificate(s) re-registered from %s\n", n, certManagedDir)
	}
	return n
}
