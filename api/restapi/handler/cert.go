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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
const certManagedDir = "/etc/loxilb/certs"

// File/permission constants — : the private key is the secret-at-rest, so the dir
// is 0700 (owner-only) and the key file is 0600. The cert/chain are public material (0644).
const (
	certDirPerm  os.FileMode = 0o700
	certKeyPerm  os.FileMode = 0o600
	certFilePerm os.FileMode = 0o644
)

// certIDMax mirrors the C CERTID_MAX (sockproxy_ssl.h) — the opaque handle bound.
const certIDMax = 64

// certStore is the in-memory certId registry metadata mirror (id -> CertArg). The C registry
// holds the SNI-store binding + derived hostnames; this Go store carries the management-side
// metadata for GET round-trip. Guarded by certStoreMu (REST handlers run concurrently).
var (
	certStore   = map[string]*cmn.CertArg{}
	certStoreMu sync.RWMutex
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
	if strings.TrimSpace(c.CertPEM) == "" {
		return fmt.Errorf("cert: certPem is required")
	}
	if strings.TrimSpace(c.KeyPEM) == "" {
		return fmt.Errorf("cert: keyPem is required")
	}
	// Structural PEM-armor validation: the cert PEM must carry a CERTIFICATE
	// armor and the key PEM a key armor (BEGIN/END markers). This rejects a non-PEM / wrong-type
	// upload at config time WITHOUT a deep base64/ASN.1 parse — validateCert is a pure, regen-free
	// gate (the 77-01 RED scaffold exercises it with armored-but-truncated fixtures). The
	// AUTHORITATIVE deep X.509 / key parse is OpenSSL's at SSL_CTX load time inside the C registry
	// (faithful to the existing path-based loader); a truly malformed body there makes
	// proxy_register_cert return an error which the handler maps to 400 (no panic, no bad material
	// ever selected at handshake).
	if !pemHasArmor(c.CertPEM, "CERTIFICATE") {
		return fmt.Errorf("cert: certPem is not a PEM CERTIFICATE (missing BEGIN/END CERTIFICATE armor)")
	}
	if !pemHasArmor(c.KeyPEM, "PRIVATE KEY") && !pemHasArmor(c.KeyPEM, "RSA PRIVATE KEY") &&
		!pemHasArmor(c.KeyPEM, "EC PRIVATE KEY") {
		return fmt.Errorf("cert: keyPem is not a PEM private key (missing BEGIN/END *PRIVATE KEY armor)")
	}
	return nil
}

// validateCertID enforces the certId contract everywhere an id reaches a
// filesystem path (upload, delete-reconcile, restore apply): required,
// bounded (< certIDMax, the C registry handle bound), and free of
// path-traversal / separator bytes so a crafted id cannot escape
// PROXY_SSL_CERTID_DIR.
func validateCertID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("cert: certId is required")
	}
	if len(id) >= certIDMax {
		return fmt.Errorf("cert: certId too long (%d >= %d)", len(id), certIDMax)
	}
	if strings.ContainsAny(id, "/\\") || id == "." || id == ".." ||
		strings.Contains(id, "..") {
		return fmt.Errorf("cert: certId %q contains illegal path characters", id)
	}
	return nil
}

// pemHasArmor reports whether s carries a "-----BEGIN <kind>-----" / "-----END <kind>-----"
// PEM armor pair (case-sensitive on the kind, which PEM mandates upper-case). Pure structural
// check — no base64/ASN.1 decode (the authoritative parse is OpenSSL's at load time).
func pemHasArmor(s, kind string) bool {
	return strings.Contains(s, "-----BEGIN "+kind+"-----") &&
		strings.Contains(s, "-----END "+kind+"-----")
}

// certPersist writes the inline PEM to PROXY_SSL_CERTID_DIR/<certId>/ with restrictive
// permissions. Layout matches what the 77-02 C loader reads: server.crt +
// server.key (the chain, if present, is appended to server.crt so the existing path loader
// picks up the full chain). Returns the managed dir on success.
func certPersist(c *cmn.CertArg) (string, error) {
	dir := filepath.Join(certManagedDir, c.CertId)
	if err := os.MkdirAll(dir, certDirPerm); err != nil {
		return "", fmt.Errorf("cert: failed to create managed dir %s: %v", dir, err)
	}
	// Enforce 0700 even if MkdirAll honored a laxer umask.
	if err := os.Chmod(dir, certDirPerm); err != nil {
		return "", fmt.Errorf("cert: failed to chmod managed dir %s: %v", dir, err)
	}
	crt := c.CertPEM
	if strings.TrimSpace(c.ChainPEM) != "" {
		if !strings.HasSuffix(crt, "\n") {
			crt += "\n"
		}
		crt += c.ChainPEM
	}
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), []byte(crt), certFilePerm); err != nil {
		return "", fmt.Errorf("cert: failed to write server.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), []byte(c.KeyPEM), certKeyPerm); err != nil {
		return "", fmt.Errorf("cert: failed to write server.key: %v", err)
	}
	return dir, nil
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
		return 0, fmt.Errorf("cert: proxy_register_cert(%s) failed: %d", certId, ret)
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
		Hostnames: append([]string(nil), c.Hostnames...),
	}
}

// --- CRUD handlers (deferred-regen: generated op types come from `make build`) -----------

// ConfigPostCert uploads inline PEM under a certId: validates (malformed PEM ⇒ 400), persists
// to the managed dir (0700/0600), and registers via the 77-02 C registry (auto-derive SAN/CN
// hostnames ⇒ SNI store). When certId is absent the server mints one.
func ConfigPostCert(params operations.PostConfigCertParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Cert %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	if params.Attr == nil {
		return operations.NewPostConfigCertBadRequest().WithPayload(ResultErrorResponseErrorMessage("cert: empty body"))
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
		return operations.NewPostConfigCertBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	if _, err := certPersist(cert); err != nil {
		tk.LogIt(tk.LogError, "api: cert persist failed: %v\n", err)
		return operations.NewPostConfigCertBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	n, err := certRegister(cert.CertId)
	if err != nil {
		tk.LogIt(tk.LogError, "api: cert register failed: %v\n", err)
		certManagedDirRemove(cert.CertId)
		return operations.NewPostConfigCertBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	cert.Hostnames = certListHostnames(cert.CertId)
	certStoreMu.Lock()
	certStore[cert.CertId] = cert
	certStoreMu.Unlock()

	tk.LogIt(tk.LogInfo, "api: Cert %s uploaded (%d hostname(s) registered)\n", cert.CertId, n)
	return operations.NewPostConfigCertCreated()
}

// ConfigPutCert rotates the material under a STABLE certId (atomic swap). Unknown
// certId ⇒ 404; malformed material ⇒ 400.
func ConfigPutCert(params operations.PutConfigCertCertIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Cert %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	certStoreMu.RLock()
	_, known := certStore[params.CertID]
	certStoreMu.RUnlock()
	if !known {
		return operations.NewPutConfigCertCertIDNotFound()
	}
	if params.Attr == nil {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage("cert: empty body"))
	}

	cert := certFromModel(params.Attr)
	// The path certId is authoritative — rotation never re-keys (the handle is stable).
	cert.CertId = params.CertID
	if err := validateCert(cert); err != nil {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	if _, err := certPersist(cert); err != nil {
		return operations.NewPutConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
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
		return operations.NewDeleteConfigCertCertIDBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

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

// certErrIsExists reports whether a C-registry error is the "already
// registered" errno (-EEXIST = -17) -- the state the re-register paths
// tolerate.
func certErrIsExists(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), ": -17")
}

// certDiskDigest hashes the managed material exactly as persisted:
// sha256 over server.crt bytes followed by server.key bytes.
func certDiskDigest(certId string) (string, error) {
	dir := filepath.Join(certManagedDir, certId)
	crt, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return "", fmt.Errorf("cert %s: read server.crt: %w", certId, err)
	}
	key, err := os.ReadFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return "", fmt.Errorf("cert %s: read server.key: %w", certId, err)
	}
	h := sha256.New()
	h.Write(crt)
	h.Write(key)
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

	if _, err := certRegister(meta.CertId); err != nil && !certErrIsExists(err) {
		return fmt.Errorf("cert %s: register: %w", meta.CertId, err)
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
	crt, err := os.ReadFile(filepath.Join(certManagedDir, certId, "server.crt"))
	if err != nil {
		return
	}
	entry := &cmn.CertArg{CertId: certId, CertPEM: string(crt)}
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
		if _, err := os.Stat(filepath.Join(certManagedDir, id, "server.crt")); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(certManagedDir, id, "server.key")); err != nil {
			continue
		}
		if _, err := certRegister(id); err != nil && !certErrIsExists(err) {
			tk.LogIt(tk.LogError, "api: cert boot reconcile: register %s failed: %v\n", id, err)
			continue
		}
		certAdoptFromDisk(id)
		n++
	}
	if n > 0 {
		tk.LogIt(tk.LogInfo, "api: cert boot reconcile: %d certificate(s) re-registered from %s\n", n, certManagedDir)
	}
	return n
}
