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

package snapshot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Secret material inside a snapshot document (IPsec pre-shared keys,
// certificate private keys, key passphrases) is stored encrypted under a
// node-local secret, never in plaintext: a captured document must be
// storable and shippable without being a credential dump. The document
// stays self-contained for same-node recovery; restoring it on a
// DIFFERENT node requires transporting the node secret file through an
// operator-controlled channel first (deliberately out of band -- the
// snapshot file itself must never carry the key that opens it).
//
// The ciphertext is DETERMINISTIC per (node secret, plaintext): the AEAD
// nonce is derived by HMAC from the plaintext (SIV-style) rather than
// drawn at random. This is load-bearing, not an optimization -- two idle
// captures of the same configuration must encode byte-identically
// (capture determinism, the digest VERIFY, and the roundtrip suite's
// idle-identical legs all depend on it). Nonce reuse across DIFFERENT
// plaintexts cannot happen (HMAC collision resistance); equal plaintexts
// intentionally produce equal ciphertexts, which only reveals equality --
// exactly what the deterministic-capture contract already requires.
const (
	// secretValuePrefix marks an encrypted secret value; everything after
	// it is base64(nonce || AES-256-GCM ciphertext).
	secretValuePrefix = "enc:v1:"
	// NodeSecretFileName is the basename of the node-local secret inside
	// the gateway's ConfigPath, hex-encoded, 0600. It deliberately lives
	// in the SAME directory as snapshot.json so the two persist (or
	// perish) together: a containerized gateway that host-mounts
	// ConfigPath -- the documented pattern for persistent deployments --
	// keeps both across container recreation, and one that mounts nothing
	// loses both consistently instead of stranding an undecryptable
	// snapshot. Backup/DR surface is therefore the ConfigPath pair, never
	// snapshot.json alone. Rotation procedure: replace the file, then
	// immediately re-persist (POST /config/persist) so the on-disk
	// snapshot lineage is re-encrypted under the new secret -- older
	// snapshots and quarantines stay decryptable only by the old secret.
	NodeSecretFileName = "snapshot-node.secret"
	nodeSecretLen      = 32
	sivNonceLen        = 12
)

var (
	nodeSecretMu sync.RWMutex
	nodeSecret   []byte
)

// InitNodeSecret loads dir/NodeSecretFileName into the package secret,
// auto-provisioning a fresh random one (hex-encoded, 0600, atomic write)
// when the file does not exist. A present-but-corrupt file is a loud
// error, never silently re-provisioned: overwriting it would strand every
// snapshot encrypted under the real secret.
func InitNodeSecret(dir string) error {
	path := filepath.Join(dir, NodeSecretFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// First boot on a node that may not even have the config dir yet
		// (fresh install, unmounted volume): provisioning owns creating
		// it -- failing here would leave every capture fail-closed for
		// want of a mkdir.
		if merr := os.MkdirAll(dir, 0o755); merr != nil {
			return fmt.Errorf("snapshot: provision node secret: %w", merr)
		}
		raw := make([]byte, nodeSecretLen)
		if _, rerr := rand.Read(raw); rerr != nil {
			return fmt.Errorf("snapshot: provision node secret: %w", rerr)
		}
		if _, werr := writeAtomic(dir, NodeSecretFileName, []byte(hex.EncodeToString(raw)+"\n")); werr != nil {
			return fmt.Errorf("snapshot: provision node secret at %s: %w", path, werr)
		}
		setNodeSecret(raw)
		return nil
	}
	if err != nil {
		return fmt.Errorf("snapshot: read node secret at %s: %w", path, err)
	}
	raw, derr := hex.DecodeString(strings.TrimSpace(string(data)))
	if derr != nil || len(raw) != nodeSecretLen {
		return fmt.Errorf("snapshot: node secret at %s is corrupt (want %d hex-encoded bytes); restore the file from backup, or remove it to re-provision -- snapshots encrypted under the old secret then need the old file to restore", path, nodeSecretLen)
	}
	setNodeSecret(raw)
	return nil
}

func setNodeSecret(raw []byte) {
	nodeSecretMu.Lock()
	defer nodeSecretMu.Unlock()
	nodeSecret = raw
}

// SetNodeSecretForTest pins the package node secret and returns a restore
// func. Tests only -- production initialization goes through
// InitNodeSecret so the secret always lives on disk.
func SetNodeSecretForTest(raw []byte) func() {
	nodeSecretMu.Lock()
	prev := nodeSecret
	nodeSecret = raw
	nodeSecretMu.Unlock()
	return func() { setNodeSecret(prev) }
}

// currentNodeSecret returns the initialized secret or a loud error:
// handling a secret value before InitNodeSecret ran must fail closed, not
// fall back to plaintext.
func currentNodeSecret() ([]byte, error) {
	nodeSecretMu.RLock()
	defer nodeSecretMu.RUnlock()
	if nodeSecret == nil {
		return nil, fmt.Errorf("snapshot: node secret not initialized; cannot handle encrypted secret values")
	}
	return nodeSecret, nil
}

// deriveKey returns HMAC-SHA256(secret, label): independent subkeys for
// encryption and nonce derivation from the one on-disk secret.
func deriveKey(secret []byte, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// IsEncryptedSecretValue reports whether v carries the encrypted-value
// prefix.
func IsEncryptedSecretValue(v string) bool {
	return strings.HasPrefix(v, secretValuePrefix)
}

// EncryptSecretValue returns the deterministic encrypted encoding of
// plain under the node secret. Empty values and values already carrying
// the prefix pass through unchanged (idempotent: capture may see a value
// that intake normalization already encrypted).
func EncryptSecretValue(plain string) (string, error) {
	if plain == "" || IsEncryptedSecretValue(plain) {
		return plain, nil
	}
	secret, err := currentNodeSecret()
	if err != nil {
		return "", err
	}
	sivMac := hmac.New(sha256.New, deriveKey(secret, "loxilb-snapshot-secret-siv-v1"))
	sivMac.Write([]byte(plain))
	nonce := sivMac.Sum(nil)[:sivNonceLen]

	block, err := aes.NewCipher(deriveKey(secret, "loxilb-snapshot-secret-enc-v1"))
	if err != nil {
		return "", fmt.Errorf("snapshot: encrypt secret value: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("snapshot: encrypt secret value: %w", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	return secretValuePrefix + base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// DecryptSecretValue reverses EncryptSecretValue. A value without the
// prefix returns unchanged -- plaintext from a pre-encryption document;
// intake normalization (restore.go) is what re-encrypts those, and apply
// paths must still accept them mid-migration. Error messages never
// include the value (secret-free logging).
func DecryptSecretValue(v string) (string, error) {
	if !IsEncryptedSecretValue(v) {
		return v, nil
	}
	secret, err := currentNodeSecret()
	if err != nil {
		return "", err
	}
	blob, err := base64.StdEncoding.DecodeString(v[len(secretValuePrefix):])
	if err != nil || len(blob) <= sivNonceLen {
		return "", fmt.Errorf("snapshot: malformed encrypted secret value")
	}
	block, err := aes.NewCipher(deriveKey(secret, "loxilb-snapshot-secret-enc-v1"))
	if err != nil {
		return "", fmt.Errorf("snapshot: decrypt secret value: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("snapshot: decrypt secret value: %w", err)
	}
	plain, err := gcm.Open(nil, blob[:sivNonceLen], blob[sivNonceLen:], nil)
	if err != nil {
		return "", fmt.Errorf("snapshot: cannot decrypt secret value: wrong or replaced node secret (a snapshot from another node needs that node's %s transported through an operator channel)", NodeSecretFileName)
	}
	return string(plain), nil
}
