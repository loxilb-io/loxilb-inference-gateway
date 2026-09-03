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

package common

// CertMeta is the persisted TLS certificate desired-state record (the
// snapshot "cert" domain payload). Secret split: the PEM material —
// certificate, chain and above all the PRIVATE KEY — never enters the
// snapshot document; it stays in the node-local managed certificate
// directory. The document carries only the stable certId and a content
// digest, enough for restore to verify that the material on disk is
// exactly what the document was captured against before re-registering
// it, and for VERIFY to detect drift. Restoring onto a node whose managed
// directory lacks (or diverges from) the material fails loudly — a
// gateway must never come up silently serving different TLS material
// than its desired state declares.
type CertMeta struct {
	// CertId - stable opaque management handle (also the managed
	// directory name).
	CertId string `json:"cert_id"`
	// Digest - "sha256:<hex>" over the managed material (server.crt
	// followed by server.key) as persisted on disk.
	Digest string `json:"digest"`
}
