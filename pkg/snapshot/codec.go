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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// checksumPrefix is prepended to the hex-encoded sha256 digest (§4:
// "sha256:<hex>").
const checksumPrefix = "sha256:"

// canonicalize returns the canonical JSON encoding of doc used both for
// checksumming and for the on-wire/on-disk representation. "Canonical" here
// means deterministic: Document and everything it embeds is built from
// structs and slices (no maps), so encoding/json already serializes fields
// in a fixed, struct-declaration order -- this function exists as a single
// choke point so that never changes by accident.
func canonicalize(doc *Document) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("snapshot: marshal: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; trim it so
	// ComputeChecksum is stable regardless of caller.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ComputeChecksum computes "sha256:<hex>" over the canonical JSON of doc
// with the Checksum field treated as "" (§4), without mutating doc.
func ComputeChecksum(doc *Document) (string, error) {
	if doc == nil {
		return "", fmt.Errorf("snapshot: compute checksum: nil document")
	}
	cp := *doc
	cp.Checksum = ""
	b, err := canonicalize(&cp)
	if err != nil {
		return "", fmt.Errorf("snapshot: compute checksum: %w", err)
	}
	sum := sha256.Sum256(b)
	return checksumPrefix + hex.EncodeToString(sum[:]), nil
}

// VerifyChecksum recomputes the checksum over doc (with Checksum treated as
// "") and compares it against doc.Checksum. Returns a descriptive error on
// mismatch or if doc.Checksum is unset.
func VerifyChecksum(doc *Document) error {
	if doc == nil {
		return fmt.Errorf("snapshot: verify checksum: nil document")
	}
	if doc.Checksum == "" {
		return fmt.Errorf("snapshot: verify checksum: document has no checksum")
	}
	want, err := ComputeChecksum(doc)
	if err != nil {
		return err
	}
	if want != doc.Checksum {
		return fmt.Errorf("snapshot: checksum mismatch: document reports %s, computed %s (document was tampered with or corrupted)", doc.Checksum, want)
	}
	return nil
}

// Encode finalizes doc (computing and setting doc.Checksum as a side
// effect) and returns its canonical JSON encoding (§4). Callers that need an
// unmodified copy should pass a copy in.
func Encode(doc *Document) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("snapshot: encode: nil document")
	}
	sum, err := ComputeChecksum(doc)
	if err != nil {
		return nil, err
	}
	doc.Checksum = sum
	b, err := canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("snapshot: encode: %w", err)
	}
	return b, nil
}

// Decode strictly parses a snapshot document from r: unknown fields are
// rejected (json.Decoder.DisallowUnknownFields), per §4.2 ("Parsing is
// strict ... so schema drift fails loudly at validate stage, not silently at
// apply stage"). Decode does NOT verify the checksum or the schema_version
// compatibility gate -- callers (the restore engine's PARSE/VALIDATE stages,
// task G-2) call VerifyChecksum and CheckSchemaVersion explicitly, so each
// failure mode is independently attributable.
func Decode(r io.Reader) (*Document, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("snapshot: decode: %w", err)
	}
	// A JSON document can (validly, per encoding/json) contain trailing
	// tokens after the top-level object only if it's a stream of multiple
	// values; a snapshot document is a single value, so reject that too --
	// it usually indicates truncation/concatenation bugs upstream.
	if dec.More() {
		return nil, fmt.Errorf("snapshot: decode: unexpected trailing data after document")
	}
	return &doc, nil
}

// ParseSchemaVersion parses a "major.minor" (or "major.minor.patch", patch
// ignored) semver-ish string as used by Document.SchemaVersion.
func ParseSchemaVersion(v string) (major, minor int, err error) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("snapshot: malformed schema_version %q (want major.minor)", v)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("snapshot: malformed schema_version %q: %w", v, err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("snapshot: malformed schema_version %q: %w", v, err)
	}
	return major, minor, nil
}

// CheckSchemaVersion implements the §4.2 compatibility gate against
// SchemaVersion (the version this build of the gateway understands):
//
//   - different major  -> refused (breaking format change)
//   - same major, docMinor > current minor -> refused (newer additive
//     fields this build doesn't know about)
//   - same major, docMinor <= current minor -> accepted (older minor is
//     fine; its additive fields are simply absent)
func CheckSchemaVersion(docVersion string) error {
	return checkSchemaVersionAgainst(docVersion, SchemaVersion)
}

// checkSchemaVersionAgainst is CheckSchemaVersion's logic parameterized over
// the "current" version, split out so unit tests can exercise the full gate
// matrix (older minor / newer minor / newer major / different major)
// without being limited to whatever SchemaVersion happens to be today.
func checkSchemaVersionAgainst(docVersion, currentVersion string) error {
	docMajor, docMinor, err := ParseSchemaVersion(docVersion)
	if err != nil {
		return err
	}
	curMajor, curMinor, err := ParseSchemaVersion(currentVersion)
	if err != nil {
		// currentVersion is a package constant in production; a parse
		// failure here is a programming error in this package, not caller
		// input.
		return fmt.Errorf("snapshot: internal: current schema version %q is malformed: %w", currentVersion, err)
	}
	if docMajor != curMajor {
		return fmt.Errorf("snapshot: schema_version %q (major %d) is incompatible with this gateway (understands major %d)", docVersion, docMajor, curMajor)
	}
	if docMinor > curMinor {
		return fmt.Errorf("snapshot: schema_version %q (minor %d) is newer than this gateway understands (minor %d); upgrade the gateway or restore with a matching version first", docVersion, docMinor, curMinor)
	}
	return nil
}
