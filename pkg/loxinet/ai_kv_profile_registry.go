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

/*
 * ai_kv_profile_registry.go — file-based ModelPromptProfile registry.
 *
 * Layout under the trusted root (default /etc/loxilb/kvprofiles):
 *   <name>.yaml           profile documents (ai_kv_profile.go schema)
 *   artifacts/...         artifact tree; profile locators resolve beneath it
 *   artifacts/sha256/<d>  content-addressed artifacts
 *
 * Trust rules enforced on every open:
 *   - paths resolve strictly beneath the root, symlinks refused at every
 *     component (openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS where available,
 *     O_NOFOLLOW component walk otherwise);
 *   - regular files only, owned by root or the gateway's effective uid, mode
 *     0644 max, size-capped; group/world-writable parent directories refuse
 *     the whole load;
 *   - the digested bytes ARE the used bytes: each artifact is read once from
 *     the verified descriptor, hashed against the profile's pinned digest,
 *     and that same buffer is what the tokenizer/renderer later consumes.
 *     There is no second path-based open anywhere downstream.
 *
 * Publication is generational and all-or-nothing: any parse, trust, digest,
 * or collision failure leaves the previously published generation serving
 * untouched. A successful publish resets the tokenizer pool so cached
 * tokenizers from the previous generation cannot outlive it.
 */

package loxinet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

// KvProfileDir is the default trusted registry root.
const KvProfileDir = "/etc/loxilb/kvprofiles"

// kvProfileArtifactSubdir is the artifact tree under the root.
const kvProfileArtifactSubdir = "artifacts"

// Size caps. Variables so tests can compress them; production values cover
// the largest real tokenizer.json files with headroom.
var (
	kvProfileDocMaxBytes      int64 = 1 << 20  // 1 MiB per profile document
	kvProfileArtifactMaxBytes int64 = 64 << 20 // 64 MiB per artifact
)

// kvProfileArtifactReceipt records the identity a loaded artifact was
// verified under (exposed to status/HA so operators can audit exactly which
// bytes a generation serves).
type kvProfileArtifactReceipt struct {
	Path     string
	Sha256   string
	Size     int64
	Mode     uint32
	UID      uint32
	Inode    uint64
	LoadedAt time.Time
}

// kvProfileEntry is one published profile with its verified artifact bytes.
// Entries are immutable after publish; a reload builds new entries.
type kvProfileEntry struct {
	Profile        ModelPromptProfile
	Gen            uint64
	DocSha256      string
	TokenizerBytes []byte
	TemplateBytes  []byte
	Receipts       []kvProfileArtifactReceipt
}

// kvProfileGeneration is one atomically published registry state.
type kvProfileGeneration struct {
	Gen        uint64
	Profiles   map[string]*kvProfileEntry // by ProfileID
	ByModel    map[string]*kvProfileEntry // by kvModelSlug(base model) and every allowed alias
	SetDigest  string                     // digest over profiles AND artifacts
	LoadedAt   time.Time
	SourceRoot string
}

var (
	// kvProfileReg is the currently published generation (nil = empty).
	kvProfileReg atomic.Pointer[kvProfileGeneration]
	// kvProfileRegGen allocates generation numbers (monotonic per process).
	kvProfileRegGen atomic.Uint64
	// kvProfileLoadMu serializes publish/retire; lookups are lock-free.
	kvProfileLoadMu sync.Mutex
)

// KvProfileRegistryLoad loads and publishes the registry from the default
// root. A missing root directory is not an error: the registry stays empty
// and profile-less legacy behavior continues.
func KvProfileRegistryLoad() error {
	if _, err := os.Stat(KvProfileDir); os.IsNotExist(err) {
		return nil
	}
	return KvProfileRegistryLoadFrom(KvProfileDir)
}

// KvProfileRegistryLoadFrom loads every profile document under root,
// verifies and loads their artifacts, and atomically publishes the new
// generation. On ANY failure the previous generation remains published and
// serving (all-or-nothing publish).
func KvProfileRegistryLoadFrom(root string) error {
	kvProfileLoadMu.Lock()
	defer kvProfileLoadMu.Unlock()

	gen, err := kvProfileLoadGeneration(root)
	if err != nil {
		return err
	}
	gen.Gen = kvProfileRegGen.Add(1)
	for _, e := range gen.Profiles {
		e.Gen = gen.Gen
	}
	kvProfileReg.Store(gen)
	// Cached tokenizers from the previous generation must not outlive it:
	// the pool reset advances the tokenizer epoch, which also invalidates
	// every in-flight singleflight load keyed under the old epoch.
	KvTokenizerPoolReset()
	log.Infof("kv-profile: published generation %d (%d profiles, set digest %.12s…) from %s",
		gen.Gen, len(gen.Profiles), gen.SetDigest, root)
	// §6.3: a registry republish moves every strict rule's trust inputs —
	// fence and re-earn the ladder everywhere (each controller re-reads the
	// new generation, manifests, and fixtures on its next pass).
	KvAttestKickAll("profile_reload")
	return nil
}

// KvProfileRegistryReset unpublishes everything (tests and shutdown).
func KvProfileRegistryReset() {
	kvProfileLoadMu.Lock()
	defer kvProfileLoadMu.Unlock()
	kvProfileReg.Store(nil)
	KvTokenizerPoolReset()
}

// kvProfileCurrent returns the published generation (nil if none).
func kvProfileCurrent() *kvProfileGeneration {
	return kvProfileReg.Load()
}

// kvProfileByModel resolves a served model name (base model or allowed
// alias) to its profile entry in the current generation.
func kvProfileByModel(modelName string) (*kvProfileEntry, bool) {
	g := kvProfileReg.Load()
	if g == nil {
		return nil, false
	}
	e, ok := g.ByModel[kvModelSlug(modelName)]
	return e, ok
}

// kvProfileByID resolves a profile ID in the current generation.
func kvProfileByID(id string) (*kvProfileEntry, bool) {
	g := kvProfileReg.Load()
	if g == nil {
		return nil, false
	}
	e, ok := g.Profiles[id]
	return e, ok
}

// kvProfileLoadGeneration performs the full trusted load. It returns a
// complete, verified generation or an error — never a partial state.
func kvProfileLoadGeneration(root string) (*kvProfileGeneration, error) {
	rootFd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("kv-profile: open root %s: %w", root, err)
	}
	defer unix.Close(rootFd)

	var rootSt unix.Stat_t
	if err := unix.Fstat(rootFd, &rootSt); err != nil {
		return nil, fmt.Errorf("kv-profile: fstat root: %w", err)
	}
	if err := kvCheckTrustedDir(&rootSt, root); err != nil {
		return nil, err
	}

	names, err := kvListProfileDocs(rootFd, root)
	if err != nil {
		return nil, err
	}

	gen := &kvProfileGeneration{
		Profiles:   make(map[string]*kvProfileEntry),
		ByModel:    make(map[string]*kvProfileEntry),
		LoadedAt:   time.Now().UTC(),
		SourceRoot: root,
	}

	for _, name := range names {
		entry, err := kvProfileLoadOne(rootFd, name)
		if err != nil {
			return nil, err
		}
		id := entry.Profile.ProfileID
		if _, dup := gen.Profiles[id]; dup {
			return nil, fmt.Errorf("kv-profile: duplicate profileId %q (%s)", id, name)
		}
		gen.Profiles[id] = entry

		models := append([]string{entry.Profile.BaseModel}, entry.Profile.AllowedAliases...)
		for _, m := range models {
			slug := kvModelSlug(m)
			if prev, clash := gen.ByModel[slug]; clash && prev != entry {
				return nil, fmt.Errorf("kv-profile: model %q claimed by profiles %q and %q — a served model resolves to exactly one profile",
					m, prev.Profile.ProfileID, id)
			}
			gen.ByModel[slug] = entry
		}
	}

	gen.SetDigest = kvProfileSetDigest(gen)
	return gen, nil
}

// kvListProfileDocs lists the *.yaml profile documents directly under the
// root (no recursion; subdirectories other than artifacts/ are ignored).
func kvListProfileDocs(rootFd int, root string) ([]string, error) {
	dupFd, err := unix.Dup(rootFd)
	if err != nil {
		return nil, fmt.Errorf("kv-profile: dup root fd: %w", err)
	}
	d := os.NewFile(uintptr(dupFd), root)
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("kv-profile: read root dir: %w", err)
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// kvProfileLoadOne loads and fully verifies one profile document and its
// artifacts.
func kvProfileLoadOne(rootFd int, name string) (*kvProfileEntry, error) {
	doc, _, err := kvReadTrustedFile(rootFd, name, kvProfileDocMaxBytes)
	if err != nil {
		return nil, err
	}
	p, err := KvParseModelPromptProfile(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	entry := &kvProfileEntry{
		Profile:   *p,
		DocSha256: kvSha256Hex(doc),
	}

	tokBytes, tokReceipt, err := kvReadArtifact(rootFd, p.TokenizerArtifact, p.TokenizerSha256)
	if err != nil {
		return nil, fmt.Errorf("%s: tokenizer artifact: %w", name, err)
	}
	entry.TokenizerBytes = tokBytes
	entry.Receipts = append(entry.Receipts, tokReceipt)

	if p.TemplateArtifact != "" {
		tplBytes, tplReceipt, err := kvReadArtifact(rootFd, p.TemplateArtifact, p.TemplateSha256)
		if err != nil {
			return nil, fmt.Errorf("%s: template artifact: %w", name, err)
		}
		entry.TemplateBytes = tplBytes
		entry.Receipts = append(entry.Receipts, tplReceipt)
	}
	return entry, nil
}

// kvReadArtifact resolves an already-validated locator beneath the artifact
// subtree, verifies trust and the pinned digest, and returns the bytes that
// were digested (the same buffer downstream consumers use).
func kvReadArtifact(rootFd int, locator, wantSha string) ([]byte, kvProfileArtifactReceipt, error) {
	rel := kvProfileArtifactSubdir + "/" + locator
	data, st, err := kvReadTrustedFile(rootFd, rel, kvProfileArtifactMaxBytes)
	if err != nil {
		return nil, kvProfileArtifactReceipt{}, err
	}
	got := kvSha256Hex(data)
	if got != wantSha {
		return nil, kvProfileArtifactReceipt{}, fmt.Errorf("%s: digest mismatch: artifact bytes hash to %s, profile pins %s", rel, got, wantSha)
	}
	return data, kvProfileArtifactReceipt{
		Path:     rel,
		Sha256:   got,
		Size:     st.Size,
		Mode:     uint32(st.Mode),
		UID:      st.Uid,
		Inode:    st.Ino,
		LoadedAt: time.Now().UTC(),
	}, nil
}

// kvReadTrustedFile opens rel beneath rootFd with symlinks refused, checks
// every parent directory against group/world write, verifies the file's
// identity (regular, trusted owner, mode 0644 max, size cap), and reads the
// full contents from the verified descriptor.
func kvReadTrustedFile(rootFd int, rel string, maxBytes int64) ([]byte, *unix.Stat_t, error) {
	if err := kvCheckParentDirs(rootFd, rel); err != nil {
		return nil, nil, err
	}
	fd, err := kvOpenBeneath(rootFd, rel)
	if err != nil {
		return nil, nil, fmt.Errorf("kv-profile: open %s: %w", rel, err)
	}
	f := os.NewFile(uintptr(fd), rel)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, nil, fmt.Errorf("kv-profile: fstat %s: %w", rel, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, nil, fmt.Errorf("kv-profile: %s is not a regular file", rel)
	}
	if err := kvCheckTrustedOwner(st.Uid, rel); err != nil {
		return nil, nil, err
	}
	if st.Mode&0o777&^0o644 != 0 {
		return nil, nil, fmt.Errorf("kv-profile: %s mode %04o exceeds 0644", rel, st.Mode&0o777)
	}
	if st.Size > maxBytes {
		return nil, nil, fmt.Errorf("kv-profile: %s size %d exceeds cap %d", rel, st.Size, maxBytes)
	}
	// Read from the verified descriptor only. LimitReader guards against the
	// file growing between fstat and read — over-cap growth surfaces as a
	// short/failed read below rather than an unbounded allocation.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("kv-profile: read %s: %w", rel, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Errorf("kv-profile: %s grew past cap %d during read", rel, maxBytes)
	}
	return data, &st, nil
}

// kvCheckParentDirs walks every directory component of rel beneath rootFd
// (symlinks refused) and rejects group/world-writable directories: a
// writable parent lets an untrusted writer swap artifacts wholesale.
func kvCheckParentDirs(rootFd int, rel string) error {
	segs := strings.Split(rel, "/")
	cur, err := unix.Dup(rootFd)
	if err != nil {
		return fmt.Errorf("kv-profile: dup root fd: %w", err)
	}
	defer func() { unix.Close(cur) }()
	walked := "."
	for _, seg := range segs[:len(segs)-1] {
		next, err := unix.Openat(cur, seg,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("kv-profile: open dir %s/%s: %w", walked, seg, err)
		}
		unix.Close(cur)
		cur = next
		walked += "/" + seg
		var st unix.Stat_t
		if err := unix.Fstat(cur, &st); err != nil {
			return fmt.Errorf("kv-profile: fstat dir %s: %w", walked, err)
		}
		if err := kvCheckTrustedDirStat(&st, walked); err != nil {
			return err
		}
	}
	return nil
}

// kvWalkOpenBeneath is the openat2 fallback: component-by-component openat
// with O_NOFOLLOW at every step. Callers pass pre-validated relative paths
// (single segments, no ".."), so refusing symlinks is sufficient to stay
// beneath the root.
func kvWalkOpenBeneath(rootFd int, rel string) (int, error) {
	segs := strings.Split(rel, "/")
	cur, err := unix.Dup(rootFd)
	if err != nil {
		return -1, err
	}
	for i, seg := range segs {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(segs)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(cur, seg, flags, 0)
		unix.Close(cur)
		if err != nil {
			return -1, err
		}
		cur = next
	}
	return cur, nil
}

// kvCheckTrustedDir validates the registry root directory's identity.
func kvCheckTrustedDir(st *unix.Stat_t, path string) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("kv-profile: %s is not a directory", path)
	}
	return kvCheckTrustedDirStat(st, path)
}

// kvCheckTrustedDirStat rejects untrusted directory identity: wrong owner or
// group/world-writable.
func kvCheckTrustedDirStat(st *unix.Stat_t, path string) error {
	if err := kvCheckTrustedOwner(st.Uid, path); err != nil {
		return err
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("kv-profile: directory %s is group/world-writable (mode %04o)", path, st.Mode&0o777)
	}
	return nil
}

// kvCheckTrustedOwner accepts root or the gateway's own effective uid — the
// process could already write files it owns, so its own uid adds no
// authority; anything else is an untrusted writer.
func kvCheckTrustedOwner(uid uint32, path string) error {
	if uid != 0 && int(uid) != os.Geteuid() {
		return fmt.Errorf("kv-profile: %s owned by uid %d (want root or the gateway uid)", path, uid)
	}
	return nil
}

// kvProfileSetDigest computes the generation's set digest: profile IDs in
// sorted order, each with its document digest and artifact digests, so the
// digest covers profiles AND artifact bytes.
func kvProfileSetDigest(gen *kvProfileGeneration) string {
	ids := make([]string, 0, len(gen.Profiles))
	for id := range gen.Profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		e := gen.Profiles[id]
		fmt.Fprintf(h, "%s\x00%s\x00", id, e.DocSha256)
		for _, r := range e.Receipts {
			fmt.Fprintf(h, "%s\x00%s\x00", r.Path, r.Sha256)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func kvSha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
