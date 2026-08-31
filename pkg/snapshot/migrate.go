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
	"fmt"

	cmn "github.com/loxilb-io/loxilb/common"
)

// Migration transforms a Document from one minor schema_version to the
// next-higher minor version within the same major (§4.2: "A migrations
// table ... is the designated home for future 1.x -> 1.y field
// transforms"). FromVersion/ToVersion are exact "major.minor" strings.
//
// Migrations only ever need to run forward from an older minor to the
// current minor -- the §4.2 gate already refuses documents whose minor is
// newer than this build understands, and same-major/same-or-older-minor
// documents decode cleanly as-is (additive fields simply default to their
// zero value), so a migration is only needed when a field's *meaning* or
// *shape* changes across minors, not merely when a field is added.
type Migration struct {
	FromVersion string
	ToVersion   string
	Apply       func(*Document) error
}

// Migrations is the ordered table of registered schema migrations, applied
// in slice order.
var Migrations = []Migration{
	// 1.0 -> 1.1: the kvexactbinding domain was added. Purely additive -- a
	// 1.0 document simply has no bindings -- so the transform only
	// normalizes the absent field to its empty value and re-stamps the
	// version, giving restore engines a uniform 1.1 shape to work on.
	{
		FromVersion: "1.0",
		ToVersion:   "1.1",
		Apply: func(doc *Document) error {
			if doc.Domains.KvExactBinding == nil {
				doc.Domains.KvExactBinding = []cmn.KvExactBindingMod{}
			}
			return nil
		},
	},
}

// ApplyMigrations runs every registered Migration whose FromVersion matches
// doc.SchemaVersion (chaining through ToVersion) until either no further
// migration applies or doc.SchemaVersion == SchemaVersion. It is a no-op
// today (Migrations is empty) and exists so the restore engine (task G-2)
// has a stable call site to wire up once migrations exist.
func ApplyMigrations(doc *Document) error {
	for {
		if doc.SchemaVersion == SchemaVersion {
			return nil
		}
		applied := false
		for _, m := range Migrations {
			if m.FromVersion != doc.SchemaVersion {
				continue
			}
			if err := m.Apply(doc); err != nil {
				return fmt.Errorf("snapshot: migration %s->%s: %w", m.FromVersion, m.ToVersion, err)
			}
			doc.SchemaVersion = m.ToVersion
			applied = true
			break
		}
		if !applied {
			// No migration found; leave doc.SchemaVersion as-is and let
			// CheckSchemaVersion (codec.go) make the final call -- an older
			// minor with no migration registered is still valid per §4.2.
			return nil
		}
	}
}
