/*
 * Copyright (c) 2025 LoxiLB Authors
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

package aikey

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	tk "github.com/loxilb-io/loxilb/internal/tk"

	cmn "github.com/loxilb-io/loxilb/common"
)

// Objectives and the class columns of tenants and keys.
//
// An objective is a named priority. A tenant row and an API key each say
// which class their requests may have at most, which objective a request
// gets by default and which objectives it may ask for. All of it lives in
// the key store, so every gateway of a deployment reads the same rows.
//
// The request path never asks the store for any of this. The whole of it is
// read into one immutable snapshot (RefreshClasses), swapped in behind an
// atomic pointer, and a request's class is resolved from that snapshot with
// map lookups. A change made through another gateway is therefore applied
// within one refresh interval, and a store outage leaves the last snapshot
// in force.

// DDL. The class columns are added to the existing tables the way burst_pct
// was; an empty string is "not set", so a row written before the columns
// existed means what it always meant.
var (
	createObjectivesTable = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.objectives (
	name       VARCHAR(64) PRIMARY KEY,
	services   TEXT NOT NULL DEFAULT '',
	priority   INTEGER NOT NULL DEFAULT 0,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, Schema)

	alterTenantAddPriorityClass = fmt.Sprintf(
		`ALTER TABLE %s.tenant_rate_limits ADD COLUMN IF NOT EXISTS priority_class VARCHAR(16) NOT NULL DEFAULT ''`, Schema)
	alterTenantAddDefaultObjective = fmt.Sprintf(
		`ALTER TABLE %s.tenant_rate_limits ADD COLUMN IF NOT EXISTS default_objective VARCHAR(64) NOT NULL DEFAULT ''`, Schema)
	alterTenantAddAllowedObjectives = fmt.Sprintf(
		`ALTER TABLE %s.tenant_rate_limits ADD COLUMN IF NOT EXISTS allowed_objectives TEXT NOT NULL DEFAULT ''`, Schema)

	alterKeyAddPriorityClass = fmt.Sprintf(
		`ALTER TABLE %s.api_keys ADD COLUMN IF NOT EXISTS priority_class VARCHAR(16) NOT NULL DEFAULT ''`, Schema)
	alterKeyAddDefaultObjective = fmt.Sprintf(
		`ALTER TABLE %s.api_keys ADD COLUMN IF NOT EXISTS default_objective VARCHAR(64) NOT NULL DEFAULT ''`, Schema)
	alterKeyAddAllowedObjectives = fmt.Sprintf(
		`ALTER TABLE %s.api_keys ADD COLUMN IF NOT EXISTS allowed_objectives TEXT NOT NULL DEFAULT ''`, Schema)
)

// classSchemaStmts is appended to ensureSchema's list.
func classSchemaStmts() []struct{ what, sql string } {
	return []struct{ what, sql string }{
		{"objectives table", createObjectivesTable},
		{"tenant_rate_limits.priority_class column", alterTenantAddPriorityClass},
		{"tenant_rate_limits.default_objective column", alterTenantAddDefaultObjective},
		{"tenant_rate_limits.allowed_objectives column", alterTenantAddAllowedObjectives},
		{"api_keys.priority_class column", alterKeyAddPriorityClass},
		{"api_keys.default_objective column", alterKeyAddDefaultObjective},
		{"api_keys.allowed_objectives column", alterKeyAddAllowedObjectives},
	}
}

var (
	sqlUpsertObjective = fmt.Sprintf(`INSERT INTO %s.objectives (name, services, priority, updated_at)`+
		` VALUES ($1, $2, $3, $4)`+
		` ON CONFLICT (name) DO UPDATE SET services = EXCLUDED.services,`+
		` priority = EXCLUDED.priority, updated_at = EXCLUDED.updated_at`, Schema)
	sqlDeleteObjective  = fmt.Sprintf(`DELETE FROM %s.objectives WHERE name = $1`, Schema)
	sqlSelectObjectives = fmt.Sprintf(`SELECT name, services, priority, updated_at FROM %s.objectives`, Schema)

	// A tenant's class columns are written without touching its limits: a
	// tenant that has a class and no limits gets a row of zero limits, which
	// is what "no limits configured" already is.
	sqlUpsertTenantClass = fmt.Sprintf(`INSERT INTO %s.tenant_rate_limits`+
		` (tenant_id, priority_class, default_objective, allowed_objectives, updated_at)`+
		` VALUES ($1, $2, $3, $4, $5)`+
		` ON CONFLICT (tenant_id) DO UPDATE SET priority_class = EXCLUDED.priority_class,`+
		` default_objective = EXCLUDED.default_objective,`+
		` allowed_objectives = EXCLUDED.allowed_objectives, updated_at = EXCLUDED.updated_at`, Schema)
	sqlSelectTenantClass = fmt.Sprintf(`SELECT priority_class, default_objective, allowed_objectives`+
		` FROM %s.tenant_rate_limits WHERE tenant_id = $1`, Schema)
	sqlSelectTenantClasses = fmt.Sprintf(`SELECT tenant_id, priority_class, default_objective, allowed_objectives`+
		` FROM %s.tenant_rate_limits`+
		` WHERE priority_class <> '' OR default_objective <> '' OR allowed_objectives <> ''`, Schema)

	sqlUpdateKeyClass = fmt.Sprintf(`UPDATE %s.api_keys SET priority_class = $2,`+
		` default_objective = $3, allowed_objectives = $4 WHERE key_id = $1`, Schema)
	sqlSelectKeyClass = fmt.Sprintf(`SELECT priority_class, default_objective, allowed_objectives`+
		` FROM %s.api_keys WHERE key_id = $1`, Schema)
	sqlSelectKeyClasses = fmt.Sprintf(`SELECT key_id, priority_class, default_objective, allowed_objectives`+
		` FROM %s.api_keys`+
		` WHERE priority_class <> '' OR default_objective <> '' OR allowed_objectives <> ''`, Schema)
)

// ErrObjectiveNotFound is returned when an objective does not exist.
var ErrObjectiveNotFound = fmt.Errorf("objective %w", ErrNotFound)

// validObjectiveName holds a name to what can travel in a header value, a
// comma-joined column and a 64-byte field: letters, digits, '-', '_', '.'.
func validObjectiveName(name string) bool {
	if name == "" || len(name) > cmn.AIObjectiveNameMax {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// ValidateObjective checks an objective row as the API received it and
// returns it in stored form (services sorted, duplicates removed).
func ValidateObjective(e cmn.AIObjectiveEntry) (cmn.AIObjectiveEntry, error) {
	if !validObjectiveName(e.Name) {
		return e, cmn.NewValidationError("name",
			"invalid objective name %q: 1 to %d characters of letters, digits, '-', '_' and '.'",
			e.Name, cmn.AIObjectiveNameMax)
	}
	if strings.HasPrefix(strings.ToLower(e.Name), "tier:") {
		return e, cmn.NewValidationError("name", "invalid objective name %q", e.Name)
	}
	if len(e.Services) > cmn.AIObjectiveServicesMax {
		return e, cmn.NewValidationError("services", "at most %d services", cmn.AIObjectiveServicesMax)
	}
	seen := make(map[string]struct{}, len(e.Services))
	out := make([]string, 0, len(e.Services))
	for _, svc := range e.Services {
		if svc == "" || strings.ContainsAny(svc, ", \t\r\n") {
			return e, cmn.NewValidationError("services", "invalid service %q: want VIP:port", svc)
		}
		if _, dup := seen[svc]; dup {
			continue
		}
		seen[svc] = struct{}{}
		out = append(out, svc)
	}
	sort.Strings(out)
	e.Services = out
	return e, nil
}

// ValidateClassPolicy checks a tenant's or key's class fields and returns
// them in stored form.
func ValidateClassPolicy(p cmn.AIClassPolicy) (cmn.AIClassPolicy, error) {
	switch p.PriorityClass {
	case "", cmn.AIClassStandard, cmn.AIClassCritical, cmn.AIClassSheddable:
	default:
		return p, cmn.NewValidationError("priority_class",
			"invalid priority_class %q: want standard, critical or sheddable", p.PriorityClass)
	}
	if p.DefaultObjective != "" && !validObjectiveName(p.DefaultObjective) {
		return p, cmn.NewValidationError("default_objective", "invalid objective name %q", p.DefaultObjective)
	}
	if len(p.AllowedObjectives) > cmn.AIObjectiveListMax {
		return p, cmn.NewValidationError("allowed_objectives", "at most %d objectives", cmn.AIObjectiveListMax)
	}
	seen := make(map[string]struct{}, len(p.AllowedObjectives))
	out := make([]string, 0, len(p.AllowedObjectives))
	for _, name := range p.AllowedObjectives {
		if !validObjectiveName(name) && !cmn.IsAITierObjective(name) {
			return p, cmn.NewValidationError("allowed_objectives", "invalid objective name %q", name)
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		out = nil
	}
	p.AllowedObjectives = out
	return p, nil
}

func joinList(l []string) string { return strings.Join(l, ",") }

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// SetObjective creates or replaces an objective and refreshes the snapshot.
func (s *Service) SetObjective(ctx context.Context, e cmn.AIObjectiveEntry) error {
	e, err := ValidateObjective(e)
	if err != nil {
		return err
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	if _, err := db.ExecContext(ctx, sqlUpsertObjective, e.Name, joinList(e.Services), e.Priority, time.Now().UTC()); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set objective %s: %v\n", e.Name, err)
		// Classified, not collapsed: a deadline after the upsert was sent
		// means the server may still apply it, and the caller is told so.
		return writeErr(err)
	}
	tk.LogIt(tk.LogInfo, "[AIKey] Set objective %s: priority=%d services=%d\n", e.Name, e.Priority, len(e.Services))
	s.refreshClassesAfterWrite()
	return nil
}

// DeleteObjective removes an objective and refreshes the snapshot. A tenant
// or key that still names it keeps the name; a request that asks for it is
// then treated as asking for an unknown objective.
func (s *Service) DeleteObjective(ctx context.Context, name string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	res, err := db.ExecContext(ctx, sqlDeleteObjective, name)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to delete objective %s: %v\n", name, err)
		return writeErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrObjectiveNotFound
	}
	tk.LogIt(tk.LogInfo, "[AIKey] Deleted objective %s\n", name)
	s.refreshClassesAfterWrite()
	return nil
}

// ListObjectives reads the objective table from the store, by name.
func (s *Service) ListObjectives(ctx context.Context) ([]cmn.AIObjectiveEntry, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	objs, err := readObjectives(ctx, db)
	if err != nil {
		return nil, readErr(err)
	}
	out := make([]cmn.AIObjectiveEntry, 0, len(objs))
	for _, o := range objs {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ObjectiveList is the API's objective list: the store's, read now, when it
// answers; else the objectives of the snapshot in force, with its source
// and the time the store answered with it. Only a gateway that has applied
// nothing yet has nothing to show while the store is away.
//
// StoreReachable and StoreLastRead say, whatever the source, whether the
// store answered its latest read (this one) and when a read last answered:
// an outage is seen in the answer, not only in the logs.
func (s *Service) ObjectiveList(ctx context.Context) (cmn.AIObjectiveList, error) {
	gen := s.class.readGen.Add(1)
	objs, err := s.ListObjectives(ctx)
	s.noteStoreRead(gen, err)
	reachable, lastOK := s.StoreHealth()
	if err == nil {
		return cmn.AIObjectiveList{Objectives: objs, Source: cmn.AIClassSourceStore,
			SourceTimestamp: time.Now().UTC(), StoreReachable: reachable, StoreLastRead: lastOK}, nil
	}
	applied, source, at, ok := s.AppliedObjectives()
	if !ok {
		return cmn.AIObjectiveList{}, err
	}
	return cmn.AIObjectiveList{Objectives: applied, Source: source, SourceTimestamp: at,
		StoreReachable: reachable, StoreLastRead: lastOK}, nil
}

func readObjectives(ctx context.Context, db DBTX) (map[string]cmn.AIObjectiveEntry, error) {
	rows, err := db.QueryContext(ctx, sqlSelectObjectives)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]cmn.AIObjectiveEntry)
	for rows.Next() {
		var e cmn.AIObjectiveEntry
		var services string
		if err := rows.Scan(&e.Name, &services, &e.Priority, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.Services = splitList(services)
		out[e.Name] = e
	}
	return out, rows.Err()
}

func readClassRows(ctx context.Context, db DBTX, query string) (map[string]cmn.AIClassPolicy, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]cmn.AIClassPolicy)
	for rows.Next() {
		var id, allowed string
		var p cmn.AIClassPolicy
		if err := rows.Scan(&id, &p.PriorityClass, &p.DefaultObjective, &allowed); err != nil {
			return nil, err
		}
		p.AllowedObjectives = splitList(allowed)
		out[id] = p
	}
	return out, rows.Err()
}

// SetTenantClass writes a tenant's class fields, all three: a field left
// empty is cleared. The tenant's limits are not touched.
func (s *Service) SetTenantClass(ctx context.Context, tenantID string, p cmn.AIClassPolicy) error {
	if err := ValidateQoSIdentity("tenant_id", tenantID); err != nil {
		return err
	}
	if tenantID == "" {
		return cmn.NewValidationError("tenant_id", "tenant_id is required")
	}
	p, err := ValidateClassPolicy(p)
	if err != nil {
		return err
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	if _, err := db.ExecContext(ctx, sqlUpsertTenantClass, tenantID, p.PriorityClass, p.DefaultObjective,
		joinList(p.AllowedObjectives), time.Now().UTC()); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set class of tenant %s: %v\n", tenantID, err)
		return writeErr(err)
	}
	s.refreshClassesAfterWrite()
	return nil
}

// GetTenantClass reads a tenant's class fields from the store. A tenant
// with no row has none.
func (s *Service) GetTenantClass(ctx context.Context, tenantID string) (cmn.AIClassPolicy, error) {
	return s.readClass(ctx, sqlSelectTenantClass, tenantID, nil)
}

// SetAPIKeyClass writes a key's class fields, all three.
func (s *Service) SetAPIKeyClass(ctx context.Context, keyID string, p cmn.AIClassPolicy) error {
	p, err := ValidateClassPolicy(p)
	if err != nil {
		return err
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	res, err := db.ExecContext(ctx, sqlUpdateKeyClass, keyID, p.PriorityClass, p.DefaultObjective, joinList(p.AllowedObjectives))
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set class of key %s: %v\n", keyID, err)
		return writeErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrKeyNotFound
	}
	s.refreshClassesAfterWrite()
	return nil
}

// GetAPIKeyClass reads a key's class fields from the store.
func (s *Service) GetAPIKeyClass(ctx context.Context, keyID string) (cmn.AIClassPolicy, error) {
	return s.readClass(ctx, sqlSelectKeyClass, keyID, ErrKeyNotFound)
}

func (s *Service) readClass(ctx context.Context, query, id string, missing error) (cmn.AIClassPolicy, error) {
	var p cmn.AIClassPolicy
	db, err := s.store()
	if err != nil {
		return p, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	var allowed string
	if err := db.QueryRowContext(ctx, query, id).Scan(&p.PriorityClass, &p.DefaultObjective, &allowed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, missing
		}
		return p, readErr(err)
	}
	p.AllowedObjectives = splitList(allowed)
	return p, nil
}
