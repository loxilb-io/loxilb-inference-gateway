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
	"fmt"
	"time"

	tk "github.com/loxilb-io/loxilb/internal/tk"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A patch is one statement: each field the patch names is written, each it
// does not name is kept by the database itself (COALESCE of a NULL
// parameter), so two patches of different fields that race both land. A
// read followed by a write could lose one of them.
var (
	sqlPatchTenantClass = fmt.Sprintf(`INSERT INTO %s.tenant_rate_limits AS t`+
		` (tenant_id, priority_class, default_objective, allowed_objectives, updated_at)`+
		` VALUES ($1, COALESCE($2::text, ''), COALESCE($3::text, ''), COALESCE($4::text, ''), $5)`+
		` ON CONFLICT (tenant_id) DO UPDATE SET`+
		` priority_class = COALESCE($2::text, t.priority_class),`+
		` default_objective = COALESCE($3::text, t.default_objective),`+
		` allowed_objectives = COALESCE($4::text, t.allowed_objectives),`+
		` updated_at = EXCLUDED.updated_at`, Schema)
	sqlPatchKeyClass = fmt.Sprintf(`UPDATE %s.api_keys SET`+
		` priority_class = COALESCE($2::text, priority_class),`+
		` default_objective = COALESCE($3::text, default_objective),`+
		` allowed_objectives = COALESCE($4::text, allowed_objectives)`+
		` WHERE key_id = $1`, Schema)
)

// classPatchArgs validates the fields a patch names and returns them as the
// statement's three parameters, NULL for a field it does not name.
func classPatchArgs(patch cmn.AIClassPatch) (pc, def, allowed sql.NullString, err error) {
	var p cmn.AIClassPolicy
	if patch.PriorityClass != nil {
		p.PriorityClass = *patch.PriorityClass
	}
	if patch.DefaultObjective != nil {
		p.DefaultObjective = *patch.DefaultObjective
	}
	if patch.AllowedObjectives != nil {
		p.AllowedObjectives = *patch.AllowedObjectives
	}
	if p, err = ValidateClassPolicy(p); err != nil {
		return
	}
	if patch.PriorityClass != nil {
		pc = sql.NullString{String: p.PriorityClass, Valid: true}
	}
	if patch.DefaultObjective != nil {
		def = sql.NullString{String: p.DefaultObjective, Valid: true}
	}
	if patch.AllowedObjectives != nil {
		allowed = sql.NullString{String: joinList(p.AllowedObjectives), Valid: true}
	}
	return
}

// PatchTenantClass changes the class fields of a tenant that the patch
// names and leaves the others, and the tenant's limits, as they are, in one
// statement. A tenant with no row gets one, with zero limits.
func (s *Service) PatchTenantClass(ctx context.Context, tenantID string, patch cmn.AIClassPatch) error {
	if patch.IsZero() {
		return nil
	}
	if err := ValidateQoSIdentity("tenant_id", tenantID); err != nil {
		return err
	}
	if tenantID == "" {
		return cmn.NewValidationError("tenant_id", "tenant_id is required")
	}
	pc, def, allowed, err := classPatchArgs(patch)
	if err != nil {
		return err
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	if _, err := db.ExecContext(ctx, sqlPatchTenantClass, tenantID, pc, def, allowed, time.Now().UTC()); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to patch class of tenant %s: %v\n", tenantID, err)
		return writeErr(err)
	}
	s.refreshClassesAfterWrite()
	return nil
}

// PatchAPIKeyClass changes the class fields of a key that the patch names
// and leaves the others as they are. One arm of PatchAPIKeyAll.
func (s *Service) PatchAPIKeyClass(ctx context.Context, keyID string, patch cmn.AIClassPatch) error {
	if patch.IsZero() {
		return nil
	}
	return s.PatchAPIKeyAll(ctx, keyID, cmn.ApiKeyPatch{Class: patch})
}

// ListAPIKeyClasses reads from the store the class fields of every key that
// sets one, by key id.
func (s *Service) ListAPIKeyClasses(ctx context.Context) (map[string]cmn.AIClassPolicy, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	out, err := readClassRows(ctx, db, sqlSelectKeyClasses)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to list key classes: %v\n", err)
		return nil, readErr(err)
	}
	return out, nil
}
