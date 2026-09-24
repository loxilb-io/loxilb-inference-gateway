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
package user

import (
	"database/sql"
	"fmt"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func delegationOf(t *testing.T, svc *UserService, name string) bool {
	t.Helper()
	users, err := svc.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	for _, u := range users {
		if u.Username == name {
			if u.DelegationAllowed == nil {
				t.Fatalf("user %q lists no delegation flag", name)
			}
			return *u.DelegationAllowed
		}
	}
	t.Fatalf("user %q not listed", name)
	return false
}

// A store provisioned before the column existed gains it on the next
// boot, and every account it already held reads false — the same answer
// a fresh table gives — so an upgrade grants nobody a delegation.
func TestUsersAddDelegationAllowedMigration(t *testing.T) {
	svc := storeFixture(t)
	db := svc.db.(*sql.DB)
	// The pre-migration shape: the column never existed.
	if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s.users DROP COLUMN delegation_allowed`, Schema)); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	insertUserRow(t, svc, "legacy", mustHash(t, "Admin123!"), "admin")
	if _, err := svc.GetUsers(); err == nil {
		t.Fatal("GetUsers succeeded against a store without the column; the listing does not select it")
	}

	// The boot-time provisioning migrates the table in place.
	if err := ensureSchema(db); err != nil {
		t.Fatalf("ensureSchema on the legacy store: %v", err)
	}
	if delegationOf(t, svc, "legacy") {
		t.Fatal("a pre-existing account reads delegation_allowed=true after the migration")
	}
	// Running it again is a no-op.
	if err := ensureSchema(db); err != nil {
		t.Fatalf("ensureSchema twice: %v", err)
	}
}

// An update states the flag or leaves it alone; only a stated value
// changes what is stored.
func TestUpdateUserDelegationAllowed(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "svc-account", mustHash(t, "Admin123!"), "admin")
	id := userID(t, svc, "svc-account")
	if delegationOf(t, svc, "svc-account") {
		t.Fatal("a new account is created with delegation allowed")
	}
	on, off := true, false
	if err := svc.UpdateUser(cmn.User{ID: id, Username: "svc-account", Password: "Viewer99!", DelegationAllowed: &on}); err != nil {
		t.Fatalf("UpdateUser(on): %v", err)
	}
	if !delegationOf(t, svc, "svc-account") {
		t.Fatal("the flag was not applied")
	}
	// A password change that says nothing about the flag keeps it.
	if err := svc.UpdateUser(cmn.User{ID: id, Username: "svc-account", Password: "Rotate77!"}); err != nil {
		t.Fatalf("UpdateUser(absent): %v", err)
	}
	if !delegationOf(t, svc, "svc-account") {
		t.Fatal("a password change revoked the delegation")
	}
	if err := svc.UpdateUser(cmn.User{ID: id, Username: "svc-account", Password: "Admin123!", DelegationAllowed: &off}); err != nil {
		t.Fatalf("UpdateUser(off): %v", err)
	}
	if delegationOf(t, svc, "svc-account") {
		t.Fatal("the flag was not cleared")
	}
}
