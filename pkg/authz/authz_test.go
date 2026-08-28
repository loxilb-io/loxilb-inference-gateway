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
package authz

import (
	"errors"
	"net/http"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

const lbPath = "/netlox/v1/config/loadbalancer"

// TestAuthorizeNonStringPrincipal covers the shape a data-plane API key hash
// takes when it is presented on the management listener: the shared credential
// cache resolves it to a *cmn.ApiKeyEntry, which the authorizer used to assert
// straight to a string. That assertion paniced the serving goroutine, so the
// caller saw the connection drop rather than a decision.
func TestAuthorizeNonStringPrincipal(t *testing.T) {
	principals := []struct {
		name      string
		principal interface{}
	}{
		{"api key entry pointer", &cmn.ApiKeyEntry{KeyID: "abc", TenantID: "t1"}},
		{"api key entry value", cmn.ApiKeyEntry{KeyID: "abc"}},
		{"nil", nil},
		{"int", 42},
		{"string slice", []string{"admin"}},
		{"map", map[string]string{"role": "admin"}},
		{"false bool", false},
	}

	for _, p := range principals {
		t.Run(p.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("authorization paniced on a %s principal: %v", p.name, r)
				}
			}()
			err := Authorize(http.MethodGet, lbPath, p.principal)
			if err == nil {
				t.Fatalf("expected a %s principal to be denied, got authorization", p.name)
			}
			// It must be indistinguishable from an unknown token. Reporting
			// "permission denied" here would confirm that the credential
			// resolved to something real, which for an API key hash makes the
			// management listener an oracle for live data-plane credentials.
			if !errors.Is(err, ErrNotManagementPrincipal) {
				t.Fatalf("a %s principal must be rejected as unauthenticated, got %v", p.name, err)
			}
		})
	}
}

// TestAuthorizeRoleMatrix pins the role model: a closed set matched exactly,
// with everything outside it denied. The previous model matched by substring
// and granted full authority to any role it did not recognise, so both halves
// are asserted here — "superviewer" must not inherit viewer's read access, and
// "reviewer" must not inherit an administrator's.
func TestAuthorizeRoleMatrix(t *testing.T) {
	const (
		allow      = true
		deny       = false
		otherPost  = "/netlox/v1/auth/users"
		adminUser  = "alice|admin"
		viewerUser = "bob|viewer"
	)

	cases := []struct {
		name      string
		principal interface{}
		method    string
		path      string
		want      bool
		// malformed marks a principal that carries no management identity at
		// all, as opposed to one whose role simply lacks authority.
		malformed bool
	}{
		// admin: full authority
		{"admin GET", adminUser, http.MethodGet, lbPath, allow, false},
		{"admin POST", adminUser, http.MethodPost, lbPath, allow, false},
		{"admin DELETE", adminUser, http.MethodDelete, lbPath, allow, false},
		{"admin PATCH", adminUser, http.MethodPatch, lbPath, allow, false},
		{"admin PUT", adminUser, http.MethodPut, lbPath, allow, false},

		// viewer: reads, plus ending its own session
		{"viewer GET", viewerUser, http.MethodGet, lbPath, allow, false},
		{"viewer POST logout", viewerUser, http.MethodPost, LogoutPath, allow, false},
		{"viewer POST elsewhere", viewerUser, http.MethodPost, otherPost, deny, false},
		{"viewer DELETE", viewerUser, http.MethodDelete, lbPath, deny, false},
		{"viewer PATCH", viewerUser, http.MethodPatch, lbPath, deny, false},
		{"viewer PUT", viewerUser, http.MethodPut, lbPath, deny, false},

		// unknown roles carry no authority, on reads as well as writes
		{"reviewer GET", "carol|reviewer", http.MethodGet, lbPath, deny, false},
		{"reviewer POST", "carol|reviewer", http.MethodPost, lbPath, deny, false},
		{"empty role GET", "dave|", http.MethodGet, lbPath, deny, false},
		{"empty role POST", "dave|", http.MethodPost, lbPath, deny, false},
		{"unknown role POST", "eve|operator", http.MethodPost, lbPath, deny, false},

		// exact match: neither a superstring nor a different case is the role
		{"superviewer GET", "mallory|superviewer", http.MethodGet, lbPath, deny, false},
		{"viewerx POST", "mallory|viewerx", http.MethodPost, lbPath, deny, false},
		{"xadmin POST", "mallory|xadmin", http.MethodPost, lbPath, deny, false},
		{"Admin case POST", "mallory|Admin", http.MethodPost, lbPath, deny, false},
		{"ADMIN case POST", "mallory|ADMIN", http.MethodPost, lbPath, deny, false},

		// malformed principals carry no role
		{"no separator", "adminonly", http.MethodGet, lbPath, deny, true},
		{"empty string", "", http.MethodGet, lbPath, deny, true},

		// OAuth2 principals are "username|role|refreshToken": the role is still
		// the second field, and it is still checked. Before this change the
		// authorizer was installed only under the user service, so an OAuth2
		// viewer was authorized for every operation.
		{"oauth admin POST", "alice|admin|refresh-token", http.MethodPost, lbPath, allow, false},
		{"oauth viewer GET", "bob|viewer|refresh-token", http.MethodGet, lbPath, allow, false},
		{"oauth viewer POST", "bob|viewer|refresh-token", http.MethodPost, lbPath, deny, false},
		{"oauth viewer logout", "bob|viewer|refresh-token", http.MethodPost, LogoutPath, allow, false},
		{"oauth unknown POST", "bob|reviewer|refresh-token", http.MethodPost, lbPath, deny, false},

		// The manual-token mode and a deployment with no authentication both
		// yield bool true: one shared credential with no role attached.
		{"unrestricted POST", true, http.MethodPost, lbPath, allow, false},
		{"unrestricted GET", true, http.MethodGet, lbPath, allow, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Authorize(c.method, c.path, c.principal)
			if c.want == allow && err != nil {
				t.Fatalf("%s %s as %v: expected authorization, got %v", c.method, c.path, c.principal, err)
			}
			if c.want == deny {
				if err == nil {
					t.Fatalf("%s %s as %v: expected denial, got authorization", c.method, c.path, c.principal)
				}
				// A principal that carries a role but not the authority is a
				// permission failure; one that carries no management identity
				// at all is an authentication failure. The two are served with
				// different statuses, so the distinction is asserted here.
				wantErr := ErrPermissionDenied
				if c.malformed {
					wantErr = ErrNotManagementPrincipal
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("%s %s as %v: expected %v, got %v", c.method, c.path, c.principal, wantErr, err)
				}
			}
		})
	}
}

// TestIsLoopbackAddr covers the bootstrap peer test. The address must come from
// the transport: a caller that is being excluded controls every header it
// sends, so a forwarded-for check would be decided by the attacker. The header
// cases are here to state that this function is never given one.
func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"ipv4 loopback", "127.0.0.1:40112", true},
		{"ipv4 loopback range", "127.5.6.7:40112", true},
		{"ipv4 loopback no port", "127.0.0.1", true},
		{"ipv6 loopback", "[::1]:40112", true},
		{"ipv6 loopback no port", "::1", true},
		{"private peer", "10.10.10.1:40112", false},
		{"public peer", "203.0.113.7:40112", false},
		{"docker bridge peer", "172.17.0.2:40112", false},
		{"empty", "", false},
		{"garbage", "not-an-address", false},
		{"hostname", "localhost:11111", false},
		{"loopback-looking hostname", "127.0.0.1.evil.com:80", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsLoopbackAddr(c.addr); got != c.want {
				t.Fatalf("IsLoopbackAddr(%q) = %v, want %v", c.addr, got, c.want)
			}
		})
	}
}

// U-28 (role validity) — the closed set is exactly {admin, viewer}, by exact
// match. IsValidRole is what the write path calls, so a role the authorizer
// would deny is refused at creation rather than stored and then found to carry
// no authority.
func TestU28_IsValidRoleIsExactAndClosed(t *testing.T) {
	for _, role := range []string{RoleAdmin, RoleViewer} {
		if !IsValidRole(role) {
			t.Errorf("IsValidRole(%q) = false, want true", role)
		}
	}
	// Case, whitespace, plurals, substrings and the empty string are all
	// outside the set. "viewers" and " viewer" matter specifically: the model
	// this replaces matched roles by substring, so anything containing
	// "viewer" was a viewer and everything else was an administrator.
	for _, role := range []string{
		"", " ", "Admin", "ADMIN", "admin ", " admin", "administrator",
		"Viewer", "viewers", "viewer ", "view", "reviewer", "operator",
		"admin,viewer", "admin\n", "róle",
	} {
		if IsValidRole(role) {
			t.Errorf("IsValidRole(%q) = true, want false", role)
		}
		// And the authorizer agrees, so the two cannot drift: a role the
		// write path refuses must also be denied if one ever reaches a
		// decision by another route.
		if err := AuthorizeRole(role, "GET", "/netlox/v1/config/loadbalancer"); err == nil {
			t.Errorf("AuthorizeRole(%q, GET) allowed a role outside the closed set", role)
		}
	}

	if got := ValidRoles(); len(got) != 2 || got[0] != RoleAdmin || got[1] != RoleViewer {
		t.Errorf("ValidRoles() = %v, want [%s %s]", got, RoleAdmin, RoleViewer)
	}
}
