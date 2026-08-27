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

// Package authz holds the management-plane authorization decision.
//
// It is deliberately free of cgo and of any REST dependency. The REST handler
// package links the eBPF datapath library, and a test binary for it cannot be
// linked at all, so decision logic that lives there cannot be covered by a unit
// test. Keeping the decision here means the rules below are testable, and the
// handler is reduced to wiring.
package authz

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// Management-plane roles. The set is closed: a role outside it carries no
// authority. The previous model matched roles by substring and handed every
// unrecognised role full authority through its else-branch, so a typo in a role
// name granted administration rather than denying it.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// LogoutPath is the one mutating route a viewer may call: ending your own
// session must not require the authority to start someone else's.
const LogoutPath = "/netlox/v1/auth/logout"

// ErrPermissionDenied is returned when a management identity is present but
// carries no authority for the request. It maps to 403.
var ErrPermissionDenied = errors.New("permission denied")

// ErrNotManagementPrincipal is returned when the credential resolves to
// something that is not a management identity at all. It maps to 401, not 403,
// and deliberately reads the same as an unknown token.
//
// A data-plane API key hash reaches this case, because it shares a credential
// cache with management tokens. Answering 403 there would confirm that the hash
// resolved to a live key, which turns the management listener into an oracle
// for the data plane's credentials — distinguishable from the 401 an unknown
// token receives. Being unable to tell the two apart is the point.
var ErrNotManagementPrincipal = errors.New("missing or invalid credentials")

// PrincipalRole reduces an authenticated principal to the role it carries.
//
// Three principal shapes reach this point:
//
//   - "username|role" from the user service, and "username|role|refreshToken"
//     from OAuth2 — the role is the second field in both.
//   - bool true, from the manual-token mode and from a deployment with no
//     authentication configured. That is a single shared credential with no role
//     attached, so it is unrestricted by construction rather than by omission.
//   - anything else. A data-plane API key hash presented as a management token
//     resolves through the shared credential cache to an API key entry;
//     asserting that to a string paniced the serving goroutine, so the caller
//     saw the connection drop instead of a decision. It is not a management
//     principal, so it gets no authority.
func PrincipalRole(principal interface{}) (role string, unrestricted bool, err error) {
	switch p := principal.(type) {
	case bool:
		if !p {
			return "", false, ErrNotManagementPrincipal
		}
		return "", true, nil
	case string:
		fields := strings.Split(p, "|")
		if len(fields) < 2 {
			return "", false, ErrNotManagementPrincipal
		}
		return fields[1], false, nil
	default:
		return "", false, ErrNotManagementPrincipal
	}
}

// IsValidRole reports whether role is one this system implements.
//
// The authorizer already denies anything outside the set, but denying at
// decision time is not the same as refusing at write time: an account created
// with "operator" was accepted, stored, and then silently had no authority at
// all, which reads to whoever created it as a broken authorizer rather than a
// rejected role. Creation and update now refuse it, and the column's CHECK
// constraint refuses it too, so the same closed set is stated in three places
// that cannot disagree.
func IsValidRole(role string) bool {
	return role == RoleAdmin || role == RoleViewer
}

// ValidRoles returns the closed set, for error messages that tell the caller
// what would have been accepted.
func ValidRoles() []string { return []string{RoleAdmin, RoleViewer} }

// AuthorizeRole decides a request against a role by exact match, denying any
// role outside the closed set.
func AuthorizeRole(role, method, path string) error {
	switch role {
	case RoleAdmin:
		return nil
	case RoleViewer:
		if method == http.MethodGet {
			return nil
		}
		if method == http.MethodPost && path == LogoutPath {
			return nil
		}
		return ErrPermissionDenied
	default:
		return ErrPermissionDenied
	}
}

// Authorize is the single management-plane authorization decision, shared by
// the generated handler chain and by the handlers dispatched outside it so the
// two cannot drift apart.
func Authorize(method, path string, principal interface{}) error {
	role, unrestricted, err := PrincipalRole(principal)
	if err != nil {
		return err
	}
	if unrestricted {
		return nil
	}
	return AuthorizeRole(role, method, path)
}

// IsLoopbackAddr reports whether addr, a transport peer address in host:port
// form, is a loopback address.
//
// Callers must pass the address the transport reports and never one derived
// from X-Forwarded-For or a similar header: a header is set by the very caller
// the check is meant to exclude, so it would read as protection while providing
// none.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
