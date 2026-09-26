/*
 * Copyright (c) 2022 NetLOX Inc
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
package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations/users"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/authz"
	tk "github.com/loxilb-io/loxilib"
)

// addUserResponse performs an authorized create and maps the outcome.
func addUserResponse(user *cmn.User) middleware.Responder {
	if _, err := ApiHooks.NetUserAdd(user); err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err.Error())
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

// UsersPostUsers creates a user.
//
// The route carries no generated security, because the first account has to be
// creatable before any credential exists. That does not make it open: an
// authenticated administrator is authorized here, and every other caller must
// satisfy the bootstrap condition — a loopback peer while the user table is
// still empty. Previously the route was unauthenticated unconditionally, so
// anyone who could reach the management listener could add an administrator at
// any time.
func UsersPostUsers(params users.PostAuthUsersParams) middleware.Responder {
	r := params.HTTPRequest
	tk.LogIt(tk.LogTrace, "api: User  %s API called. url : %s\n", r.Method, r.URL)
	var user cmn.User
	if params.User.Username != nil {
		user.Username = *params.User.Username
	}
	if params.User.Password != nil {
		user.Password = *params.User.Password
	}
	user.CreatedAt = time.Now()
	user.Role = params.User.Role
	// The account being created is the record's subject; the password is
	// never part of it.
	AuditDetail(r, func(d *audit.MgmtDetail) {
		d.Username = user.Username
		d.Role = user.Role
	})

	// With no authentication mode configured there is no credential to present
	// and the whole management API is open, so this endpoint must not be
	// stricter than the rest of it.
	if !managementAuthConfigured() {
		return addUserResponse(&user)
	}

	// A credential was presented: it decides the request either way. Falling
	// through to the bootstrap on a bad credential would let a caller reach the
	// unauthenticated path by sending a wrong token.
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		principal, err := BearerAuthAuth(authHeader)
		if err != nil || principal == nil {
			return errorResponseWithCode(http.StatusUnauthorized, "Missing or invalid credentials")
		}
		// This route has no generated authorizer, so the principal is
		// handed to the audit gate here, as the chain would have done.
		RecordAuditPrincipal(r, principal)
		if err := authz.Authorize(r.Method, r.URL.Path, principal); err != nil {
			if authStatus(err) == http.StatusUnauthorized {
				return errorResponseWithCode(http.StatusUnauthorized, "Missing or invalid credentials")
			}
			return errorResponseWithCode(http.StatusForbidden, err.Error())
		}
		return addUserResponse(&user)
	}

	// No credential: the bootstrap path. The peer address comes from the
	// transport, never from a forwarded-for header, and the table-is-empty half
	// of the condition is enforced inside the insert. Whether it is accepted
	// or refused, the record says the bootstrap branch was taken and that
	// no principal stands behind it.
	RecordAuditActor(r, audit.Actor{Auth: audit.AuthNone, Bootstrap: true, Mechanism: "none"})
	AuditDetail(r, func(d *audit.MgmtDetail) { d.Bootstrap = true })
	if !isLoopbackRequest(r) {
		tk.LogIt(tk.LogCritical, "Rejected unauthenticated user creation from non-loopback peer %v\n", r.RemoteAddr)
		return errorResponseWithCode(http.StatusUnauthorized, "Missing or invalid credentials")
	}
	if _, err := ApiHooks.NetUserBootstrap(&user); err != nil {
		if errors.Is(err, cmn.ErrBootstrapClosed) {
			tk.LogIt(tk.LogCritical, "Rejected unauthenticated user creation: bootstrap already closed\n")
			return errorResponseWithCode(http.StatusUnauthorized, "Missing or invalid credentials")
		}
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err.Error())
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

// UsersDeleteUsers function
// This function is used to delete a user
func UsersDeleteUsers(params users.DeleteAuthUsersIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: User %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	err := ApiHooks.NetUserDel(int(params.ID))
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err.Error())
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

// UsersGetUsers function
// This function is used to get all users
func UsersGetUsers(params users.GetAuthUsersParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: User %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	res, err := ApiHooks.NetUserGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err.Error())
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	// A listing-class read records how much was listed, never what.
	count := len(res)
	AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) { d.Count = count })

	// Convert to the response model. UserSummary has no password field, so
	// there is nothing here to forget to omit — the store no longer selects
	// the column and the model could not carry it if it did.
	result := make([]*models.UserSummary, 0, len(res))
	for _, user := range res {
		result = append(result, &models.UserSummary{
			ID:                int64(user.ID),
			Username:          user.Username,
			Role:              user.Role,
			CreatedAt:         user.CreatedAt.Format(time.RFC3339),
			DelegationAllowed: user.DelegationAllowed != nil && *user.DelegationAllowed,
		})
	}

	return users.NewGetAuthUsersOK().WithPayload(result)
}

// UsersPutUsers function
// This function is used to update a user
func UsersPutUsers(params users.PutAuthUsersIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: User %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	var user cmn.User
	if params.User.Username != nil {
		user.Username = *params.User.Username
	}
	if params.User.Password != nil {
		user.Password = *params.User.Password
	}
	user.ID = int(params.ID)
	// Absent, the flag keeps what is stored; present, it is applied and
	// the gate names it among the changed fields.
	user.DelegationAllowed = params.User.DelegationAllowed
	// The record names the account and, when a role is applied, both
	// role values; the changed field names come from the gate and the
	// password never leaves the request.
	roleFrom := ""
	if user.Role != "" {
		roleFrom = currentUserRole(user.ID)
	}
	AuditDetail(params.HTTPRequest, func(d *audit.MgmtDetail) {
		d.Username = user.Username
		d.RoleFrom, d.RoleTo = roleFrom, user.Role
	})
	err := ApiHooks.NetUserUpdate(&user)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err.Error())
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

// currentUserRole is the role stored for the account before an update, so
// a role change can be recorded with both values. Empty when the account
// or the store cannot be read: the update itself reports that.
func currentUserRole(id int) string {
	users, err := ApiHooks.NetUserGet()
	if err != nil {
		return ""
	}
	for _, u := range users {
		if u.ID == id {
			return u.Role
		}
	}
	return ""
}
