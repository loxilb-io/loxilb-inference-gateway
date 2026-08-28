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
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	openapierrors "github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations/auth"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/authz"
	tk "github.com/loxilb-io/loxilib"
)

// BearerAuthAuth parses and validates a JWT token string.
// It returns the claims contained in the token if it is valid, or an error if the token is invalid or parsing fails.
// But if the UserServiceEnable option is disabled, it will return true.
//
// Parameters:
//   - tokenString: the JWT token string to be validated.
//
// Returns:
//   - bool: the claims contained in the token if it is valid.
//   - error: an error if the token is invalid or parsing fails.
func BearerAuthAuth(tokenString string) (interface{}, error) {
	// go-swagger APIKeyAuthenticator passes the full header value including
	// the "Bearer " prefix. Strip it before validation.
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	var (
		principal interface{}
		err       error
	)
	switch {
	case opts.Opts.UserServiceEnable:
		principal, err = ApiHooks.NetUserValidate(tokenString)
	case opts.Opts.Oauth2Enable:
		principal, err = ApiHooks.NetOauthUserValidate(tokenString)
	case opts.Opts.ManualTokenEnable:
		principal, err = ManualTokenValidate(tokenString)
	default:
		return true, nil
	}
	if err != nil {
		return nil, authFailure(err)
	}
	return principal, nil
}

// authFailure gives a failed authentication the status it must be served with.
//
// go-openapi renders an error carrying no code as 500, so an unknown token was
// reported on generated routes as a server fault — and with the store's own
// wording — while the same token got a 401 from a route dispatched outside the
// chain. A store that cannot be reached is a different condition from a
// credential that is wrong, and keeps its own status: answering 401 there would
// tell a caller their credential was rejected when it was never examined.
func authFailure(err error) error {
	// A store that cannot be reached has not examined the credential, so it
	// keeps its own status rather than reporting the caller's token as wrong.
	if errors.Is(err, cmn.ErrDBUnavailable) {
		return openapierrors.New(http.StatusServiceUnavailable, "Credential store unavailable")
	}
	// Everything else is the authenticator declining the credential. Rejecting
	// is the fail-closed answer, and it is the one an unauthenticated caller
	// may learn: the wording is the same for an unknown token, an expired one
	// and a wrong manual token, so none of them can be told apart.
	//
	// A raw driver error that survives the store's retries also lands here and
	// is reported as a rejection. Classifying those as their own condition
	// needs the retry rework that is scheduled separately; until then the
	// answer is at least fail-closed.
	return openapierrors.New(http.StatusUnauthorized, "Missing or invalid credentials")
}

// managementAuthConfigured reports whether any authentication mode is active.
// With none configured, BearerAuthAuth authorizes every caller and there is no
// credential for one to present.
func managementAuthConfigured() bool {
	return opts.Opts.UserServiceEnable || opts.Opts.Oauth2Enable || opts.Opts.ManualTokenEnable
}

// AuthPostLogin function
// This function is used to authenticate the user and generate a token
func AuthPostLogin(params auth.PostAuthLoginParams) middleware.Responder {
	var response models.LoginResponse
	var user cmn.User
	if params.User.Username != nil {
		user.Username = *params.User.Username
	}
	if params.User.Password != nil {
		user.Password = *params.User.Password
	}
	token, valid, err := ApiHooks.NetUserLogin(&user)
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if !valid {
		// A failed login is a failure on the wire, not a success carrying an
		// empty body. This previously fell through to 200 with {}, so the only
		// thing separating a rejected credential from an accepted one was the
		// presence of the token field: a caller that checked the status — the
		// ordinary thing to do — read a refusal as a success, and nothing
		// counting 401s (rate limiting, alerting, access-log review) could see
		// failed attempts at all.
		//
		// The wording and status are the ones authFailure() serves, and both
		// the unknown-user and wrong-password cases reach this single branch,
		// so the two remain indistinguishable to the caller. The work done
		// before this point is unchanged, so they remain indistinguishable by
		// timing as well.
		return errorResponseWithCode(http.StatusUnauthorized, "Missing or invalid credentials")
	}
	response.Token = token
	return auth.NewPostAuthLoginOK().WithPayload(&response)
}

// AuthPostLogout function
// This function is used to logout the user
func AuthPostLogout(params auth.PostAuthLogoutParams, principal interface{}) middleware.Responder {
	token := params.HTTPRequest.Header.Get("Authorization")
	err := ApiHooks.NetUserLogout(token)
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return auth.NewPostAuthLogoutOK()
}

// The role model, the principal decoding and the loopback test live in
// pkg/authz: this package links the datapath library, and a test binary for it
// cannot be linked, so decision logic kept here could not be unit tested.

// Authorized returns the authorizer for the generated handler chain. The role
// logic applies in every authentication mode: previously it was installed only
// under UserServiceEnable, so an OAuth2 or manual-token deployment authorized
// every authenticated caller for every operation regardless of role.
func Authorized() runtime.Authorizer {
	return runtime.AuthorizerFunc(authorizePrincipal)
}

// authorizePrincipal runs the shared decision and gives the generated chain a
// status to serve. go-openapi renders a plain error as 403; a credential that
// is not a management identity must read as 401 instead, indistinguishable from
// an unknown token.
func authorizePrincipal(r *http.Request, principal interface{}) error {
	err := authz.Authorize(r.Method, r.URL.Path, principal)
	if errors.Is(err, authz.ErrNotManagementPrincipal) {
		return openapierrors.New(http.StatusUnauthorized, "Missing or invalid credentials")
	}
	return err
}

// authStatus maps an authorization error to the status it must be served with.
func authStatus(err error) int {
	if errors.Is(err, authz.ErrNotManagementPrincipal) {
		return http.StatusUnauthorized
	}
	return http.StatusForbidden
}

// RequireManagementAuth authenticates and authorizes a request that is
// dispatched outside the generated handler chain. It reports whether the
// request may proceed; when it may not, the response has already been written.
//
// Handlers routed ahead of the generated chain returned before any
// authentication ran, leaving them reachable without credentials in every
// authentication mode. Running them through the same BearerAuthAuth and
// authorization pair the generated chain uses is what keeps the two behaviours
// identical.
func RequireManagementAuth(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	// An absent credential is a decided answer, so refuse it without a store
	// lookup. Validating the empty string instead would spend the token
	// lookup's full retry budget before reaching the same conclusion, which
	// turns an unauthenticated request into a way to occupy a serving
	// goroutine for seconds at a time.
	if managementAuthConfigured() && authHeader == "" {
		writeAuthError(w, http.StatusUnauthorized, "Missing or invalid credentials")
		return false
	}
	principal, err := BearerAuthAuth(authHeader)
	if err != nil || principal == nil {
		// Serve exactly what the generated chain would, including a store
		// outage's 503: the two paths must be indistinguishable.
		code, msg := http.StatusUnauthorized, "Missing or invalid credentials"
		var coded openapierrors.Error
		if errors.As(err, &coded) {
			code, msg = int(coded.Code()), coded.Error()
		}
		writeAuthError(w, code, msg)
		return false
	}
	if err := authz.Authorize(r.Method, r.URL.Path, principal); err != nil {
		code := authStatus(err)
		msg := err.Error()
		if code == http.StatusUnauthorized {
			msg = "Missing or invalid credentials"
		}
		writeAuthError(w, code, msg)
		return false
	}
	return true
}

// writeAuthError emits the same error envelope the generated chain produces, so
// a client cannot tell the two dispatch paths apart from the response alone.
func writeAuthError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	body, err := json.Marshal(&models.Error{
		Code:    int32(code),
		Message: msg,
		Result:  msg,
		Fields:  []string{},
	})
	if err != nil {
		return
	}
	w.Write(body)
}

// isLoopbackRequest reports whether the request arrived from a loopback peer,
// reading the address from the transport and never from a header.
func isLoopbackRequest(r *http.Request) bool {
	return authz.IsLoopbackAddr(r.RemoteAddr)
}

// ManualTokenValidate function
// This function is used to validate the manual token
func ManualTokenValidate(tokenString string) (interface{}, error) {
	manualTokenPath := opts.Opts.ManualTokenPath

	data, err := os.ReadFile(manualTokenPath)
	if err != nil {
		// File not found but return invalid token
		tk.LogIt(tk.LogError, "Manual token file not found: %v\n", err)
		return nil, errors.New("invalid token")
	}
	manualToken := strings.TrimSpace(string(data))
	if tokenString == manualToken {
		return true, nil
	}
	return nil, errors.New("invalid token")
}

func AuthPostManualTokenUpdate(params auth.PostAuthTokenUpgradeParams, principal interface{}) middleware.Responder {
	token := params.Token.LicenseKey
	err := UpdateManualToken(*token)
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return auth.NewPostAuthTokenUpgradeOK().WithPayload(params.Token)
}

// UpdateManualToken function
// Licence key as manual token is updated in the file
func UpdateManualToken(newToken string) error {
	manualTokenPath := opts.Opts.ManualTokenPath
	err := os.WriteFile(manualTokenPath, []byte(newToken), 0600)
	if err != nil {
		tk.LogIt(tk.LogError, "Failed to update manual token file: %v\n", err)
		return err
	}
	return nil
}
