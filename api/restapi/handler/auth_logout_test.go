package handler

import (
	"errors"
	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/restapi/operations/auth"
	cmn "github.com/loxilb-io/loxilb/common"
	"net/http"
	"net/http/httptest"
	"testing"
)

type logoutHook struct {
	cmn.NetHookInterface
	live map[string]bool
	err  error
}

func (h *logoutHook) NetUserLogout(token string) error {
	if h.err != nil {
		return h.err
	}
	delete(h.live, token)
	return nil
}
func TestLogoutRevokesTheAuthenticatedCredential(t *testing.T) {
	for _, header := range []string{"Bearer fixture-token", "fixture-token"} {
		t.Run(header, func(t *testing.T) {
			previous := ApiHooks
			defer func() { ApiHooks = previous }()
			hook := &logoutHook{live: map[string]bool{"fixture-token": true, "separate-session": true}}
			ApiHooks = hook
			req := httptest.NewRequest(http.MethodPost, "/netlox/v1/auth/logout", nil)
			req.Header.Set("Authorization", header)
			result := AuthPostLogout(auth.PostAuthLogoutParams{HTTPRequest: req}, "admin|admin")
			rec := httptest.NewRecorder()
			result.WriteResponse(rec, runtime.JSONProducer())
			if rec.Code != http.StatusOK {
				t.Fatalf("logout status %d", rec.Code)
			}
			if hook.live["fixture-token"] {
				t.Fatal("authenticated credential survived logout")
			}
			if !hook.live["separate-session"] {
				t.Fatal("another session was revoked")
			}
		})
	}
}
func TestLogoutRevocationFailureIsNotSuccess(t *testing.T) {
	previous := ApiHooks
	defer func() { ApiHooks = previous }()
	ApiHooks = &logoutHook{err: errors.New("fixture store failure")}
	req := httptest.NewRequest(http.MethodPost, "/netlox/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer fixture-token")
	result := AuthPostLogout(auth.PostAuthLogoutParams{HTTPRequest: req}, "admin|admin")
	rec := httptest.NewRecorder()
	result.WriteResponse(rec, runtime.JSONProducer())
	if rec.Code == http.StatusOK {
		t.Fatal("failed revocation reported success")
	}
}
