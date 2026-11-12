package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

type recoveryCompletionHook struct {
	cmn.NetHookInterface
	completed int
}

func (h *recoveryCompletionHook) NetBGPRecoveryComplete() {
	h.completed++
	snapshot.SetBGPDaemonConfigPending(false)
}
func (*recoveryCompletionHook) NetGoBGPGCGet() (cmn.GoBGPGlobalConfig, error) {
	return cmn.GoBGPGlobalConfig{}, nil
}
func (*recoveryCompletionHook) NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error) { return nil, nil }
func (*recoveryCompletionHook) NetGoBGPPolicyDefinedSetGet(string, string) ([]cmn.GoBGPPolicyDefinedSetMod, error) {
	return nil, nil
}
func (*recoveryCompletionHook) NetGoBGPPolicyDefinitionsGet() ([]cmn.GoBGPPolicyDefinitionsMod, error) {
	return nil, nil
}
func (*recoveryCompletionHook) NetGoBGPPolicyApplyGet() ([]cmn.GoBGPPolicyApply, error) {
	return nil, nil
}
func (*recoveryCompletionHook) NetRecoveryDepsGet() ([]cmn.RecoveryDependency, error) {
	return nil, nil
}

// The final all-domain write-through fails explicitly, after the committed BGP
// replacement. Recovery must still complete, even with degraded durability.
func (*recoveryCompletionHook) NetEpHostGet() ([]cmn.EndPointMod, error) {
	return nil, errors.New("injected post-commit persist failure")
}

func TestBGPCommittedRestoreAndImportNotifyWithoutPendingGroup(t *testing.T) {
	if snapshot.BGPPending() {
		t.Fatal("fixture requires no pending BGP group")
	}
	oldHooks, oldPath := ApiHooks, opts.Opts.ConfigPath
	oldGate := snapshot.BGPDaemonConfigPending()
	defer func() {
		ApiHooks = oldHooks
		opts.Opts.ConfigPath = oldPath
		snapshot.SetBGPDaemonConfigPending(oldGate)
	}()
	opts.Opts.ConfigPath = t.TempDir()
	d := snapshot.NewDocument(cmn.Version, "review", snapshot.TriggerManual)
	d.IncludedDomains = []string{snapshot.DomainBGP, snapshot.DomainBGPPolicyAssignment}
	raw, err := snapshot.Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	var body any
	if err = json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"dry-run", "commit", "import"} {
		t.Run(kind, func(t *testing.T) {
			h := &recoveryCompletionHook{}
			ApiHooks = h
			snapshot.SetBGPDaemonConfigPending(true)
			req := httptest.NewRequest("POST", apiBasePath+"/config/restore", nil)
			rec := httptest.NewRecorder()
			if kind == "import" {
				ConfigPostImport(operations.PostConfigImportParams{HTTPRequest: req, Configuration: io.NopCloser(bytes.NewReader(raw))}, nil).WriteResponse(rec, runtime.JSONProducer())
			} else {
				ConfigPostRestore(operations.PostConfigRestoreParams{HTTPRequest: req, Mode: &kind, Snapshot: body}, nil).WriteResponse(rec, runtime.JSONProducer())
			}
			if rec.Code != 200 {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			var result snapshot.Result
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Result != snapshot.ResultOK {
				t.Fatalf("%+v %v", result, err)
			}
			want := kind != "dry-run"
			if (h.completed == 1) != want || snapshot.BGPDaemonConfigPending() == want {
				t.Fatalf("kind=%s notifications=%d gate=%v", kind, h.completed, snapshot.BGPDaemonConfigPending())
			}
		})
	}
}
