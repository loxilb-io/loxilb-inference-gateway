/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

type pendingSpeakerHook struct{ cmn.NetHookInterface }

func (*pendingSpeakerHook) NetGoBGPGCReplace(*cmn.GoBGPGlobalConfig) (int, error) {
	return -1, errors.New("rpc error: code = Unavailable desc = connection refused")
}

func TestBGPPendingMutation409(t *testing.T) {
	snapshot.MarkBootConfigSettled()
	d := snapshot.NewDocument(cmn.Version, "pending-test", snapshot.TriggerManual)
	d.IncludedDomains = []string{snapshot.DomainBGP}
	d.Domains.BGP.GlobalConfig = &cmn.GoBGPGlobalConfig{LocalAs: 65122, RouterID: "192.0.2.22", ListenPort: 1179}
	dir := t.TempDir()
	if _, _, _, err := snapshot.Persist(d, dir); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(dir, snapshot.PersistFileName))
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	snapshot.SetBGPRecoveryContext(parent)
	e := snapshot.NewEngine(&pendingSpeakerHook{}, cmn.Version, "pending-test", dir)
	if err = e.StartPendingBGP(original, []string{snapshot.DomainBGP}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = snapshot.StopBGPRecovery(ctx)
		defer snapshot.LockBGPRecovery()()
		snapshot.ResolvePendingBGP()
	})
	reached := 0
	h := SnapshotFreezeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(200) }))
	for _, path := range []string{"global", "neigh", "neigh/192.0.2.1", "policy/definedsets/prefix", "policy/definitions", "policy/apply"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			r := httptest.NewRecorder()
			h.ServeHTTP(r, httptest.NewRequest(method, apiBasePath+"/config/bgp/"+path, nil))
			if r.Code != 409 || !strings.Contains(r.Body.String(), "bgp_domain_pending") {
				t.Fatalf("%s %s: %d %s", method, path, r.Code, r.Body.String())
			}
		}
	}
	if reached != 0 {
		t.Fatal("pending BGP mutation reached handler")
	}
	for _, request := range []struct{ method, path string }{{"POST", "/config/loadbalancer"}, {"GET", "/config/bgp/neigh/all"}, {"POST", "/config/persist"}, {"POST", "/config/restore"}} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(request.method, apiBasePath+request.path, nil))
		if r.Code != 200 {
			t.Fatalf("safe path refused: %+v %d", request, r.Code)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, snapshot.PersistFileName))
	if !bytes.Equal(original, after) {
		t.Fatal("409 changed durable pending intent")
	}
}
