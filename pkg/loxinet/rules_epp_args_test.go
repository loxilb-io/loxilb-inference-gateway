/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// The Endpoint Picker arguments of a rule: an EPP rule needs the fullproxy
// data path and must not enable loxilb's own P/D orchestration; its empty
// failure mode and zero timeout resolve to FailClose / 3000 ms; a rule
// without an EPP keeps every EPP field at zero (byte-identical to before).
func TestEppArgsValidateResolvesDefaults(t *testing.T) {
	serv := cmn.LbServiceArg{EppEndpoint: "pd-disaggregation-epp.llm-d.svc:9002"}
	if err := eppArgsValidate(&serv, cmn.LBModeFullProxy); err != nil {
		t.Fatalf("minimal EPP rule refused: %v", err)
	}
	if serv.EppFailureMode != cmn.EppFailureModeFailClose {
		t.Fatalf("failure mode default = %q, want FailClose", serv.EppFailureMode)
	}
	if serv.EppTimeoutMs != cmn.EppDefaultTimeoutMs {
		t.Fatalf("timeout default = %d, want %d", serv.EppTimeoutMs, cmn.EppDefaultTimeoutMs)
	}
	if serv.EppPlaintext {
		t.Fatal("plaintext must default to false")
	}
}

func TestEppArgsValidateKeepsExplicitValues(t *testing.T) {
	serv := cmn.LbServiceArg{EppEndpoint: "10.0.0.5:9002", EppFailureMode: cmn.EppFailureModeFailOpen, EppTimeoutMs: 1500, EppPlaintext: true}
	if err := eppArgsValidate(&serv, cmn.LBModeFullProxy); err != nil {
		t.Fatalf("explicit EPP rule refused: %v", err)
	}
	if serv.EppFailureMode != cmn.EppFailureModeFailOpen || serv.EppTimeoutMs != 1500 || !serv.EppPlaintext {
		t.Fatalf("explicit values rewritten: %+v", serv)
	}
}

func TestEppArgsValidateWithoutEndpointIsInert(t *testing.T) {
	for _, mode := range []cmn.LBMode{cmn.LBModeDefault, cmn.LBModeFullProxy} {
		serv := cmn.LbServiceArg{PDDisaggMode: true}
		if err := eppArgsValidate(&serv, mode); err != nil {
			t.Fatalf("rule without an EPP refused (mode %d): %v", mode, err)
		}
		if serv.EppFailureMode != "" || serv.EppTimeoutMs != 0 {
			t.Fatalf("defaults resolved on a rule without an EPP: %+v", serv)
		}
	}
	// The inert fields are still shape-checked so a typo never hides.
	serv := cmn.LbServiceArg{EppFailureMode: "failopen"}
	if err := eppArgsValidate(&serv, cmn.LBModeFullProxy); err == nil || !strings.Contains(err.Error(), "eppFailureMode") {
		t.Fatalf("lower-case failure mode accepted: %v", err)
	}
}

func TestEppArgsValidateRejects(t *testing.T) {
	tests := []struct {
		name string
		serv cmn.LbServiceArg
		mode cmn.LBMode
		want string
	}{
		{"not fullproxy", cmn.LbServiceArg{EppEndpoint: "epp:9002"}, cmn.LBModeDefault, "mode=fullproxy"},
		{"dsr", cmn.LbServiceArg{EppEndpoint: "epp:9002"}, cmn.LBModeDSR, "mode=fullproxy"},
		{"pd disagg default FailClose", cmn.LbServiceArg{EppEndpoint: "epp:9002", PDDisaggMode: true}, cmn.LBModeFullProxy, "eppFailureMode=FailOpen"},
		{"pd disagg FailClose", cmn.LbServiceArg{EppEndpoint: "epp:9002", PDDisaggMode: true, EppFailureMode: cmn.EppFailureModeFailClose}, cmn.LBModeFullProxy, "eppFailureMode=FailOpen"},
		{"bad failure mode", cmn.LbServiceArg{EppEndpoint: "epp:9002", EppFailureMode: "Retry"}, cmn.LBModeFullProxy, "eppFailureMode"},
		{"timeout over max", cmn.LbServiceArg{EppEndpoint: "epp:9002", EppTimeoutMs: cmn.EppTimeoutMsMax + 1}, cmn.LBModeFullProxy, "eppTimeoutMs"},
		{"no port", cmn.LbServiceArg{EppEndpoint: "epp.svc"}, cmn.LBModeFullProxy, "host:port"},
		{"scheme", cmn.LbServiceArg{EppEndpoint: "grpc://epp:9002"}, cmn.LBModeFullProxy, "host:port"},
		{"nul", cmn.LbServiceArg{EppEndpoint: "epp\x00:9002"}, cmn.LBModeFullProxy, "NUL"},
		{"too long", cmn.LbServiceArg{EppEndpoint: strings.Repeat("h", cmn.EppEndpointMaxBytes) + ":9002"}, cmn.LBModeFullProxy, "eppEndpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serv := tt.serv
			err := eppArgsValidate(&serv, tt.mode)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want %q", err, tt.want)
			}
			// A refused rule must not have had its defaults resolved either.
			if serv.EppFailureMode != tt.serv.EppFailureMode || serv.EppTimeoutMs != tt.serv.EppTimeoutMs {
				t.Fatalf("defaults resolved on a refused rule: %+v", serv)
			}
		})
	}
}

// An EPP on a pd_disagg rule is the EPP-primary P/D shape: the picker's
// decision is served plainly and the rule's own prefill/decode ladder is
// the FailOpen fallback. Only FailOpen makes that fallback reachable.
func TestEppArgsValidateAcceptsPdDisaggFailOpen(t *testing.T) {
	serv := cmn.LbServiceArg{EppEndpoint: "epp:9002", PDDisaggMode: true, EppFailureMode: cmn.EppFailureModeFailOpen}
	if err := eppArgsValidate(&serv, cmn.LBModeFullProxy); err != nil {
		t.Fatalf("pd_disagg_mode + FailOpen refused: %v", err)
	}
	if serv.EppFailureMode != cmn.EppFailureModeFailOpen || serv.EppTimeoutMs != cmn.EppDefaultTimeoutMs {
		t.Fatalf("defaults not resolved: %+v", serv)
	}
}
