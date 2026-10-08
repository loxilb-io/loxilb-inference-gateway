//go:build linux

package loxinet

import (
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func securityRateTestState(t *testing.T, proxyOnly bool) *NetAPIStruct {
	t.Helper()
	savedMode, savedDP, savedConfig := mh.disBPF, mh.dpEbpf, mh.securityRateConfig
	mh.disBPF = proxyOnly
	// Leave the datapath absent: tests must not invoke C map metadata before
	// process initialization. The full boot-restore regression runs against
	// an initialized proxyonly process in the dedicated integration lab.
	mh.dpEbpf = nil
	mh.securityRateConfig = cmn.SecurityRateConfig{}
	t.Cleanup(func() {
		mh.disBPF, mh.dpEbpf, mh.securityRateConfig = savedMode, savedDP, savedConfig
	})
	return &NetAPIStruct{}
}

func TestProxyOnlySecurityRateDisabledStateDoesNotNeedKernelMaps(t *testing.T) {
	api := securityRateTestState(t, true)
	for _, ips := range [][]string{nil, {}} {
		cfg := cmn.SecurityRateConfig{WhitelistIPs: ips}
		rc, err := api.NetSecurityRateSet(&cfg)
		if err != nil || rc != 0 {
			t.Fatalf("disabled proxyonly state must restore without kernel maps: rc=%d err=%v", rc, err)
		}
		if !reflect.DeepEqual(mh.securityRateConfig, cmn.SecurityRateConfig{}) {
			t.Fatalf("reported proxyonly state must remain disabled: %+v", mh.securityRateConfig)
		}
	}
}

func TestProxyOnlySecurityRateRejectsKernelControlSettings(t *testing.T) {
	api := securityRateTestState(t, true)
	cases := []cmn.SecurityRateConfig{
		{SYNEnabled: true}, {ConnRateEnabled: true}, {UDPEnabled: true},
		{SYNThreshold: 1}, {CookieThreshold: 1}, {RatePerSec: 1},
		{UDPPktThreshold: 1}, {UDPBandwidthMB: 1}, {WhitelistIPs: []string{"192.0.2.1"}},
	}
	for _, cfg := range cases {
		if rc, err := api.NetSecurityRateSet(&cfg); err == nil || rc == 0 {
			t.Fatalf("proxyonly must not claim kernel enforcement for %+v: rc=%d err=%v", cfg, rc, err)
		}
		if !reflect.DeepEqual(mh.securityRateConfig, cmn.SecurityRateConfig{}) {
			t.Fatalf("rejected setting changed reported state: %+v", mh.securityRateConfig)
		}
	}
}

func TestNativeSecurityRateBGPModeStillRejected(t *testing.T) {
	api := securityRateTestState(t, false)
	api.BgpPeerMode = true
	before := cmn.SecurityRateConfig{SYNEnabled: true, SYNThreshold: 42}
	mh.securityRateConfig = before
	if rc, err := api.NetSecurityRateSet(&cmn.SecurityRateConfig{}); err == nil || rc == 0 {
		t.Fatalf("BGP mode must remain unsupported: rc=%d err=%v", rc, err)
	}
	if !reflect.DeepEqual(mh.securityRateConfig, before) {
		t.Fatalf("native failure changed reported state: %+v", mh.securityRateConfig)
	}
}
