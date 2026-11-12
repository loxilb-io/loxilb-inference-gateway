package snapshot

import (
	"errors"
	dto "github.com/prometheus/client_model/go"
	"testing"
)

type adoptionReviewHook struct {
	*mockHooks
	warnings    map[string][]string
	err         error
	static      bool
	inspections int
	warns       int
}

func (h *adoptionReviewHook) NetBGPAdoptionWarnings() (map[string][]string, error) {
	h.inspections++
	return h.warnings, h.err
}
func (h *adoptionReviewHook) NetBGPStaticConfigPresent() bool     { return h.static }
func (h *adoptionReviewHook) NetBGPAdoptionWarn(string, []string) { h.warns++ }
func adoptionMetric(t *testing.T) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := bgpAdoptionDroppedAttributes.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}
func TestBGPAdoptionWarningGaugeOnlyChangesOnSuccessfulAdoption(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	hook := &adoptionReviewHook{mockHooks: h, static: true, warnings: map[string][]string{"192.0.2.23": {"timers.hold_time", "auth_password"}}}
	old := adoptionMetric(t)
	defer bgpAdoptionDroppedAttributes.Set(old)
	bgpAdoptionDroppedAttributes.Set(44)
	failure := errors.New("mutation failed")
	if _, err := ChangeBGPIntent(hook, d.Domains.BGP.GlobalConfig, true, func() (int, error) { return 0, failure }); err != failure || adoptionMetric(t) != 44 || BGPIntentAdopted() {
		t.Fatal("failed mutation recorded adoption", err)
	}
	if _, err := ChangeBGPIntent(hook, d.Domains.BGP.GlobalConfig, true, func() (int, error) { return 0, nil }); err != nil || adoptionMetric(t) != 2 || !BGPIntentAdopted() {
		t.Fatal("successful adoption omitted warning", err)
	}
}
func TestBGPAdoptionInspectionFailureDoesNotBlockMutation(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	hook := &adoptionReviewHook{mockHooks: h, static: true, err: errors.New("unavailable")}
	old := adoptionMetric(t)
	defer bgpAdoptionDroppedAttributes.Set(old)
	if _, err := ChangeBGPIntent(hook, d.Domains.BGP.GlobalConfig, true, func() (int, error) { return 0, nil }); err != nil || adoptionMetric(t) != -1 || !BGPIntentAdopted() {
		t.Fatal("inspection blocked adoption", err)
	}
}

func TestBGPAPIOnlyAdoptionSkipsInspectionAndLeavesGaugeUntouched(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		name := "REST mutation"
		if interactive {
			name = "interactive restore"
		}
		t.Run(name, func(t *testing.T) {
			h, d, e := intentFixture(t)
			h.bgpGC = d.Domains.BGP.GlobalConfig
			// This inspection spy represents the extra ListPeer RPC and would fail
			// on an unstarted speaker if the static-file guard were missing.
			hook := &adoptionReviewHook{mockHooks: h, err: errors.New("ListPeer: speaker not started")}
			old := adoptionMetric(t)
			defer bgpAdoptionDroppedAttributes.Set(old)
			bgpAdoptionDroppedAttributes.Set(37)
			if interactive {
				e.Hooks = hook
				result, err := e.Restore(encodeDoc(t, d), RestoreOptions{Mode: ModeCommit, Components: bgpComponents})
				if err != nil || result.Result != ResultOK {
					t.Fatalf("restore: %+v %v", result, err)
				}
			} else {
				if _, err := ChangeBGPIntent(hook, d.Domains.BGP.GlobalConfig, true, func() (int, error) { return 0, nil }); err != nil {
					t.Fatal(err)
				}
			}
			if hook.inspections != 0 || hook.warns != 0 || adoptionMetric(t) != 37 {
				t.Fatalf("API-only inspection=%d WARN=%d gauge=%v", hook.inspections, hook.warns, adoptionMetric(t))
			}
			if !BGPIntentAdopted() {
				t.Fatal("inspection scope changed adoption behavior")
			}
		})
	}
}
