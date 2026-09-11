package prometheus

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// savePolicerStore snapshots the attachment store and returns a restore func,
// so tests do not leak state into each other through the package-level store.
func savePolicerStore(t *testing.T) func() {
	t.Helper()
	policerAttachmentStoreMutex.Lock()
	saved := policerAttachmentStore
	policerAttachmentStoreMutex.Unlock()
	return func() {
		policerAttachmentStoreMutex.Lock()
		policerAttachmentStore = saved
		policerAttachmentStoreMutex.Unlock()
	}
}

// With no policer configured the collector must emit nothing: absence of the
// feature, not a zero-valued series.
func TestPolicerAttachmentCollectorEmptyStore(t *testing.T) {
	defer savePolicerStore(t)()
	PublishPolicerAttachment(nil)

	if n := testutil.CollectAndCount(policerAttachmentCollector{}); n != 0 {
		t.Errorf("empty store emitted %d metrics, want 0", n)
	}
}

// The published states must come back verbatim on gather: 0 for a pending
// policer, 1 for an attached one — the distinction the REST create answer
// cannot carry.
func TestPolicerAttachmentCollectorEmitsPerIdentState(t *testing.T) {
	defer savePolicerStore(t)()
	PublishPolicerAttachment([]PolicerAttachmentSample{
		{Ident: "pol-sse", Attached: true},
		{Ident: "pol-ghost", Attached: false},
	})

	want := `
# HELP loxilb_policer_attached Whether the policer and all of its attachment points are programmed in the datapath (1) or at least one attachment is pending re-drive and the policer currently shapes nothing (0). A series exists per configured policer; a deleted policer's series disappears.
# TYPE loxilb_policer_attached gauge
loxilb_policer_attached{ident="pol-ghost"} 0
loxilb_policer_attached{ident="pol-sse"} 1
`
	if err := testutil.CollectAndCompare(policerAttachmentCollector{}, strings.NewReader(want),
		"loxilb_policer_attached"); err != nil {
		t.Errorf("attachment series mismatch: %v", err)
	}
}

// Wholesale republish is the presence contract: a policer missing from the
// next snapshot loses its series instead of freezing at the last value, and a
// state flip is visible on the next gather.
func TestPolicerAttachmentRepublishDropsAndFlips(t *testing.T) {
	defer savePolicerStore(t)()
	PublishPolicerAttachment([]PolicerAttachmentSample{
		{Ident: "pol-a", Attached: false},
		{Ident: "pol-b", Attached: true},
	})
	PublishPolicerAttachment([]PolicerAttachmentSample{
		{Ident: "pol-a", Attached: true},
	})

	want := `
# HELP loxilb_policer_attached Whether the policer and all of its attachment points are programmed in the datapath (1) or at least one attachment is pending re-drive and the policer currently shapes nothing (0). A series exists per configured policer; a deleted policer's series disappears.
# TYPE loxilb_policer_attached gauge
loxilb_policer_attached{ident="pol-a"} 1
`
	if err := testutil.CollectAndCompare(policerAttachmentCollector{}, strings.NewReader(want),
		"loxilb_policer_attached"); err != nil {
		t.Errorf("republished series mismatch: %v", err)
	}
	if n := testutil.CollectAndCount(policerAttachmentCollector{}); n != 1 {
		t.Errorf("collected %d series after republish, want 1 (pol-b must vanish)", n)
	}
}
