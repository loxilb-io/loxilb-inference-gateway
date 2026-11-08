package loxinet

import "testing"

// Model a CT add notification delivered before the root zone is published.
// Zero-filled, oversized key/value storage keeps all C reads in bounds; node
// zero matches the uninitialized test datapath and reaches the rule lookup.
func TestHANotifierBeforeRootZone(t *testing.T) {
	oldDP, oldZR := mh.dpEbpf, mh.zr
	oldReady := mh.ctNotificationsReady.Load()
	mh.ctNotificationsReady.Store(false)
	mh.dpEbpf = &DpEbpfH{ctMap: map[string]*DpCtInfo{}}
	mh.zr = nil
	defer func() { mh.dpEbpf, mh.zr = oldDP, oldZR; mh.ctNotificationsReady.Store(oldReady) }()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CT callback used root zone before readiness: %v", r)
		}
	}()
	dpCTMapNotifierWorker(&DpCtInfo{PKey: make([]byte, 4096), PVal: make([]byte, 4096)})
}
