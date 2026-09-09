package loxinet

import (
	"strings"
	"testing"
)

func TestAIMultitierFixedCStringBridgeMatchesCABI(t *testing.T) {
	var dat proxyActs
	if got, want := len(dat.host_url), lbHostURLMaxBytes+1; got != want {
		t.Fatalf("host C ABI size=%d, admission size=%d", got, want)
	}
	if got, want := len(dat.path_prefix), lbPathPrefixMaxBytes+1; got != want {
		t.Fatalf("path_prefix C ABI size=%d, admission size=%d", got, want)
	}
	if got, want := len(dat.session_header_name), lbSessionHeaderNameMaxBytes+1; got != want {
		t.Fatalf("session_header_name C ABI size=%d, admission size=%d", got, want)
	}
	if got, want := len(dat.model_name), lbModelNameMaxBytes+1; got != want {
		t.Fatalf("model_name C ABI size=%d, admission size=%d", got, want)
	}

	if !copyLBFixedCString(dat.host_url[:], strings.Repeat("a", lbHostURLMaxBytes)) {
		t.Fatal("exact host boundary rejected by C bridge")
	}
	if dat.host_url[lbHostURLMaxBytes] != 0 {
		t.Fatal("host C bridge did not terminate at the final byte")
	}
	if copyLBFixedCString(dat.host_url[:], strings.Repeat("a", lbHostURLMaxBytes+1)) {
		t.Fatal("host overflow accepted by C bridge")
	}
	if copyLBFixedCString(dat.model_name[:], "model\x00shadow") {
		t.Fatal("embedded NUL accepted by C bridge")
	}
}

func TestAIMultitierFixedCStringBridgeRejectsAdmissionBypass(t *testing.T) {
	tests := []struct {
		name string
		work LBDpWorkQ
	}{
		{name: "host", work: LBDpWorkQ{HostURL: strings.Repeat("h", lbHostURLMaxBytes+1)}},
		{name: "path_prefix", work: LBDpWorkQ{PathPrefix: strings.Repeat("p", lbPathPrefixMaxBytes+1)}},
		{name: "session_header_name", work: LBDpWorkQ{SessionHeaderName: strings.Repeat("s", lbSessionHeaderNameMaxBytes+1)}},
		{name: "model_name", work: LBDpWorkQ{ModelName: strings.Repeat("m", lbModelNameMaxBytes+1)}},
		{name: "composite", work: LBDpWorkQ{
			HostURL: strings.Repeat("h", 255), PathPrefix: strings.Repeat("p", 128), ModelName: strings.Repeat("m", 127),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DpLBRuleMod(&tt.work); got != EbpfErrNat4Add {
				t.Fatalf("unrepresentable value crossed Go-to-C boundary: got %d, want %d", got, EbpfErrNat4Add)
			}
		})
	}
}
