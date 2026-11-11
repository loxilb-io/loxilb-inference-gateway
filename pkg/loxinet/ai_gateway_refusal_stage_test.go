package loxinet

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The data plane names the stage of a refusal on the wire
// (X-Loxilb-Refusal-Stage, sp_refusal_stage_name in
// loxilb-ebpf/common/sockproxy_refusal_mark.h) and the control plane names
// it in the sec.ai.deny record (aiDenyStage). A client joins the two by that
// name, so the two tables have to be the same table: every stage number the
// header names must carry the audit name, and every audit stage must be
// named by the header. The header is read as text; nothing of it is built.
func TestRefusalStageHeaderNamesAreTheAuditStageNames(t *testing.T) {
	const path = "../../loxilb-ebpf/common/sockproxy_refusal_mark.h"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the loxilb-ebpf submodule has to be checked out)", path, err)
	}
	text := string(src)
	start := strings.Index(text, "sp_refusal_stage_name(int stage)")
	if start < 0 {
		t.Fatalf("%s: sp_refusal_stage_name(int stage) not found", path)
	}
	end := strings.Index(text[start:], "default:")
	if end < 0 {
		t.Fatalf("%s: sp_refusal_stage_name has no default arm", path)
	}
	body := text[start : start+end]

	wire := map[int]string{}
	for _, m := range regexp.MustCompile(`case\s+(\d+)\s*:\s*return\s+"([a-z]+)"\s*;`).FindAllStringSubmatch(body, -1) {
		n, _ := strconv.Atoi(m[1])
		if prev, dup := wire[n]; dup {
			t.Fatalf("%s: stage %d is named twice (%q, %q)", path, n, prev, m[2])
		}
		wire[n] = m[2]
	}
	if len(wire) == 0 {
		t.Fatalf("%s: no `case N: return \"name\";` arm was read from sp_refusal_stage_name", path)
	}

	// Every audit stage is named on the wire, by the audit name.
	for stage := aiStageAuth; stage <= aiStageSecurity; stage++ {
		want := aiDenyStage(stage)
		got, ok := wire[stage]
		if !ok {
			t.Errorf("stage %d (%q in the audit record) has no name in sp_refusal_stage_name", stage, want)
			continue
		}
		if got != want {
			t.Errorf("stage %d: the header says %q, the audit record says %q", stage, got, want)
		}
	}
	// The wire names nothing the audit trail does not: no stage 0, none past the last.
	for n, name := range wire {
		if n < aiStageAuth || n > aiStageSecurity {
			t.Errorf("sp_refusal_stage_name names stage %d (%q), which is not an audit stage", n, name)
		}
	}
	// A stage with no name of its own must not reach the wire as one:
	// aiDenyStage's fallback is "keyless", and the header has no such value.
	for _, name := range wire {
		if name == aiDenyStage(aiStageNone) {
			t.Errorf("the header names %q, aiDenyStage's fallback for a stage without a name", name)
		}
	}
	// "queue" is the header's own value for a request that ended while it
	// waited (audit stage capacity); it is not a stage name in either table.
	if !strings.Contains(text, `#define SP_REFUSAL_STAGE_QUEUE  "queue"`) {
		t.Errorf("%s: SP_REFUSAL_STAGE_QUEUE is not \"queue\"", path)
	}
	for n, name := range wire {
		if name == "queue" {
			t.Errorf("stage %d is named \"queue\": that value is reserved for the reaper endings", n)
		}
	}
}
