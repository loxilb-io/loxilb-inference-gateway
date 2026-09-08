package loxinet

import (
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestAIMultitierReservedModeAdmission(t *testing.T) {
	for _, engine := range []string{"", "vllm", "sglang", "trtllm", "llamacpp"} {
		t.Run(engine, func(t *testing.T) {
			// Supply working dependencies: a missing tokenizer must not hide
			// acceptance of an unimplemented transport.
			serv := cmn.LbServiceArg{KvEngineType: engine, KvExactMode: 2, ModelName: "model-a"}
			_, err := kvEngineAdmissionValidate(&serv, admissionDeps(nil))
			if err == nil || !strings.Contains(err.Error(), "kvExactMode") {
				t.Fatalf("reserved mode must be refused for engine %q, got %v", engine, err)
			}
		})
	}
}

func TestAIMultitierReservedModeDependencyOrder(t *testing.T) {
	for _, engine := range []string{"vllm", "sglang"} {
		serv := cmn.LbServiceArg{KvEngineType: engine, KvExactMode: 2, ModelName: "model-a"}
		deps := admissionDeps(func(d *kvExactAdmissionDeps) {
			d.getenv = func(string) (string, bool) { t.Fatal("reserved mode queried dependencies"); return "", false }
			d.tokenizerReady = func(string) bool { t.Fatal("reserved mode queried tokenizer"); return false }
		})
		_, err := kvEngineAdmissionValidate(&serv, deps)
		if err == nil || !strings.Contains(err.Error(), "kvExactMode") {
			t.Fatalf("engine=%s: want mode rejection, got %v", engine, err)
		}
	}
}
