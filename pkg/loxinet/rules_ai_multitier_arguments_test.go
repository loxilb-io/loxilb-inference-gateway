package loxinet

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestAIMultitierEngineRankScope(t *testing.T) {
	for _, engine := range []string{"", "vllm", "sglang", "trtllm", "llamacpp"} {
		for _, ranks := range []uint16{0, 1, 2, 8, 9, 65535} {
			t.Run(fmt.Sprintf("%s/ranks=%d", engine, ranks), func(t *testing.T) {
				err := kvEngineConfigValidate(engine, ranks)
				wantReject := ranks > 8 || (engine != "sglang" && ranks > 1)
				if wantReject && (err == nil || !strings.Contains(err.Error(), "rank")) {
					t.Fatalf("SGLang-only rank fanout must reject engine=%q ranks=%d, got %v", engine, ranks, err)
				}
				if !wantReject && err != nil {
					t.Fatalf("valid rank control rejected: %v", err)
				}
			})
		}
	}
}

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

func TestAIMultitierFixedCStringAdmissionPrecedesRuleMutation(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*cmn.LbServiceArg)
	}{
		{name: "host-overflow", field: "host", set: func(s *cmn.LbServiceArg) { s.HostUrl = strings.Repeat("h", 256) }},
		{name: "path-prefix-overflow", field: "path_prefix", set: func(s *cmn.LbServiceArg) { s.PathPrefix = strings.Repeat("p", 256) }},
		{name: "session-header-overflow", field: "session_header_name", set: func(s *cmn.LbServiceArg) { s.SessionHeaderName = strings.Repeat("s", 128) }},
		{name: "model-name-overflow", field: "model_name", set: func(s *cmn.LbServiceArg) { s.ModelName = strings.Repeat("m", 128) }},
		{name: "host-nul", field: "host", set: func(s *cmn.LbServiceArg) { s.HostUrl = "api.example\x00.invalid" }},
		{name: "path-prefix-nul", field: "path_prefix", set: func(s *cmn.LbServiceArg) { s.PathPrefix = "/v1\x00/admin" }},
		{name: "session-header-nul", field: "session_header_name", set: func(s *cmn.LbServiceArg) { s.SessionHeaderName = "x-session\x00-shadow" }},
		{name: "model-name-nul", field: "model_name", set: func(s *cmn.LbServiceArg) { s.ModelName = "model-a\x00-shadow" }},
		{name: "composite-overflow", field: "composite", set: func(s *cmn.LbServiceArg) {
			s.HostUrl = strings.Repeat("h", 255)
			s.PathPrefix = strings.Repeat("p", 128)
			s.ModelName = strings.Repeat("m", 127)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serv := cmn.LbServiceArg{ServIP: "192.0.2.10", Proto: "tcp"}
			tt.set(&serv)

			// A nil receiver is deliberate: these arguments must be refused at
			// admission before AddLbRule can inspect or mutate RuleH state.
			var rules *RuleH
			code, err := rules.AddLbRule(serv, nil, nil, nil, nil)
			if code != RuleArgsErr || err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("want pre-mutation %s rejection (%d), got code=%d err=%v", tt.field, RuleArgsErr, code, err)
			}
			var argErr *cmn.RuleArgumentError
			if !errors.As(err, &argErr) {
				t.Fatalf("REST boundary cannot classify %s structurally: %T", tt.field, err)
			}
		})
	}
}

func TestAIMultitierFixedCStringByteLimits(t *testing.T) {
	tests := []struct {
		field string
		limit int
	}{
		{field: "host", limit: lbHostURLMaxBytes},
		{field: "path_prefix", limit: lbPathPrefixMaxBytes},
		{field: "session_header_name", limit: lbSessionHeaderNameMaxBytes},
		{field: "model_name", limit: lbModelNameMaxBytes},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			if err := validateLBFixedCString(tt.field, "", tt.limit); err != nil {
				t.Fatalf("empty optional value rejected: %v", err)
			}
			if err := validateLBFixedCString(tt.field, strings.Repeat("a", tt.limit), tt.limit); err != nil {
				t.Fatalf("exact ASCII byte boundary rejected: %v", err)
			}
			if err := validateLBFixedCString(tt.field, strings.Repeat("a", tt.limit+1), tt.limit); err == nil {
				t.Fatal("ASCII overflow accepted")
			}

			exactUTF8 := strings.Repeat("é", tt.limit/2)
			if tt.limit%2 != 0 {
				exactUTF8 += "a"
			}
			if len(exactUTF8) != tt.limit {
				t.Fatalf("bad test fixture: got %d bytes, want %d", len(exactUTF8), tt.limit)
			}
			if err := validateLBFixedCString(tt.field, exactUTF8, tt.limit); err != nil {
				t.Fatalf("exact UTF-8 byte boundary rejected: %v", err)
			}
			if err := validateLBFixedCString(tt.field, exactUTF8+"é", tt.limit); err == nil {
				t.Fatal("multibyte UTF-8 overflow accepted")
			}
			if err := validateLBFixedCString(tt.field, string([]byte{0xff}), tt.limit); err == nil {
				t.Fatal("invalid UTF-8 accepted")
			}
		})
	}
}

func TestAIMultitierFixedCStringCompositeKeyLimit(t *testing.T) {
	tests := []struct {
		name  string
		serv  cmn.LbServiceArg
		valid bool
	}{
		{name: "host-only", serv: cmn.LbServiceArg{HostUrl: strings.Repeat("h", 255)}, valid: true},
		{name: "host-path-exact-511", serv: cmn.LbServiceArg{
			HostUrl: strings.Repeat("h", 255), PathPrefix: strings.Repeat("p", 255),
		}, valid: true},
		{name: "host-empty-path-model", serv: cmn.LbServiceArg{
			HostUrl: strings.Repeat("h", 255), ModelName: strings.Repeat("m", 127),
		}, valid: true},
		{name: "host-path-model-exact-511", serv: cmn.LbServiceArg{
			HostUrl: strings.Repeat("h", 255), PathPrefix: strings.Repeat("p", 127), ModelName: strings.Repeat("m", 127),
		}, valid: true},
		{name: "host-path-model-overflow-512", serv: cmn.LbServiceArg{
			HostUrl: strings.Repeat("h", 255), PathPrefix: strings.Repeat("p", 128), ModelName: strings.Repeat("m", 127),
		}, valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLBFixedCStringFields(tt.serv)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, error=%v", tt.valid, err)
			}
			if !tt.valid && !strings.Contains(err.Error(), "composite") {
				t.Fatalf("composite overflow must be diagnosable, got %v", err)
			}
		})
	}
}
