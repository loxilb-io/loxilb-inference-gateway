/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// configure_trace_persist_test.go — restore/secret-split semantics of the
// OTLP configuration store: a document-declared header NAME must stay in
// desired state even when this node holds no value for it. Dropping the
// name made the post-apply state diverge from the document, which failed
// restore VERIFY and rolled back the WHOLE boot replay (found live by the
// cfg-persist-roundtrip red twin).

package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
)

// withOtlpTestState points the node-local secret store at a temp dir and
// snapshots/restores the package-level OTLP state around the test.
func withOtlpTestState(t *testing.T, secrets map[string]string) {
	t.Helper()
	savedCfg, savedConfigured := otlpConfig, otlpConfigured
	savedPath := opts.Opts.ConfigPath
	dir := t.TempDir()
	opts.Opts.ConfigPath = dir
	if secrets != nil {
		data, err := json.Marshal(secrets)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, otlpHeaderSecretFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		otlpMutex.Lock()
		otlpConfig, otlpConfigured = savedCfg, savedConfigured
		otlpMutex.Unlock()
		opts.Opts.ConfigPath = savedPath
	})
}

// TestOtlpApplyKeepsMissingHeaderNames: a restore whose document declares
// two header names, on a node whose secret store holds only one value,
// must keep BOTH names in desired state (empty value = re-provision
// marker) so capture/VERIFY still match the document.
func TestOtlpApplyKeepsMissingHeaderNames(t *testing.T) {
	withOtlpTestState(t, map[string]string{"X-API-Key": "node-local-value"})

	cfg := &cmn.TracingConfig{
		Endpoint:    "127.0.0.1:4317",
		Protocol:    "grpc",
		HeaderNames: []string{"Authorization", "X-API-Key"},
	}
	if err := OtlpApplyConfig(cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}

	out := OtlpExportConfig()
	if out == nil {
		t.Fatal("export returned nil after an explicit apply")
	}
	if !reflect.DeepEqual(out.HeaderNames, []string{"Authorization", "X-API-Key"}) {
		t.Fatalf("desired-state header names drifted from the document: %v (a dropped name fails restore VERIFY and rolls back the whole boot replay)", out.HeaderNames)
	}

	live := GetOtlpConfig()
	if v := live.Headers["X-API-Key"]; v != "node-local-value" {
		t.Fatalf("provisioned header lost its value: %q", v)
	}
	if v, ok := live.Headers["Authorization"]; !ok || v != "" {
		t.Fatalf("missing-secret header must stay present with an EMPTY value (re-provision marker), got (%q, present=%v)", v, ok)
	}
}
