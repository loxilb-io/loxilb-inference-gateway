/*
 * Copyright (c) 2025 LoxiLB Authors
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
package user

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/options"
)

// The constructor must not block on the store dial. The dial against an
// unreachable store spends its full retry budget — backoff sleeps alone come
// to tens of seconds before any connect timeout is counted — and a caller
// blocked for that long holds everything sequenced after it hostage to the
// management store's availability. The observed cost of getting this wrong:
// the boot snapshot restore gave up waiting for later subsystems, rolled the
// data plane's persisted config back to empty, and quarantined the snapshot,
// all because an unrelated PostgreSQL was down during a restart.
//
// The bound below (3s) sits far under the smallest possible synchronous dial
// (>= 8s of backoff sleeps even when every connect fails instantly), so the
// test fails against a constructor that dials before returning and cannot
// pass by timing luck.
func TestNewUserServiceDoesNotBlockOnUnreachableStore(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("testpass"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	saved := options.Opts
	t.Cleanup(func() { options.Opts = saved })
	options.Opts.MgmtDBHost = "192.0.2.1" // TEST-NET-1: never routable
	options.Opts.MgmtDBPort = "5432"
	options.Opts.MgmtDBUser = "u"
	options.Opts.MgmtDBName = "d"
	options.Opts.MgmtDBPasswordPath = pwFile
	options.Opts.MgmtSSLOption = false

	// Non-vacuity: the DSN must build, or the constructor would return fast
	// for the trivial reason that no dial was ever attempted.
	if _, err := mgmtDSN(); err != nil {
		t.Fatalf("precondition: mgmtDSN must succeed so the dial path is reached: %v", err)
	}

	start := time.Now()
	svc := NewUserService() // leaks a background dial against TEST-NET-1 for
	// the retry budget; it fails on its own and holds no test resources.
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("NewUserService blocked %v on an unreachable store; the dial must complete in the background", elapsed)
	}
	if svc == nil {
		t.Fatal("NewUserService returned nil service")
	}
	// Degraded from the first instant: store-backed calls must answer "store
	// unavailable" rather than panic or block while the background dial runs.
	if _, err := svc.store(); !errors.Is(err, ErrDBUnavailable) {
		t.Fatalf("degraded service: store() = %v, want ErrDBUnavailable", err)
	}
}
