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
package aikey

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/options"
)

// A degraded start installs the pool while the data plane is already reading
// it. The pool must therefore be handed over under a lock, and every statement
// must run against the handle its caller was given rather than re-reading the
// field.
//
// Run this leg under -race: without the guard it reports a write/read pair on
// Service.db, and without the handle being passed down it can also fail
// outright when a reader observes nil between the check and the query.
func TestStoreHandoverIsRaceFree(t *testing.T) {
	fixture := storeFixture(t)
	pool := poolOf(t, fixture)

	// A service in the state a boot-time store outage leaves behind: cache
	// present, no pool.
	svc := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers of every shape the data plane uses: the authentication lookup,
	// the tenant quota read, and the per-model quota read. All three must
	// tolerate the pool appearing underneath them.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				svc.ValidateAPIKey("lxb_" + strings.Repeat("a", 64)) //nolint:errcheck
				svc.GetTenantRateLimit("race-tenant")
				svc.GetTenantModelRateLimit("race-tenant", "race-model")
			}
		}()
	}

	// The reconnect tick's half of the handover.
	if err := svc.Attach(pool); err != nil {
		close(stop)
		wg.Wait()
		t.Fatalf("attach the pool: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if _, err := svc.store(); err != nil {
		t.Fatalf("service still degraded after Attach: %v", err)
	}
}

// A service that has no pool answers ErrDBUnavailable rather than admitting
// traffic or panicking. This is the state the data plane sees between a failed
// boot connect and the first successful tick.
func TestDegradedServiceRefusesEveryStoreCall(t *testing.T) {
	svc := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}

	if _, err := svc.ValidateAPIKey("lxb_" + strings.Repeat("b", 64)); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("ValidateAPIKey on a degraded service = %v, want ErrDBUnavailable", err)
	}
	if _, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "t"}); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("CreateAPIKey on a degraded service = %v, want ErrDBUnavailable", err)
	}
	if err := svc.RevokeAPIKey("nosuch"); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("RevokeAPIKey on a degraded service = %v, want ErrDBUnavailable", err)
	}
	if _, err := svc.ListAPIKeys(""); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("ListAPIKeys on a degraded service = %v, want ErrDBUnavailable", err)
	}
	// The quota reads have no error channel: they report "no limit", which is
	// what an unconfigured tenant reports too. That is deliberate — the key
	// check has already failed closed by the time these run.
	if rps, tpm, burst := svc.GetTenantRateLimit("t"); rps != 0 || tpm != 0 || burst != 0 {
		t.Errorf("GetTenantRateLimit on a degraded service = (%d,%d,%d), want zeroes", rps, tpm, burst)
	}
	if tpm := svc.GetTenantModelRateLimit("t", "m"); tpm != 0 {
		t.Errorf("GetTenantModelRateLimit on a degraded service = %d, want 0", tpm)
	}
}

// configureFromTestDSN points options.Opts at the test store, so the paths
// that build their own connection from configuration — the boot connect and
// the reconnect tick — can actually reach it.
//
// Without this the tick has nothing to dial, and a leg that asks whether it
// reconnects would pass no matter what the code did.
func configureFromTestDSN(t *testing.T) {
	t.Helper()

	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Fatalf("%s is unset", testDSNEnv)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", RedactDSN(dsn), err)
	}
	password, _ := u.User.Password()
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host/port of %s: %v", RedactDSN(dsn), err)
	}

	saved := options.Opts
	savedPw, hadPw := os.LookupEnv(PasswordEnv)
	t.Cleanup(func() {
		options.Opts = saved
		if hadPw {
			os.Setenv(PasswordEnv, savedPw) //nolint:errcheck
		} else {
			os.Unsetenv(PasswordEnv) //nolint:errcheck
		}
	})

	options.Opts.AIKeyDBHost = host
	options.Opts.AIKeyDBPort = port
	options.Opts.AIKeyDBUser = u.User.Username()
	options.Opts.AIKeyDBName = strings.TrimPrefix(u.Path, "/")
	options.Opts.AIKeyDBPasswordPath = ""
	options.Opts.AIKeySSLOption = u.Query().Get("sslmode") == SSLModeVerifyFull
	os.Setenv(PasswordEnv, password) //nolint:errcheck
}

// A store that was down at boot leaves a service with no pool. The tick is the
// only thing that makes it usable afterwards, so it has to both connect and
// provision — a pool that answers ready against a store with no tables would
// fail every statement instead of admitting it was not ready.
func TestTickerHealsADegradedStart(t *testing.T) {
	storeFixture(t) // provisions the store and asserts it is reachable
	configureFromTestDSN(t)

	svc := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}
	if _, err := svc.store(); !errors.Is(err, ErrDBUnavailable) {
		t.Fatalf("fresh service store() = %v, want ErrDBUnavailable", err)
	}

	svc.Ticker()

	if _, err := svc.store(); err != nil {
		t.Fatalf("service still degraded after Ticker: %v", err)
	}
	// Provisioned, not merely connected: a statement against the tables has to
	// work.
	if _, err := svc.ListAPIKeys(""); err != nil {
		t.Fatalf("ListAPIKeys after Ticker healed the service: %v", err)
	}
}

// The tick must not disturb a healthy service: swapping a live pool would
// strand the statements in flight on the old one.
//
// The store configuration is installed first on purpose. Without it the tick
// could not dial even if it tried, and this leg would report success for the
// wrong reason.
func TestTickerKeepsAHealthyPool(t *testing.T) {
	svc := storeFixture(t)
	configureFromTestDSN(t)
	before := poolOf(t, svc)

	svc.Ticker()

	if after := poolOf(t, svc); after != before {
		t.Fatal("Ticker replaced a live pool")
	}
}

// A nil service is what the data plane holds when no store is configured at
// all. The tick runs on every housekeeping pass regardless, so it has to
// tolerate that rather than take the process down with it.
func TestTickerOnNilServiceIsSafe(t *testing.T) {
	var svc *Service
	svc.Ticker()
}

// New must hand back a service that is already safe to publish: the caller
// assigns the pointer and only then dials, so everything that reads the
// pointer during the dial must find a working object that reports the store as
// unavailable. If New were to leave any of these paths nil-dereferencing, the
// caller would be forced back into publishing after the dial — which is the
// arrangement that made a configured store look unconfigured for the whole
// length of the retry loop.
func TestNewIsUsableBeforeConnect(t *testing.T) {
	svc := New()
	if svc == nil {
		t.Fatal("New returned nil")
	}
	if svc.Cache == nil {
		t.Fatal("New returned a service with no cache: cached keys could not validate during a degraded start")
	}
	if _, err := svc.ValidateAPIKey("lxb_" + strings.Repeat("c", 64)); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("ValidateAPIKey before Connect = %v, want ErrDBUnavailable", err)
	}
	if _, err := svc.ListAPIKeys(""); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("ListAPIKeys before Connect = %v, want ErrDBUnavailable", err)
	}
	// ErrDBUnavailable and ErrKeyStoreUnconfigured are different conditions and
	// the API renders them differently. A service that has not connected yet is
	// the first, never the second — the second is reserved for a nil service,
	// which means no store was configured at all.
	if _, err := svc.ListAPIKeys(""); errors.Is(err, cmn.ErrKeyStoreUnconfigured) {
		t.Error("a service that has not connected yet reports itself as unconfigured")
	}
}
