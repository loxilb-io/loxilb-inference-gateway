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

package opa

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "state.json")

	cache := NewRuleCache(fp)
	key := DiffKey("10.0.0.1/32|10.0.0.2/32|6|0|0|0|0|100")
	rule := cmn.FwRuleArg{SrcIP: "10.0.0.1/32", DstIP: "10.0.0.2/32", Proto: 6, Pref: 100}
	opt := cmn.FwOptArg{Drop: true}

	cache.Set(key, rule, opt)

	if err := cache.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load into a fresh cache
	cache2 := NewRuleCache(fp)
	if err := cache2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	rules := cache2.GetAllRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after load, got %d", len(rules))
	}
	loaded, ok := rules[key]
	if !ok {
		t.Fatalf("expected key %s in loaded rules", key)
	}
	if loaded.SrcIP != rule.SrcIP || loaded.DstIP != rule.DstIP || loaded.Proto != rule.Proto || loaded.Pref != rule.Pref {
		t.Errorf("loaded rule mismatch: got %+v, want %+v", loaded, rule)
	}

	opts := cache2.GetAllOpts()
	if len(opts) != 1 {
		t.Fatalf("expected 1 opt after load, got %d", len(opts))
	}
	loadedOpt, ok := opts[key]
	if !ok {
		t.Fatalf("expected key %s in loaded opts", key)
	}
	if loadedOpt.Drop != opt.Drop {
		t.Errorf("loaded opt mismatch: got %+v, want %+v", loadedOpt, opt)
	}
}

func TestCacheLoadNonExistentFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "does_not_exist.json")

	cache := NewRuleCache(fp)
	err := cache.Load()
	if err != nil {
		t.Errorf("Load on non-existent file should return nil, got %v", err)
	}

	rules := cache.GetAllRules()
	if len(rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(rules))
	}
}

func TestCacheLoadCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "corrupt.json")

	if err := os.WriteFile(fp, []byte("{this is not valid json!!!}"), 0644); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	cache := NewRuleCache(fp)
	err := cache.Load()
	if err != nil {
		t.Errorf("Load on corrupt JSON should return nil, got %v", err)
	}

	rules := cache.GetAllRules()
	if len(rules) != 0 {
		t.Errorf("expected empty rules after corrupt load, got %d", len(rules))
	}
}

func TestCacheDeleteKey(t *testing.T) {
	cache := NewRuleCache("")
	key := DiffKey("test-key")
	cache.Set(key, cmn.FwRuleArg{SrcIP: "1.2.3.4/32"}, cmn.FwOptArg{Allow: true})

	if cache.Len() != 1 {
		t.Fatalf("expected 1 rule, got %d", cache.Len())
	}

	cache.Delete(key)

	if cache.Len() != 0 {
		t.Errorf("expected 0 rules after delete, got %d", cache.Len())
	}

	opts := cache.GetAllOpts()
	if len(opts) != 0 {
		t.Errorf("expected 0 opts after delete, got %d", len(opts))
	}
}

func TestCacheConcurrentSafety(t *testing.T) {
	cache := NewRuleCache("")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			key := DiffKey("key-" + string(rune('A'+n%26)))
			cache.Set(key, cmn.FwRuleArg{Proto: uint8(n % 256)}, cmn.FwOptArg{})
		}(i)
		go func() {
			defer wg.Done()
			_ = cache.GetAllRules()
			_ = cache.GetAllOpts()
		}()
	}

	wg.Wait()

	// No panic means the concurrent access is safe
	if cache.Len() < 1 {
		t.Errorf("expected at least 1 rule after concurrent writes, got %d", cache.Len())
	}
}

func TestCacheGetAllReturnsDeepCopy(t *testing.T) {
	cache := NewRuleCache("")
	key := DiffKey("test-key")
	cache.Set(key, cmn.FwRuleArg{SrcIP: "1.2.3.4/32"}, cmn.FwOptArg{Allow: true})

	rules := cache.GetAllRules()
	// Mutate the returned copy
	rules[DiffKey("extra")] = cmn.FwRuleArg{SrcIP: "5.6.7.8/32"}

	// Original should be unaffected
	if cache.Len() != 1 {
		t.Errorf("modifying returned map should not affect cache, got len %d", cache.Len())
	}
}
