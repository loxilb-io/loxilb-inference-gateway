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

package loxinet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aikey"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestAIObjectiveStrictResolve(t *testing.T) {
	if aiObjectiveStrictResolve(nil, &cmn.LbServiceArg{}) {
		t.Fatal("a rule created without the field is strict")
	}
	if !aiObjectiveStrictResolve(nil, &cmn.LbServiceArg{AIObjectiveStrict: true}) {
		t.Fatal("a rule created strict is not")
	}
	stored := &ruleEnt{aiObjectiveStrict: true}
	if !aiObjectiveStrictResolve(stored, &cmn.LbServiceArg{}) {
		t.Fatal("a replace that does not name the field cleared it")
	}
	if aiObjectiveStrictResolve(stored, &cmn.LbServiceArg{AIObjectiveStrictPresent: true}) {
		t.Fatal("a replace that names the field false kept it true")
	}
	if !aiObjectiveStrictResolve(&ruleEnt{}, &cmn.LbServiceArg{AIObjectiveStrict: true}) {
		t.Fatal("a replace that names the field true left it false")
	}
}

// keyStoreFor stands a key store in for the process's until the test ends.
func keyStoreFor(t *testing.T, svc *aikey.Service) {
	t.Helper()
	prev := mh.AIKeyService.Load()
	mh.AIKeyService.Store(svc)
	t.Cleanup(func() { mh.AIKeyService.Store(prev) })
}

// The source of the class configuration, and the count of intervals served
// from the last-known-good file: nothing without a store, nothing from a
// store that has not been read, and the file - counted - from a store that
// does not answer beside a file it wrote earlier.
func TestAIClassConfigSource(t *testing.T) {
	keyStoreFor(t, nil)
	if got := aiClassConfigSource(); got != cmn.AIClassSourceNone {
		t.Fatalf("source without a key store = %q, want none", got)
	}
	var eff cmn.FcEffectiveArg
	if aiClassStoreHealth(&eff); eff.StoreReachable != nil || eff.StoreLastRead != nil {
		t.Fatalf("store fields without a key store: %v %v", eff.StoreReachable, eff.StoreLastRead)
	}
	if n := aiClassLKGIntervals(); n != 0 {
		t.Fatalf("file intervals without a key store = %d", n)
	}

	keyStoreFor(t, &aikey.Service{})
	if got := aiClassConfigSource(); got != cmn.AIClassSourceNone {
		t.Fatalf("source before anything was read = %q, want none", got)
	}

	dir := t.TempDir()
	file := map[string]interface{}{
		"version": 1, "source_timestamp": time.Now().UTC().Add(-time.Hour),
		"objectives": []cmn.AIObjectiveEntry{{Name: "batch", Priority: -5}},
		"tenants":    map[string]cmn.AIClassPolicy{"t1": {PriorityClass: cmn.AIClassSheddable}},
		"keys":       map[string]cmn.AIClassPolicy{},
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, aikey.ClassLKGFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// A store that was configured and never connected: its first refresh
	// fails and the file is served.
	svc := &aikey.Service{}
	keyStoreFor(t, svc)
	svc.StartClassRefresher(dir)
	deadline := time.Now().Add(5 * time.Second)
	for aiClassConfigSource() != cmn.AIClassSourceLKG {
		if time.Now().After(deadline) {
			t.Fatalf("source = %q after the first refresh of an unreachable store with a file, want lkg", aiClassConfigSource())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for aiClassLKGIntervals() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("an interval served from the file was not counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Served from the file, the store away: the read-back says so, with
	// the time of the read the file was written after.
	eff = cmn.FcEffectiveArg{}
	aiClassStoreHealth(&eff)
	if eff.StoreReachable == nil || *eff.StoreReachable || eff.StoreLastRead == nil ||
		eff.StoreLastRead.Sub(time.Now().UTC().Add(-time.Hour)).Abs() > time.Minute {
		t.Fatalf("store fields served from the file: %v %v", eff.StoreReachable, eff.StoreLastRead)
	}
	if snap := svc.Classes(); snap == nil || snap.Objectives["batch"].Priority != -5 ||
		snap.Tenants["t1"].PriorityClass != cmn.AIClassSheddable {
		t.Fatalf("the file's content is not the snapshot in force: %+v", snap)
	}
}

// classOnFor resets the published switch around a test.
func classOnFor(t *testing.T) {
	t.Helper()
	reset := func() {
		aiClassOnNow.Store(false)
		aiClassOnPublish(false)
	}
	reset()
	t.Cleanup(reset)
}

// Callers on different goroutines (the store's refresher, a REST write, a
// binding commit, a profile change) work out the switch at the same time.
// Whatever the order, the data plane ends holding the value of the state
// that is there when they are done, and Go and the data plane agree.
func TestAIClassRecomputeConcurrent(t *testing.T) {
	classOnFor(t)
	prevProfiles := mh.JWTAuthProfiles
	prevNetid := netidActive.Load()
	prevSrc := aiClassSnapshotSrc
	var cur atomic.Pointer[aikey.ClassSnapshot]
	mh.JWTAuthProfiles = nil
	netidActive.Store(nil)
	aiClassSnapshotSrc = func() *aikey.ClassSnapshot { return cur.Load() }
	t.Cleanup(func() {
		mh.JWTAuthProfiles = prevProfiles
		netidActive.Store(prevNetid)
		aiClassSnapshotSrc = prevSrc
	})
	some := &aikey.ClassSnapshot{Objectives: map[string]cmn.AIObjectiveEntry{"batch": {Name: "batch", Priority: -5}}}
	for round := 0; round < 2000; round++ {
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				if (g+round)%2 == 0 {
					cur.Store(some)
				} else {
					cur.Store(nil)
				}
				aiClassRecompute()
			}(g)
		}
		wg.Wait()
		want := cur.Load() != nil
		if aiClassOnNow.Load() != want || aiClassOnRead() != want {
			t.Fatalf("round %d: switch is %v here and %v in the data plane, want %v", round, aiClassOnNow.Load(), aiClassOnRead(), want)
		}
	}
}

// The switch the data plane reads is on exactly while something could give
// a request a class other than standard: content in the class snapshot, a
// sheddable binding, a sheddable JWT profile. A cap of standard or critical
// alone does not turn it on, and it goes off when the last reason goes.
func TestAIClassRecompute(t *testing.T) {
	classOnFor(t)
	prevProfiles := mh.JWTAuthProfiles
	prevNetid := netidActive.Load()
	t.Cleanup(func() {
		mh.JWTAuthProfiles = prevProfiles
		netidActive.Store(prevNetid)
	})
	profiles := JWTAuthProfileInit()
	defer profiles.Manager().Close()
	mh.JWTAuthProfiles = profiles
	holder, _ := newNidHolder(nidIfs{})
	netidActive.Store(holder)

	want := func(step string, on bool) {
		t.Helper()
		if aiClassOnNow.Load() != on || aiClassOnRead() != on {
			t.Fatalf("%s: switch is %v here and %v in the data plane, want %v", step, aiClassOnNow.Load(), aiClassOnRead(), on)
		}
	}

	classSnapshotFor(t, nil)
	aiClassRecompute()
	want("nothing configured", false)

	classSnapshotFor(t, &aikey.ClassSnapshot{})
	aiClassRecompute()
	want("an empty snapshot", false)

	classSnapshotFor(t, &aikey.ClassSnapshot{Objectives: map[string]cmn.AIObjectiveEntry{"batch": {Name: "batch", Priority: -5}}})
	aiClassRecompute()
	want("one objective", true)

	classSnapshotFor(t, &aikey.ClassSnapshot{Keys: map[string]cmn.AIClassPolicy{"k": {PriorityClass: cmn.AIClassStandard}}})
	aiClassRecompute()
	want("one key with a class field", true)

	classSnapshotFor(t, nil)
	aiClassRecompute()
	want("the snapshot gone again", false)

	// Bindings: the holder recomputes on every commit.
	b := nidCIDR("line-std", "t1", []string{"10.20.0.0/24"})
	mustAdd(t, holder, b)
	want("a binding at the default class", false)
	crit := nidCIDR("line-crit", "t2", []string{"10.21.0.0/24"})
	crit.PriorityClass = cmn.AIClassCritical
	mustAdd(t, holder, crit)
	want("a critical binding", false)
	shed := nidCIDR("line-shed", "t3", []string{"10.22.0.0/24"})
	shed.PriorityClass = cmn.AIClassSheddable
	mustAdd(t, holder, shed)
	want("a sheddable binding", true)
	if got := netidClassOf("line-shed"); got != cmn.AIClassSheddable {
		t.Fatalf("class of the sheddable binding = %q", got)
	}
	if got := netidClassOf("line-std"); got != cmn.AIClassStandard {
		t.Fatalf("class of a binding that set none = %q, want the default standard", got)
	}
	if got := netidClassOf("line-crit"); got != cmn.AIClassCritical {
		t.Fatalf("class of the critical binding = %q", got)
	}
	if netidClassOf("no-such-binding") != "" || netidClassOf("") != "" {
		t.Fatal("a binding that does not exist has a class")
	}
	if _, err := holder.BindingDel("line-shed"); err != nil {
		t.Fatal(err)
	}
	want("the sheddable binding deleted", false)
	if netidClassOf("line-shed") != "" {
		t.Fatal("a deleted binding still has a class")
	}

	// JWT profiles.
	std := testJWTProfileMod("kc-std")
	std.PriorityClass = cmn.AIClassStandard
	if _, err := profiles.ProfileAdd(&std); err != nil {
		t.Fatal(err)
	}
	plain := testJWTProfileMod("kc-plain")
	if _, err := profiles.ProfileAdd(&plain); err != nil {
		t.Fatal(err)
	}
	want("a standard profile and one without a class", false)
	if profiles.ProfileClass("kc-std") != cmn.AIClassStandard || profiles.ProfileClass("kc-plain") != "" ||
		profiles.ProfileClass("no-such-profile") != "" || profiles.ProfileClass("") != "" {
		t.Fatalf("profile classes: std=%q plain=%q", profiles.ProfileClass("kc-std"), profiles.ProfileClass("kc-plain"))
	}
	var none *JWTAuthProfileH
	if none.ProfileClass("kc-std") != "" {
		t.Fatal("a nil profile holder has a class")
	}
	shedProf := testJWTProfileMod("kc-shed")
	shedProf.PriorityClass = cmn.AIClassSheddable
	if _, err := profiles.ProfileAdd(&shedProf); err != nil {
		t.Fatal(err)
	}
	want("a sheddable profile", true)
	// Replaced without the class: off again.
	shedProf.PriorityClass = ""
	if _, err := profiles.ProfileAdd(&shedProf); err != nil {
		t.Fatal(err)
	}
	want("the profile replaced without its class", false)
	shedProf.PriorityClass = cmn.AIClassSheddable
	if _, err := profiles.ProfileAdd(&shedProf); err != nil {
		t.Fatal(err)
	}
	want("sheddable again", true)
	if _, err := profiles.ProfileDel("kc-shed"); err != nil {
		t.Fatal(err)
	}
	want("the sheddable profile deleted", false)

	bad := testJWTProfileMod("kc-bad")
	bad.PriorityClass = "urgent"
	if _, err := profiles.ProfileAdd(&bad); err == nil {
		t.Fatal("a profile with an unknown class was accepted")
	}
}
