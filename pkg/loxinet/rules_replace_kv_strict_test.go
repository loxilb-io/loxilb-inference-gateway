/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// A strict KV-exact rule whose data-plane pool is created again by a replace:
// the new pool starts without the contract word, and a request reaching it
// before the word is back would run the path of a rule without a contract.
// So the rule is fenced again at once (the tokenize bridge answers not-ready)
// and the word is installed again (eligible 0, full ACK) before attestation
// lets it serve on the strict path. A pool that is refreshed keeps its word
// and is not fenced. A rule without a contract is not touched.

type kvRecSetter struct {
	mu    sync.Mutex
	calls []uint8 // eligible of each call
}

func (s *kvRecSetter) fn(_ net.IP, _ uint16, _ uint8, gen uint32, apiMode, eligible uint8) (uint64, bool) {
	s.mu.Lock()
	s.calls = append(s.calls, eligible)
	s.mu.Unlock()
	return KvContractPack(gen, 0, apiMode, eligible), true
}

func (s *kvRecSetter) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func kvRecSetterInstall(t *testing.T) *kvRecSetter {
	t.Helper()
	s := &kvRecSetter{}
	prev := kvContractSetter_get()
	KvRegisterContractSetter(s.fn)
	t.Cleanup(func() { KvRegisterContractSetter(prev) })
	return s
}

func TestKvStrictPoolRecreatedFencesAndReinstalls(t *testing.T) {
	kvDataplaneTestSetup(t)
	s := kvRecSetterInstall(t)
	kvTestRegister(61, "rule-recreate", KvContractAPIBoth)
	b, err := KvBindingAllocate("rule-recreate", kvTestComponents(1))
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := kvDataplaneContractInstall(61, s.fn, 3, 0); err != nil || kvSvcDenied(61) {
		t.Fatalf("set-up: install ACK must clear the fence (err %v, denied %v)", err, kvSvcDenied(61))
	}
	before := s.n()

	kvStrictPoolRecreated(61)

	if !kvSvcDenied(61) {
		t.Errorf("after the pool was created again the rule is not fenced")
	}
	if rc := kvBridgeGate(61, 0); rc != KvTokErrNotReady {
		t.Errorf("a request reaching the new pool (no contract word, generation 0) is let through: gate %d, want not-ready", rc)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.n() == before {
		time.Sleep(20 * time.Millisecond)
	}
	if s.n() == before {
		t.Fatalf("the contract word was not installed again")
	}
	s.mu.Lock()
	last := s.calls[len(s.calls)-1]
	s.mu.Unlock()
	if last != 0 {
		t.Errorf("the word was installed again with eligible=%d; only attestation may write eligible=1", last)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && kvSvcDenied(61) {
		time.Sleep(20 * time.Millisecond)
	}
	if kvSvcDenied(61) {
		t.Errorf("the fence was not lifted by the install ACK")
	}
	if rc := kvBridgeGate(61, b.BindingGen); rc != 0 {
		t.Errorf("after the install ACK the gate refuses the current generation: %d", rc)
	}
}

func TestKvStrictPoolRecreatedLeavesRuleWithoutContract(t *testing.T) {
	kvDataplaneTestSetup(t)
	s := kvRecSetterInstall(t)
	kvStrictPoolRecreated(62)
	time.Sleep(500 * time.Millisecond)
	if kvSvcDenied(62) {
		t.Errorf("a rule without a contract was fenced")
	}
	if s.n() != 0 {
		t.Errorf("a contract word was written for a rule without a contract (%d calls)", s.n())
	}
}

// A strict rule that is already fenced for a reason of its own keeps that
// fence when its pool is created again: a rule restored without a profile
// (no binding; only a migration lifts its fence) and a rule restored with a
// profile the registry cannot resolve (binding kept, install withheld until
// the registry is repaired). Nothing is installed for either, and the fence
// and its recorded fault stay as they were.
func TestKvStrictPoolRecreatedLeavesRestoredFenceAlone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding bool
	}{
		{"restored without a profile", false},
		{"restored with an unresolved profile", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kvDataplaneTestSetup(t)
			s := kvRecSetterInstall(t)
			kvTestRegister(63, "rule-restored", KvContractAPIBoth)
			if tc.binding {
				if _, err := KvBindingAllocate("rule-restored", kvTestComponents(1)); err != nil {
					t.Fatalf("allocate: %v", err)
				}
			}
			before, _ := KvSvcContractEnforcement(63)
			if !before.GoFenced {
				t.Fatalf("set-up: a restored rule is registered fenced")
			}

			kvStrictPoolRecreated(63)
			time.Sleep(time.Second)

			after, _ := KvSvcContractEnforcement(63)
			if !after.GoFenced {
				t.Errorf("the restored rule's fence was lifted by the re-create")
			}
			if after.Fault != before.Fault {
				t.Errorf("the recorded fault changed: %q, was %q", after.Fault, before.Fault)
			}
			if s.n() != 0 {
				t.Errorf("a contract word was installed for a restored, fenced rule (%d calls)", s.n())
			}
		})
	}
}

// kvPoolFake is a data plane whose rule gets a new pool, without the word,
// at each re-create; the setter writes the word into the pool that is
// current when it is called. A pool's install can be held (delayed) or made
// to fail, and its acknowledgement can be held after the word is written.
type kvPoolFake struct {
	mu      sync.Mutex
	words   []uint64
	hold    map[int]chan struct{}
	entered map[int]chan struct{}
	ackHold map[int]chan struct{}
	written map[int]chan struct{}
	fail    map[int]bool
	tries   map[int]int
	elig1   int // setter calls with eligible 1 (attestation's write)
}

func newKvPoolFake() *kvPoolFake {
	return &kvPoolFake{words: []uint64{0}, hold: map[int]chan struct{}{},
		entered: map[int]chan struct{}{}, ackHold: map[int]chan struct{}{},
		written: map[int]chan struct{}{}, fail: map[int]bool{}, tries: map[int]int{}}
}

func (f *kvPoolFake) newPool() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.words = append(f.words, 0)
	return len(f.words) - 1
}

func (f *kvPoolFake) latestWord() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.words[len(f.words)-1]
}

func (f *kvPoolFake) latestPool() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.words) - 1
}

func (f *kvPoolFake) attempts(pool int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tries[pool]
}

func (f *kvPoolFake) fn(_ net.IP, _ uint16, _ uint8, gen uint32, apiMode, eligible uint8) (uint64, bool) {
	f.mu.Lock()
	idx := len(f.words) - 1
	f.tries[idx]++
	if eligible == 1 {
		f.elig1++
	}
	hold, entered, fail := f.hold[idx], f.entered[idx], f.fail[idx]
	if entered != nil {
		close(entered)
		f.entered[idx] = nil
	}
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if fail {
		return 0, false
	}
	w := KvContractPack(gen, 0, apiMode, eligible)
	f.mu.Lock()
	f.words[idx] = w
	ack, written := f.ackHold[idx], f.written[idx]
	if written != nil {
		close(written)
		f.written[idx] = nil
	}
	f.mu.Unlock()
	if ack != nil {
		<-ack
	}
	return w, true
}

// kvRecreateRun drives a strict rule through re-creates on a kvPoolFake and
// watches, all along, that the rule is never unfenced while its current pool
// has no word. step(i) runs before re-create i (1-based) and may hold or
// fail that pool's install.
func kvRecreateRun(t *testing.T, n int, plan func(f *kvPoolFake, i, pool int), between func(f *kvPoolFake, i, pool int)) *kvPoolFake {
	t.Helper()
	return kvRecreateRunPre(t, n, nil, plan, between)
}

// kvRecreateRunPre is kvRecreateRun with pre run once the rule is installed,
// before the first re-create (the watcher already looking).
func kvRecreateRunPre(t *testing.T, n int, pre func(f *kvPoolFake), plan func(f *kvPoolFake, i, pool int), between func(f *kvPoolFake, i, pool int)) *kvPoolFake {
	t.Helper()
	kvDataplaneTestSetup(t)
	f := newKvPoolFake()
	prev := kvContractSetter_get()
	KvRegisterContractSetter(f.fn)
	t.Cleanup(func() { KvRegisterContractSetter(prev) })
	kvTestRegister(64, "rule-recreated", KvContractAPIBoth)
	if _, err := KvBindingAllocate("rule-recreated", kvTestComponents(1)); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := kvDataplaneContractInstall(64, f.fn, 3, 0); err != nil || kvSvcDenied(64) {
		t.Fatalf("set-up: install ACK must clear the fence (err %v)", err)
	}

	var step sync.Mutex // a re-create (new pool + the call) is one step for the watcher
	var bad []string
	var badMu sync.Mutex
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case <-stop:
				return
			default:
			}
			step.Lock()
			if f.latestWord() == 0 && !kvSvcDenied(64) {
				badMu.Lock()
				if len(bad) < 3 {
					bad = append(bad, fmt.Sprintf("pool %d has no word and the rule is not fenced", f.latestPool()))
				}
				badMu.Unlock()
			}
			step.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()

	if pre != nil {
		pre(f)
	}
	for i := 1; i <= n; i++ {
		step.Lock()
		pool := f.newPool()
		plan(f, i, pool)
		kvStrictPoolRecreated(64)
		step.Unlock()
		if between != nil {
			between(f, i, pool)
		}
	}
	// let every install settle: no setter call for a second
	last := -1
	for k := 0; k < 100; k++ {
		f.mu.Lock()
		total := 0
		for _, c := range f.tries {
			total += c
		}
		f.mu.Unlock()
		if total == last {
			break
		}
		last = total
		time.Sleep(time.Second)
	}
	close(stop)
	<-watched
	for _, b := range bad {
		t.Errorf("%s", b)
	}
	return f
}

// Two re-creates in quick succession: the first install is held until the
// second has failed. The first install then completes on a pool that is
// already gone; that must not lift the fence the second re-create set.
func TestKvStrictRecreateTwiceLateFirstInstall(t *testing.T) {
	release := make(chan struct{})
	f := kvRecreateRun(t, 2, func(f *kvPoolFake, i, pool int) {
		if i == 1 {
			f.hold[pool], f.entered[pool] = release, make(chan struct{})
		} else {
			f.fail[pool] = true
		}
	}, func(f *kvPoolFake, i, pool int) {
		if i == 1 {
			f.mu.Lock()
			ch := f.entered[pool]
			f.mu.Unlock()
			if ch != nil {
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					t.Fatalf("the first install never started")
				}
			}
		}
		if i == 2 {
			for k := 0; k < 100 && f.attempts(pool) < 20; k++ {
				time.Sleep(100 * time.Millisecond)
			}
			close(release)
		}
	})
	if f.latestWord() == 0 && !kvSvcDenied(64) {
		t.Errorf("afterwards: the current pool has no word and the rule is not fenced")
	}
	if !kvSvcDenied(64) {
		t.Errorf("afterwards: the rule is not fenced although the current pool's install failed")
	}
}

// Three re-creates: the first install held, the second failing, the third
// working. Afterwards the third pool has its word and the rule is released,
// and in between the rule was never unfenced with a pool without a word.
func TestKvStrictRecreateThreeTimes(t *testing.T) {
	release := make(chan struct{})
	f := kvRecreateRun(t, 3, func(f *kvPoolFake, i, pool int) {
		switch i {
		case 1:
			f.hold[pool], f.entered[pool] = release, make(chan struct{})
		case 2:
			f.fail[pool] = true
		}
	}, func(f *kvPoolFake, i, pool int) {
		switch i {
		case 1:
			f.mu.Lock()
			ch := f.entered[pool]
			f.mu.Unlock()
			if ch != nil {
				select {
				case <-ch:
				case <-time.After(5 * time.Second):
					t.Fatalf("the first install never started")
				}
			}
		case 2:
			for k := 0; k < 100 && f.attempts(pool) < 20; k++ {
				time.Sleep(100 * time.Millisecond)
			}
			time.Sleep(200 * time.Millisecond)
		case 3:
			time.Sleep(500 * time.Millisecond)
			close(release)
		}
	})
	if f.latestWord() == 0 {
		t.Errorf("afterwards: the third pool never got its word")
	}
	if f.latestWord() != 0 && kvSvcDenied(64) {
		t.Errorf("afterwards: the third pool has its word but the rule is still fenced")
	}
}

// Two re-creates: the first install writes its word on the first pool, and
// its acknowledgement comes back only after the second re-create has fenced
// the rule and the second pool's install is under way. That late
// acknowledgement is for a pool that is gone and must not lift the fence;
// the second pool's install does, once it has its word.
func TestKvStrictRecreateFirstAckAfterSecond(t *testing.T) {
	ack1, hold2 := make(chan struct{}), make(chan struct{})
	f := kvRecreateRun(t, 2, func(f *kvPoolFake, i, pool int) {
		if i == 1 {
			f.ackHold[pool], f.written[pool] = ack1, make(chan struct{})
		} else {
			f.hold[pool], f.entered[pool] = hold2, make(chan struct{})
		}
	}, func(f *kvPoolFake, i, pool int) {
		f.mu.Lock()
		ch := f.written[pool]
		if i == 2 {
			ch = f.entered[pool]
		}
		f.mu.Unlock()
		if i == 2 {
			close(ack1)
		}
		if ch != nil {
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				t.Fatalf("the install of pool %d never got that far", pool)
			}
		}
		if i == 2 {
			time.Sleep(300 * time.Millisecond) // the watcher looks while pool 2 has no word
			close(hold2)
		}
	})
	if f.latestWord() == 0 {
		t.Errorf("afterwards: the second pool never got its word")
	}
	if f.latestWord() != 0 && kvSvcDenied(64) {
		t.Errorf("afterwards: the second pool has its word but the rule is still fenced")
	}
}

func kvWaitClosed(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never happened", what)
	}
}

func kvSvcFault(svcID uint32) string {
	kvSvcMu.RLock()
	defer kvSvcMu.RUnlock()
	if c := kvSvcContracts[svcID]; c != nil {
		return c.fault
	}
	return ""
}

// An attestation write (eligible 1, outside any re-create) is acknowledged
// only after a re-create has fenced the rule and the new pool's install is
// under way. The acknowledgement is for the pool that is gone: it is refused,
// and the fence stays until the new pool has its word.
func TestKvStrictAttestAckDuringRecreate(t *testing.T) {
	ack0, hold1 := make(chan struct{}), make(chan struct{})
	res := make(chan error, 1)
	f := kvRecreateRunPre(t, 1, func(f *kvPoolFake) {
		f.mu.Lock()
		w := make(chan struct{})
		f.ackHold[0], f.written[0] = ack0, w
		f.mu.Unlock()
		go func() { res <- kvDataplaneContractApply(64, f.fn, 1, 0, 1) }()
		kvWaitClosed(t, w, "the attestation write")
	}, func(f *kvPoolFake, i, pool int) {
		f.hold[pool], f.entered[pool] = hold1, make(chan struct{})
	}, func(f *kvPoolFake, i, pool int) {
		f.mu.Lock()
		e := f.entered[pool]
		f.mu.Unlock()
		close(ack0)
		kvWaitClosed(t, e, "the new pool's install")
		time.Sleep(300 * time.Millisecond)
		close(hold1)
	})
	if err := <-res; err == nil {
		t.Errorf("the attestation acknowledged during the re-create lifted the fence (no error)")
	}
	if f.latestWord() == 0 || kvSvcDenied(64) {
		t.Errorf("afterwards: the new pool's word %#x, fenced %v; want the word and released", f.latestWord(), kvSvcDenied(64))
	}
}

// A re-create whose install fails for good leaves the rule fenced; a later
// install outside a re-create (attestation, a restore's kick) that succeeds
// releases it.
func TestKvStrictReleasedAfterFailedRecreate(t *testing.T) {
	f := kvRecreateRun(t, 1, func(f *kvPoolFake, i, pool int) {
		f.fail[pool] = true
	}, nil)
	if !kvSvcDenied(64) {
		t.Fatalf("the rule is not fenced although the re-create's install failed")
	}
	last := f.latestPool()
	f.mu.Lock()
	f.fail[last] = false
	f.mu.Unlock()
	if err := kvDataplaneContractApply(64, f.fn, 1, 0, 0); err != nil || kvSvcDenied(64) {
		t.Errorf("an install after the failed re-create: err %v, fenced %v; want released", err, kvSvcDenied(64))
	}
}

// A superseded re-create's install that keeps retrying must stop: it must
// not write its word (eligible 0) over the word attestation wrote on the
// current pool.
func TestKvStrictStaleInstallLeavesAttestedWord(t *testing.T) {
	hold1 := make(chan struct{})
	var attested uint64
	f := kvRecreateRun(t, 2, func(f *kvPoolFake, i, pool int) {
		if i == 1 {
			f.hold[pool], f.entered[pool], f.fail[pool] = hold1, make(chan struct{}), true
		}
	}, func(f *kvPoolFake, i, pool int) {
		f.mu.Lock()
		e := f.entered[pool]
		f.mu.Unlock()
		if i == 1 {
			kvWaitClosed(t, e, "the first install")
			return
		}
		close(hold1)
		// the first install retries 200ms after its failure; attestation
		// writes as soon as the second install has released the rule
		for k := 0; k < 5000 && (kvSvcDenied(64) || f.latestWord() == 0); k++ {
			time.Sleep(time.Millisecond)
		}
		if err := kvDataplaneContractApply(64, f.fn, 1, 0, 1); err != nil {
			t.Fatalf("the attestation write: %v", err)
		}
		attested = f.latestWord()
		time.Sleep(1500 * time.Millisecond) // the first install's retries
	})
	if got := f.latestWord(); got != attested {
		t.Errorf("the current pool's word went from %#x (attested) to %#x", attested, got)
	}
}

// A superseded re-create's install that fails records no fault on the rule:
// the rule's state is the latest re-create's.
func TestKvStrictStaleFailureRecordsNoFault(t *testing.T) {
	hold1, hold2 := make(chan struct{}), make(chan struct{})
	var fault string
	kvRecreateRun(t, 2, func(f *kvPoolFake, i, pool int) {
		if i == 1 {
			f.hold[pool], f.entered[pool], f.fail[pool] = hold1, make(chan struct{}), true
		} else {
			f.hold[pool], f.entered[pool] = hold2, make(chan struct{})
		}
	}, func(f *kvPoolFake, i, pool int) {
		f.mu.Lock()
		e := f.entered[pool]
		f.mu.Unlock()
		if i == 1 {
			kvWaitClosed(t, e, "the first install")
			return
		}
		close(hold1)
		kvWaitClosed(t, e, "the second install")
		fault = kvSvcFault(64)
		close(hold2)
	})
	if fault != "" {
		t.Errorf("while the second install ran, the rule carried the fault %q of the first", fault)
	}
}

func (f *kvPoolFake) eligibleWrites() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elig1
}

// While a re-create of the rule's pool is running, an install outside it
// (attestation writing eligible 1) does not reach the data plane: it returns
// errKvRecreateRunning without a setter call.
func TestKvStrictAttestNoWriteDuringRecreate(t *testing.T) {
	var err error
	var writes int
	kvRecreateRun(t, 1, func(f *kvPoolFake, i, pool int) {
		f.fail[pool] = true // the re-create's install keeps retrying
	}, func(f *kvPoolFake, i, pool int) {
		for k := 0; k < 50 && f.attempts(pool) < 2; k++ {
			time.Sleep(50 * time.Millisecond)
		}
		before := f.eligibleWrites()
		err = kvDataplaneContractApply(64, f.fn, 1, 0, 1)
		writes = f.eligibleWrites() - before
	})
	if writes != 0 {
		t.Errorf("attestation's eligible-1 write reached the setter %d time(s) while the re-create ran", writes)
	}
	if !errors.Is(err, errKvRecreateRunning) {
		t.Errorf("attestation's write during the re-create returned %v, want errKvRecreateRunning", err)
	}
}

// Attestation meeting a running re-create publishes no fault: neither on its
// fence-first step nor on the eligible-1 flip.
func TestKvAttestRecreateRunningIsNoFault(t *testing.T) {
	for _, row := range []struct {
		name string
		at   int // apply call that meets the re-create: 1 fence, 2 flip
	}{{"fence-first step", 1}, {"eligible-1 flip", 2}} {
		t.Run(row.name, func(t *testing.T) {
			h := newAttestHarness(t)
			var faults int
			kvAttestFaultGaugeFn = func(rule string, fault bool) {
				if fault {
					faults++
				}
			}
			h.rec.applyErrAt[row.at] = errKvRecreateRunning
			c := h.controller()
			c.fenceAndReattest("activation")
			if c.enforced == KvExactStateEnforcementFault || faults != 0 {
				t.Errorf("enforced %s, fault gauge raised %d time(s); want no fault (events %v)", c.enforced, faults, h.rec.list())
			}
		})
	}
}

// kvAttestStartFor starts a controller for svcID whose apply is the real
// contract transaction on the fake data plane, and waits until it is READY.
func kvAttestStartFor(t *testing.T, svcID uint32, f *kvPoolFake) *kvAttestController {
	t.Helper()
	h := newAttestHarness(t)
	h.info.svcID = svcID
	h.deps.apply = func(svc uint32, eligible uint8) error {
		return kvDataplaneContractApply(svc, f.fn, 3, 0, eligible)
	}
	c := KvAttestStart(h.info, h.deps)
	t.Cleanup(func() {
		KvAttestStop(svcID)
		c.wg.Wait() // the loop's last publish before the harness restores the gauges
	})
	for k := 0; k < 100; k++ {
		_, enforced, _, _ := KvAttestStatus(svcID)
		if enforced == KvExactStateReady {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, enforced, reasons, _ := KvAttestStatus(svcID)
	t.Fatalf("the controller never reached READY: %s %v", enforced, reasons)
	return nil
}

// A re-create whose install fails for good leaves the rule in a visible
// fault: its controller publishes ENFORCEMENT_FAULT.
func TestKvStrictRecreateFailedInstallIsFault(t *testing.T) {
	kvRecreateRunPre(t, 1, func(f *kvPoolFake) {
		kvAttestStartFor(t, 64, f)
	}, func(f *kvPoolFake, i, pool int) {
		f.fail[pool] = true
	}, nil)
	var enforced string
	for k := 0; k < 100; k++ {
		if _, enforced, _, _ = KvAttestStatus(64); enforced == KvExactStateEnforcementFault {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if enforced != KvExactStateEnforcementFault {
		t.Errorf("after the re-create's install failed for good the rule is %s, want ENFORCEMENT_FAULT", enforced)
	}
	_, _, reasons, _ := KvAttestStatus(64)
	if strings.Join(reasons, ",") != KvAttestReasonEnforcementFault+","+KvAttestReasonBindingDataplanePending {
		t.Errorf("fault reasons %v, want [%s %s] (published vocabulary only)", reasons, KvAttestReasonEnforcementFault, KvAttestReasonBindingDataplanePending)
	}
	if !kvSvcDenied(64) {
		t.Errorf("the rule is not fenced although its pool has no word")
	}
}

// After the re-create's install failed for good, it is tried again: once the
// data plane takes the word, the rule's pool has it and the fence is lifted.
func TestKvStrictRecreateFailedInstallRetried(t *testing.T) {
	prev := kvRecreateRetryNs.Load()
	kvRecreateRetryNs.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { kvRecreateRetryNs.Store(prev) })
	f := kvRecreateRun(t, 1, func(f *kvPoolFake, i, pool int) {
		f.fail[pool] = true
	}, nil)
	if !kvSvcDenied(64) {
		t.Fatalf("the rule is not fenced although the re-create's install failed")
	}
	last := f.latestPool()
	f.mu.Lock()
	f.fail[last] = false
	f.mu.Unlock()
	for k := 0; k < 100 && (kvSvcDenied(64) || f.latestWord() == 0); k++ {
		time.Sleep(20 * time.Millisecond)
	}
	if f.latestWord() == 0 || kvSvcDenied(64) {
		t.Errorf("no retry after the failed install: word %#x, fenced %v", f.latestWord(), kvSvcDenied(64))
	}
}

// A strict rule already fenced for a reason of its own is left as it is by a
// re-create: one whose install is not acknowledged yet, and one fenced by a
// fault. No re-create state, no setter call, the fence and fault unchanged.
func TestKvStrictPoolRecreatedLeavesOwnFenceAlone(t *testing.T) {
	for _, row := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"install not yet acknowledged", func(t *testing.T) {}},
		{"fenced by a fault", func(t *testing.T) {
			fail := func(net.IP, uint16, uint8, uint32, uint8, uint8) (uint64, bool) { return 0, false }
			if err := kvDataplaneContractInstall(64, fail, 1, 0); err == nil {
				t.Fatalf("set-up: the failing install succeeded")
			}
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			kvDataplaneTestSetup(t)
			kvTestRegister(64, "rule-own-fence", KvContractAPIBoth)
			if _, err := KvBindingAllocate("rule-own-fence", kvTestComponents(1)); err != nil {
				t.Fatalf("allocate: %v", err)
			}
			row.setup(t)
			s := kvRecSetterInstall(t)
			fault := kvSvcFault(64)
			if !kvSvcDenied(64) {
				t.Fatalf("set-up: the rule is not fenced")
			}
			kvStrictPoolRecreated(64)
			time.Sleep(500 * time.Millisecond)
			kvSvcMu.RLock()
			st := kvSvcRecreating[64]
			kvSvcMu.RUnlock()
			if st != nil {
				t.Errorf("a re-create state was taken for a rule fenced for a reason of its own")
			}
			if n := s.n(); n != 0 {
				t.Errorf("the re-create wrote the word %d time(s)", n)
			}
			if !kvSvcDenied(64) || kvSvcFault(64) != fault {
				t.Errorf("fence %v fault %q after the re-create, want fenced with %q", kvSvcDenied(64), kvSvcFault(64), fault)
			}
		})
	}
}

// AddLbRule asks for it after every pool removal of a replace and after the
// undo that creates a removed pool again; nowhere else (a refreshed pool is
// not fenced).
func TestKvStrictReplaceWired(t *testing.T) {
	add := addLbRuleBody(t)
	i := strings.Index(add, "chwblTxn :=")
	if i < 0 {
		t.Fatal("chwblTxn not found in AddLbRule")
	}
	rep := lineComment.ReplaceAllString(add[i:], "")
	call := "kvStrictPoolRecreated(uint32(eRule.ruleNum))"
	removals := regexp.MustCompile(`eRule\.DP\(DpRemove\)[^\n]*\n[^\n]*\n?[^\n]*`).FindAllString(rep, -1)
	if len(removals) == 0 {
		t.Fatal("no pool removal found in the replace")
	}
	for _, m := range removals {
		if !strings.Contains(m, call) {
			t.Errorf("a pool removal is not followed by %s: %s", call, strings.TrimSpace(m))
		}
	}
	u := strings.Index(rep, "R.lbReplaceUndo(eRule, replaceUndo, activateProbe)")
	if u < 0 {
		t.Fatal("the undo of a refused push not found")
	}
	if !strings.Contains(rep[u:u+400], call) {
		t.Errorf("the undo that creates a removed pool again is not followed by %s", call)
	}
	if got, want := strings.Count(rep, call), len(removals)+1; got != want {
		t.Errorf("%s is called %d times in the replace, want %d (each removal and the undo, nowhere else)", call, got, want)
	}
}
