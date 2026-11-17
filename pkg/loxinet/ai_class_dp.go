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

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ai_gw_class_t comes from the datapath header (see ai_gw_exports.h).
#include "ai_gw_exports.h"
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/loxilb-io/loxilb/pkg/aikey"
)

// llb_ai_class_resolve decides the class of a request whose tenant is
// known. The admission gate calls it at most once per request, and only
// while classes are configured (aiClassRecompute).
//
// Parameters:
//
//	tenant        – the request's tenant
//	keyID         – its API key's id ("" when no key decided it)
//	binding       – the network-identity binding that named the tenant ("")
//	profile       – the JWT profile that verified its token ("")
//	svcIdent      – the service identity, "VIP:port"
//	objectiveHint – the objective name the request's header asks for ("")
//	tierHint      – the body's service_tier as AI_TIER_* (0 = none)
//	out           – the answer; zeroed here before anything is written
//
// Returns 0 when it answered and -1 when it could not. It reads immutable
// snapshots and takes no lock.
//
//export llb_ai_class_resolve
func llb_ai_class_resolve(tenant *C.char, keyID *C.char, binding *C.char, profile *C.char,
	svcIdent *C.char, objectiveHint *C.char, tierHint C.int, out *C.ai_gw_class_t) (ret C.int) {
	if out == nil {
		return -1
	}
	*out = C.ai_gw_class_t{}
	defer func() {
		if r := recover(); r != nil {
			*out = C.ai_gw_class_t{}
			ret = -1
		}
	}()
	in := classInput{
		tenant: C.GoString(tenant),
		keyID:  C.GoString(keyID),
		svc:    C.GoString(svcIdent),
		hint:   C.GoString(objectiveHint),
		tier:   int(tierHint),
	}
	if b := C.GoString(binding); b != "" {
		in.bindingClass = netidClassOf(b)
	}
	if p := C.GoString(profile); p != "" {
		in.profileClass = mh.JWTAuthProfiles.ProfileClass(p)
	}
	ans := classResolve(aiClassSnapshot(), in)
	out.priority = C.int32_t(ans.priority)
	out.priority_class = C.uint8_t(ans.class)
	if ans.denied {
		out.objective_denied = 1
	}
	cCopyStr((*C.char)(unsafe.Pointer(&out.objective[0])), ans.objective, 64)
	return 0
}

// aiClassSnapshot is the store's class snapshot, nil with no store or
// before anything was read.
func aiClassSnapshot() *aikey.ClassSnapshot {
	return aiClassSnapshotSrc()
}

// aiClassSnapshotSrc is where the snapshot is read from. A variable so the
// package's tests can stand a snapshot in without a store.
var aiClassSnapshotSrc = func() *aikey.ClassSnapshot {
	if svc := mh.AIKeyService.Load(); svc != nil {
		return svc.Classes()
	}
	return nil
}

// aiClassResolveC calls llb_ai_class_resolve with C arguments, the way the
// admission gate does, and reads the answer back out of the C struct. The
// package's tests reach the export through it: a test file cannot hold C
// types.
func aiClassResolveC(in classInput, binding, profile string) (rc int, ans classAnswer) {
	args := []*C.char{C.CString(in.tenant), C.CString(in.keyID), C.CString(binding),
		C.CString(profile), C.CString(in.svc), C.CString(in.hint)}
	defer func() {
		for _, a := range args {
			C.free(unsafe.Pointer(a))
		}
	}()
	var out C.ai_gw_class_t
	// Not zero on entry: the export owes the caller a struct it has cleared.
	C.memset(unsafe.Pointer(&out), 0xff, C.size_t(unsafe.Sizeof(out)))
	rc = int(llb_ai_class_resolve(args[0], args[1], args[2], args[3], args[4], args[5],
		C.int(in.tier), &out))
	ans.priority = int32(out.priority)
	ans.class = int(out.priority_class)
	ans.denied = out.objective_denied != 0
	ans.objective = C.GoString((*C.char)(unsafe.Pointer(&out.objective[0])))
	return rc, ans
}

// aiClassOnNow is the switch as last published.
var aiClassOnNow atomic.Bool

// aiClassOnMu orders the publications: the value is worked out and handed to
// the data plane as one step, so two callers that work out different values
// cannot publish them in the other order and leave the data plane holding
// the older one.
var aiClassOnMu sync.Mutex

// aiClassRecompute works out whether any class is configured and tells the
// data plane. A request is looked at for a class only while this is on:
// with no objective, no tenant or key that sets a class field, and no
// binding or JWT profile that makes its requests sheddable, every request
// is standard whatever it asks for, so nothing is asked. A binding or
// profile whose class is standard or critical does not turn it on: alone,
// a cap that admits standard changes nothing.
//
// Called after every published class snapshot and every change of the
// bindings or the profiles.
func aiClassRecompute() {
	aiClassOnMu.Lock()
	defer aiClassOnMu.Unlock()
	on := aiClassSnapshot().Configured() || netidLowersClass() || mh.JWTAuthProfiles.lowersClass()
	if aiClassOnNow.Swap(on) != on {
		aiClassOnPublish(on)
	}
}
