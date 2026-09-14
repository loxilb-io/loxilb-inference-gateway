/*
 * Copyright (c) 2026 LoxiLB Authors
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
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

// The same startup window the key store legs describe, for the JWT profile
// holder: loxiNetInit builds it partway through a long initialisation while
// the REST listener is already answering, so the pointer is nil early in every
// boot. The difference that mattered is what happens when a caller arrives
// then.
//
// The snapshot registry reads this domain on every capture, plan and restore,
// so the caller is not hypothetical -- it is POST /config/restore, the recovery
// the readiness surface points an operator at after a failed boot. Locking a
// mutex on a nil receiver panics; net/http recovers the panic and closes the
// connection with no response, so the operator sees an empty reply rather than
// an error. Every other late-initialized subsystem here answers the window with
// a startup error instead, and the wording matters: the boot replay and the
// REST commit restore both retry on it.
func TestJWTAuthProfileNilHolderAnswersTheStartupWindow(t *testing.T) {
	// Fail rather than skip, like the key-store legs: if some later test
	// constructs a holder in this process, a skip would delete this coverage
	// silently and the guard it pins could be removed without anything going
	// red.
	if mh.JWTAuthProfiles != nil {
		t.Fatal("a profile holder is constructed in this test process; these legs are about the window in which none is")
	}
	na := &NetAPIStruct{}

	t.Run("get", func(t *testing.T) {
		profiles, err := na.NetJWTAuthProfileGet()
		if err == nil {
			t.Fatal("a nil profile holder returned no error: the caller cannot tell the window from an empty configuration")
		}
		if profiles != nil {
			t.Fatalf("a failed read returned profiles: %v", profiles)
		}
		if !snapshot.SubsystemStartupErrors([]string{err.Error()}) {
			t.Fatalf("error %q is not recognized as a startup-window message, so neither the boot replay nor the REST commit restore will retry it", err)
		}
	})

	t.Run("add", func(t *testing.T) {
		_, err := na.NetJWTAuthProfileAdd(&cmn.JWTAuthProfileMod{Name: "startup-window"})
		if err == nil {
			t.Fatal("a nil profile holder accepted a write")
		}
		if !snapshot.SubsystemStartupErrors([]string{err.Error()}) {
			t.Fatalf("error %q is not recognized as a startup-window message", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		_, err := na.NetJWTAuthProfileDel("startup-window")
		if err == nil {
			t.Fatal("a nil profile holder accepted a delete")
		}
		if !snapshot.SubsystemStartupErrors([]string{err.Error()}) {
			t.Fatalf("error %q is not recognized as a startup-window message", err)
		}
	})
}
