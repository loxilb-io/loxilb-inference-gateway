/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A MinPolRate refusal must be a typed validation rejection whose text names
// the floor: it is the operator's answer, and untyped it reaches the wire as
// a 500 whose body is a correlation reference instead of the reason.
func TestPolInfoXlateValidateFloorRefusalIsTypedAndNamesTheFloor(t *testing.T) {
	tests := []struct {
		name  string
		cir   uint64
		pir   uint64
		field string
	}{
		{name: "cir below floor", cir: MinPolRate - 1, pir: 0, field: "committedInfoRate"},
		{name: "pir below floor", cir: MinPolRate, pir: MinPolRate - 1, field: "peakInfoRate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pInfo := cmn.PolInfo{CommittedInfoRate: tc.cir, PeakInfoRate: tc.pir}
			err := PolInfoXlateValidate(&pInfo)
			if err == nil {
				t.Fatalf("rate %d:%d below MinPolRate %d unexpectedly accepted", tc.cir, tc.pir, MinPolRate)
			}
			var invalid *cmn.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("floor refusal is untyped (%T: %v); it will answer as a 500 correlation ref", err, err)
			}
			if invalid.Field != tc.field {
				t.Fatalf("refusal attributes field %q, want %q", invalid.Field, tc.field)
			}
			if !strings.Contains(err.Error(), "minimum policer rate 8") {
				t.Fatalf("refusal %q does not name the 8 Mbps floor", err.Error())
			}
		})
	}
}

// The floor itself must pass, srTCM's PeakInfoRate=0 included, and the
// accepted info must come back translated to internal units.
func TestPolInfoXlateValidateAcceptsFloorAndTranslatesUnits(t *testing.T) {
	for _, pir := range []uint64{0, MinPolRate} {
		pInfo := cmn.PolInfo{CommittedInfoRate: MinPolRate, PeakInfoRate: pir}
		if err := PolInfoXlateValidate(&pInfo); err != nil {
			t.Fatalf("rate %d:%d at the floor refused: %v", MinPolRate, pir, err)
		}
		if pInfo.CommittedInfoRate != MinPolRate*1000000 || pInfo.PeakInfoRate != pir*1000000 {
			t.Fatalf("accepted info not translated to bps: cir=%d pir=%d", pInfo.CommittedInfoRate, pInfo.PeakInfoRate)
		}
		if pInfo.CommittedBlkSize != DflPolBlkSz || pInfo.ExcessBlkSize != 2*DflPolBlkSz {
			t.Fatalf("block sizes not defaulted: cbs=%d ebs=%d", pInfo.CommittedBlkSize, pInfo.ExcessBlkSize)
		}
	}
}
