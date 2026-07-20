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
package common

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConnectionLimitOmitemptyAbsent verifies that an unset ConnectionLimit (0)
// round-trips with the field ABSENT from the JSON (omitempty back-compat).
func TestConnectionLimitOmitemptyAbsent(t *testing.T) {
	in := LbServiceArg{ServIP: "10.0.0.1", ServPort: 80, Proto: "tcp"}
	b, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(b), "connectionLimit") {
		t.Fatalf("ConnectionLimit=0 must be omitted (omitempty); got: %s", string(b))
	}
	var out LbServiceArg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if out.ConnectionLimit != 0 {
		t.Fatalf("expected ConnectionLimit 0, got %d", out.ConnectionLimit)
	}
}

// TestConnectionLimitRoundTrip verifies that a set ConnectionLimit marshals to
// "connectionLimit":N and unmarshals back to N.
func TestConnectionLimitRoundTrip(t *testing.T) {
	in := LbServiceArg{ServIP: "10.0.0.1", ServPort: 80, Proto: "tcp", ConnectionLimit: 1234}
	b, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(b), `"connectionLimit":1234`) {
		t.Fatalf("expected connectionLimit:1234 in JSON, got: %s", string(b))
	}
	var out LbServiceArg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if out.ConnectionLimit != 1234 {
		t.Fatalf("expected ConnectionLimit 1234, got %d", out.ConnectionLimit)
	}
}
