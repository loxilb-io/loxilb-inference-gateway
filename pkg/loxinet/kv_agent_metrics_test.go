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

	"github.com/prometheus/client_golang/prometheus"
)

// loxilb_kv_agent_up is outside the default package profile (kv-agent-health
// class): it must reach the default registry only when a KV agent client is
// actually created, and creating more than one client must not double-register.
func TestKvAgentUpGaugeRegistersOnClientCreation(t *testing.T) {
	gathered := func() bool {
		mfs, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatalf("gather: %v", err)
		}
		for _, mf := range mfs {
			if mf.GetName() == "loxilb_kv_agent_up" {
				return true
			}
		}
		return false
	}

	_ = NewKVAgentClient("")
	_ = NewKVAgentClient("127.0.0.1:9099") // second create must not panic
	if !gathered() {
		t.Fatalf("loxilb_kv_agent_up absent after NewKVAgentClient")
	}
}
