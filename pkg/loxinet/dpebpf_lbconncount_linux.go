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

/*
unsigned long long llb_nat_conc_fixups(void);
*/
import "C"

import (
	prom "github.com/loxilb-io/loxilb/api/prometheus"
)

// The data plane compares each rule's live connection count and, on
// least-connections rules, its per-endpoint session counts with the
// connections that exist after every conntrack ageing run and corrects a
// count that differs (loxilb-ebpf/kernel/loxilb_libdp.c). The number of
// corrections is read at scrape time; it is zero until the data plane is up.
func init() {
	prom.SetLBConnCountCorrectionsSource(func() uint64 {
		return uint64(C.llb_nat_conc_fixups())
	})
}
