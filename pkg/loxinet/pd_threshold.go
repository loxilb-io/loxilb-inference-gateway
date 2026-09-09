/*
 * Copyright (c) 2026 NetLOX Inc
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

const (
	pdCacheThresholdDefault      uint8 = 20
	pdBalanceAbsThresholdDefault uint8 = 3
)

// pdThresholdOnReplace returns the stored declaration for an existing rule.
// Presence authorizes zero as a reset declaration. A nonzero incoming value
// remains an update for legacy in-process callers that predate presence bits.
func pdThresholdOnReplace(current, incoming uint8, present bool) uint8 {
	if present || incoming != 0 {
		return incoming
	}
	return current
}

func pdCacheThresholdEffective(declared uint8) uint8 {
	if declared == 0 {
		return pdCacheThresholdDefault
	}
	return declared
}

func pdBalanceAbsThresholdEffective(declared uint8) uint8 {
	if declared == 0 {
		return pdBalanceAbsThresholdDefault
	}
	return declared
}
