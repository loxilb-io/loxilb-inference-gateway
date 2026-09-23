//go:build audit_faults

/*
 * Copyright (c) 2026 NetLOX Inc
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

package audit

import "os"

// FaultsEnabled reports whether fault points were compiled in. This build
// has them; the point is selected at run time by FaultEnv.
const FaultsEnabled = true

// FaultEnv names the environment variable that selects the armed fault
// point in a fault-enabled build.
const FaultEnv = "LOXILB_AUDIT_FAULT"

var armedFault = os.Getenv(FaultEnv)

// buildFaultArmed reports whether point is the one selected by FaultEnv.
func buildFaultArmed(point string) bool { return armedFault == point }

// buildFaultClear disarms a one-shot point after it fired.
func buildFaultClear() { armedFault = "" }
