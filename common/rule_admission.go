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

package common

// RuleArgumentError marks a load-balancer admission refusal caused by an
// operator-supplied argument. The REST boundary uses this structure to return
// a stable 400 response without classifying arbitrary internal error text.
type RuleArgumentError struct {
	Err error
}

func (e *RuleArgumentError) Error() string { return e.Err.Error() }

func (e *RuleArgumentError) Unwrap() error { return e.Err }
