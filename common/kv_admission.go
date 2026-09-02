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

// KvAdmissionError marks a create/replace-time KV rule validation refusal.
// The API layer classifies it structurally (HTTP 400 with the refusal text as
// the answer) instead of matching message substrings — an admission refusal
// whose wording matches no classifier phrase must never surface as an
// internal 500 that hides the reason behind a correlation ref.
type KvAdmissionError struct {
	// Reason optionally carries a stable machine-readable refusal code
	// (e.g. an engine-contract capability code); empty when the refusal has
	// no code vocabulary.
	Reason string
	// Err is the underlying refusal whose text is the operator-facing answer.
	Err error
}

func (e *KvAdmissionError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying refusal to errors.Is/As chains.
func (e *KvAdmissionError) Unwrap() error { return e.Err }
