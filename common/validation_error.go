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

import "fmt"

// ValidationError marks a rejection of caller-supplied input: the request was
// understood and refused on its contents, so the answer is HTTP 400 and the
// refusal text is what the caller needs in order to fix the request.
//
// It exists because the API layer's fallback classifier decides the status by
// searching the message for one of an open-ended list of phrases. That is
// positional — whoever writes the wording decides the status — so two adjacent
// branches of one validator can classify differently, and a rejection whose
// wording happens to match nothing becomes a 500 whose real message is
// replaced by a correlation reference. A caller is then told nothing about
// what to fix. Returning this type instead states the classification at the
// point where it is actually known.
type ValidationError struct {
	// Field optionally names the input that was refused; empty when the
	// rejection is not attributable to a single field.
	Field string
	// Err is the underlying rejection whose text is the caller-facing answer.
	Err error
}

func (e *ValidationError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying rejection to errors.Is/As chains.
func (e *ValidationError) Unwrap() error { return e.Err }

// NewValidationError builds a ValidationError for a field from a format string.
func NewValidationError(field, format string, args ...any) *ValidationError {
	return &ValidationError{Field: field, Err: fmt.Errorf(format, args...)}
}
