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

// ConflictError marks a request that is well-formed and would be valid on
// its own, but collides with the configuration as it stands right now: the
// caller changes nothing about the request to succeed, it changes the state
// the request collides with. That is HTTP 409, not 400 — a delete refused
// because live rules still reference the object is the archetype.
//
// It is the 409 counterpart of ValidationError, and exists for the same
// reason: without a type the API layer's fallback classifier picks the
// status by searching the message for one of an open-ended phrase list, so
// the wording silently decides the status and a rejection matching no
// phrase degrades to a 500 whose text is replaced by a correlation
// reference.
type ConflictError struct {
	// Err is the underlying refusal whose text is the caller-facing answer;
	// it should name what the object collides with, not merely that it does.
	Err error
}

func (e *ConflictError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying refusal to errors.Is/As chains.
func (e *ConflictError) Unwrap() error { return e.Err }

// NewConflictError builds a ConflictError from a format string.
func NewConflictError(format string, args ...any) *ConflictError {
	return &ConflictError{Err: fmt.Errorf(format, args...)}
}
