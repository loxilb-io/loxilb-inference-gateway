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

// Package audit is the gateway's audit trail: one record envelope for the
// management, data and audit_system streams, a non-blocking producer path
// for the data plane, a durable synchronous path for management intents,
// and a segment writer that owns the audit directory.
//
// Design in brief:
//
//   - One envelope (Record), typed detail per stream. Serialisation is from
//     the typed structs only; there is no field the schema does not name,
//     so a request body, a credential or a raw URL has nowhere to go.
//   - Producers (one per data-plane worker) call Emit, which stamps a
//     per-producer sequence and does a non-blocking send to a bounded
//     channel. A full channel drops the record and the producer itself
//     records the drop (counter plus a small ring the writer drains), so a
//     gap is reported from evidence rather than inferred.
//   - Management intents call Write, which returns only after the record is
//     appended and fsynced. When the writer cannot do that within the
//     caller's deadline the caller refuses the mutation.
//   - A single writer goroutine assigns the per-boot sequence, encodes,
//     appends and batches fsyncs. It is supervised: a panic is counted,
//     recorded and followed by a restart, and a fixed-interval heartbeat
//     gives a positive liveness signal so a dead writer never looks like an
//     idle one.
//   - Segments live in a 0700 directory as 0600 files. The active segment
//     is audit.jsonl; a sealed segment is audit-<UTC>.jsonl, compressed to
//     .jsonl.gz by one bounded worker. Each segment opens with a header
//     carrying its UUID and its predecessor's UUID, and closes with a
//     footer carrying record count and sequence/time bounds. Pruning is
//     governed only by the retention policy (age, byte quota, disk reserve,
//     legal hold), announced by an audit_system record before the delete,
//     and bounded per pass so a policy change can never delete history at
//     once.
//
// The segment names are deliberately outside the operational log family
// (loxilb*.log, *.log.gz) so the debug-log API never lists or serves them.
package audit
