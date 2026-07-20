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
package snapshot

import "fmt"

// Capture builds a snapshot Document of the live configuration for the
// selected components (nil/empty = every v1 domain), in registry apply
// order. It is the GET /config/snapshot capture path (task G-3) and the
// write-through persist source (task G-5); the restore engine's PRESERVE
// stage does the same walk internally over its own selection.
//
// The returned document's Checksum is unset -- Encode computes it while
// producing the canonical wire form.
func Capture(hooks Hooks, gatewayVersion, hostname string, trigger Trigger, components []string) (*Document, error) {
	selected, err := Select(components)
	if err != nil {
		return nil, err
	}
	doc := NewDocument(gatewayVersion, hostname, trigger)
	for _, entry := range selected {
		if err := entry.Get(hooks, doc); err != nil {
			return nil, fmt.Errorf("capture %s: %w", entry.Name, err)
		}
	}
	snapshotTotal.WithLabelValues(string(trigger)).Inc()
	return doc, nil
}
