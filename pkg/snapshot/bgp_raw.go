/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func cloneBGPRaw(source map[string]json.RawMessage) map[string]json.RawMessage {
	copy := make(map[string]json.RawMessage, len(source))
	for name, raw := range source {
		copy[name] = append(json.RawMessage(nil), raw...)
	}
	return copy
}

func extractBGPRaw(raw []byte) (map[string]json.RawMessage, error) {
	var envelope struct {
		Domains map[string]json.RawMessage `json:"domains"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	values := make(map[string]json.RawMessage)
	for _, name := range []string{DomainBGP, DomainBGPPolicyAssignment} {
		if value, exists := envelope.Domains[name]; exists {
			values[name] = value
		}
	}
	return values, nil
}

// replaceJSONMember replaces an immediate object's value without re-encoding
// its bytes. Decoder offsets avoid matching nested keys or quoted strings.
func replaceJSONMember(object []byte, name string, value []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(object))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') || !json.Valid(value) {
		return nil, fmt.Errorf("pending BGP: invalid JSON object or value")
	}
	count := 0
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var old json.RawMessage
		if err := dec.Decode(&old); err != nil {
			return nil, err
		}
		count++
		if key == name {
			end := int(dec.InputOffset())
			result := append([]byte(nil), object[:end-len(old)]...)
			result = append(result, value...)
			return append(result, object[end:]...), nil
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	closeAt := int(dec.InputOffset()) - 1
	result := append([]byte(nil), object[:closeAt]...)
	if count != 0 {
		result = append(result, ',')
	}
	key, _ := json.Marshal(name)
	result = append(result, key...)
	result = append(result, ':')
	result = append(result, value...)
	return append(result, object[closeAt:]...), nil
}

// Preserve the on-disk intent verbatim while retaining the existing typed
// checksum contract. Refuse any mismatch before the atomic rename: a caller
// cannot silently persist raw intent inconsistent with its captured document.
func preservePendingBGPRaw(encoded []byte, values map[string]json.RawMessage) ([]byte, error) {
	if len(values) == 0 {
		return encoded, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, err
	}
	domains := []byte(envelope["domains"])
	for _, name := range []string{DomainBGP, DomainBGPPolicyAssignment} {
		if value, exists := values[name]; exists {
			var err error
			domains, err = replaceJSONMember(domains, name, value)
			if err != nil {
				return nil, err
			}
		}
	}
	result, err := replaceJSONMember(encoded, "domains", domains)
	if err != nil {
		return nil, err
	}
	if _, err := stageParse(result); err != nil {
		return nil, fmt.Errorf("pending BGP: merged intent mismatch: %w", err)
	}
	return result, nil
}
