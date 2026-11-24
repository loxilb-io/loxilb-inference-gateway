// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package models

import (
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
)

// A date-time needs a time of day, in a body and in a parameter, and the
// refusal reads as it did before strfmt v0.27.
func TestDateTimeRefusesBareDate(t *testing.T) {
	var req APIKeyCreateRequest
	err := req.UnmarshalBinary([]byte(`{"expires_at":"2026-11-24"}`))
	if err == nil {
		t.Fatalf("bare date accepted as expires_at %v", time.Time(req.ExpiresAt))
	}
	if !strings.Contains(err.Error(), `as "2006-01-02 15:04:05"`) {
		t.Errorf("refusal changed: %v", err)
	}
	if _, err := strfmt.Default.Parse("date-time", "2026-11-24"); err == nil {
		t.Error("bare date accepted as a date-time parameter")
	}

	for _, value := range []string{"2026-11-24T10:00:00Z", "2026-11-24T10:00:00.123+09:00", "2026-11-24 10:00:00"} {
		if err := req.UnmarshalBinary([]byte(`{"expires_at":"` + value + `"}`)); err != nil {
			t.Errorf("expires_at %q refused: %v", value, err)
		}
	}
}
