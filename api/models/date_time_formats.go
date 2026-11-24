// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package models

import (
	"slices"

	"github.com/go-openapi/strfmt"
)

// The API refuses a date-time without a time of day (422): an API key's
// expires_at "2026-11-24" is an error, not midnight UTC. strfmt v0.27 began
// accepting the bare-date layout in ParseDateTime, which every date-time
// body field and parameter goes through. Remove that layout so the contract
// stays as it was. The setting is process-wide and is applied before any
// model is decoded.
func init() {
	strfmt.DateTimeFormats = slices.DeleteFunc(slices.Clone(strfmt.DateTimeFormats),
		func(layout string) bool {
			return layout == strfmt.ISO8601TimeUniversalSortableDateTimePatternShortForm
		})
}
