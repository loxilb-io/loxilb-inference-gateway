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

package schema

import (
	"fmt"
	"strconv"
	"strings"
)

// semver is the minimal parsed form the selectors need: numeric
// major/minor/patch plus an optional pre-release tail. Build metadata
// (after "+") is ignored for ordering per semver 2.0.
type semver struct {
	major, minor, patch uint64
	pre                 string
}

// parseSemver parses "v1.2.3", "1.2.3", or "1.2.3-rc1". Anything else —
// including bare "1.2" — is an error: an identity the parser cannot order
// must use the exact selector scheme instead of silently sorting wrong.
func parseSemver(s string) (semver, error) {
	orig := s
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v semver
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH semver", orig)
	}
	nums := make([]uint64, 3)
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return semver{}, fmt.Errorf("version %q: component %q not numeric", orig, p)
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, nil
}

// compareSemver orders two parsed versions: -1, 0, or 1. A pre-release
// sorts before its release (1.2.3-rc1 < 1.2.3); two pre-releases order
// lexically, which is sufficient for the rcN identities the selectors use.
func compareSemver(a, b semver) int {
	for _, d := range [3]int64{
		int64(a.major) - int64(b.major),
		int64(a.minor) - int64(b.minor),
		int64(a.patch) - int64(b.patch),
	} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	switch {
	case a.pre == b.pre:
		return 0
	case a.pre == "":
		return 1
	case b.pre == "":
		return -1
	case a.pre < b.pre:
		return -1
	default:
		return 1
	}
}
