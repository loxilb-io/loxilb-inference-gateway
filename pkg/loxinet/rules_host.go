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

package loxinet

import (
	"fmt"
	"strings"
)

// canonicalLBHost - a rule's host as routing compares it. Host names compare
// without regard to case (RFC 9110 section 4.2.3), so the host is kept in
// lower case: a rule sent in any case is stored, found, replaced and deleted
// as one, and GET returns it in lower case. The data plane folds the request
// host the same way, ASCII letters only, so this folds exactly those.
func canonicalLBHost(host string) string {
	for i := 0; i < len(host); i++ {
		if c := host[i]; c >= 'A' && c <= 'Z' {
			b := []byte(host)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return host
}

// validateLBHostWildcard - the one wildcard form a host may take: "*." and
// then one or more labels, none of them empty ("*.example.com"). It matches a
// request host with one or more labels in front of the suffix, never the
// suffix itself (Gateway API hostname semantics). "*" anywhere else ("a*.b",
// "x.*.b"), alone, or with nothing after it ("*.") is refused rather than
// stored as a literal no request can ever match.
func validateLBHostWildcard(host string) error {
	if !strings.Contains(host, "*") {
		return nil
	}
	refuse := func(why string) error {
		return fmt.Errorf("host %q is not a valid wildcard host: %s; a wildcard host is \"*.\" followed by one or more labels, such as \"*.example.com\"", host, why)
	}
	if !strings.HasPrefix(host, "*.") {
		return refuse("\"*\" may only be the whole first label")
	}
	suffix := host[2:]
	if suffix == "" {
		return refuse("no label follows \"*.\"")
	}
	for _, label := range strings.Split(suffix, ".") {
		switch {
		case label == "":
			return refuse("it has an empty label")
		case strings.Contains(label, "*"):
			return refuse("\"*\" may only be the whole first label")
		}
	}
	return nil
}
