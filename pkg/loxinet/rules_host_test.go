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
	"slices"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestCanonicalLBHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"api.example.com", "api.example.com"},
		{"API.Example.COM", "api.example.com"},
		{"*.Wild.Example.com", "*.wild.example.com"},
		{"10.0.0.1:443", "10.0.0.1:443"},
		// ASCII letters only, as the data plane folds them
		{"Ünïcode.Example", "Ünïcode.example"},
	} {
		if got := canonicalLBHost(tc.in); got != tc.want {
			t.Errorf("canonicalLBHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateLBHostWildcard(t *testing.T) {
	for _, ok := range []string{
		"", "api.example.com", "10.0.0.1:443",
		"*.example.com", "*.com", "*.runai-inference.cluster.example",
	} {
		if err := validateLBHostWildcard(ok); err != nil {
			t.Errorf("validateLBHostWildcard(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"*", "*.", "a*.b", "x.*.b", "*a.example.com", "**.example.com",
		"*.*.example.com", "*.example..com", "*.example.com.", "example.*",
	} {
		if err := validateLBHostWildcard(bad); err == nil {
			t.Errorf("validateLBHostWildcard(%q) accepted, want refused", bad)
		}
	}
}

func TestVersionFeaturesAdvertiseWildcardHost(t *testing.T) {
	if !slices.Contains(cmn.VersionFeatures(), cmn.FeatureWildcardHost) {
		t.Fatalf("VersionFeatures() = %v, want %q in it", cmn.VersionFeatures(), cmn.FeatureWildcardHost)
	}
}
