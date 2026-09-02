//go:build !linux

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

// kvOpenBeneath on non-Linux platforms uses the O_NOFOLLOW component walk
// directly (openat2 is Linux-only). The registry pre-validates every path to
// single relative segments, so the walk provides the same no-symlink,
// no-escape guarantees.
func kvOpenBeneath(rootFd int, rel string) (int, error) {
	return kvWalkOpenBeneath(rootFd, rel)
}
