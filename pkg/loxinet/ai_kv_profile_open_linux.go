//go:build linux

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
	"errors"

	"golang.org/x/sys/unix"
)

// kvOpenBeneath opens rel (a validated relative path) beneath rootFd with
// symlink resolution disabled everywhere and escape from the root forbidden
// by the kernel (openat2 RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS). On kernels
// without openat2 it falls back to the O_NOFOLLOW component walk, which gives
// the same guarantees for the pre-validated single-segment paths the profile
// registry passes (no "..", no absolute components).
func kvOpenBeneath(rootFd int, rel string) (int, error) {
	how := unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(rootFd, rel, &how)
	if err == nil {
		return fd, nil
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EPERM) {
		return kvWalkOpenBeneath(rootFd, rel)
	}
	return -1, err
}
