/*
 * Copyright (c) 2022 NetLOX Inc
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

package utils

import (
	"bytes"
	"errors"
	"io/fs"
	"io/ioutil"
	"os"
	"strconv"
	"sync"
	"syscall"

	tk "github.com/loxilb-io/loxilib"
)

// fileExistsWarned remembers the paths whose stat failed with an error other
// than "not found", so that each such path is reported once and not on every
// probe (FileExists is on the boot path and on the endpoint add path).
var fileExistsWarned sync.Map

// FileExists - Check if file exists
//
// It reports true only for a path that stats successfully and is not a
// directory. Any stat error is treated as "absent": a missing path silently,
// every other error (EACCES, ENOTDIR, ELOOP, ENAMETOOLONG, EIO, ...) with one
// warning per path, so that an unreadable certificate or a regular file in
// place of a directory is visible in the log instead of crashing the caller.
func FileExists(fname string) bool {
	info, err := os.Stat(fname)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			if _, seen := fileExistsWarned.LoadOrStore(fname, struct{}{}); !seen {
				tk.LogIt(tk.LogWarning, "FileExists: %s: %v - treated as absent\n", fname, err)
			}
		}
		return false
	}
	return !info.IsDir()
}

// FileCreate - Create a file
func FileCreate(fname string) int {
	file, e := os.Create(fname)
	if e != nil {
		return -1
	}
	file.Close()
	return 0
}

// WriteFile - Write a string to a file
func WriteFile(fname, what string) error {
	f, err := os.OpenFile(fname, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(what)
	return err
}

// ReadPIDFile - Read a PID file
func ReadPIDFile(pf string) int {

	if exists := FileExists(pf); !exists {
		return 0
	}

	d, err := ioutil.ReadFile(pf)
	if err != nil {
		return 0
	}

	pid, err := strconv.Atoi(string(bytes.TrimSpace(d)))
	if err != nil {
		return 0
	}

	p, err1 := os.FindProcess(int(pid))
	if err1 != nil {
		return 0
	}

	err = p.Signal(syscall.Signal(0))
	if err != nil {
		return 0
	}

	return pid
}
