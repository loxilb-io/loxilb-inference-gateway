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

// halfclose.go — NetHookInterface surface over the process-wide half-close
// hold settings (cmn.HalfCloseConfig): whether new holds may be taken, the
// idle bound on a hold and the default mode of the services that leave their
// own unset, all handed to the data path, and the one-shot
// release of every held client. The settings are desired state, captured and
// replayed by the config snapshot like any other domain; the defaults are
// not configuration and are captured as absent. No BgpPeerMode guard: the
// settings hold nothing that needs the data path to be up to be stored.

package loxinet

import (
	"errors"
	"sync"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

var halfClose struct {
	mtx sync.Mutex
	cfg *cmn.HalfCloseConfig // nil: the defaults are in force
}

// halfCloseMergedHook, when set (tests only), runs inside NetHalfCloseUpdate
// between reading the settings in force and storing the merge: the window a
// concurrent update must not be able to enter.
var halfCloseMergedHook func()

// halfCloseApply hands the settings to the data path, when there is one.
func halfCloseApply(c cmn.HalfCloseConfig) {
	if mh.dpEbpf == nil {
		return
	}
	mh.dpEbpf.DpHalfCloseConfig(c.Allow, c.CapSeconds, c.DefaultRule())
}

// halfCloseInForce - the settings in force: as set, else the defaults.
func halfCloseInForce() cmn.HalfCloseConfig {
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	if halfClose.cfg == nil {
		return cmn.DefaultHalfCloseConfig()
	}
	return *halfClose.cfg
}

// NetHalfCloseGet - the settings as set; nil while the defaults are in force.
func (na *NetAPIStruct) NetHalfCloseGet() (*cmn.HalfCloseConfig, error) {
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	if halfClose.cfg == nil {
		return nil, nil
	}
	c := *halfClose.cfg
	return &c, nil
}

// halfCloseStoreLocked validates the settings, hands them to the data path
// and stores them. halfClose.mtx held.
func halfCloseStoreLocked(c cmn.HalfCloseConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	c = c.Normalized()
	halfCloseApply(c)
	halfClose.cfg = &c
	tk.LogIt(tk.LogInfo, "half-close holds %s, bound %d s, default mode %s\n",
		map[bool]string{true: "allowed", false: "blocked"}[c.Allow], c.CapSeconds, c.DefaultMode)
	return nil
}

// NetHalfCloseSet - replace the settings (overwrite semantics).
func (na *NetAPIStruct) NetHalfCloseSet(cfg *cmn.HalfCloseConfig) (int, error) {
	if cfg == nil {
		return RuleArgsErr, cmn.NewValidationError("", "half-close settings missing")
	}
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	if err := halfCloseStoreLocked(*cfg); err != nil {
		return RuleArgsErr, err
	}
	return 0, nil
}

// NetHalfCloseUpdate - set the fields given, keep the others, and return the
// settings in force once applied. The settings in force are read, merged,
// handed over and returned under one lock: two partial updates at once - an
// operator blocking holds while another changes the bound - cannot undo each
// other, and each answer is what that update left in force.
func (na *NetAPIStruct) NetHalfCloseUpdate(u *cmn.HalfCloseUpdate) (cmn.HalfCloseConfig, error) {
	if u == nil || (u.Allow == nil && u.CapSeconds == nil && u.DefaultMode == nil) {
		return cmn.HalfCloseConfig{}, cmn.NewValidationError("",
			"give at least one of allow, capSeconds and defaultMode")
	}
	if u.DefaultMode != nil {
		if err := cmn.HalfCloseDefaultModeCheck(*u.DefaultMode); err != nil {
			return cmn.HalfCloseConfig{}, err
		}
	}
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	c := cmn.DefaultHalfCloseConfig()
	if halfClose.cfg != nil {
		c = *halfClose.cfg
	}
	if u.Allow != nil {
		c.Allow = *u.Allow
	}
	if u.CapSeconds != nil {
		c.CapSeconds = *u.CapSeconds
	}
	if u.DefaultMode != nil {
		c.DefaultMode = *u.DefaultMode
	}
	if halfCloseMergedHook != nil {
		halfCloseMergedHook()
	}
	if err := halfCloseStoreLocked(c); err != nil {
		return cmn.HalfCloseConfig{}, err
	}
	return *halfClose.cfg, nil
}

// NetHalfCloseReset - back to the defaults.
func (na *NetAPIStruct) NetHalfCloseReset() (int, error) {
	halfClose.mtx.Lock()
	defer halfClose.mtx.Unlock()
	halfCloseApply(cmn.DefaultHalfCloseConfig())
	halfClose.cfg = nil
	return 0, nil
}

// NetHalfCloseRelease - close every held client at the data path's next pass.
func (na *NetAPIStruct) NetHalfCloseRelease() (int, error) {
	if mh.dpEbpf == nil {
		return RuleErrBase, errors.New("half-close release: the data path is not running")
	}
	mh.dpEbpf.DpHalfCloseRelease()
	tk.LogIt(tk.LogInfo, "half-close: release of every held client requested\n")
	return 0, nil
}
