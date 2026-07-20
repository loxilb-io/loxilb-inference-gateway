/*
 * Copyright (c) 2025 LoxiLB Authors
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

package opa

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
)

const defaultStatePath = "/var/lib/loxilb/opa_l4_state.json"

// cacheFile is the on-disk serialization format for the rule cache.
type cacheFile struct {
	Rules map[DiffKey]cmn.FwRuleArg `json:"rules"`
	Opts  map[DiffKey]cmn.FwOptArg  `json:"opts"`
}

// RuleCache maintains the current set of OPA-managed firewall rules in memory
// with persistence to a JSON file. All operations are thread-safe.
type RuleCache struct {
	mu       sync.RWMutex
	rules    map[DiffKey]cmn.FwRuleArg
	opts     map[DiffKey]cmn.FwOptArg
	filePath string
}

// NewRuleCache creates a RuleCache backed by the given file path.
// If filePath is empty, it defaults to "/var/lib/loxilb/opa_l4_state.json".
func NewRuleCache(filePath string) *RuleCache {
	if filePath == "" {
		filePath = defaultStatePath
	}
	return &RuleCache{
		rules:    make(map[DiffKey]cmn.FwRuleArg),
		opts:     make(map[DiffKey]cmn.FwOptArg),
		filePath: filePath,
	}
}

// Set stores a rule and its options under the given key.
func (c *RuleCache) Set(key DiffKey, rule cmn.FwRuleArg, opt cmn.FwOptArg) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[key] = rule
	c.opts[key] = opt
}

// Delete removes a rule and its options by key.
func (c *RuleCache) Delete(key DiffKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.rules, key)
	delete(c.opts, key)
}

// GetAllRules returns a deep copy of all cached rules.
func (c *RuleCache) GetAllRules() map[DiffKey]cmn.FwRuleArg {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[DiffKey]cmn.FwRuleArg, len(c.rules))
	for k, v := range c.rules {
		out[k] = v
	}
	return out
}

// GetAllOpts returns a deep copy of all cached options.
func (c *RuleCache) GetAllOpts() map[DiffKey]cmn.FwOptArg {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[DiffKey]cmn.FwOptArg, len(c.opts))
	for k, v := range c.opts {
		out[k] = v
	}
	return out
}

// Len returns the number of rules in the cache.
func (c *RuleCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.rules)
}

// Save persists the cache to disk using atomic write (write to .tmp, then rename).
func (c *RuleCache) Save() error {
	c.mu.RLock()
	data := cacheFile{
		Rules: make(map[DiffKey]cmn.FwRuleArg, len(c.rules)),
		Opts:  make(map[DiffKey]cmn.FwOptArg, len(c.opts)),
	}
	for k, v := range c.rules {
		data.Rules[k] = v
	}
	for k, v := range c.opts {
		data.Opts[k] = v
	}
	c.mu.RUnlock()

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(c.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpPath := c.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, b, 0644); err != nil {
		return err
	}

	return os.Rename(tmpPath, c.filePath)
}

// Load reads the cache from disk. Returns nil if the file does not exist.
// On corrupt JSON, logs a warning and starts with an empty cache.
func (c *RuleCache) Load() error {
	b, err := os.ReadFile(c.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var data cacheFile
	if err := json.Unmarshal(b, &data); err != nil {
		tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] corrupt state file %s, starting empty: %v\n", c.filePath, err)
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if data.Rules != nil {
		c.rules = data.Rules
	} else {
		c.rules = make(map[DiffKey]cmn.FwRuleArg)
	}

	if data.Opts != nil {
		c.opts = data.Opts
	} else {
		c.opts = make(map[DiffKey]cmn.FwOptArg)
	}

	return nil
}
