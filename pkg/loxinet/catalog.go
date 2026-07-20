/*
 * Copyright (c) 2025 NetLOX Inc
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
	"os"
	"path/filepath"
	"sync"

	tk "github.com/loxilb-io/loxilib"
	"gopkg.in/yaml.v3"
)

const (
	// Tracing Catalogs (for trace_type)
	DefaultTraceCatalogDir = "/etc/loxilb/trace-catalogs"
	BuiltinTraceCatalogDir = "/opt/loxilb/trace-catalogs"
)

// TracingCatalog represents a tracing/deep inspection profile
// Used for trace_type parameter (protocol parsing and observability)
type TracingCatalog struct {
	CatalogName    string               `yaml:"catalog_name"`
	Description    string               `yaml:"description"`
	Version        string               `yaml:"version"`
	DeepInspection DeepInspectionConfig `yaml:"deep_inspection"` // Required for tracing
}

// DeepInspectionConfig controls payload parsing for deep inspection
type DeepInspectionConfig struct {
	Enabled       bool     `yaml:"enabled"`        // Enable deep inspection
	SampleRate    uint8    `yaml:"sample_rate"`    // 0-100 (percent)
	ParserType    string   `yaml:"parser_type"`    // "openai", "mcp", "graphql", "mock"
	MaxBodySize   uint32   `yaml:"max_body_size"`  // Bytes (default: 16384)
	RedactPII     bool     `yaml:"redact_pii"`     // Enable PII redaction
	ParserTimeout string   `yaml:"parser_timeout"` // e.g., "2s"
	Fields        []string `yaml:"fields"`         // Fields to extract (empty = all)
}

// TracingCatalogManager handles tracing catalog loading
type TracingCatalogManager struct {
	mu           sync.RWMutex
	catalogs     map[string]*TracingCatalog
	catalogsByID map[uint16]*TracingCatalog // ID-to-catalog mapping for shared memory lookup
	searchPaths  []string
}

func NewTracingCatalogManager() *TracingCatalogManager {
	tcm := &TracingCatalogManager{
		catalogs:     make(map[string]*TracingCatalog),
		catalogsByID: make(map[uint16]*TracingCatalog),
		searchPaths: []string{
			DefaultTraceCatalogDir, // /etc/loxilb/trace-catalogs (user tracing)
			BuiltinTraceCatalogDir, // /opt/loxilb/trace-catalogs (builtin tracing)
		},
	}
	tcm.loadAllCatalogs()
	return tcm
}

func (tcm *TracingCatalogManager) loadAllCatalogs() error {
	for _, dir := range tcm.searchPaths {
		// Check if directory exists
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			tk.LogIt(tk.LogDebug, "Tracing catalog directory does not exist: %s\n", dir)
			continue
		}

		files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			tk.LogIt(tk.LogWarning, "Failed to scan tracing catalog directory %s: %v\n", dir, err)
			continue
		}

		for _, file := range files {
			catalog, err := tcm.loadTracingCatalog(file)
			if err != nil {
				tk.LogIt(tk.LogWarning, "Failed to load tracing catalog %s: %v\n", file, err)
				continue
			}

			// Only add if not already loaded (user catalogs override built-in)
			if _, exists := tcm.catalogs[catalog.CatalogName]; !exists {
				tcm.catalogs[catalog.CatalogName] = catalog
				tk.LogIt(tk.LogInfo, "Loaded tracing catalog: %s (sample=%d%%, parser=%s)\n",
					catalog.CatalogName,
					catalog.DeepInspection.SampleRate,
					catalog.DeepInspection.ParserType)
			} else {
				tk.LogIt(tk.LogDebug, "Tracing catalog %s already loaded (skipping duplicate from %s)\n",
					catalog.CatalogName, file)
			}
		}
	}

	// No automatic default for tracing - users must be explicit
	tk.LogIt(tk.LogInfo, "Loaded %d tracing catalog(s)\n", len(tcm.catalogs))
	return nil
}

func (tcm *TracingCatalogManager) loadTracingCatalog(path string) (*TracingCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var catalog TracingCatalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	// Validate tracing catalog
	if err := catalog.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return &catalog, nil
}

// Validate ensures tracing catalog configuration is sane
func (c *TracingCatalog) Validate() error {
	// Catalog name required
	if c.CatalogName == "" {
		return fmt.Errorf("catalog_name is required")
	}

	// Deep inspection required for tracing catalogs
	if c.DeepInspection.ParserType == "" {
		return fmt.Errorf("deep_inspection.parser_type is required")
	}
	tk.LogIt(tk.LogDebug, "[CATALOG_VALIDATE] Tracing catalog '%s' validated: parser_type=%s sample_rate=%d%%",
		c.CatalogName, c.DeepInspection.ParserType, c.DeepInspection.SampleRate)

	// Sample rate must be 0-100
	if c.DeepInspection.SampleRate > 100 {
		return fmt.Errorf("sample_rate must be 0-100, got %d", c.DeepInspection.SampleRate)
	}

	// Max body size should be reasonable
	if c.DeepInspection.MaxBodySize == 0 {
		c.DeepInspection.MaxBodySize = 16384 // Default 16KB
	}
	if c.DeepInspection.MaxBodySize > 10*1024*1024 {
		return fmt.Errorf("max_body_size too large (max 10MB)")
	}

	return nil
}

func (tcm *TracingCatalogManager) GetCatalog(name string) (*TracingCatalog, error) {
	catalog, ok := tcm.catalogs[name]
	if !ok {
		return nil, fmt.Errorf("tracing catalog '%s' not found", name)
	}
	return catalog, nil
}

func (tcm *TracingCatalogManager) ListCatalogs() []string {
	names := make([]string, 0, len(tcm.catalogs))
	for name := range tcm.catalogs {
		names = append(names, name)
	}
	return names
}

func (tcm *TracingCatalogManager) CatalogExists(name string) bool {
	_, ok := tcm.catalogs[name]
	return ok
}

func (tcm *TracingCatalogManager) GetAllCatalogs() map[string]*TracingCatalog {
	result := make(map[string]*TracingCatalog)
	for k, v := range tcm.catalogs {
		result[k] = v
	}
	return result
}

// GetCatalogByID retrieves a tracing catalog by its numeric ID (assigned during sync)
func (tcm *TracingCatalogManager) GetCatalogByID(id uint16) *TracingCatalog {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	catalog, ok := tcm.catalogsByID[id]
	if !ok {
		return nil
	}
	return catalog
}
