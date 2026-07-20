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
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// PluginRegistry manages all payload parsers
// Thread-safe: Use RWMutex for concurrent access
// Singleton: Access via GetRegistry
type PluginRegistry struct {
	mu       sync.RWMutex
	parsers  map[string]PayloadParser  // protocol -> parser
	metadata map[string]PluginMetadata // protocol -> metadata cache
}

// Global registry instance (singleton)
var (
	globalRegistry     *PluginRegistry
	globalRegistryOnce sync.Once
)

// GetRegistry returns the global plugin registry
// Safe to call from multiple goroutines
func GetRegistry() *PluginRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = &PluginRegistry{
			parsers:  make(map[string]PayloadParser),
			metadata: make(map[string]PluginMetadata),
		}
	})
	return globalRegistry
}

// Register adds a parser to the registry
// Returns error if:
// - Invalid metadata (missing name or protocol)
// - Protocol conflict (existing parser with different version)
func (r *PluginRegistry) Register(parser PayloadParser) error {
	meta := parser.Metadata()

	// Validate metadata
	if meta.Name == "" {
		return fmt.Errorf("invalid plugin metadata: name is required")
	}
	if meta.Protocol == "" {
		return fmt.Errorf("invalid plugin metadata: protocol is required")
	}
	if meta.Version == "" {
		return fmt.Errorf("invalid plugin metadata: version is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for conflicts
	if existing, exists := r.parsers[meta.Protocol]; exists {
		existingMeta := existing.Metadata()

		// Allow re-registration if same version (idempotent)
		if existingMeta.Version == meta.Version {
			tk.LogIt(tk.LogInfo, "[PluginRegistry] Re-registering parser: %s v%s (idempotent)\n",
				meta.Name, meta.Version)
			r.parsers[meta.Protocol] = parser
			r.metadata[meta.Protocol] = meta
			return nil
		}

		// Warn about version conflict
		tk.LogIt(tk.LogWarning, "[PluginRegistry] Replacing parser: %s v%s -> v%s\n",
			meta.Protocol, existingMeta.Version, meta.Version)
	}

	// Register parser
	r.parsers[meta.Protocol] = parser
	r.metadata[meta.Protocol] = meta

	tk.LogIt(tk.LogInfo, "[PluginRegistry] Registered parser: %s v%s (protocol=%s)\n",
		meta.Name, meta.Version, meta.Protocol)

	return nil
}

// Deregister removes a parser from the registry
// Returns error if parser not found
func (r *PluginRegistry) Deregister(protocol string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.parsers[protocol]; !exists {
		return fmt.Errorf("parser not found for protocol: %s", protocol)
	}

	meta := r.metadata[protocol]

	delete(r.parsers, protocol)
	delete(r.metadata, protocol)

	tk.LogIt(tk.LogInfo, "[PluginRegistry] Deregistered parser: %s v%s (protocol=%s)\n",
		meta.Name, meta.Version, protocol)

	return nil
}

// GetParser retrieves a parser by protocol
// Thread-safe: Uses read lock
func (r *PluginRegistry) GetParser(protocol string) (PayloadParser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	parser, exists := r.parsers[protocol]
	if !exists {
		return nil, fmt.Errorf("no parser registered for protocol: %s", protocol)
	}

	return parser, nil
}

// ListParsers returns all registered parsers
// Thread-safe: Returns a copy of metadata
func (r *PluginRegistry) ListParsers() []PluginMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]PluginMetadata, 0, len(r.metadata))
	for _, meta := range r.metadata {
		result = append(result, meta)
	}

	return result
}

// ParseWithTimeout invokes parser with timeout protection
// This is the PRIMARY API used by span enricher
// Features:
// - Timeout protection (default 5s, configurable)
// - Panic recovery (parser bugs don't crash control plane)
// - Error logging (helps debug parser issues)
func (r *PluginRegistry) ParseWithTimeout(protocol string, req *ParseRequest) (*ParseResponse, error) {
	// Step 1: Get parser
	parser, err := r.GetParser(protocol)
	if err != nil {
		return nil, err
	}

	// Step 2: Determine timeout
	timeout := req.Config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second // Default: 5 seconds
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Step 3: Run parser in goroutine (for timeout control)
	resultCh := make(chan *ParseResponse, 1)
	errorCh := make(chan error, 1)

	go func() {
		// Panic recovery
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				tk.LogIt(tk.LogError, "[PluginRegistry] Parser panic: %v\n", r)
				tk.LogIt(tk.LogError, "[PluginRegistry] Stack trace:\n%s\n", string(stack))
				errorCh <- fmt.Errorf("parser panic: %v", r)
			}
		}()

		// Call parser
		resp, err := parser.Parse(ctx, req)
		if err != nil {
			errorCh <- err
			return
		}

		resultCh <- resp
	}()

	// Step 4: Wait for result or timeout
	select {
	case resp := <-resultCh:
		return resp, nil

	case err := <-errorCh:
		tk.LogIt(tk.LogWarning, "[PluginRegistry] Parser error for protocol=%s: %v\n",
			protocol, err)
		return nil, err

	case <-ctx.Done():
		tk.LogIt(tk.LogWarning, "[PluginRegistry] Parser timeout for protocol=%s after %v\n",
			protocol, timeout)
		return nil, fmt.Errorf("parser timeout after %v", timeout)
	}
}

// ParseWithTimeoutOrDefault attempts parsing, returns empty attrs on failure
// Used when graceful degradation is desired (common case)
func (r *PluginRegistry) ParseWithTimeoutOrDefault(protocol string, req *ParseRequest) *ParseResponse {
	resp, err := r.ParseWithTimeout(protocol, req)
	if err != nil {
		// Return empty response on error (graceful degradation)
		return &ParseResponse{
			Attributes: make(map[string]interface{}),
		}
	}
	return resp
}

// HasParser checks if a parser is registered for the given protocol
// Thread-safe: Uses read lock
func (r *PluginRegistry) HasParser(protocol string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.parsers[protocol]
	return exists
}

// GetMetadata retrieves parser metadata without instantiating parser
// Thread-safe: Uses read lock
func (r *PluginRegistry) GetMetadata(protocol string) (PluginMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	meta, exists := r.metadata[protocol]
	if !exists {
		return PluginMetadata{}, fmt.Errorf("no parser registered for protocol: %s", protocol)
	}

	return meta, nil
}
