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

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <string.h>
#include "lxb_catalog.h"
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"
)

const (
	catalogSharedMemPath = "/dev/shm/loxilb-catalog-config"
	catalogConfigOffset  = 0
	catalogConfigSize    = C.LXB_MAX_CATALOGS * C.sizeof_lxb_catalog_config_t // 256 * 128 = 32KB
	serviceMapOffset     = catalogConfigSize
	serviceMapSize       = C.LXB_MAX_SERVICES * C.sizeof_lxb_service_catalog_map_t // 256 * 16 = 4KB
	catalogSharedMemSize = catalogConfigSize + serviceMapSize                      // 36KB total
)

// CatalogSyncManager handles shared memory synchronization for tracing catalogs
type CatalogSyncManager struct {
	sharedMem         []byte
	catalogConfig     *[C.LXB_MAX_CATALOGS]C.lxb_catalog_config_t
	serviceCatalogMap *[C.LXB_MAX_SERVICES]C.lxb_service_catalog_map_t
	tracingMgr        *TracingCatalogManager // Use TracingCatalogManager instead
	parserRegistry    *TraceParserRegistry   // Parser registry for dynamic mapping
	nameToID          map[string]uint16      // Maps catalog name to ID (1-255)
	synced            bool                   // Track if catalogs have been synced
}

// NewCatalogSyncManager creates shared memory manager for tracing catalogs
// Parser registry can be set later via SetParserRegistry for dynamic parser selection
func NewCatalogSyncManager(tracingMgr *TracingCatalogManager) (*CatalogSyncManager, error) {
	csm := &CatalogSyncManager{
		tracingMgr:     tracingMgr,
		parserRegistry: nil, // Will be set later via SetParserRegistry
		nameToID:       make(map[string]uint16),
	}

	if err := csm.initSharedMemory(); err != nil {
		return nil, err
	}

	return csm, nil
}

// SetParserRegistry sets the parser registry for dynamic catalog -> parser mapping
// Must be called before SyncToSharedMemory to enable dynamic parser selection
func (csm *CatalogSyncManager) SetParserRegistry(registry *TraceParserRegistry) {
	csm.parserRegistry = registry
	tk.LogIt(tk.LogInfo, "[CatalogSync] Parser registry attached (dynamic parser selection enabled)\n")
}

// initSharedMemory creates and maps shared memory
func (csm *CatalogSyncManager) initSharedMemory() error {
	// Open/create shared memory file
	file, err := os.OpenFile(catalogSharedMemPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open shared memory file: %w", err)
	}
	defer file.Close()

	// Truncate to required size
	if err := file.Truncate(int64(catalogSharedMemSize)); err != nil {
		return fmt.Errorf("failed to truncate shared memory: %w", err)
	}

	// Memory-map the file
	sharedMem, err := syscall.Mmap(
		int(file.Fd()),
		0,
		int(catalogSharedMemSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
	)
	if err != nil {
		return fmt.Errorf("failed to mmap shared memory: %w", err)
	}

	csm.sharedMem = sharedMem
	csm.catalogConfig = (*[C.LXB_MAX_CATALOGS]C.lxb_catalog_config_t)(unsafe.Pointer(&sharedMem[catalogConfigOffset]))
	csm.serviceCatalogMap = (*[C.LXB_MAX_SERVICES]C.lxb_service_catalog_map_t)(unsafe.Pointer(&sharedMem[serviceMapOffset]))

	tk.LogIt(tk.LogInfo, "[CatalogSync] Initialized shared memory: path=%s size=%d bytes (catalogs=%d, services=%d)\n",
		catalogSharedMemPath, catalogSharedMemSize, catalogConfigSize, serviceMapSize)

	return nil
}

// SyncToSharedMemory writes catalog configs to shared memory
func (csm *CatalogSyncManager) SyncToSharedMemory() error {
	if csm.catalogConfig == nil {
		return fmt.Errorf("shared memory not initialized")
	}

	// Clear existing entries
	for i := 0; i < C.LXB_MAX_CATALOGS; i++ {
		C.memset(unsafe.Pointer(&csm.catalogConfig[i]), 0, C.sizeof_lxb_catalog_config_t)
	}

	// Clear name-to-ID mapping
	csm.nameToID = make(map[string]uint16)

	syncedCount := 0

	// Map catalog names to IDs (simple sequential allocation for now)
	catalogID := uint16(1) // Start from 1 (0 is reserved)

	// IMPORTANT: Sort catalog names to ensure consistent ordering
	// Maps have randomized iteration order in Go, causing catalog ID mismatches
	catalogNames := make([]string, 0, len(csm.tracingMgr.catalogs))
	for name := range csm.tracingMgr.catalogs {
		catalogNames = append(catalogNames, name)
	}
	sort.Strings(catalogNames) // Alphabetical order ensures Go and C agree on IDs

	for _, name := range catalogNames {
		catalog := csm.tracingMgr.catalogs[name]
		if catalogID >= C.LXB_MAX_CATALOGS {
			tk.LogIt(tk.LogWarning, "[CatalogSync] Too many catalogs, stopping at %d\n", catalogID-1)
			break
		}

		// Tracing catalogs always have deep inspection (no need to check)
		// Populate catalog config
		entry := &csm.catalogConfig[catalogID]
		entry.id = C.uint16_t(catalogID)
		entry.enabled = boolToC(catalog.DeepInspection.Enabled)
		entry.sample_rate = C.uint8_t(catalog.DeepInspection.SampleRate)
		entry.parser_type = parserTypeToC(catalog.DeepInspection.ParserType)
		entry.redact_pii = boolToC(catalog.DeepInspection.RedactPII)
		entry.max_body_size = C.uint32_t(catalog.DeepInspection.MaxBodySize)

		// L4 Tracing Configuration
		// Use same enabled/sampling as deep inspection for now
		// TODO: Add explicit l4_tracing fields to catalog YAML
		entry.l4_tracing_enabled = entry.enabled   // Inherit from HTTP tracing
		entry.l4_sampling_rate = entry.sample_rate // Inherit from HTTP sampling

		// Copy path prefix (use catalog name as path hint for now)
		// TODO: Add explicit path_prefix field to DeepInspectionConfig
		// For now: use "/" (root) to match all paths for testing
		pathPrefix := "/"
		if name != "default" && name != "test" {
			// Non-default catalogs use their name as path prefix
			pathPrefix = fmt.Sprintf("/%s", strings.ToLower(name))
		}
		if len(pathPrefix) >= C.LXB_MAX_PATH_LEN {
			pathPrefix = pathPrefix[:C.LXB_MAX_PATH_LEN-1]
		}
		copyStringToC(entry.path_prefix[:], pathPrefix)

		tk.LogIt(tk.LogInfo, "[CatalogSync] Synced catalog[%d]: name=%s enabled=%v sample_rate=%d%% parser=%s path=%s\n",
			catalogID, name, catalog.DeepInspection.Enabled, catalog.DeepInspection.SampleRate,
			catalog.DeepInspection.ParserType, pathPrefix)

		// Store name-to-ID mapping
		csm.nameToID[name] = catalogID

		// Store ID-to-catalog mapping in tracing catalog manager for efficient lookup
		if csm.tracingMgr != nil {
			csm.tracingMgr.catalogsByID[catalogID] = catalog
		}

		// DYNAMIC PARSER SELECTION: Sync catalog_id -> parser mapping
		// Maps YAML parser_type field to actual parser instance at runtime
		if csm.parserRegistry != nil {
			if err := csm.parserRegistry.SyncCatalogParser(catalogID, catalog.DeepInspection.ParserType); err != nil {
				tk.LogIt(tk.LogWarning, "[CatalogSync] Failed to sync parser for catalog[%d]: %v\n", catalogID, err)
			} else {
				tk.LogIt(tk.LogInfo, "[CatalogSync] Synced parser '%s' for catalog[%d]\n",
					catalog.DeepInspection.ParserType, catalogID)
			}
		}

		catalogID++
		syncedCount++
	}

	tk.LogIt(tk.LogInfo, "[CatalogSync] Synchronized %d catalog(s) to shared memory\n", syncedCount)
	csm.synced = true // Mark as synced

	return nil
}

// IsSynced returns whether catalogs have been synced to shared memory
func (csm *CatalogSyncManager) IsSynced() bool {
	return csm.synced
}

// GetCatalogID returns the catalog ID for a given catalog name
// Returns 0 if catalog not found or doesn't have deep_inspection enabled
func (csm *CatalogSyncManager) GetCatalogID(catalogName string) uint16 {
	if id, ok := csm.nameToID[catalogName]; ok {
		return id
	}
	return 0 // No catalog found
}

// AddServiceCatalogMapping adds a service-to-catalog mapping to shared memory
// This is called when a service is created with trace_type
func (csm *CatalogSyncManager) AddServiceCatalogMapping(vipIP net.IP, port uint16, protocol uint8, catalogID uint16) error {
	if csm.serviceCatalogMap == nil {
		return fmt.Errorf("shared memory not initialized")
	}

	// Convert to network byte order (same as proxy key format)
	vipNetOrder := tk.IPtonl(vipIP)
	portNetOrder := tk.Htons(port)

	// Find empty slot or existing entry
	var emptySlot int = -1
	for i := 0; i < C.LXB_MAX_SERVICES; i++ {
		entry := &csm.serviceCatalogMap[i]

		// Check if entry already exists
		if entry.xip == C.uint32_t(vipNetOrder) &&
			entry.xport == C.uint16_t(portNetOrder) &&
			entry.protocol == C.uint8_t(protocol) {
			// Update existing entry
			entry.catalog_id = C.uint16_t(catalogID)
			tk.LogIt(tk.LogInfo, "[CatalogSync] Updated service mapping: %s:%d proto=%d -> catalog_id=%d\n",
				vipIP.String(), port, protocol, catalogID)
			return nil
		}

		// Track first empty slot
		if emptySlot == -1 && entry.catalog_id == 0 {
			emptySlot = i
		}
	}

	// Add new entry
	if emptySlot == -1 {
		return fmt.Errorf("service catalog map full (max=%d services)", C.LXB_MAX_SERVICES)
	}

	entry := &csm.serviceCatalogMap[emptySlot]
	entry.xip = C.uint32_t(vipNetOrder)
	entry.xport = C.uint16_t(portNetOrder)
	entry.protocol = C.uint8_t(protocol)
	entry.catalog_id = C.uint16_t(catalogID)

	tk.LogIt(tk.LogInfo, "[CatalogSync] Added service mapping: %s:%d proto=%d -> catalog_id=%d\n",
		vipIP.String(), port, protocol, catalogID)

	return nil
}

// Close unmaps shared memory
func (csm *CatalogSyncManager) Close() error {
	if csm.sharedMem != nil {
		if err := syscall.Munmap(csm.sharedMem); err != nil {
			return fmt.Errorf("failed to munmap shared memory: %w", err)
		}
		csm.sharedMem = nil
		csm.catalogConfig = nil
	}
	return nil
}

// Helper functions

func boolToC(b bool) C.uint8_t {
	if b {
		return 1
	}
	return 0
}

func parserTypeToC(parserType string) C.uint8_t {
	switch strings.ToLower(parserType) {
	case "openai":
		return C.LXB_PARSER_OPENAI
	case "mcp":
		return C.LXB_PARSER_MCP
	case "graphql":
		return C.LXB_PARSER_GRAPHQL
	case "mock":
		return C.LXB_PARSER_MOCK
	default:
		return C.LXB_PARSER_GENERIC
	}
}

func copyStringToC(dst []C.char, src string) {
	for i := 0; i < len(src) && i < len(dst)-1; i++ {
		dst[i] = C.char(src[i])
	}
	dst[len(src)] = 0 // Null terminator
}
