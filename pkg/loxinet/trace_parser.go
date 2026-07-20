// trace_parser.go - HTTP/HTTPS body parser infrastructure for deep protocol inspection
// Updated to use PayloadParser plugin architecture
package loxinet

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// TraceParserContext provides metadata for parser routing decisions
type TraceParserContext struct {
	CatalogID   uint16 // Catalog/service identifier
	ContentType string // Content-Type header hint
	Method      string // HTTP method (GET, POST, etc.)
	URLPath     string // Request URL path
	IsStreaming bool   // Streaming response flag
	IsJSON      bool   // JSON content hint
}

// TraceParserRegistry manages protocol-specific parsers with routing logic
// Now wraps PayloadParser interface for unified plugin architecture
type TraceParserRegistry struct {
	mu             sync.RWMutex
	catalogParsers map[uint16]PayloadParser // catalog_id -> parser (dynamic)
	pathParsers    map[string]PayloadParser // URL path prefix -> parser (static)
	parsersByName  map[string]PayloadParser // parser name -> parser instance (registry)
	defaultParser  PayloadParser            // fallback parser
}

// NewTraceParserRegistry creates initialized parser registry
func NewTraceParserRegistry() *TraceParserRegistry {
	return &TraceParserRegistry{
		catalogParsers: make(map[uint16]PayloadParser),
		pathParsers:    make(map[string]PayloadParser),
		parsersByName:  make(map[string]PayloadParser),
	}
}

// RegisterCatalogParser registers parser for specific catalog/service ID
func (r *TraceParserRegistry) RegisterCatalogParser(catalogID uint16, parser PayloadParser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.catalogParsers[catalogID] = parser
	meta := parser.Metadata()
	tk.LogIt(tk.LogInfo, "[TRACE_PARSER] Registered %s parser (%s) for catalog_id=%d\n", meta.Name, meta.Version, catalogID)
}

// RegisterPathParser registers parser for URL path prefix (e.g., "/v1/chat/completions")
func (r *TraceParserRegistry) RegisterPathParser(pathPrefix string, parser PayloadParser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pathParsers[pathPrefix] = parser
	meta := parser.Metadata()
	tk.LogIt(tk.LogInfo, "[TRACE_PARSER] Registered %s parser (%s) for path=%s\n", meta.Name, meta.Version, pathPrefix)
}

// RegisterDefaultParser sets fallback parser when no specific match found
func (r *TraceParserRegistry) RegisterDefaultParser(parser PayloadParser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultParser = parser
	meta := parser.Metadata()
	tk.LogIt(tk.LogInfo, "[TRACE_PARSER] Registered %s parser (%s) as default\n", meta.Name, meta.Version)
}

// RegisterParserByName registers a parser with a friendly name for dynamic lookup
// Names: "openai", "mcp", "mock", "graphql", etc.
func (r *TraceParserRegistry) RegisterParserByName(name string, parser PayloadParser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsersByName[name] = parser
	meta := parser.Metadata()
	tk.LogIt(tk.LogInfo, "[TRACE_PARSER] Registered %s parser (%s) with name '%s'\n", meta.Name, meta.Version, name)
}

// GetParserByName retrieves a parser by its registered name
// Returns nil if parser not found
func (r *TraceParserRegistry) GetParserByName(name string) PayloadParser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.parsersByName[name]
}

// HasParser checks if a parser is registered with the given name
// Thread-safe: Uses read lock
func (r *TraceParserRegistry) HasParser(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.parsersByName[name]
	return exists
}

// SyncCatalogParser dynamically updates catalog_id -> parser mapping
// Used when YAML catalogs are loaded/updated to establish parser routing
func (r *TraceParserRegistry) SyncCatalogParser(catalogID uint16, parserName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if catalogID == 0 {
		return fmt.Errorf("catalog_id 0 is reserved")
	}

	parser, ok := r.parsersByName[parserName]
	if !ok {
		return fmt.Errorf("parser '%s' not registered (available: %v)", parserName, r.listParserNames())
	}

	r.catalogParsers[catalogID] = parser
	meta := parser.Metadata()
	tk.LogIt(tk.LogInfo, "[TRACE_PARSER] Synced catalog[%d] -> %s parser (%s)\n", catalogID, meta.Name, meta.Version)
	return nil
}

// RemoveCatalogParser removes catalog_id -> parser mapping
// Used when catalog is deleted or parser assignment is cleared
func (r *TraceParserRegistry) RemoveCatalogParser(catalogID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.catalogParsers[catalogID]; ok {
		delete(r.catalogParsers, catalogID)
		tk.LogIt(tk.LogInfo, "[TRACE_PARSER] Removed parser mapping for catalog[%d]\n", catalogID)
	}
}

// ListAvailableParsers returns all registered parser names
func (r *TraceParserRegistry) ListAvailableParsers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.listParserNames()
}

// listParserNames returns parser names (must hold lock)
func (r *TraceParserRegistry) listParserNames() []string {
	names := make([]string, 0, len(r.parsersByName))
	for name := range r.parsersByName {
		names = append(names, name)
	}
	return names
}

// GetCatalogParserName returns the parser name assigned to a catalog_id
// Returns empty string if no parser assigned
func (r *TraceParserRegistry) GetCatalogParserName(catalogID uint16) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	parser, ok := r.catalogParsers[catalogID]
	if !ok {
		return ""
	}

	// Find parser name by comparing instances
	for name, p := range r.parsersByName {
		if p == parser {
			return name
		}
	}

	return "unknown"
}

// SelectParser chooses appropriate parser based on context
func (r *TraceParserRegistry) SelectParser(ctx TraceParserContext) PayloadParser {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tk.LogIt(tk.LogDebug, "[PARSER_SELECT] Selecting parser: catalog_id=%d path=%s\n", ctx.CatalogID, ctx.URLPath)

	// Priority 1: Catalog-based routing (most specific)
	if parser, ok := r.catalogParsers[ctx.CatalogID]; ok {
		meta := parser.Metadata()
		tk.LogIt(tk.LogDebug, "[PARSER_SELECT_TIER1] Selected catalog parser: catalog_id=%d -> %s (%s)\n",
			ctx.CatalogID, meta.Name, meta.Version)
		return parser
	}
	if ctx.CatalogID != 0 {
		tk.LogIt(tk.LogDebug, "[PARSER_SELECT_TIER1] No parser found for catalog_id=%d, trying tier 2\n", ctx.CatalogID)
	}

	// Priority 2: Path-based routing (for multi-tenant services)
	for prefix, parser := range r.pathParsers {
		if strings.HasPrefix(ctx.URLPath, prefix) {
			meta := parser.Metadata()
			tk.LogIt(tk.LogDebug, "[PARSER_SELECT_TIER2] Selected path parser: path=%s matches prefix=%s -> %s (%s)\n",
				ctx.URLPath, prefix, meta.Name, meta.Version)
			return parser
		}
	}
	tk.LogIt(tk.LogDebug, "[PARSER_SELECT_TIER2] No path match for %s, falling back to default\n", ctx.URLPath)

	// Priority 3: Default parser (or nil if none registered)
	if r.defaultParser != nil {
		meta := r.defaultParser.Metadata()
		tk.LogIt(tk.LogDebug, "[PARSER_SELECT_TIER3] Using default parser: %s (%s)\n", meta.Name, meta.Version)
	}
	return r.defaultParser
}

// Parse routes event to appropriate parser and returns extracted attributes
// Bridge method that adapts old inline/file interface to new PayloadParser interface
func (r *TraceParserRegistry) Parse(ctx TraceParserContext, inlineBody []byte, bodyFilePath string, isRequest bool) ParsedAttributes {
	parser := r.SelectParser(ctx)
	if parser == nil {
		return nil // No parser available for this context
	}

	// Read body content (inline or file)
	var bodyContent []byte
	if len(inlineBody) > 0 && bodyFilePath == "" {
		bodyContent = inlineBody
	} else if bodyFilePath != "" {
		data, err := os.ReadFile(bodyFilePath)
		if err != nil {
			tk.LogIt(tk.LogWarning, "[TRACE_PARSER] Failed to read body file %s: %v\n", bodyFilePath, err)
			return nil
		}
		bodyContent = data
	} else {
		return nil // No body available
	}

	// Build ParseRequest for new interface
	req := &ParseRequest{
		Body:        bodyContent,
		Headers:     make(map[string]string),
		Method:      ctx.Method,
		Path:        ctx.URLPath,
		ContentType: ctx.ContentType,
		CatalogID:   ctx.CatalogID,
		Config: PluginConfig{
			Timeout: 5 * time.Second,
		},
	}

	meta := parser.Metadata()
	tk.LogIt(tk.LogDebug, "[PARSER_INVOKE] Calling %s.Parse for catalog_id=%d method=%s path=%s body_len=%d\n",
		meta.Name, ctx.CatalogID, ctx.Method, ctx.URLPath, len(bodyContent))

	// Call parser with timeout
	parseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := parser.Parse(parseCtx, req)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[PARSER_FAILED] Parser %s failed for catalog_id=%d path=%s: %v\n",
			meta.Name, ctx.CatalogID, ctx.URLPath, err)
		return nil
	}

	if resp != nil && resp.Attributes != nil {
		tk.LogIt(tk.LogDebug, "[PARSER_SUCCESS] Parser %s extracted %d attributes for catalog_id=%d path=%s\n",
			meta.Name, len(resp.Attributes), ctx.CatalogID, ctx.URLPath)
		return resp.Attributes
	}

	return nil
}

// --- Utility Functions ---

// ReadBodyFromFile reads full body content from /dev/shm file (utility for parsers)
func ReadBodyFromFile(bodyFilePath string) ([]byte, error) {
	file, err := os.Open(bodyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open body file: %w", err)
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read body file: %w", err)
	}

	return body, nil
}
