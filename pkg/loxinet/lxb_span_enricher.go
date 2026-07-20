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
	"os"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	tk "github.com/loxilb-io/loxilib"
)

// EnrichSpanWithPayload adds payload-derived attributes to span
// This is called by span assembler for sampled requests with body files
func EnrichSpanWithPayload(evt *TraceEvent, span trace.Span, tracingCatalogMgr *TracingCatalogManager, parserRegistry *TraceParserRegistry) {
	// Step 1: Check if body was captured
	if !evt.HasBodyFile || evt.BodyFilePath == "" {
		return
	}

	// Step 2: Read body from tmpfs
	// Prepend /dev/shm/ to relative filename (C stores basename only)
	bodyPath := "/dev/shm/" + evt.BodyFilePath
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[SpanEnricher] Failed to read body file: %s (error: %v)\n",
			bodyPath, err)
		span.SetAttributes(attribute.String("loxilb.enrichment_error", "body_read_failed"))
		return
	}

	// Step 3: Delete body file immediately after reading (cleanup layer 1)
	defer func() {
		if err := os.Remove(bodyPath); err != nil {
			tk.LogIt(tk.LogWarning, "[SpanEnricher] Failed to delete body file: %s (error: %v)\n",
				bodyPath, err)
		} else {
			tk.LogIt(tk.LogDebug, "[SpanEnricher] ✓ Deleted body file: %s (span=%016x)\n", bodyPath, evt.SpanID)
		}
	}()

	// Record body size metric
	RecordParsedBodySize("generic", len(body))

	// Step 4: Get catalog configuration
	if tracingCatalogMgr == nil {
		tk.LogIt(tk.LogWarning, "[SpanEnricher] TracingCatalogManager is nil, cannot enrich span\n")
		span.SetAttributes(attribute.String("loxilb.enrichment_error", "catalog_manager_nil"))
		return
	}

	catalog := tracingCatalogMgr.GetCatalogByID(evt.CatalogID)
	if catalog == nil {
		// Not an error - catalog might not be configured for this service
		span.SetAttributes(
			attribute.Int("loxilb.catalog_id", int(evt.CatalogID)),
			attribute.String("loxilb.catalog_status", "not_found"),
		)
		return
	}

	// Step 5: Check if deep inspection is enabled
	if !catalog.DeepInspection.Enabled {
		return
	}

	// Step 6: Get parser from registry
	parserType := catalog.DeepInspection.ParserType
	if parserType == "" {
		parserType = "generic" // Default parser
	}

	if parserRegistry == nil {
		tk.LogIt(tk.LogWarning, "[SpanEnricher] ParserRegistry is nil, cannot enrich span\n")
		span.SetAttributes(attribute.String("loxilb.enrichment_error", "parser_registry_nil"))
		return
	}

	if !parserRegistry.HasParser(parserType) {
		tk.LogIt(tk.LogWarning, "[SpanEnricher] No parser registered for type=%s (catalog=%s)\n",
			parserType, catalog.CatalogName)
		span.SetAttributes(
			attribute.String("loxilb.parser_type", parserType),
			attribute.String("loxilb.enrichment_error", "parser_not_found"),
		)
		return
	}

	// Step 7: Build parser request
	parseReq := &ParseRequest{
		Body:        body,
		Headers:     extractHeadersFromEvent(evt),
		Method:      evt.HTTPMethod,
		Path:        evt.HTTPTarget,
		ContentType: evt.ContentType,
		CatalogID:   evt.CatalogID,
		Config:      buildPluginConfig(&catalog.DeepInspection),
	}

	tk.LogIt(tk.LogDebug, "[SpanEnricher] Calling parser '%s' with body_len=%d method='%s' path='%s'\n",
		parserType, len(body), evt.HTTPMethod, evt.HTTPTarget)

	// Step 8: Parse with timeout
	startTime := time.Now()
	parser := parserRegistry.GetParserByName(parserType)
	if parser == nil {
		tk.LogIt(tk.LogWarning, "[SpanEnricher] Parser '%s' not found in registry\n", parserType)
		span.SetAttributes(
			attribute.String("loxilb.parser_type", parserType),
			attribute.String("loxilb.enrichment_error", "parser_not_found"),
		)
		return
	}

	ctx := context.Background()
	parseResp, err := parser.Parse(ctx, parseReq)
	duration := time.Since(startTime).Seconds()

	// Record metrics
	if err != nil {
		status := "error"
		if err.Error() == "timeout" {
			status = "timeout"
		} else if err.Error() == "panic" {
			status = "panic"
		}
		RecordParseCall(parserType, status, duration)

		tk.LogIt(tk.LogWarning, "[SpanEnricher] Parser error for catalog=%s parser=%s: %v\n",
			catalog.CatalogName, parserType, err)
		span.SetAttributes(
			attribute.String("loxilb.parser_type", parserType),
			attribute.String("loxilb.enrichment_error", err.Error()),
		)
		return
	}

	RecordParseCall(parserType, "success", duration)

	// Step 9: Add parsed attributes to span
	if parseResp != nil && len(parseResp.Attributes) > 0 {
		tk.LogIt(tk.LogDebug, "[SpanEnricher] Parser returned %d attributes\n", len(parseResp.Attributes))
		attrs := make([]attribute.KeyValue, 0, len(parseResp.Attributes)+2)

		// Add parser metadata
		attrs = append(attrs,
			attribute.String("loxilb.parser_type", parserType),
			attribute.String("loxilb.catalog_name", catalog.CatalogName),
		)

		// Add parsed attributes
		for key, value := range parseResp.Attributes {
			attrs = append(attrs, convertToAttribute(key, value))
		}

		span.SetAttributes(attrs...)
		RecordAttributesExtracted(parserType, len(parseResp.Attributes))

		tk.LogIt(tk.LogInfo, "[SpanEnricher] Enriched span: catalog=%s parser=%s attributes=%d duration=%.3fs\n",
			catalog.CatalogName, parserType, len(parseResp.Attributes), duration)
	}

	// Step 10: Optional - store redacted body if provided
	// (Currently just used for validation - could write back to tmpfs if needed)
}

// extractHeadersFromEvent extracts HTTP headers from trace event
// Note: Current event structure doesn't store all headers, only key fields
// This can be enhanced in future by adding header storage to ring buffer
func extractHeadersFromEvent(evt *TraceEvent) map[string]string {
	headers := make(map[string]string)

	if evt.HTTPHost != "" {
		headers["Host"] = evt.HTTPHost
	}
	if evt.ContentType != "" {
		headers["Content-Type"] = evt.ContentType
	}

	return headers
}

// buildPluginConfig constructs parser config from catalog
func buildPluginConfig(cfg *DeepInspectionConfig) PluginConfig {
	timeout := 5 * time.Second // Default
	if cfg.ParserTimeout != "" {
		if d, err := time.ParseDuration(cfg.ParserTimeout); err == nil {
			timeout = d
		}
	}

	return PluginConfig{
		Timeout:      timeout,
		MaxBodySize:  int(cfg.MaxBodySize),
		EnableDebug:  false,
		CustomConfig: make(map[string]string),
	}
}

// convertToAttribute converts interface{} value to OpenTelemetry attribute
func convertToAttribute(key string, value interface{}) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case float64:
		return attribute.Float64(key, v)
	case bool:
		return attribute.Bool(key, v)
	default:
		// Fallback: convert to string
		return attribute.String(key, fmt.Sprintf("%v", v))
	}
}
