/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"
)

// rawLoadbalancerBodyKey carries the LB request body past go-swagger's body
// consumer. The generated numeric model cannot distinguish an omitted field,
// an explicit zero, and JSON null, so handlers consult this raw presence map.
type rawLoadbalancerBodyKey struct{}

// WithRawLoadbalancerBody stores a load-balancer POST/PATCH body in the request
// context. setupGlobalMiddleware calls it before generated binding drains Body.
func WithRawLoadbalancerBody(ctx context.Context, raw []byte) context.Context {
	return context.WithValue(ctx, rawLoadbalancerBodyKey{}, raw)
}

// WithRawLoadbalancerBodyBuffer stores a lazy middleware capture. The request
// body is teed while generated binding consumes it, so the generated stack
// retains ownership of body consumption and read-error handling.
func WithRawLoadbalancerBodyBuffer(ctx context.Context, raw *bytes.Buffer) context.Context {
	return context.WithValue(ctx, rawLoadbalancerBodyKey{}, raw)
}

func rawLoadbalancerBodyFromContext(ctx context.Context) []byte {
	switch v := ctx.Value(rawLoadbalancerBodyKey{}).(type) {
	case []byte:
		return v
	case *bytes.Buffer:
		return v.Bytes()
	}
	return nil
}

// WithRawPatchBody is retained for callers and tests compiled against the
// original PATCH-only presence helper.
func WithRawPatchBody(ctx context.Context, raw []byte) context.Context {
	return WithRawLoadbalancerBody(ctx, raw)
}

func rawPatchBodyFromContext(ctx context.Context) []byte {
	return rawLoadbalancerBodyFromContext(ctx)
}

// loadbalancerRequestPresence records the exact keys and raw values supplied
// by a caller. Typed models remain the source of validated non-null values.
type loadbalancerRequestPresence struct {
	top map[string]json.RawMessage
	svc map[string]json.RawMessage
}

type patchPresence = loadbalancerRequestPresence

func parseLoadbalancerRequestPresence(raw []byte) (*loadbalancerRequestPresence, error) {
	p := &loadbalancerRequestPresence{
		top: map[string]json.RawMessage{},
		svc: map[string]json.RawMessage{},
	}
	if len(raw) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(raw, &p.top); err != nil {
		return nil, err
	}
	if svcRaw, ok := p.top["serviceArguments"]; ok && len(svcRaw) > 0 {
		// serviceArguments:null is handled by generated required-field validation;
		// it intentionally yields no child-field presence here.
		_ = json.Unmarshal(svcRaw, &p.svc)
	}
	return p, nil
}

func parsePatchPresence(raw []byte) (*patchPresence, error) {
	return parseLoadbalancerRequestPresence(raw)
}

func (p *loadbalancerRequestPresence) svcPresent(key string) bool {
	_, ok := p.svc[key]
	return ok
}

func (p *loadbalancerRequestPresence) svcIsNull(key string) bool {
	v, ok := p.svc[key]
	return ok && bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}

func (p *loadbalancerRequestPresence) topPresent(key string) bool {
	_, ok := p.top[key]
	return ok
}

func (p *loadbalancerRequestPresence) validatePDThresholds() error {
	for _, key := range []string{"pd_cache_threshold", "pd_balance_abs_threshold"} {
		if p.svcIsNull(key) {
			return fmt.Errorf("%s must not be null", key)
		}
	}
	return nil
}

// validateKVNumericArguments performs the semantic and destination-width
// checks before handlers narrow generated signed values into uint32/uint16.
// Zero is an intentional declaration sentinel for these fields. JSON null is
// never a sentinel: go-swagger decodes it to the same scalar zero, so the raw
// presence map must reject it explicitly.
func (p *loadbalancerRequestPresence) validateKVNumericArguments(
	src *models.LoadbalanceEntryServiceArguments,
) error {
	for _, key := range []string{"kvBlockSize", "kvZmqPort", "kvDpRankCount", "pdBootstrapPort"} {
		if p.svcIsNull(key) {
			return fmt.Errorf("%s must not be null", key)
		}
	}
	if src == nil {
		return nil
	}

	if src.KvBlockSize < 0 || src.KvBlockSize > int64(cmn.KVBlockSizeMax) {
		return fmt.Errorf("kvBlockSize must be 0 or within 1..%d", cmn.KVBlockSizeMax)
	}
	if src.KvZmqPort < 0 || src.KvZmqPort > 65535 {
		return fmt.Errorf("kvZmqPort must be 0 or within 1..65535")
	}
	if src.KvDpRankCount < 0 || src.KvDpRankCount > 8 {
		return fmt.Errorf("kvDpRankCount must be 0 or within 1..8")
	}
	if src.PdBootstrapPort < 0 || src.PdBootstrapPort > 65535 {
		return fmt.Errorf("pdBootstrapPort must be within 0..65535")
	}

	// Only exact modes create subscribers. Resolve both zero sentinels before
	// checking the inclusive last rank port, and keep the sum widened until it
	// has been proven to fit uint16.
	if src.KvExactMode == 1 || src.KvExactMode == 3 {
		base := uint64(src.KvZmqPort)
		if base == 0 {
			base = 5557
		}
		ranks := uint64(src.KvDpRankCount)
		if ranks == 0 {
			ranks = 1
		}
		if base+ranks-1 > 65535 {
			return fmt.Errorf("kvZmqPort + kvDpRankCount - 1 must be <= 65535 (base %d, ranks %d)", base, ranks)
		}
	}
	return nil
}

// validateUnsupportedKVNumericPatch makes PATCH ownership explicit. The
// canonical PATCH path supports the two P/D thresholds, but not KV transport
// geometry. Silently ignoring these keys would turn a successful response into
// false configuration evidence.
func (p *loadbalancerRequestPresence) validateUnsupportedKVNumericPatch() error {
	for _, key := range []string{"kvBlockSize", "kvZmqPort", "kvDpRankCount", "pdBootstrapPort"} {
		if p.svcPresent(key) {
			return fmt.Errorf("PATCH does not support field: %s", key)
		}
	}
	return nil
}

// applyPDThresholds copies validated declarations and their presence bits.
// A nonzero typed value remains an update for direct/legacy handler callers
// that do not pass raw context. Explicit zero still requires wire presence.
// For PATCH the destination starts with the current stored declaration.
func (p *loadbalancerRequestPresence) applyPDThresholds(
	dst *cmn.LbServiceArg,
	src *models.LoadbalanceEntryServiceArguments,
) {
	if p.svcPresent("pd_cache_threshold") || src.PdCacheThreshold != 0 {
		dst.PDCacheThreshold = uint8(src.PdCacheThreshold)
		dst.PDCacheThresholdPresent = p.svcPresent("pd_cache_threshold")
	}
	if p.svcPresent("pd_balance_abs_threshold") || src.PdBalanceAbsThreshold != 0 {
		dst.PDBalanceAbsThreshold = uint8(src.PdBalanceAbsThreshold)
		dst.PDBalanceAbsThresholdPresent = p.svcPresent("pd_balance_abs_threshold")
	}
}
