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
