package loxilog

import (
	"context"

	"github.com/rs/zerolog"
)

// EventBuilder provides a fluent API for constructing and emitting structured
// audit log events. Chain methods set fields, and Msg or Send dispatches
// the event to the underlying zerolog logger.
//
// Usage:
//
//	loxilog.Event(ctx).
//	    Component("network").
//	    Action("rule-add").
//	    Outcome(OutcomeSuccess).
//	    ErrCode(ErrNatPoolExhausted).
//	    Msg("NAT rule created")
type EventBuilder struct {
	ctx            context.Context
	logger         *zerolog.Logger
	level          zerolog.Level
	category       Category
	securityBypass bool
	component      string
	action         string
	outcome        string
	errCode        int
	hasErrCode     bool
	reason         string
	eventType      string
	eventCategory  string
	extraStr       [][2]string
	extraInt       [][2]interface{}
}

// Level sets the log level for this event.
func (b *EventBuilder) Level(l zerolog.Level) *EventBuilder {
	b.level = l
	return b
}

// Category sets the category for level filtering.
func (b *EventBuilder) Category(c Category) *EventBuilder {
	b.category = c
	return b
}

// Component sets the service.component field.
func (b *EventBuilder) Component(v string) *EventBuilder {
	b.component = v
	return b
}

// Action sets the event.action field.
func (b *EventBuilder) Action(v string) *EventBuilder {
	b.action = v
	return b
}

// Outcome sets the event.outcome field. Use OutcomeSuccess, OutcomeFailure, or OutcomeUnknown.
func (b *EventBuilder) Outcome(v string) *EventBuilder {
	b.outcome = v
	return b
}

// ErrCode sets the error.code field.
func (b *EventBuilder) ErrCode(v int) *EventBuilder {
	b.errCode = v
	b.hasErrCode = true
	return b
}

// SecurityBypass marks this event to bypass category-level filtering.
// SecurityBypass events are always emitted regardless of the category's
// current log level setting.
func (b *EventBuilder) SecurityBypass() *EventBuilder {
	b.securityBypass = true
	return b
}

// Str adds an arbitrary string field.
func (b *EventBuilder) Str(key, val string) *EventBuilder {
	b.extraStr = append(b.extraStr, [2]string{key, val})
	return b
}

// Int adds an arbitrary int field.
func (b *EventBuilder) Int(key string, val int) *EventBuilder {
	b.extraInt = append(b.extraInt, [2]interface{}{key, val})
	return b
}

// Reason sets the event.reason field.
func (b *EventBuilder) Reason(v string) *EventBuilder {
	b.reason = v
	return b
}

// Type sets the event.type field.
func (b *EventBuilder) Type(v string) *EventBuilder {
	b.eventType = v
	return b
}

// EventCategory sets the event.category field (ECS category, distinct from log Category).
func (b *EventBuilder) EventCategory(v string) *EventBuilder {
	b.eventCategory = v
	return b
}

// shouldEmit checks whether the event should be dispatched based on
// the category's current log level. SecurityBypass events always emit.
func (b *EventBuilder) shouldEmit() bool {
	if b.securityBypass {
		return true
	}
	minLevel := zerolog.Level(categoryLevels[b.category].Load())
	return b.level >= minLevel
}

// Msg dispatches the event with the given message.
// If the event's level is below the category's minimum level (and
// SecurityBypass is not set), the event is silently dropped.
func (b *EventBuilder) Msg(msg string) {
	if !b.shouldEmit() {
		return
	}

	e := b.logger.WithLevel(b.level)

	// Apply ECS fields.
	if b.component != "" {
		e = e.Str(FieldComponent, b.component)
	}
	if b.action != "" {
		e = e.Str(FieldEventAction, b.action)
	}
	if b.outcome != "" {
		e = e.Str(FieldEventOutcome, b.outcome)
	}
	if b.hasErrCode {
		e = e.Int(FieldErrCode, b.errCode)
	}
	if b.reason != "" {
		e = e.Str(FieldEventReason, b.reason)
	}
	if b.eventType != "" {
		e = e.Str(FieldEventType, b.eventType)
	}
	if b.eventCategory != "" {
		e = e.Str(FieldEventCategory, b.eventCategory)
	}

	// Extract trace ID from context.
	if b.ctx != nil {
		if traceID := TraceIDFromCtx(b.ctx); traceID != "" {
			e = e.Str(FieldTraceID, traceID)
		}
	}

	// Apply extra fields.
	for _, kv := range b.extraStr {
		e = e.Str(kv[0], kv[1])
	}
	for _, kv := range b.extraInt {
		e = e.Int(kv[0].(string), kv[1].(int))
	}

	e.Msg(msg)
}

// Send dispatches the event with an empty message.
// Equivalent to Msg("").
func (b *EventBuilder) Send() {
	b.Msg("")
}
