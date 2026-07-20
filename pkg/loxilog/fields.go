// Package loxilog provides structured audit logging for LoxiLB.
//
// It produces dual-output events (ECS JSON + ConsoleWriter plaintext)
// through an ergonomic fluent builder API with per-category dynamic
// level control and async diode buffering.
package loxilog

// ECS v8 field name constants.
// These follow Elastic Common Schema v8.11 naming conventions.
const (
	// ECSVersion is the ECS specification version used by this logger.
	ECSVersion = "8.11"

	// Core ECS fields
	FieldECSVersion    = "ecs.version"
	FieldEventAction   = "event.action"
	FieldEventOutcome  = "event.outcome"
	FieldEventCategory = "event.category"
	FieldEventType     = "event.type"
	FieldEventReason   = "event.reason"
	FieldEventSeverity = "event.severity"
	FieldComponent     = "service.component"
	FieldErrCode       = "error.code"
	FieldLogLogger     = "log.logger"
	FieldTraceID       = "trace.id"
)

// ECS event.outcome allowed values.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeUnknown = "unknown"
)

// ECS event.category allowed values.
const (
	CategoryNetwork        = "network"
	CategoryAuthentication = "authentication"
	CategoryConfiguration  = "configuration"
	CategoryProcess        = "process"
	CategoryDatabase       = "database"
	CategoryWeb            = "web"
)

// ECS event.type allowed values.
const (
	TypeChange   = "change"
	TypeCreation = "creation"
	TypeDeletion = "deletion"
	TypeError    = "error"
	TypeInfo     = "info"
	TypeAccess   = "access"
	TypeStart    = "start"
	TypeEnd      = "end"
)
