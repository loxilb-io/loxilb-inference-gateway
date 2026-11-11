package models

import "github.com/go-openapi/errors"

// validateEndPointHostStateTuple is kept outside the generated model. The
// generation hook calls it before generated field checks, including for nil
// payloads, and retains the existing management API error behavior.
func validateEndPointHostStateTuple(m *EndPointHostState) error {
	if m == nil {
		return errors.New(400, "endpoint host state is required")
	}
	if m.EpPort < 0 || m.EpPort > 65535 {
		return errors.New(400, "epPort must be between 0 and 65535")
	}
	if (m.EpPort == 0) != (m.EpProto == "") {
		return errors.New(400, "nonzero epPort and epProto must be supplied together")
	}
	switch m.EpProto {
	case "", "tcp", "udp", "sctp", "http", "https", "ping", "tls-hello", "none":
	default:
		return errors.New(400, "unknown epProto %q", m.EpProto)
	}
	return nil
}
