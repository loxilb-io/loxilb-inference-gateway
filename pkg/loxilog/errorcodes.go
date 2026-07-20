package loxilog

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed error-codes.json
var errorCodesJSON []byte

// ErrorCodeEntry represents a single error code entry from the embedded registry.
type ErrorCodeEntry struct {
	Code        int    `json:"code"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	RootCause   string `json:"root_cause"`
	Remediation string `json:"remediation"`
	DocsURL     string `json:"docs_url"`
}

// errorCodeMap is the parsed lookup table, populated in init.
var errorCodeMap map[int]*ErrorCodeEntry

func init() {
	var entries []*ErrorCodeEntry
	if err := json.Unmarshal(errorCodesJSON, &entries); err != nil {
		panic(fmt.Sprintf("loxilog: failed to parse embedded error-codes.json: %v", err))
	}

	errorCodeMap = make(map[int]*ErrorCodeEntry, len(entries))
	for _, e := range entries {
		errorCodeMap[e.Code] = e
	}
}

// GetErrorCode returns the error code entry for the given code, or nil if unknown.
func GetErrorCode(code int) *ErrorCodeEntry {
	return errorCodeMap[code]
}

// GetAllErrorCodes returns all error code entries from the embedded registry.
func GetAllErrorCodes() []*ErrorCodeEntry {
	var entries []*ErrorCodeEntry
	// Re-unmarshal to preserve insertion order from JSON.
	_ = json.Unmarshal(errorCodesJSON, &entries)
	return entries
}

// GetErrorCodesJSON returns the raw embedded error-codes.json bytes.
func GetErrorCodesJSON() []byte {
	return errorCodesJSON
}
