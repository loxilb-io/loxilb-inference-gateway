//go:build !securityrate_faults

package loxinet

// Production builds have no failure-injection map or management surface.
func securityRateResetFaultMask() (uint32, error) { return 0, nil }
