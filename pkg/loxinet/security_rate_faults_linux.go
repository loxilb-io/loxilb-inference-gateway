//go:build linux && cgo && securityrate_faults

package loxinet

/*
#include "../../loxilb-ebpf/libbpf/src/bpf.h"
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Test-only key 1 forces selected reset writes to fail. Key 0 injects source
// tracking failure in the test-only XDP image. Production never compiles this.
func securityRateResetFaultMask() (uint32, error) {
	path := C.CString("/opt/loxilb/dp/bpf/sec_rate_fault")
	defer C.free(unsafe.Pointer(path))
	fd := C.bpf_obj_get(path)
	if fd < 0 {
		return 0, fmt.Errorf("test-only security reset fault map unavailable")
	}
	defer C.close(fd)
	key := C.uint(1)
	var mask C.uint
	if C.bpf_map_lookup_elem(fd, unsafe.Pointer(&key), unsafe.Pointer(&mask)) != 0 {
		return 0, fmt.Errorf("test-only security reset fault mask unavailable")
	}
	return uint32(mask), nil
}
