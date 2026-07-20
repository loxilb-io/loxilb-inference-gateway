/*
 * Copyright (c) 2024 NetLOX Inc
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
package handler

/*
#cgo CFLAGS: -I./../../../loxilb-ebpf/libbpf/src/ -I./../../../loxilb-ebpf/common -I./../../../loxilb-ebpf/kernel
#cgo LDFLAGS: -L. -L/lib64 -L./../../../loxilb-ebpf/kernel -L./../../../loxilb-ebpf/libbpf/src/build/usr/lib64/ -Wl,-rpath=/lib64/ -l:libloxilbdp.a -l:libbpf.a -lelf -lz -lssl -lcrypto -lnghttp2
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "loxilb_libdp.h"
#include "uthash.h"
#include "sockproxy.h"

// String array structure to pass to C callback
typedef struct {
    char **hostnames;
    char **cert_paths;
    int count;
    int capacity;
} hostname_array_t;

// Callback function to collect certificate hostnames and cert_paths
static void collect_hostname_cb(const char *hostname, const char *cert_path, void *data) {
    hostname_array_t *arr = (hostname_array_t *)data;
    if (arr->count >= arr->capacity) {
        // Need to expand - but let's just prevent overflow for now
        return;
    }
    arr->hostnames[arr->count] = strdup(hostname);
    arr->cert_paths[arr->count] = strdup(cert_path);
    arr->count++;
}

// Helper function to collect all hostnames and cert_paths
static int collect_all_hostnames(char ***out_hostnames, char ***out_cert_paths, int *out_count) {
    hostname_array_t arr;
    arr.capacity = 256;  // Max 256 certificates
    arr.count = 0;
    arr.hostnames = (char **)malloc(sizeof(char *) * arr.capacity);
    arr.cert_paths = (char **)malloc(sizeof(char *) * arr.capacity);
    if (!arr.hostnames || !arr.cert_paths) {
        if (arr.hostnames) free(arr.hostnames);
        if (arr.cert_paths) free(arr.cert_paths);
        return -1;
    }

    proxy_list_sni_certificates_with_path(collect_hostname_cb, &arr);

    *out_hostnames = arr.hostnames;
    *out_cert_paths = arr.cert_paths;
    *out_count = arr.count;
    return 0;
}

// Helper to free hostname and cert_path arrays
static void free_hostnames(char **hostnames, char **cert_paths, int count) {
    for (int i = 0; i < count; i++) {
        free(hostnames[i]);
        free(cert_paths[i]);
    }
    free(hostnames);
    free(cert_paths);
}
*/
import "C"
import (
	"fmt"
	"net/http"
	"unsafe"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	tk "github.com/loxilb-io/loxilib"
)

// SNICertificateGetResponse represents the response for GET /sni/certificates
type SNICertificateGetResponse struct {
	SniAttr []models.SNICertificateEntry `json:"sniAttr"`
}

// Implement the Responder interface for SNICertificateGetResponse
func (s *SNICertificateGetResponse) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if err := producer.Produce(rw, s); err != nil {
		panic(err)
	}
}

// SNI Certificate Management Functions

// ConfigPostSNICertificate handles POST /netlox/v1/sni/certificates
// Registers an SNI certificate globally (shared by all proxies)
func ConfigPostSNICertificate(params operations.PostSniCertificatesParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SNI Certificate POST API called. url : %s\n", params.HTTPRequest.URL)

	// Extract parameters from request body
	hostname := *params.Attr.Hostname
	var certPath string
	if params.Attr.CertPath != "" {
		certPath = params.Attr.CertPath
	}

	// Prepare C strings
	cHostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHostname))

	var cCertPath *C.char
	if certPath != "" {
		cCertPath = C.CString(certPath)
		defer C.free(unsafe.Pointer(cCertPath))
	}

	// Call C function with new simplified API
	ret := C.proxy_add_sni_certificate(cHostname, cCertPath)

	if ret != 0 {
		tk.LogIt(tk.LogDebug, "api: SNI certificate registration failed for %s: %d\n", hostname, ret)

		// Map error codes to meaningful messages
		switch ret {
		case -2: // ENOENT
			if certPath != "" {
				return &ResultResponse{Result: fmt.Sprintf("Error: Failed to load certificate for %s. Check certificate files at %s", hostname, certPath)}
			}
			return &ResultResponse{Result: fmt.Sprintf("Error: Failed to load certificate for %s. Check certificate files at /opt/loxilb/cert/%s", hostname, hostname)}
		case -17: // EEXIST
			return &ResultResponse{Result: fmt.Sprintf("Error: Certificate already registered for %s", hostname)}
		default:
			return &ResultResponse{Result: fmt.Sprintf("Error: Failed to register SNI certificate: %d", ret)}
		}
	}

	tk.LogIt(tk.LogInfo, "api: SNI certificate registered globally for %s\n", hostname)
	return &ResultResponse{Result: "Success"}
}

// ConfigDeleteSNICertificate handles DELETE /netlox/v1/sni/certificates
// Unregisters an SNI certificate globally
func ConfigDeleteSNICertificate(params operations.DeleteSniCertificatesParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SNI Certificate DELETE API called. url : %s\n", params.HTTPRequest.URL)

	// Extract hostname from request body
	hostname := *params.Attr.Hostname

	// Prepare C string
	cHostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHostname))

	// Call C function
	ret := C.proxy_remove_sni_certificate(cHostname)

	if ret != 0 {
		tk.LogIt(tk.LogDebug, "api: SNI certificate removal failed for %s: %d\n", hostname, ret)

		switch ret {
		case -2: // ENOENT
			return &ResultResponse{Result: fmt.Sprintf("Error: Certificate for %s not found", hostname)}
		default:
			return &ResultResponse{Result: fmt.Sprintf("Error: Failed to remove SNI certificate: %d", ret)}
		}
	}

	tk.LogIt(tk.LogInfo, "api: SNI certificate removed globally for %s\n", hostname)
	return &ResultResponse{Result: "Success"}
}

// ConfigGetSNICertificates handles GET /netlox/v1/sni/certificates
// Lists all global SNI certificates
func ConfigGetSNICertificates(params operations.GetSniCertificatesParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SNI Certificate GET API called. url : %s\n", params.HTTPRequest.URL)

	// Collect all hostnames and cert_paths from C
	var cHostnames **C.char
	var cCertPaths **C.char
	var count C.int

	ret := C.collect_all_hostnames(&cHostnames, &cCertPaths, &count)
	if ret != 0 {
		tk.LogIt(tk.LogError, "api: Failed to collect SNI certificates\n")
		return &ResultResponse{Result: "Error: Failed to list certificates"}
	}
	defer C.free_hostnames(cHostnames, cCertPaths, count)

	// Convert C string arrays to Go slice and create response
	var sniEntries []models.SNICertificateEntry

	if count > 0 {
		// Access the C arrays
		hostnameSlice := (*[1 << 30]*C.char)(unsafe.Pointer(cHostnames))[:count:count]
		certPathSlice := (*[1 << 30]*C.char)(unsafe.Pointer(cCertPaths))[:count:count]
		for i := 0; i < int(count); i++ {
			hostname := C.GoString(hostnameSlice[i])
			certPath := C.GoString(certPathSlice[i])
			hostnameCopy := hostname // Create a copy for the pointer
			entry := models.SNICertificateEntry{
				Hostname: &hostnameCopy,
				CertPath: certPath,
			}
			sniEntries = append(sniEntries, entry)
		}
	}

	tk.LogIt(tk.LogInfo, "api: Listed %d global SNI certificates\n", len(sniEntries))

	// Return proper JSON structure
	return &SNICertificateGetResponse{
		SniAttr: sniEntries,
	}
}
