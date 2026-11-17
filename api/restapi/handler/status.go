/*
 * Copyright (c) 2022 NetLOX Inc
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

import (
	"github.com/loxilb-io/loxilb/api/apiutils/status"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

func ConfigGetProcess(params operations.GetStatusProcessParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Status %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	process, err := status.ProcessInfoGet()
	return processStatusResponse(process, err)
}

// Process collection has no client-supplied selector. Any failure is a server
// fault, regardless of the typed cause or its diagnostic wording.
func processStatusResponse(process []*models.ProcessInfoEntry, err error) middleware.Responder {
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: process status collection failed: %v\n", err)
		return errorResponseWithCode(http.StatusInternalServerError, "Process status collection failed")
	}

	return operations.NewGetStatusProcessOK().WithPayload(&models.ProcessStatus{ProcessAttr: process})
}

func ConfigGetDevice(params operations.GetStatusDeviceParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Status %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	// Get Conntrack informations
	res, err := status.DeviceInfoGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return operations.NewGetStatusDeviceOK().WithPayload(res)
}

func ConfigGetFileSystem(params operations.GetStatusFilesystemParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Status %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	res, err := status.FileSystemInfoGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return operations.NewGetStatusFilesystemOK().WithPayload(&models.FilesystemStatus{FilesystemAttr: res})
}
