/*
 * Copyright (c) 2026 LoxiLB Authors
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
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/pkg/maintenance"
	tk "github.com/loxilb-io/loxilib"
)

// maintenanceStatusModel renders a maintenance snapshot as the wire
// contract. Refusal fields are derived from what THIS state actually
// makes the gateway refuse: the maintenance gate rejects mutating config
// calls, and it does not touch the data path -- refusing_new_inference
// is therefore hardwired false rather than mirroring the state, so the
// read-back never claims a traffic drain that is not happening.
func maintenanceStatusModel(st maintenance.Status) *models.MaintenanceStatus {
	state := string(st.State)
	inMaint := st.State == maintenance.StateMaintenance
	refusingInference := false
	cancellable := true
	inFlight := ApiHooks.NetAiInFlightStreamsGet()
	elapsed := int64(st.Elapsed / time.Second)
	deadlineExceeded := st.DeadlineExceeded
	m := &models.MaintenanceStatus{
		State:                 &state,
		OperationID:           st.OperationID,
		RefusingNewConfig:     &inMaint,
		RefusingNewInference:  &refusingInference,
		Cancellable:           &cancellable,
		InFlightStreams:       &inFlight,
		ElapsedSeconds:        &elapsed,
		DrainTimeoutSeconds:   uint32(st.DrainTimeout / time.Second),
		DrainDeadlineExceeded: &deadlineExceeded,
	}
	if !st.EnteredAt.IsZero() {
		m.EnteredAt = strfmt.DateTime(st.EnteredAt)
	}
	return m
}

// ConfigGetMaintenance implements GET /maintenance: the operator
// maintenance state with its drain read-back.
func ConfigGetMaintenance(params operations.GetMaintenanceParams, principal any) middleware.Responder {
	return operations.NewGetMaintenanceOK().WithPayload(maintenanceStatusModel(maintenance.Get()))
}

// ConfigPutMaintenance implements PUT /maintenance: idempotent operator
// enter/leave. The generated layer already enforced the body and its
// required enabled field, so a nil here is a programming error worth a
// 400 rather than a panic.
func ConfigPutMaintenance(params operations.PutMaintenanceParams, principal any) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api called. url : %s\n", params.HTTPRequest.URL)
	attr := params.Attr
	if attr == nil || attr.Enabled == nil {
		return operations.NewPutMaintenanceBadRequest().WithPayload(&models.Error{
			Code:    400,
			Message: "Malformed arguments for API call",
			Result:  "enabled is required",
		})
	}
	var st maintenance.Status
	if *attr.Enabled {
		before := maintenance.Get()
		st = maintenance.Enter(time.Duration(attr.DrainTimeoutSeconds) * time.Second)
		if before.State != maintenance.StateMaintenance {
			tk.LogIt(tk.LogInfo, "[MAINT] operator maintenance entered: op=%s drain_timeout=%ds\n",
				st.OperationID, attr.DrainTimeoutSeconds)
		}
	} else {
		st = maintenance.Leave()
		if st.OperationID != "" {
			tk.LogIt(tk.LogInfo, "[MAINT] operator maintenance left: op=%s\n", st.OperationID)
		}
	}
	return operations.NewPutMaintenanceOK().WithPayload(maintenanceStatusModel(st))
}
