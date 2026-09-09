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
	"net/http"
	"sync/atomic"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/prometheus"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// promHandler is constructed once: promhttp.Handler() instruments itself on
// every call, so building it per scrape would leak allocations
var promHandler = promhttp.Handler()

// metricsAuthRequired is resolved once at startup by options.MetricsAuthPlan
// and read on every scrape. It is a plain bool behind a setter rather than a
// read of options.Opts, so the decision -- which combines --metrics-auth with
// the management profile -- exists in exactly one place and cannot be
// re-derived differently here.
var metricsAuthRequired atomic.Bool

// SetMetricsAuthRequired records the startup decision. Called from api.go
// before any listener binds.
func SetMetricsAuthRequired(required bool) { metricsAuthRequired.Store(required) }

// MetricsAuthRequired reports the resolved decision, for tests and callers
// that need to know what the route will do.
func MetricsAuthRequired() bool { return metricsAuthRequired.Load() }

// ConfigGetPrometheusCounter serves the Prometheus exposition.
//
// The route keeps `security: []` in the API spec because whether a credential
// is needed is a DEPLOYMENT property, not a property of the route: a scraper
// on a loopback-only appliance sends no bearer and should not have to, while
// the same route under mgmt-profile remote-tls hands out every tenant label to
// anyone who can reach the port. The generated chain can only express one of
// those, so the requirement is applied here instead, from the single decision
// options.MetricsAuthPlan made at startup.
//
// It runs the same RequireManagementAuth the other non-generated routes use,
// so an unauthenticated scrape is refused with byte-identical wording and
// status to every other route on this listener -- including a credential
// store's 503, which must not be confused with the metrics-disabled 503 below.
func ConfigGetPrometheusCounter(params operations.GetMetricsParams) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Prometheus %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	if !options.Opts.Prometheus {
		// 503 keeps scrapers reporting a clean "down" state instead of a
		// 200 with a body that is invalid exposition format.
		//
		// Answered before the credential check on purpose: whether metrics
		// collection is switched on is not a secret, it is the same answer for
		// every caller, and making an operator authenticate to be told the
		// subsystem is off helps nobody. No metric values are disclosed.
		return CustomResponder(func(w http.ResponseWriter, _ runtime.Producer) {
			http.Error(w, "Prometheus option is disabled.", http.StatusServiceUnavailable)
		})
	}
	return CustomResponder(func(w http.ResponseWriter, _ runtime.Producer) {
		if metricsAuthRequired.Load() && !RequireManagementAuth(w, params.HTTPRequest) {
			// RequireManagementAuth has already written 401, 403 or 503.
			return
		}
		promHandler.ServeHTTP(w, params.HTTPRequest)
	})
}

func ConfigGetPrometheusOption(params operations.GetConfigMetricsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "[API] Prometheus %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	return operations.NewGetConfigMetricsOK().WithPayload(&models.MetricsConfig{Prometheus: &options.Opts.Prometheus})
}

func ConfigPostPrometheus(params operations.PostConfigMetricsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] Prometheus %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	// Prometheus Init status check
	if err := prometheus.CheckInit(); err == nil {
		return &ResultResponse{Result: "Prometheus is already enabled."}
	}

	// Prometheus on
	err := ApiHooks.NetPrometheusEnable()
	if err != nil {
		tk.LogIt(tk.LogDebug, "[API] Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	// Prometheus Option state change
	prometheus.OptionStateChange(true)
	return &ResultResponse{Result: "Success"}
}

func ConfigDeletePrometheus(params operations.DeleteConfigMetricsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "[API] Prometheus %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	// Prometheus Init status check
	if err := prometheus.CheckInit(); err != nil {
		return &ResultResponse{Result: "Prometheus is already disabled."}
	}
	// Prometheus off
	err := prometheus.PrometheusTurnOff()
	if err != nil {
		tk.LogIt(tk.LogDebug, "[API] Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	// Prometheus Option state change
	prometheus.OptionStateChange(false)
	return &ResultResponse{Result: "Success"}
}
