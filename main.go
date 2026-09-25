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

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/audit"
	ln "github.com/loxilb-io/loxilb/pkg/loxinet"
	tk "github.com/loxilb-io/loxilib"
)

// var version string = "0.9.7-beta"
// var buildInfo string = ""

func main() {
	fmt.Printf("loxilb start\n")

	// Parse command-line arguments
	_, err := flags.Parse(&opts.Opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Validate options
	if err := opts.ValidateOpts(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if opts.Opts.Version {
		fmt.Printf("loxilb version: %s %s\n", common.Version, common.BuildInfo)
		// A binary that carries optional build tags says so here. The one
		// that matters is audit_faults: it can be told at run time to
		// break its own audit trail, so an operator holding an image must
		// be able to tell it from a release without unpacking it.
		if common.BuildTags != "" {
			fmt.Printf("loxilb build tags: %s\n", common.BuildTags)
		}
		os.Exit(0)
	}

	if opts.Opts.AuditProducerBench > 0 {
		os.Exit(runAuditProducerBench(opts.Opts.AuditProducerBench))
	}

	// Register built-in parsers (: Plugin Architecture)
	// Must be done here to avoid import cycles (main -> loxinet, main -> mock)
	registry := ln.GetRegistry()
	// if err := registry.Register(mock.MockParser{ValidateResult: true}); err != nil {
	// 	tk.LogIt(tk.LogError, "[Main] Failed to register Mock parser: %v\n", err)
	// }
	// TODO: Register OpenAI, MCP, GraphQL parsers when implemented
	parsers := registry.ListParsers()
	tk.LogIt(tk.LogInfo, "[Main] Registered %d parser(s)\n", len(parsers))
	for _, meta := range parsers {
		tk.LogIt(tk.LogInfo, "[Main]   - %s v%s (protocol=%s)\n",
			meta.Name, meta.Version, meta.Protocol)
	}

	go ln.LoxiXsyncMain(opts.Opts.RPC)
	// Need some time for RPC Handler to be up
	time.Sleep(2 * time.Second)

	ln.Main()
}

// runAuditProducerBench measures what a relay worker pays to record one
// completed request, and exits without starting the gateway.
//
// It runs the harness twice: once with no trail behind the export, and once
// with the trail open. The export also feeds the Prometheus counters, and
// that work is not the audit trail's — so the cost the gate is about is the
// DELTA between the two arms, not the absolute of either. The second arm
// needs a real writer: with none, every record would take the producer's
// drop path and the number would be the cost of giving up.
func runAuditProducerBench(iters uint64) int {
	// Arm 1: the export as it was before the trail existed.
	audit.SetGlobal(nil)
	base, err := ln.RunAuditProducerBench(iters)
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	w, err := audit.New(audit.Config{
		Dir:        opts.Opts.AuditDir,
		CreateDir:  true,
		InstanceID: "audit-producer-bench",
		Logf: func(format string, args ...interface{}) {
			fmt.Printf(format+"\n", args...)
		},
	})
	if err != nil {
		fmt.Printf("audit producer bench: trail unavailable: %s\n", err)
		return 1
	}
	w.Start()
	audit.SetGlobal(w)

	// Arm 2: the same export with the trail behind it.
	withTrail, err := ln.RunAuditProducerBench(iters)

	audit.SetGlobal(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if cerr := w.Close(ctx); cerr != nil {
		fmt.Printf("audit producer bench: trail did not close cleanly: %s\n", cerr)
	}
	if err != nil {
		fmt.Printf("%s\n", err)
		return 1
	}

	fmt.Printf("audit producer cost over %d calls per arm\n", iters)
	fmt.Printf("  trail off: p50 %.0f ns  p95 %.0f ns  p99 %.0f ns  max %.0f ns\n",
		base.P50Ns, base.P95Ns, base.P99Ns, base.MaxNs)
	fmt.Printf("  trail on : p50 %.0f ns  p95 %.0f ns  p99 %.0f ns  max %.0f ns\n",
		withTrail.P50Ns, withTrail.P95Ns, withTrail.P99Ns, withTrail.MaxNs)
	fmt.Printf("  audit    : p50 %+.0f ns  p95 %+.0f ns  p99 %+.0f ns\n",
		withTrail.P50Ns-base.P50Ns, withTrail.P95Ns-base.P95Ns,
		withTrail.P99Ns-base.P99Ns)
	return 0
}
