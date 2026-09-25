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
// Two readings, both absolute, neither to be subtracted from the other. The
// floor is the harness with the trail closed: the C call and the CGO
// crossing, returning where there is nothing to record to. The second is
// the same call with the trail open. The floor is there to say how much of
// the cost is the crossing rather than the recording — it is not an arm to
// difference away, because a difference of percentiles is not the
// percentile of differences.
//
// The hand-off does not block, so a loop that emits faster than the writer
// drains fills the queue and the rest of the run times the drop path
// instead. The producer's counters are printed for that reason: a run that
// dropped is not a measurement of what recording costs, and the count is
// what says so. A request-shaped rate never gets near it; a tight loop
// does, within a queue's worth of calls.
func runAuditProducerBench(iters uint64) int {
	// Floor: the crossing with no trail behind it.
	audit.SetGlobal(nil)
	floor, err := ln.RunAuditProducerBench(iters)
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

	cost, err := ln.RunAuditProducerBench(iters)
	st := w.Stats()

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

	fmt.Printf("audit producer cost over %d calls\n", cost.Iters)
	fmt.Printf("  crossing: p50 %.0f ns  p95 %.0f ns  p99 %.0f ns  max %.0f ns\n",
		floor.P50Ns, floor.P95Ns, floor.P99Ns, floor.MaxNs)
	fmt.Printf("  emit    : p50 %.0f ns  p95 %.0f ns  p99 %.0f ns  max %.0f ns\n",
		cost.P50Ns, cost.P95Ns, cost.P99Ns, cost.MaxNs)
	for _, p := range st.Producers {
		fmt.Printf("  producer %s: accepted %d  dropped %v\n", p.ID, p.Accepted, p.Dropped)
	}
	return 0
}
