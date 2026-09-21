/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package prometheus

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Listen-backlog pressure, read from the kernel's TcpExt counters for the
// network namespace loxilb runs in. The proxy's own accept loop shares a worker
// with the relay, so under a connect burst the kernel backlog is what absorbs
// the wait; when it is full the kernel drops the SYN and the client waits for
// a retransmit. Nothing in the process sees that drop, only the kernel does.
//
// The counters are namespace-wide: every listening socket in the namespace
// contributes, loxilb's or not. On a dedicated node or in a container that is
// loxilb alone.
var (
	proxyListenOverflowsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_listen_overflows_total",
			Help: "Connection requests the kernel could not queue because a listen backlog in loxilb's network namespace was full (TcpExt ListenOverflows, counted from process start). Clients behind a nonzero value waited for a SYN retransmit or were refused; growth under a connect burst means the accept loop is not draining its backlog.",
		},
	)
	proxyListenDropsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_proxy_listen_drops_total",
			Help: "Connection requests dropped at a listening socket in loxilb's network namespace for any reason, backlog overflow included (TcpExt ListenDrops, counted from process start).",
		},
	)
)

// Indirected so the tests can point the reader at a fixture.
var netstatPath = "/proc/net/netstat"

// The previous sample, for the delta. The kernel counters are cumulative from
// boot; the exported counters are cumulative from process start.
var (
	prevListenOverflows uint64
	prevListenDrops     uint64
	listenBacklogInited bool
)

// readTcpExt returns the TcpExt counters of a /proc/net/netstat file by
// name. The file is pairs of lines, a header line naming the fields and a
// value line in the same order, one pair per protocol family.
func readTcpExt(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		header := scanner.Text()
		if !strings.HasPrefix(header, "TcpExt:") {
			continue
		}
		if !scanner.Scan() {
			return nil, fmt.Errorf("%s: TcpExt header with no value line", path)
		}
		names := strings.Fields(header)[1:]
		values := strings.Fields(scanner.Text())[1:]
		if len(names) != len(values) {
			return nil, fmt.Errorf("%s: TcpExt has %d names and %d values", path, len(names), len(values))
		}
		out := make(map[string]uint64, len(names))
		for i, name := range names {
			v, err := strconv.ParseUint(values[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s: TcpExt %s: %v", path, name, err)
			}
			out[name] = v
		}
		return out, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s: no TcpExt section", path)
}

// sampleListenBacklog reads the counters once and adds what grew since the
// previous sample. The first sample only sets the baseline, so the exported
// counters start at zero rather than at the kernel's boot-cumulative value.
func sampleListenBacklog() error {
	ext, err := readTcpExt(netstatPath)
	if err != nil {
		return err
	}
	overflows, drops := ext["ListenOverflows"], ext["ListenDrops"]
	if listenBacklogInited {
		if overflows >= prevListenOverflows {
			proxyListenOverflowsTotal.Add(float64(overflows - prevListenOverflows))
		}
		if drops >= prevListenDrops {
			proxyListenDropsTotal.Add(float64(drops - prevListenDrops))
		}
	}
	prevListenOverflows, prevListenDrops = overflows, drops
	listenBacklogInited = true
	return nil
}

// RunListenBacklogMetrics samples the kernel's listen counters on the default
// period until ctx is done.
func RunListenBacklogMetrics(ctx context.Context) {
	ticker := time.NewTicker(PrometheusDefaultPeriod)
	defer ticker.Stop()

	safeGoroutineOperation(func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			return sampleListenBacklog()
		}
	}, "ListenBacklogMetrics", ctx)
}
