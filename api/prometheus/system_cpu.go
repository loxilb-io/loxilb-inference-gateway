/*
 * Copyright (c) 2023 NetLOX Inc
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
package prometheus

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// CPU utilization is measured from one of three sources. Which one applies is
// decided once, at the first sample, and does not change for the lifetime of
// the process -- the cgroup a process belongs to can be rewritten from outside,
// but not in a way that would make an already-chosen source stop working.
type cpuUtilSource int

const (
	cpuSourceProcStat cpuUtilSource = iota // whole machine, from /proc/stat
	cpuSourceCgroupV2                      // this container's share, from cpu.stat
	cpuSourceCgroupV1                      // this container's share, from cpuacct.usage
)

func (s cpuUtilSource) String() string {
	switch s {
	case cpuSourceCgroupV2:
		return "cgroup-v2"
	case cpuSourceCgroupV1:
		return "cgroup-v1"
	default:
		return "proc-stat"
	}
}

// Filesystem roots and markers, indirected so the tests can point them at a
// fixture tree rather than at whatever the machine running them happens to be.
var (
	sysFsRoot        = "/sys/fs/cgroup"
	procRoot         = "/proc"
	containerMarkers = []string{"/.dockerenv", "/run/.containerenv"}
)

var (
	cpuSourceOnce sync.Once
	cpuSource     cpuUtilSource

	// Previous cgroup CPU-time counter, for delta computation. Unlike
	// /proc/stat, cgroup accounting has no idle counter to divide by -- it
	// reports consumed CPU-time only -- so the denominator is wall-clock
	// elapsed x the number of cores the cgroup is allowed to use, and that
	// requires remembering when the previous sample was taken.
	prevCgroupUsage uint64
	prevCgroupAt    time.Time
	cgroupInited    bool
)

// isContainerized reports whether this process is running inside a container.
//
// It deliberately does not treat "the cgroup path is not /" as containerized:
// on a cgroup-v2 host every service lives under its own .slice, so that test
// would flip a bare-metal install over to cgroup accounting and silently change
// what the gauge means.
func isContainerized() bool {
	// Docker and podman both drop a marker file in the container's root.
	for _, marker := range containerMarkers {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}

	// Otherwise look for a runtime-managed cgroup path. Kubernetes writes
	// kubepods, plain docker/containerd write their own prefixes.
	f, err := os.Open(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, marker := range []string{"/docker/", "/docker-", "kubepods", "/containerd", "/lxc/", "/podman"} {
			if strings.Contains(line, marker) {
				return true
			}
		}
	}
	return false
}

// detectCPUSource picks the accounting source once.
//
// Preferring cgroup accounting inside a container is the whole point: Docker
// does not namespace /proc/stat, so a containerized loxilb reading it reports
// the utilization of the whole host -- including every unrelated process on the
// box -- under a gauge that operators read as "the gateway". Anything the host
// does to saturate its CPUs pins this gauge at 100 while loxilb itself is idle.
func detectCPUSource() cpuUtilSource {
	if !isContainerized() {
		return cpuSourceProcStat
	}
	if _, err := readCgroupV2Usage(); err == nil {
		return cpuSourceCgroupV2
	}
	if _, err := readCgroupV1Usage(); err == nil {
		return cpuSourceCgroupV1
	}
	// Containerized but the cgroup filesystem is not mounted or not readable
	// (an unprivileged container with cgroupns=host and a masked mount, say).
	// Host-wide numbers are wrong for this gauge but they are still a
	// measurement; reporting nothing at all would be worse.
	return cpuSourceProcStat
}

// readCgroupV2Usage returns the cgroup's cumulative CPU time in microseconds.
func readCgroupV2Usage() (uint64, error) {
	f, err := os.Open(filepath.Join(sysFsRoot, "cpu.stat"))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "usage_usec" {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("usage_usec not found in cpu.stat")
}

// readCgroupV1Usage returns the cgroup's cumulative CPU time in microseconds.
// cpuacct.usage is in nanoseconds, so it is scaled to match the v2 unit.
func readCgroupV1Usage() (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(sysFsRoot, "cpuacct", "cpuacct.usage"))
	if err != nil {
		// cgroupns=private mounts the controller at the root instead.
		raw, err = os.ReadFile(filepath.Join(sysFsRoot, "cpuacct.usage"))
		if err != nil {
			return 0, err
		}
	}
	nsec, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, err
	}
	return nsec / 1000, nil
}

// cgroupCPULimit returns how many cores this cgroup may use, which is the
// denominator utilization is expressed against.
//
// An explicit quota (docker --cpus, k8s limits.cpu) is authoritative. Without
// one the container may use every core it can be scheduled on, so the limit is
// the affinity-constrained core count -- runtime.NumCPU honours sched_setaffinity
// and cpuset, which is what --cpuset-cpus produces.
func cgroupCPULimit() float64 {
	if cores, ok := cgroupV2Quota(); ok {
		return cores
	}
	if cores, ok := cgroupV1Quota(); ok {
		return cores
	}
	if n := runtime.NumCPU(); n > 0 {
		return float64(n)
	}
	return 1
}

// cgroupV2Quota parses cpu.max, whose format is "$QUOTA $PERIOD" with a literal
// "max" for no quota.
func cgroupV2Quota() (float64, bool) {
	raw, err := os.ReadFile(filepath.Join(sysFsRoot, "cpu.max"))
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || fields[0] == "max" {
		return 0, false
	}
	quota, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	period, err := strconv.ParseFloat(fields[1], 64)
	if err != nil || period <= 0 || quota <= 0 {
		return 0, false
	}
	return quota / period, true
}

// cgroupV1Quota reads the quota/period pair, where a quota of -1 means unlimited.
func cgroupV1Quota() (float64, bool) {
	readVal := func(name string) (float64, bool) {
		for _, p := range []string{
			filepath.Join(sysFsRoot, "cpu", name),
			filepath.Join(sysFsRoot, name),
		} {
			raw, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
			if err != nil {
				continue
			}
			return v, true
		}
		return 0, false
	}

	quota, ok := readVal("cpu.cfs_quota_us")
	if !ok || quota <= 0 {
		return 0, false
	}
	period, ok := readVal("cpu.cfs_period_us")
	if !ok || period <= 0 {
		return 0, false
	}
	return quota / period, true
}

// readCgroupCPUUtilization computes the cgroup's CPU utilization as a
// percentage of the cores it is allowed to use, over the interval since the
// previous call.
func readCgroupCPUUtilization(src cpuUtilSource) (float64, error) {
	var usage uint64
	var err error

	if src == cpuSourceCgroupV2 {
		usage, err = readCgroupV2Usage()
	} else {
		usage, err = readCgroupV1Usage()
	}
	if err != nil {
		return 0, err
	}

	now := time.Now()
	if !cgroupInited {
		prevCgroupUsage = usage
		prevCgroupAt = now
		cgroupInited = true
		return 0, nil // first sample has no delta
	}

	elapsed := now.Sub(prevCgroupAt).Seconds()
	// The counter is cumulative and monotonic; a decrease means it was reset
	// under us (cgroup recreated), so re-baseline rather than report a
	// negative-turned-huge figure.
	if usage < prevCgroupUsage {
		prevCgroupUsage = usage
		prevCgroupAt = now
		return 0, nil
	}
	usedSec := float64(usage-prevCgroupUsage) / 1e6

	prevCgroupUsage = usage
	prevCgroupAt = now

	if elapsed <= 0 {
		return 0, fmt.Errorf("non-positive elapsed interval")
	}

	usage100 := usedSec / (elapsed * cgroupCPULimit()) * 100.0
	if usage100 < 0 {
		usage100 = 0
	} else if usage100 > 100 {
		// A cgroup can briefly exceed its quota across a sampling boundary.
		usage100 = 100
	}
	return usage100, nil
}

// sampleCPUUtilization takes one reading of both CPU gauges.
//
// scoped is the utilization of whatever loxilb runs in -- this container's
// share of its CPU allowance, or the whole machine on bare metal. host is
// always the whole machine, so a saturated box stays visible even when the
// scoped gauge correctly reports that loxilb itself is idle.
//
// Both come out of a single pass on purpose: readCPUUtilization consumes the
// /proc/stat delta it measures, so calling it twice in one tick would leave the
// second call with a near-zero interval and no usable measurement.
func sampleCPUUtilization() (scoped float64, host float64, err error) {
	cpuSourceOnce.Do(func() {
		cpuSource = detectCPUSource()
		tk.LogIt(tk.LogInfo, "[Metrics] CPU utilization source: %s\n", cpuSource)
	})

	host, err = readCPUUtilization()
	if err != nil {
		return 0, 0, err
	}
	if cpuSource == cpuSourceProcStat {
		return host, host, nil
	}

	scoped, err = readCgroupCPUUtilization(cpuSource)
	if err != nil {
		return 0, host, err
	}
	return scoped, host, nil
}
