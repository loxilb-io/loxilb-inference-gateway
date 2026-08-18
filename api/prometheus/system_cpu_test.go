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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withFixture points the cgroup and proc roots at a temporary tree and clears
// the sampler's carried-over state, so each test starts from a known position.
func withFixture(t *testing.T) (cgroupDir string, procDir string) {
	t.Helper()

	cgroupDir = t.TempDir()
	procDir = t.TempDir()

	origSys, origProc, origMarkers := sysFsRoot, procRoot, containerMarkers
	sysFsRoot, procRoot = cgroupDir, procDir
	// A container marker on the machine running the tests must not leak into
	// the cases that assert a bare-metal host.
	containerMarkers = nil

	origUsage, origAt, origInited := prevCgroupUsage, prevCgroupAt, cgroupInited
	prevCgroupUsage, prevCgroupAt, cgroupInited = 0, time.Time{}, false

	t.Cleanup(func() {
		sysFsRoot, procRoot, containerMarkers = origSys, origProc, origMarkers
		prevCgroupUsage, prevCgroupAt, cgroupInited = origUsage, origAt, origInited
	})
	return cgroupDir, procDir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestCgroupV2Quota(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantOK   bool
		wantCore float64
	}{
		{"no quota", "max 100000\n", false, 0},
		{"two cores", "200000 100000\n", true, 2},
		{"half core", "50000 100000\n", true, 0.5},
		{"malformed", "garbage\n", false, 0},
		{"zero period", "100000 0\n", false, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cgroupDir, _ := withFixture(t)
			writeFile(t, filepath.Join(cgroupDir, "cpu.max"), tc.content)

			cores, ok := cgroupV2Quota()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && cores != tc.wantCore {
				t.Errorf("cores = %v, want %v", cores, tc.wantCore)
			}
		})
	}
}

func TestCgroupV1Quota(t *testing.T) {
	t.Run("unlimited quota is not a limit", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu", "cpu.cfs_quota_us"), "-1\n")
		writeFile(t, filepath.Join(cgroupDir, "cpu", "cpu.cfs_period_us"), "100000\n")

		if _, ok := cgroupV1Quota(); ok {
			t.Error("quota -1 should report no limit")
		}
	})

	t.Run("quota over period yields cores", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu", "cpu.cfs_quota_us"), "150000\n")
		writeFile(t, filepath.Join(cgroupDir, "cpu", "cpu.cfs_period_us"), "100000\n")

		cores, ok := cgroupV1Quota()
		if !ok {
			t.Fatal("expected a limit")
		}
		if cores != 1.5 {
			t.Errorf("cores = %v, want 1.5", cores)
		}
	})
}

func TestReadCgroupUsage(t *testing.T) {
	t.Run("v2 reads usage_usec", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"),
			"usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n")

		usage, err := readCgroupV2Usage()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage != 123456 {
			t.Errorf("usage = %d, want 123456", usage)
		}
	})

	t.Run("v2 without usage_usec errors", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "nr_periods 0\n")

		if _, err := readCgroupV2Usage(); err == nil {
			t.Error("expected an error when usage_usec is absent")
		}
	})

	t.Run("v1 converts nanoseconds to microseconds", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpuacct", "cpuacct.usage"), "5000000\n")

		usage, err := readCgroupV1Usage()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage != 5000 {
			t.Errorf("usage = %d us, want 5000", usage)
		}
	})

	t.Run("v1 falls back to the root-mounted controller", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpuacct.usage"), "2000000\n")

		usage, err := readCgroupV1Usage()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage != 2000 {
			t.Errorf("usage = %d us, want 2000", usage)
		}
	})
}

func TestReadCgroupCPUUtilization(t *testing.T) {
	t.Run("first sample has no delta", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.max"), "100000 100000\n")
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "usage_usec 1000000\n")

		got, err := readCgroupCPUUtilization(cpuSourceCgroupV2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Errorf("first sample = %v, want 0", got)
		}
		if !cgroupInited {
			t.Error("first sample should have established a baseline")
		}
	})

	t.Run("half of a one-core quota reads 50 percent", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.max"), "100000 100000\n") // 1 core
		// 5 CPU-seconds consumed over a 10 second window against a 1 core
		// allowance is 50%.
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "usage_usec 5000000\n")
		prevCgroupUsage = 0
		prevCgroupAt = time.Now().Add(-10 * time.Second)
		cgroupInited = true

		got, err := readCgroupCPUUtilization(cpuSourceCgroupV2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got < 49 || got > 51 {
			t.Errorf("utilization = %v, want ~50", got)
		}
	})

	t.Run("quota of two cores halves the same consumption", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.max"), "200000 100000\n") // 2 cores
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "usage_usec 5000000\n")
		prevCgroupUsage = 0
		prevCgroupAt = time.Now().Add(-10 * time.Second)
		cgroupInited = true

		got, err := readCgroupCPUUtilization(cpuSourceCgroupV2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got < 24 || got > 26 {
			t.Errorf("utilization = %v, want ~25", got)
		}
	})

	t.Run("burst above quota is clamped to 100", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.max"), "100000 100000\n") // 1 core
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "usage_usec 30000000\n")
		prevCgroupUsage = 0
		prevCgroupAt = time.Now().Add(-10 * time.Second)
		cgroupInited = true

		got, err := readCgroupCPUUtilization(cpuSourceCgroupV2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 100 {
			t.Errorf("utilization = %v, want 100", got)
		}
	})

	t.Run("counter reset re-baselines instead of reporting a spike", func(t *testing.T) {
		cgroupDir, _ := withFixture(t)
		writeFile(t, filepath.Join(cgroupDir, "cpu.max"), "100000 100000\n")
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "usage_usec 10\n")
		prevCgroupUsage = 9_000_000 // counter was much higher before the reset
		prevCgroupAt = time.Now().Add(-10 * time.Second)
		cgroupInited = true

		got, err := readCgroupCPUUtilization(cpuSourceCgroupV2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Errorf("utilization = %v, want 0 after a counter reset", got)
		}
		if prevCgroupUsage != 10 {
			t.Errorf("baseline = %d, want it re-established at 10", prevCgroupUsage)
		}
	})
}

func TestIsContainerized(t *testing.T) {
	t.Run("host cgroup paths are not a container", func(t *testing.T) {
		_, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"),
			"0::/user.slice/user-1000.slice/session-3.scope\n")

		if isContainerized() {
			t.Error("a systemd slice on a host must not read as containerized")
		}
	})

	t.Run("docker cgroup path is a container", func(t *testing.T) {
		_, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"),
			"0::/docker/3b1f2c4d5e6a7b8c9d0e1f2a3b4c5d6e\n")

		if !isContainerized() {
			t.Error("a docker cgroup path should read as containerized")
		}
	})

	t.Run("kubernetes cgroup path is a container", func(t *testing.T) {
		_, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"),
			"0::/kubepods.slice/kubepods-burstable.slice/pod1234/container5678\n")

		if !isContainerized() {
			t.Error("a kubepods cgroup path should read as containerized")
		}
	})

	t.Run("marker file alone is enough", func(t *testing.T) {
		_, procDir := withFixture(t)
		marker := filepath.Join(procDir, "dockerenv")
		writeFile(t, marker, "")
		containerMarkers = []string{marker}

		if !isContainerized() {
			t.Error("a container marker file should read as containerized")
		}
	})

	t.Run("missing cgroup file is not a container", func(t *testing.T) {
		withFixture(t) // empty proc tree, no self/cgroup

		if isContainerized() {
			t.Error("an unreadable cgroup file should not read as containerized")
		}
	})
}

func TestDetectCPUSource(t *testing.T) {
	t.Run("bare metal uses proc stat", func(t *testing.T) {
		_, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"), "0::/init.scope\n")

		if got := detectCPUSource(); got != cpuSourceProcStat {
			t.Errorf("source = %v, want proc-stat", got)
		}
	})

	t.Run("container with cgroup v2 uses cgroup v2", func(t *testing.T) {
		cgroupDir, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"), "0::/docker/abc\n")
		writeFile(t, filepath.Join(cgroupDir, "cpu.stat"), "usage_usec 1000\n")

		if got := detectCPUSource(); got != cpuSourceCgroupV2 {
			t.Errorf("source = %v, want cgroup-v2", got)
		}
	})

	t.Run("container with only cgroup v1 uses cgroup v1", func(t *testing.T) {
		cgroupDir, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"), "0::/docker/abc\n")
		writeFile(t, filepath.Join(cgroupDir, "cpuacct", "cpuacct.usage"), "1000000\n")

		if got := detectCPUSource(); got != cpuSourceCgroupV1 {
			t.Errorf("source = %v, want cgroup-v1", got)
		}
	})

	t.Run("container without a readable cgroup falls back to proc stat", func(t *testing.T) {
		_, procDir := withFixture(t)
		writeFile(t, filepath.Join(procDir, "self", "cgroup"), "0::/docker/abc\n")

		if got := detectCPUSource(); got != cpuSourceProcStat {
			t.Errorf("source = %v, want proc-stat fallback", got)
		}
	})
}
