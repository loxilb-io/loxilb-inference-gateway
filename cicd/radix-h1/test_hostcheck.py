#!/usr/bin/env python3
"""Tests of hostcheck.check() on snapshots recorded by a failed run of the
radix-h2 job (testdata/hostcheck: the "prerun" and "poststart-on" bpftool
prog and cgroup snapshots, bpftool net and lsmod; sysctl is written here,
equal on both sides). In that run systemd started systemd-timedated during
the ON arm and attached its own filters to the unit's cgroup: programs 206
(cgroup_device) and 207, 208 (cgroup_skb), with no name and no pids.

  python3 -m unittest discover -s cicd/radix-h1 -p 'test_hostcheck.py'
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hostcheck  # noqa: E402

DATA = os.path.join(HERE, "testdata", "hostcheck")
TAG = "poststart-on"
# The scopes of that run: the gateway container and the four other scenario
# containers (the client and three mocks).
GW = "docker-bb8b8bb8effff23217644587b267f53e8d920aec6989b805b50a8d50a58de11c.scope"
SCENARIO = [GW] + ["docker-%s.scope" % c for c in (
    "87186754ebb1dc728952822049ecbb8a352d704b241c905f428bce90c3bb8818",
    "1b026cbcc4d62c13c57b691fda98f31d98bd74204002eeb17dc4d1f0d0a83aa1",
    "908926f47887f82040603a6dc2e70d49c497915684b47655567970ea1841196a",
    "992bdaf8293a8aadeec8a1b024a87e41bbda1139747feed7255c12e55824f033")]
UNIT = "/sys/fs/cgroup/system.slice/systemd-timedated.service"
STRANGER = "/sys/fs/cgroup/system.slice/docker-%s.scope" % ("ab" * 32)


class HostCheck(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        for f in os.listdir(DATA):
            shutil.copy(os.path.join(DATA, f), self.d)
        for t in ("prerun", TAG):
            with open(self.snap(t)["sysctl"], "w") as f:
                f.write("net.ipv4.ip_forward = 1\n")

    def tearDown(self):
        shutil.rmtree(self.d)

    def snap(self, tag):
        return hostcheck.snapshot(self.d, tag)

    def run_check(self):
        return hostcheck.check(self.snap("prerun"), self.snap(TAG), GW, SCENARIO)

    # edits of the recorded snapshot
    def progs(self, fn):
        p = self.snap(TAG)["prog"]
        with open(p) as f:
            progs = json.load(f)
        progs = fn(progs) or progs
        with open(p, "w") as f:
            json.dump(progs, f)

    def prog(self, pid, **kw):
        def fn(progs):
            for x in progs:
                if x["id"] == pid:
                    x.update(kw)
        self.progs(fn)

    def cgroup(self, old, new):
        p = self.snap(TAG)["cgroup"]
        with open(p) as f:
            s = f.read()
        self.assertIn(old, s)
        with open(p, "w") as f:
            f.write(s.replace(old, new, 1))

    def move_attachment(self, line_start, to_path):
        """Move the attachment line of one program to another cgroup path."""
        p = self.snap(TAG)["cgroup"]
        with open(p) as f:
            lines = f.read().splitlines()
        i = next(n for n, l in enumerate(lines) if l.strip().startswith(line_start))
        moved = lines.pop(i)
        lines += [to_path, moved]
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")

    def assertOK(self):
        notes, problems = self.run_check()
        self.assertEqual(problems, [], notes)
        return notes

    def assertSTOP(self, *want):
        notes, problems = self.run_check()
        self.assertTrue(problems, "expected a STOP; notes: %s" % notes)
        for w in want:
            self.assertTrue(any(w in p for p in problems), "no problem names %r: %s" % (w, problems))
        return problems

    # ---- the recorded run --------------------------------------------------
    def test_recorded_run_is_ok_and_names_the_unit(self):
        notes = self.assertOK()
        line = [n for n in notes if n.startswith("systemd unit filters accepted")]
        self.assertEqual(len(line), 1, notes)
        self.assertIn("3", line[0])
        self.assertIn("systemd-timedated.service", line[0])

    # ---- teeth: each edit must still STOP ----------------------------------
    def test_sock_ops_on_the_unit_stops(self):
        self.prog(207, type="sock_ops")
        self.assertSTOP("program 207", UNIT)

    def test_filter_on_a_foreign_docker_scope_stops(self):
        self.move_attachment("206 ", STRANGER)
        self.assertSTOP("program 206", STRANGER)

    def test_cgroup_skb_loaded_by_another_process_stops(self):
        self.prog(207, pids=[{"pid": 4242, "comm": "notsystemd"}])
        self.assertSTOP("program 207")

    def test_cgroup_skb_without_the_sd_prefix_stops(self):
        self.prog(208, name="egress_fw")
        self.assertSTOP("program 208")

    def test_new_kprobe_stops(self):
        self.progs(lambda ps: ps + [{"id": 9001, "type": "kprobe", "name": "kp"}])
        self.assertSTOP("host-wide program types loaded")

    def test_changed_bpftool_net_stops(self):
        with open(self.snap(TAG)["bpf-net"], "a") as f:
            f.write("eth0(2) clsact/ingress extra id 9002\n")
        self.assertSTOP("bpf-net differs from prerun")

    def test_unit_type_outside_the_list_stops(self):
        self.move_attachment("206 ", "/sys/fs/cgroup/system.slice/var-lib-x.mount")
        self.assertSTOP("program 206")

    def test_path_outside_the_two_slices_stops(self):
        self.move_attachment("206 ", "/sys/fs/cgroup/machine.slice/x.service")
        self.assertSTOP("program 206")

    # ---- what systemd versions that report more still pass -----------------
    def test_systemd_pids_and_sd_names_pass(self):
        self.prog(206, pids=[{"pid": 1, "comm": "systemd"}], name="sd_devices")
        self.prog(207, pids=[{"pid": 1, "comm": "systemd"}], name="sd_fw_egress")
        self.prog(208, name="sd_fw_ingress")
        self.assertOK()

    def test_user_slice_unit_passes(self):
        self.move_attachment("207 ", "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service")
        notes = self.assertOK()
        self.assertTrue(any("user@1000.service" in n for n in notes), notes)

    # ---- the existing behaviour --------------------------------------------
    def test_scenario_runtime_filters_and_gateway_scope_pass(self):
        self.move_attachment("206 ", "/sys/fs/cgroup/system.slice/" + SCENARIO[1])
        self.move_attachment("207 ", "/sys/fs/cgroup/system.slice/" + GW)
        self.prog(207, type="sock_ops")
        self.move_attachment("208 ", "/sys/fs/cgroup/system.slice/" + GW)
        notes = self.assertOK()
        self.assertTrue(any("runtime cgroup_device filters under the other scenario containers: 5" in n
                            for n in notes), notes)

    def test_runtime_filter_type_other_than_device_on_a_scenario_container_stops(self):
        self.move_attachment("207 ", "/sys/fs/cgroup/system.slice/" + SCENARIO[1])
        self.assertSTOP("program 207")


if __name__ == "__main__":
    unittest.main()
