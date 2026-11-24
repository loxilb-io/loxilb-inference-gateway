#!/usr/bin/env python3
"""hostcheck.py - the comparison behind hostcheck.sh, kept apart so it can be
tested on recorded snapshots without docker (test_hostcheck.py).

  hostcheck.py <out-dir> <tag> <gateway-container> [<other containers>...]

check() takes the snapshot files and the cgroup scopes; main() resolves the
scopes of the named containers with docker and prints the verdict.
"""
import json
import re
import subprocess
import sys

HOST_WIDE = ("kprobe", "tracepoint", "raw_tracepoint", "tracing", "perf_event", "lsm", "ext")
KINDS = ("bpf-net", "lsmod", "sysctl")
# systemd attaches its own filters to a unit's cgroup when the unit has
# device or IP access settings (DevicePolicy=, IPAddressDeny=, ...): a
# cgroup_device program, and cgroup_skb programs on ingress and egress.
UNIT_FILTER_TYPES = ("cgroup_device", "cgroup_skb")
UNIT_PATH = re.compile(r"^/sys/fs/cgroup/(system|user)\.slice(/[^/]+)*/[^/]+\.(service|scope|socket)$")


def systemd_unit_filter(prog, path):
    """True when the program is a filter systemd attached to one of its own
    units: its type is one systemd uses, the cgroup is a systemd unit under
    system.slice or user.slice and not a container's scope, and what bpftool
    reports of it points at systemd. pids and name are optional (systemd 249
    names nothing and bpftool may not report pids); when present they must
    agree."""
    if prog is None or prog.get("type") not in UNIT_FILTER_TYPES:
        return False
    if not UNIT_PATH.match(path) or any(c.startswith("docker-") for c in path.split("/")):
        return False
    pids = prog.get("pids")
    if pids is not None and (not pids or any(p.get("comm") != "systemd" for p in pids)):
        return False
    name = prog.get("name")
    if name and not name.startswith("sd_"):
        return False
    return True


def rd(p):
    with open(p) as f:
        return f.read()


def check(pre, now, gw_scope, scopes, diff_path=None):
    """pre, now: {"prog", "cgroup", "bpf-net", "lsmod", "sysctl"} -> file path
    of the prerun snapshot and of the one to check. gw_scope: the gateway
    container's cgroup scope name (or None); scopes: those of the other
    scenario containers. diff_path(kind) -> where to write a differing
    snapshot's diff (None: not written). Returns (notes, problems)."""
    problems, notes = [], []
    pre_p = {p["id"]: p for p in json.loads(rd(pre["prog"]))}
    now_p = {p["id"]: p for p in json.loads(rd(now["prog"]))}
    new = [now_p[i] for i in sorted(set(now_p) - set(pre_p))]
    gone = sorted(set(pre_p) - set(now_p))
    types = {}
    for p in new:
        types[p.get("type")] = types.get(p.get("type"), 0) + 1
    notes.append("new programs by type: %s" % (types or "none"))
    if gone:
        notes.append("programs present before and now gone: %d (ids %s)" % (len(gone), gone[:10]))
    bad = [p for p in new if p.get("type") in HOST_WIDE]
    if bad:
        problems.append("host-wide program types loaded: %s" %
                        [(p["id"], p.get("type"), p.get("name")) for p in bad])
    newids = {p["id"] for p in new}
    path, attached = None, []
    for line in rd(now["cgroup"]).splitlines():
        if line.startswith("/"):
            path = line.strip()
            continue
        f = line.split()
        if f and f[0].isdigit() and int(f[0]) in newids:
            attached.append((int(f[0]), f[1] if len(f) > 1 else "?", path))
    notes.append("new cgroup attachments: %d" % len(attached))
    runtime, units = 0, {}
    for pid_, at, pth in attached:
        pth = pth or ""
        if gw_scope and gw_scope in pth:
            continue
        if at == "cgroup_device" and any(s in pth for s in scopes):
            runtime += 1
            continue
        if systemd_unit_filter(now_p.get(pid_), pth):
            unit = pth.rsplit("/", 1)[-1]
            units[unit] = units.get(unit, 0) + 1
            continue
        problems.append("program %d (%s) attached outside the scenario's containers: %s" % (pid_, at, pth))
    if attached and gw_scope:
        notes.append("under the gateway scope %s: %d; runtime cgroup_device filters under the other scenario containers: %d"
                     % (gw_scope, sum(1 for a in attached if gw_scope in (a[2] or "")), runtime))
    notes.append("systemd unit filters accepted: %d%s" % (
        sum(units.values()), " (%s)" % ", ".join("%s: %d" % u for u in sorted(units.items())) if units else ""))
    for name in KINDS:
        a = rd(pre[name]).splitlines()
        b = rd(now[name]).splitlines()
        if a != b:
            sa, sb = set(a), set(b)
            diff = ["-" + x for x in sorted(sa - sb)] + ["+" + x for x in sorted(sb - sa)]
            where = diff_path(name) if diff_path else None
            if where:
                with open(where, "w") as f:
                    f.write("\n".join(diff) + "\n")
            problems.append("%s differs from prerun (%d lines, %s): %s" %
                            (name, len(diff), where.rsplit("/", 1)[-1] if where else "no diff file", diff[:6]))
        else:
            notes.append("%s unchanged" % name)
    return notes, problems


def snapshot(out, tag):
    return {"prog": "%s/bpf-prog-%s.json" % (out, tag), "cgroup": "%s/bpf-cgroup-%s.txt" % (out, tag),
            "bpf-net": "%s/bpf-net-%s.txt" % (out, tag), "lsmod": "%s/lsmod-%s.txt" % (out, tag),
            "sysctl": "%s/sysctl-%s.txt" % (out, tag)}


def scope_of(name):
    cid = subprocess.run(["docker", "inspect", "-f", "{{.Id}}", name],
                         capture_output=True, text=True).stdout.strip()
    return "docker-%s.scope" % cid if cid else None


def main(argv):
    out, tag, gw = argv[1], argv[2], argv[3]
    gw_scope = scope_of(gw) if gw else None
    scopes = [s for s in (scope_of(n) for n in argv[4:]) if s]
    notes, problems = check(snapshot(out, "prerun"), snapshot(out, tag), gw_scope, scopes,
                            lambda kind: "%s/%s-%s.diff" % (out, kind, tag))
    for n in notes:
        print("  " + n)
    for p in problems:
        print("  PROBLEM " + p)
    print("HOSTCHECK %s %s" % (tag, "OK" if not problems else "STOP: %d problem(s)" % len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
