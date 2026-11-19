#!/bin/bash
# hostcheck.sh <tag> <out-dir> [<gateway-container> [<other scenario containers>...]]
#
# Host-global state of a shared testbed, compared with the "prerun" snapshot
# taken by the same script before the first container started:
#   sysctl -a (keys that change on their own are filtered), lsmod (module
#   names), bpftool prog / cgroup tree / net (host network namespace).
# With a gateway container named, the mandatory post-start check:
#   - no new kprobe, tracepoint, raw_tracepoint, tracing, perf_event, lsm or
#     ext program;
#   - every new program attached to a cgroup is under the gateway container's
#     scope, except the runtime's own cgroup_device filter, which Docker
#     attaches to every container's cgroup: accepted only under the scope of
#     one of the scenario's containers;
#   - bpftool net of the host namespace unchanged.
# Prints a verdict line "HOSTCHECK <tag> OK" or "HOSTCHECK <tag> STOP: ...".
# Exit 0 on OK, 1 on STOP. Tag "prerun" only records.
set -u
TAG=$1
OUT=$2
GW=${3:-}
CONTAINERS="${*:3}"
mkdir -p "$OUT"
VOLATILE='^(fs\.dentry-state|fs\.file-nr|fs\.inode-nr|fs\.inode-state|fs\.aio-nr|fs\.quota\.|kernel\.ns_last_pid|kernel\.random\.|kernel\.pty\.nr|net\.netfilter\.nf_conntrack_count|kernel\.sched_domain\.|vm\.stat_|kernel\.tainted|fs\.binfmt_misc)'

sysctl -a 2>/dev/null | grep -Ev "$VOLATILE" | LC_ALL=C sort > "$OUT/sysctl-$TAG.txt"
lsmod | awk 'NR>1 {print $1}' | LC_ALL=C sort > "$OUT/lsmod-$TAG.txt"
bpftool -j prog show > "$OUT/bpf-prog-$TAG.json" 2>/dev/null
bpftool cgroup tree > "$OUT/bpf-cgroup-$TAG.txt" 2>/dev/null
bpftool net > "$OUT/bpf-net-$TAG.txt" 2>/dev/null
[ "$TAG" = prerun ] && { echo "HOSTCHECK prerun recorded"; exit 0; }

python3 - "$OUT" "$TAG" "$GW" $CONTAINERS <<'EOF'
import json, subprocess, sys
out, tag, gw = sys.argv[1], sys.argv[2], sys.argv[3]
def rd(p):
    with open(p) as f:
        return f.read()
problems, notes = [], []
pre = {p["id"]: p for p in json.loads(rd(f"{out}/bpf-prog-prerun.json"))}
now = {p["id"]: p for p in json.loads(rd(f"{out}/bpf-prog-{tag}.json"))}
new = [now[i] for i in sorted(set(now) - set(pre))]
gone = sorted(set(pre) - set(now))
types = {}
for p in new:
    types[p.get("type")] = types.get(p.get("type"), 0) + 1
notes.append("new programs by type: %s" % (types or "none"))
if gone:
    notes.append("programs present before and now gone: %d (ids %s)" % (len(gone), gone[:10]))
bad = [p for p in new if p.get("type") in
       ("kprobe", "tracepoint", "raw_tracepoint", "tracing", "perf_event", "lsm", "ext")]
if bad:
    problems.append("host-wide program types loaded: %s" %
                    [(p["id"], p.get("type"), p.get("name")) for p in bad])
def scope_of(name):
    cid = subprocess.run(["docker", "inspect", "-f", "{{.Id}}", name],
                         capture_output=True, text=True).stdout.strip()
    return "docker-%s.scope" % cid if cid else None
scope = scope_of(gw) if gw else None
ours = [s for s in (scope_of(n) for n in sys.argv[4:]) if s]
newids = {p["id"] for p in new}
path, attached = None, []
for line in rd(f"{out}/bpf-cgroup-{tag}.txt").splitlines():
    if line.startswith("/"):
        path = line.strip()
        continue
    f = line.split()
    if f and f[0].isdigit() and int(f[0]) in newids:
        attached.append((int(f[0]), f[1] if len(f) > 1 else "?", path))
notes.append("new cgroup attachments: %d" % len(attached))
runtime = 0
for pid_, at, pth in attached:
    pth = pth or ""
    if scope and scope in pth:
        continue
    if at == "cgroup_device" and any(s in pth for s in ours):
        runtime += 1
        continue
    problems.append("program %d (%s) attached outside the scenario's containers: %s" % (pid_, at, pth))
if attached and scope:
    notes.append("under the gateway scope %s: %d; runtime cgroup_device filters under the other scenario containers: %d"
                 % (scope, sum(1 for a in attached if scope in (a[2] or "")), runtime))
for name in ("bpf-net", "lsmod", "sysctl"):
    a = rd(f"{out}/{name}-prerun.txt").splitlines()
    b = rd(f"{out}/{name}-{tag}.txt").splitlines()
    if a != b:
        sa, sb = set(a), set(b)
        diff = ["-" + x for x in sorted(sa - sb)] + ["+" + x for x in sorted(sb - sa)]
        with open(f"{out}/{name}-{tag}.diff", "w") as f:
            f.write("\n".join(diff) + "\n")
        problems.append("%s differs from prerun (%d lines, %s-%s.diff): %s" %
                        (name, len(diff), name, tag, diff[:6]))
    else:
        notes.append("%s unchanged" % name)
for n in notes:
    print("  " + n)
for p in problems:
    print("  PROBLEM " + p)
print("HOSTCHECK %s %s" % (tag, "OK" if not problems else "STOP: %d problem(s)" % len(problems)))
sys.exit(1 if problems else 0)
EOF
