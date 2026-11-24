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
#     one of the scenario's containers, and the filters systemd attaches to
#     its own units (DevicePolicy=, IPAddressDeny= and the like): accepted
#     only for a cgroup_device or cgroup_skb program on a .service, .scope or
#     .socket unit under system.slice or user.slice that is not a container's
#     docker-*.scope, loaded by systemd and named sd_* where bpftool reports
#     a loader or a name; counted with the unit names in a notes line;
#   - bpftool net of the host namespace unchanged.
# The comparison is hostcheck.py (tests: test_hostcheck.py).
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

python3 "$(dirname "$0")/hostcheck.py" "$OUT" "$TAG" "$GW" $CONTAINERS
