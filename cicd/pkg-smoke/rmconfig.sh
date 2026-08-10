#!/bin/bash
# pkg-smoke teardown: endpoints, service, netns topology, drill artifacts.
#
# Ordering matters here. loxilb attaches its TC (clsact) and XDP programs
# directly to this scenario's pks* veths -- config.sh blacklists every host
# interface except those, so the datapath is bound to exactly the devices we
# are about to remove. Those programs are only detached by DpEbpfUnInit(),
# which runs when the service stops. Deleting a netdev while eBPF hooks still
# hold a reference to it parks the kernel in
#
#   unregister_netdevice: waiting for <dev> to become free. Usage count = N
#
# which is an uninterruptible (D-state) wait: SIGKILL does not clear it, so
# the job burns its timeout plus GitHub's five-minute force-kill grace and
# corrupts its own log upload on the way out. Hence: stop the datapath first,
# then remove the topology it was attached to.
#
# Every step that touches a netdev is additionally wrapped in `timeout` so a
# residual wedge surfaces as a fast, diagnosable failure rather than a
# 25-minute silent hang with no log.

WORK=/tmp/pkg-smoke
rc=0

# Bounded wrapper: report and keep going, so one wedged step still lets the
# rest of the teardown run (and still marks the script failed).
try() {
    local secs=$1; shift
    local st=0
    sudo timeout -k 5 "$secs" "$@" 2>/dev/null || st=$?
    # timeout(1) exits 124 on expiry; anything else here is a benign
    # "already gone" from an idempotent delete, which we ignore.
    if [ "$st" -eq 124 ]; then
        echo "pkg-smoke rmconfig: TIMEOUT after ${secs}s: $*" >&2
        rc=1
    fi
}

# 1. Stop the endpoint servers and make sure they are actually gone: a live
#    process inside a netns keeps that netns pinned even after `netns del`.
for ep in ep1 ep2; do
    if [ -f "$WORK/$ep.pid" ]; then
        pid=$(cat "$WORK/$ep.pid")
        [ -n "$pid" ] || continue
        sudo kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            sudo kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        sudo kill -9 "$pid" 2>/dev/null || true
    fi
done

# 2. Stop the datapath BEFORE the devices it is attached to disappear. This is
#    the step that runs DpEbpfUnInit() and detaches TC/XDP from the pks*
#    veths. Bounded well above the unit's default TimeoutStopSec (90s) so a
#    genuine slow stop is not misreported as a wedge.
try 120 systemctl stop loxilb

# 3. Unmount the bpffs the service mounted at /opt/loxilb/dp (ExecStartPre=
#    mkllb-bpffs). systemctl stop kills loxilb but leaves this mount in place;
#    its pinned eBPF maps keep datapath objects alive and can wedge the hosted
#    runner's post-job cleanup ("Complete job" hang observed on the 22.04
#    runner). Fall back to a lazy detach so a busy mount still leaves the tree
#    clean.
sudo timeout -k 5 30 umount /opt/loxilb/dp 2>/dev/null \
    || sudo timeout -k 5 30 umount -l /opt/loxilb/dp 2>/dev/null \
    || true

# 4. Drop any eBPF still attached to the veths, explicitly. Stopping the
#    service is supposed to do this via DpEbpfUnInit(), but that detach is
#    best-effort: it can fail silently, it is skipped entirely if systemd
#    reaches TimeoutStopSec and SIGKILLs loxilb mid-cleanup, and programs
#    pinned under /opt/loxilb/dp outlive the process regardless. Any leftover
#    TC filter or XDP program holds a reference to the netdev and turns the
#    delete below into an unkillable unregister_netdevice wait, so tear the
#    attachments down here rather than trusting the datapath to have done it.
for hveth in pksh1 pksep1 pksep2; do
    ip link show "$hveth" >/dev/null 2>&1 || continue
    try 15 tc qdisc del dev "$hveth" clsact
    try 15 ip link set dev "$hveth" xdp off
done

# 5. Now the topology is safe to remove. Delete the host-side veth first: that
#    removes its peer inside the netns too, so the netns is empty by the time
#    we drop it.
for hveth in pksh1 pksep1 pksep2; do
    try 30 ip link del "$hveth"
done
for ns in pks-h1 pks-ep1 pks-ep2; do
    try 30 ip netns del "$ns"
done

sudo rm -f /etc/systemd/system/loxilb.service.d/pkg-smoke.conf
sudo rmdir /etc/systemd/system/loxilb.service.d 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true

# Remove the snapshot the drill persisted (keep /etc/loxilb itself)
sudo rm -f /etc/loxilb/snapshot.json
rm -rf "$WORK"

# A leftover netdev is the signature of the wedge above; surface it while the
# runner can still upload a log.
if ip link show 2>/dev/null | grep -qE '\bpks(h1|ep1|ep2)\b'; then
    echo "pkg-smoke rmconfig: pks* veths survived teardown (netdev wedge)" >&2
    ip link show | grep -E '\bpks' >&2 || true
    rc=1
fi

if [ "$rc" = 0 ]; then
    echo "pkg-smoke rmconfig done"
else
    echo "pkg-smoke rmconfig [FAIL]" >&2
fi
exit $rc
