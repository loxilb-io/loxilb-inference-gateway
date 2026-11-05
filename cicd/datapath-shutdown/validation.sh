#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run on a disposable Linux testbed with Docker and passwordless sudo.
# The anchor keeps the network namespace alive after the gateway is removed.
set -euo pipefail

image=${1:?usage: validation.sh IMAGE [docker run options]}
shift
run_options=("$@")
tmp=$(mktemp -d)
suffix=${tmp##*.}
anchor="dp-shutdown-net-$suffix"
gateway="dp-shutdown-gw-$suffix"
cleanup() {
    docker rm -f "$gateway" "$anchor" >/dev/null 2>&1 || true
    rm -rf -- "$tmp"
}
trap cleanup EXIT

docker run -d --name "$anchor" --network none "${DP_TEST_ANCHOR_IMAGE:-alpine:3}" sleep 600 >/dev/null
pid=$(docker inspect -f '{{.State.Pid}}' "$anchor")
ns() { sudo -n nsenter -t "$pid" -n -- "$@"; }

wait_ready() {
    for _ in $(seq 1 45); do
        if ns curl -fsS --max-time 1 http://127.0.0.1:11111/netlox/v1/status/ready >/dev/null 2>&1 &&
            ns curl -fsS --max-time 1 http://127.0.0.1:11111/netlox/v1/version >"$tmp/version" 2>/dev/null &&
            ns bpftool net show >"$tmp/hooks" &&
            grep -Eq 'llb0.*(generic|driver).* id ' "$tmp/hooks" &&
            grep -Eq 'llb0.*clsact/ingress.*tc_packet_func' "$tmp/hooks"; then
            cat "$tmp/version"
            return
        fi
        sleep 1
    done
    docker logs "$gateway" >&2
    return 1
}

docker run -d --name "$gateway" --privileged --network "container:$anchor" \
    "${run_options[@]}" "$image" --egr-hooks >/dev/null
wait_ready

# Restart uses the same container and namespace, including its persistent hooks.
docker restart --time 15 "$gateway" >/dev/null
wait_ready
grep -Eq 'llb0.*clsact/egress.*tc_packet_func' "$tmp/hooks"

# Share the gateway's clsact qdisc with a filter at a different priority.
ns tc filter add dev llb0 ingress protocol all pref 50 matchall action pass
ns tc filter show dev llb0 ingress | grep -q 'pref 50 matchall'
cat "$tmp/hooks"

docker stop --time 15 "$gateway" >/dev/null
exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$gateway")
docker logs "$gateway" >"$tmp/gateway.log" 2>&1
docker rm "$gateway" >/dev/null

ns bpftool net show | tee "$tmp/after"
if [ "$exit_code" != 0 ] ||
    grep -Eq 'llb0.*(generic|driver).* id |llb0.*clsact.*tc_packet_func' "$tmp/after" ||
    ! ns tc filter show dev llb0 ingress | grep -q 'pref 50 matchall'; then
    tail -60 "$tmp/gateway.log" >&2
    echo "FAIL: exit=$exit_code or datapath/foreign-filter state is wrong" >&2
    exit 1
fi
grep -E '\[shutdown\].*(detached|stage=ebpf)' "$tmp/gateway.log"
echo 'PASS: Gateway XDP and tc ingress/egress detached, unrelated tc filter preserved'

# The state directory outlives the removed gateway container. A second
# container in the anchor namespace runs only the offline recovery command.
mkdir "$tmp/state"
state_args=(-v "$tmp/state:/state")
docker run -d --name "$gateway" --privileged --network "container:$anchor" \
    "${run_options[@]}" "${state_args[@]}" "$image" --egr-hooks --datapath-state=/state/datapath.json >/dev/null
wait_ready
grep -Eq 'llb0.*clsact/egress.*tc_packet_func' "$tmp/hooks"
ns tc filter add dev llb0 ingress protocol all pref 50 matchall action pass

offline() {
    local network=$1
    docker run --rm --privileged --network "$network" \
        "${run_options[@]}" "${state_args[@]}" "$image" --detach-datapath=/state/datapath.json
}
if offline "container:$anchor" >"$tmp/recover.log" 2>&1 || ! grep -q 'is locked' "$tmp/recover.log"; then
    cat "$tmp/recover.log" >&2
    exit 1
fi

docker kill "$gateway" >/dev/null
test "$(docker inspect -f '{{.State.ExitCode}}' "$gateway")" = 137
docker rm "$gateway" >/dev/null
ns bpftool net show >"$tmp/after-kill"
diff -u "$tmp/hooks" "$tmp/after-kill"
if offline none >"$tmp/recover.log" 2>&1 || ! grep -q 'another network namespace' "$tmp/recover.log"; then
    cat "$tmp/recover.log" >&2
    exit 1
fi

offline "container:$anchor"
offline "container:$anchor"
ns bpftool net show >"$tmp/after-recover"
if grep -Eq 'llb0.*(generic|driver).* id |llb0.*clsact.*tc_packet_func' "$tmp/after-recover" ||
    ! ns tc filter show dev llb0 ingress | grep -q 'pref 50 matchall'; then
    cat "$tmp/after-recover" >&2
    exit 1
fi
test ! -e "$tmp/state/datapath.json"
echo 'PASS: offline recovery after SIGKILL, live lock and namespace guard, unrelated tc filter preserved'
