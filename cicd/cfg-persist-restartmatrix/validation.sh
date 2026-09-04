#!/bin/bash
# validation.sh — cfg-persist-restartmatrix: the three restart classes a
# persisted configuration has to survive, each ending on the SAME oracle.
#
#   (a) in-place       the process is killed and relaunched; the container,
#                      its netns and its veths survive
#   (b) container      docker stop/start: a new netns (the veths die with
#       recreate       it), a new process, the SAME host-mounted config
#                      volume — the class a container upgrade lands in
#   (c) cold config    snapshot.json removed before the boot: the gateway
#                      must come up empty and SAY SO on the boot surface,
#                      never report a recovery it did not perform, and
#                      still take the operator's restore afterwards
#
# The oracle after every class is the canonical deep-compare against the
# pre-restart dump plus a live traffic probe — a class that loses, invents
# or half-applies configuration fails on the diff, not on a spot check.
# Class (c) additionally asserts that the dump DIFFERS while it is empty,
# so the comparison cannot pass vacuously.

source ../common.sh
source ../common/persist_lib.sh
echo SCENARIO-cfg-persist-restartmatrix

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }

VIP=20.20.20.1
CFG=llb1_config

lb_count() {
    plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]?] | length'
}
fw_count() {
    plib_curl llb1 "$PLIB_API/config/firewall/all" | jq '[.fwAttr[]?] | length'
}

# wait_boot_settled — the readiness surface cites the boot gate until the
# boot config replay finishes; a cold boot has no replay receipt to poll,
# so this is the receipt for the empty class.
wait_boot_settled() {
    local i r
    for i in $(seq 1 30); do
        r=$(plib_curl llb1 "$PLIB_API/status/ready" | jq -r '(.reasons // []) | join(" ")')
        [[ "$r" != *"boot config replay has not settled"* ]] && return 0
        sleep 2
    done
    echo "  boot config replay never settled; readiness reasons: $r"
    return 1
}

assert_traffic() { # assert_traffic <label>
    local resp
    resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
    echo "$resp" | grep -q 'X-Echo-Backend' \
        && pass "$1: the restored VIP serves traffic" \
        || fail "$1: VIP probe returned: $resp"
}

# assert_replayed_boot <label> <expected-generation> — the boot surface
# must report the snapshot it actually replayed, at the lineage position
# the persist recorded. A boot that applied nothing but claims success
# (or succeeds while reporting no snapshot) fails here.
assert_replayed_boot() {
    local label=$1 wantgen=$2 f="$PLIB_ARTIFACTS/ready-$label.json" rc
    rc=$(plib_curl llb1 -o "$f" -w "%{http_code}" "$PLIB_API/status/ready")
    local ready found ok degraded legacy gen
    ready=$(jq -r '.ready' < "$f")
    found=$(jq -r '.boot.snapshot_found' < "$f")
    ok=$(jq -r '.boot.succeeded' < "$f")
    degraded=$(jq -r '.boot.degraded' < "$f")
    legacy=$(jq -r '.boot.legacy_fallback' < "$f")
    gen=$(jq -r '.boot.generation // 0' < "$f")
    if [[ "$rc" == "200" && "$ready" == "true" && "$found" == "true" && "$ok" == "true" \
          && "$degraded" == "false" && "$legacy" == "false" ]]; then
        pass "$label: boot surface reports a clean snapshot replay, gateway READY"
    else
        fail "$label: boot surface HTTP $rc ready=$ready found=$found ok=$ok degraded=$degraded legacy=$legacy"
    fi
    [[ "$gen" == "$wantgen" ]] \
        && pass "$label: replayed the persisted lineage generation ($gen)" \
        || fail "$label: boot generation $gen, want $wantgen"
}

#################################################################################
echo "=== baseline: persist the fixture and record the canonical dump ==="
#################################################################################
persist_and_verify llb1 || fail "baseline persist"
GEN=$(jq -r '.generation // 0' < "$PLIB_ARTIFACTS/persist-response.json")
[[ "$GEN" -ge 1 ]] \
    && pass "baseline persist stamped a lineage generation ($GEN)" \
    || fail "baseline persist carried no generation"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/good.json"
[[ $(sudo jq -r '.kind' "$PLIB_ARTIFACTS/good.json" 2>/dev/null) == "loxilb-snapshot" ]] \
    && pass "known-good document captured for the recovery leg" \
    || fail "good capture"
canonical_get_all llb1 "$PLIB_ARTIFACTS/base" || fail "baseline canonical dump"
[[ "$(lb_count)" == "2" && "$(fw_count)" == "1" ]] \
    && pass "fixture in place (2 LB rules, 1 firewall rule)" \
    || fail "fixture: lb=$(lb_count) fw=$(fw_count)"
assert_traffic "baseline"

# RED-TWIN hooks (inert unless PLIB_RED_MUTATE is set): each injection
# targets a DIFFERENT mode's own assert class. PLIB_RED_MUTATE=1 arms all
# three at once -- useful, but mode (b)'s break wedges the node, so the
# later modes then fail on the cascade rather than on their own class.
# PLIB_RED_MUTATE=a|b|c arms exactly one, which is how a single class is
# proven able to fire. Run deliberately, never in a green gate.
red_mode() { # red_mode <a|b|c> — is this injection armed?
    case "$PLIB_RED_MUTATE" in
    1|all) return 0 ;;
    "$1")  return 0 ;;
    *)     return 1 ;;
    esac
}
if red_mode a; then
    echo "  RED-TWIN: dropping the firewall rule after the baseline capture (mode (a) deep-compare must fire)"
    plib_curl llb1 -o /dev/null -X DELETE \
        "$PLIB_API/config/firewall?sourceIP=77.77.77.7%2F32&destinationIP=20.20.20.1%2F32"
    persist_and_verify llb1 >/dev/null
fi

#################################################################################
echo "=== mode (a): in-place process restart ==="
#################################################################################
# The container, its netns and its veths all survive; only the gateway
# process is killed (SIGTERM, escalating) and relaunched.
restart_inplace_keep llb1 || fail "mode (a): gateway did not come back"
canonical_get_all llb1 "$PLIB_ARTIFACTS/mode-a" || fail "mode (a) canonical dump"
deep_diff "$PLIB_ARTIFACTS/base" "$PLIB_ARTIFACTS/mode-a" mode-a \
    && pass "mode (a): every domain deep-equal across the process restart" \
    || fail "mode (a): configuration changed across the process restart"
assert_replayed_boot "mode-a" "$GEN"
assert_traffic "mode (a)"

#################################################################################
echo "=== mode (b): container stop/start — new netns, same config volume ==="
#################################################################################
# The container-recreate class: the network namespace and every veth in it
# die, the host-mounted config volume does not. This is the class a
# container image upgrade or a node reboot lands in, and the one where a
# gateway that kept its state only in memory silently comes back empty.
if red_mode b; then
    echo "  RED-TWIN: removing the managed cert material before the recreate (mode (b) volume assert must fire)"
    sudo rm -rf "$CFG/certs/rm-cert1"
fi
sum_b=$(sudo jq -r '.checksum' "$CFG/snapshot.json")
pid_before=$(docker inspect --format '{{.State.Pid}}' llb1)
docker stop -t 5 llb1 >/dev/null 2>&1
docker start llb1 >/dev/null 2>&1
sleep 3
pid_after=$(docker inspect --format '{{.State.Pid}}' llb1)
[[ -n "$pid_after" && "$pid_after" != "$pid_before" && "$pid_after" != "0" ]] \
    && pass "mode (b): container really recreated (PID $pid_before -> $pid_after, fresh netns)" \
    || fail "mode (b): container PID $pid_before -> $pid_after, the netns was NOT recreated"
# The /var/run/netns handle still bind-mounts the DEAD namespace: every
# $hexec llb1 would silently run in it. Re-register before anything else.
sudo umount /var/run/netns/llb1 2>/dev/null
sudo rm -f /var/run/netns/llb1
sudo touch /var/run/netns/llb1
sudo mount -o bind "/proc/${pid_after}/ns/net" /var/run/netns/llb1
# The veth pairs died with the old namespace (both ends): rebuild and
# re-address them exactly as config.sh did.
disconnect_docker_hosts l3h1  llb1
disconnect_docker_hosts l3ep1 llb1
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
sleep 3
config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
sleep 2
# The document and the managed key material live on the host mount, so
# the new container must find both exactly as the old one left them.
[[ "$(sudo jq -r '.checksum' "$CFG/snapshot.json")" == "$sum_b" ]] \
    && pass "mode (b): the config volume outlived the container (same document)" \
    || fail "mode (b): snapshot.json changed across the container recreate"
sudo test -s "$CFG/certs/rm-cert1/server.crt" \
    && pass "mode (b): managed certificate material survived on the volume" \
    || fail "mode (b): managed cert material missing after the recreate"
plib_start_gw llb1 || fail "mode (b): gateway did not start in the new container"
plib_wait_api llb1 || fail "mode (b): API never came back"
wait_replay_receipt llb1 || fail "mode (b): boot replay never settled"
canonical_get_all llb1 "$PLIB_ARTIFACTS/mode-b" || fail "mode (b) canonical dump"
deep_diff "$PLIB_ARTIFACTS/base" "$PLIB_ARTIFACTS/mode-b" mode-b \
    && pass "mode (b): every domain deep-equal across the container recreate" \
    || fail "mode (b): configuration changed across the container recreate"
assert_replayed_boot "mode-b" "$GEN"
assert_traffic "mode (b)"

#################################################################################
echo "=== mode (c): cold config — an empty boot must be reported as empty ==="
#################################################################################
# The volume is there but the document is gone (the "missing volume"
# class: a mis-mounted or wiped config directory). The gateway must come
# up EMPTY and say so on the boot surface — a node that reports a
# successful recovery it never performed is how an operator loses a
# configuration for good. Legacy *.txt artifacts are removed too: the
# legacy-fallback class is the negative suite's compat leg, this leg is
# about the empty class.
if red_mode c; then
    echo "  RED-TWIN: leaving snapshot.json in place (mode (c) empty-boot classification must fire)"
else
    sudo rm -f "$CFG/snapshot.json" "$CFG"/*.txt
fi
plib_start_gw llb1 || fail "mode (c): gateway did not come back"
plib_wait_api llb1 || fail "mode (c): API never came back"
wait_boot_settled || fail "mode (c): the boot gate never opened"
f="$PLIB_ARTIFACTS/ready-mode-c.json"
rc=$(plib_curl llb1 -o "$f" -w "%{http_code}" "$PLIB_API/status/ready")
cready=$(jq -r '.ready' < "$f")
cfound=$(jq -r '.boot.snapshot_found' < "$f")
cok=$(jq -r '.boot.succeeded' < "$f")
cdeg=$(jq -r '.boot.degraded' < "$f")
clegacy=$(jq -r '.boot.legacy_fallback' < "$f")
crestore=$(jq -r '.last_restore // "none"' < "$f")
if [[ "$cfound" == "false" && "$cok" == "false" && "$clegacy" == "false" ]]; then
    pass "mode (c): the boot reports no snapshot found and no replay performed"
else
    fail "mode (c): boot surface found=$cfound succeeded=$cok legacy_fallback=$clegacy"
fi
[[ "$crestore" == "none" ]] \
    && pass "mode (c): the empty boot claims no restore it never made" \
    || fail "mode (c): last_restore reported on a cold boot: $crestore"
[[ "$rc" == "200" && "$cready" == "true" && "$cdeg" == "false" ]] \
    && pass "mode (c): a cold boot is READY and not degraded (empty is a state, not a failure)" \
    || fail "mode (c): readiness HTTP $rc ready=$cready degraded=$cdeg"
[[ "$(lb_count)" == "0" && "$(fw_count)" == "0" ]] \
    && pass "mode (c): came up genuinely empty (nothing invented from a missing document)" \
    || fail "mode (c): lb=$(lb_count) fw=$(fw_count) after a cold boot"
# The same oracle, inverted: while the node is empty the canonical dump
# MUST differ from the baseline. If it did not, every deep-compare in
# this suite would be passing on stale or fabricated data.
canonical_get_all llb1 "$PLIB_ARTIFACTS/mode-c-empty" || fail "mode (c) empty dump"
if deep_diff "$PLIB_ARTIFACTS/base" "$PLIB_ARTIFACTS/mode-c-empty" mode-c-empty >/dev/null 2>&1; then
    fail "mode (c): the empty node's dump equals the baseline — the oracle is not reading live state"
else
    pass "mode (c): the empty node's dump differs from the baseline (the oracle can fail)"
fi
# Operator recovery: the last good document goes back in through REST.
rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/good.json")
[[ "$rc" == "200" ]] \
    && pass "mode (c): the operator restore of the last good document is accepted" \
    || fail "mode (c): recovery restore HTTP $rc"
canonical_get_all llb1 "$PLIB_ARTIFACTS/mode-c-recovered" || fail "mode (c) recovered dump"
deep_diff "$PLIB_ARTIFACTS/base" "$PLIB_ARTIFACTS/mode-c-recovered" mode-c-recovered \
    && pass "mode (c): the recovered node is deep-equal to the baseline" \
    || fail "mode (c): recovered state differs from the baseline"
assert_traffic "mode (c) recovery"
# The commit restore writes through, so the volume is armed again: the
# next boot of this node replays instead of coming up empty.
sudo test -s "$CFG/snapshot.json" \
    && pass "mode (c): the recovery wrote the document back to the volume" \
    || fail "mode (c): no snapshot.json after the recovery restore"
restart_inplace_keep llb1 || fail "mode (c): gateway did not come back after the recovery"
canonical_get_all llb1 "$PLIB_ARTIFACTS/mode-c-reboot" || fail "mode (c) reboot dump"
deep_diff "$PLIB_ARTIFACTS/base" "$PLIB_ARTIFACTS/mode-c-reboot" mode-c-reboot \
    && pass "mode (c): the recovered configuration survives the next boot on its own" \
    || fail "mode (c): the recovered configuration did not survive a reboot"
assert_traffic "mode (c) post-recovery reboot"

plib_collect_logs llb1
exit $code
