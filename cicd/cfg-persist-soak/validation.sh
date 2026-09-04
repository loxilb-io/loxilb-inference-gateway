#!/bin/bash
# validation.sh — cfg-persist-soak: the drift and leak classes that only
# repetition finds. Nightly/dispatch, not a per-PR gate.
#
#   SK-01  mutate -> debounce -> restart -> deep-compare, N cycles: the
#          restored configuration must be identical every single cycle
#          (a restore that re-applies a default, drops an empty list or
#          rounds a field shows up as cumulative drift, not on cycle 1)
#   SK-02  restart N times WITHOUT mutating: the persisted document must
#          be byte-stable modulo the fields that legitimately move
#          (timestamp, generation, checksum), and the gateway's open
#          descriptor count must not creep across restarts
#   SK-03  a 200-mutation storm through the debounce: the writes must
#          collapse (the debounce exists so a burst is not 200 disk
#          writes), the final state must survive a restart deep-equal,
#          and neither descriptors nor RSS may run away during the burst
#   SK-04  concurrent persist / dry-run restore / mutation rounds: the
#          gate contract holds every round and the document stays valid
#
# Loop sizes are env-tunable so a dispatch run can shorten them; the
# defaults are what the nightly runs.

source ../common.sh
source ../common/persist_lib.sh
echo SCENARIO-cfg-persist-soak

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }

VIP=20.20.20.1
CFG=llb1_config
CYCLES="${PLIB_SOAK_CYCLES:-20}"
IDLE_CYCLES="${PLIB_SOAK_IDLE_CYCLES:-20}"
STORM_MUTATIONS="${PLIB_SOAK_MUTATIONS:-200}"
CONC_ROUNDS="${PLIB_SOAK_CONC_ROUNDS:-10}"

fw_count() {
    plib_curl llb1 "$PLIB_API/config/firewall/all" | jq '[.fwAttr[]?] | length'
}
lb_count() {
    plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]?] | length'
}
add_fw() { # add_fw <a> <b> — a unique drop rule; echoes the HTTP code
    plib_curl llb1 -o /dev/null -w "%{http_code}" -X POST "$PLIB_API/config/firewall" \
        -H 'Content-Type: application/json' \
        -d "{\"ruleArguments\":{\"sourceIP\":\"9.$1.$2.1/32\",\"destinationIP\":\"6.6.6.6/32\"},\"opts\":{\"drop\":true}}"
}
gw_pid() {
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' 2>/dev/null | head -1
}
gw_fds() {
    docker exec llb1 sh -c "ls /proc/$(gw_pid)/fd 2>/dev/null | wc -l" 2>/dev/null
}
gw_rss_kb() {
    docker exec llb1 sh -c "awk '/VmRSS/{print \$2}' /proc/$(gw_pid)/status" 2>/dev/null
}
# doc_fingerprint — the persisted document with the fields that MUST move
# per capture removed. Everything else is desired state and has to be
# byte-stable on an idle node.
doc_fingerprint() {
    sudo jq -S 'del(.created_at,.checksum,.generation,.trigger)' "$CFG/snapshot.json" 2>/dev/null \
        | sha256sum | cut -d' ' -f1
}
metric_val() { # metric_val <full metric selector>
    plib_curl llb1 "$PLIB_API/metrics" 2>/dev/null | awk -v m="$1" '$1 == m {print $2}' | tail -1
}
ondisk_doc_valid() { # ondisk_doc_valid <label>
    local label=$1 stage="$PLIB_ARTIFACTS/ondisk-$label.json" rc res
    if ! sudo cp "$CFG/snapshot.json" "$stage" 2>"$PLIB_ARTIFACTS/ondisk-$label.err"; then
        echo "  on-disk document unreadable: $(cat "$PLIB_ARTIFACTS/ondisk-$label.err")"
        echo "  $CFG contents: $(sudo ls -la "$CFG" | tr '\n' ' ')"
        return 1
    fi
    sudo chmod 644 "$stage"
    rc=$(restore_dryrun llb1 "$stage")
    res=$(jq -r '.result' < "$PLIB_ARTIFACTS/restore-response.json")
    [[ "$rc" == "200" && "$res" == "ok" ]] && return 0
    echo "  dry-run of the on-disk document: HTTP $rc result=$res"
    return 1
}
assert_traffic() { # assert_traffic <label>
    local resp
    resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
    echo "$resp" | grep -q 'X-Echo-Backend' \
        && pass "$1: the VIP still serves traffic" \
        || fail "$1: VIP probe returned: $resp"
}

#################################################################################
echo "=== baseline ==="
#################################################################################
persist_and_verify llb1 || fail "baseline persist"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/good.json"
[[ $(sudo jq -r '.kind' "$PLIB_ARTIFACTS/good.json" 2>/dev/null) == "loxilb-snapshot" ]] \
    && pass "known-good document captured" || fail "good capture"
assert_traffic "baseline"

#################################################################################
echo "=== SK-01: $CYCLES x (mutate -> debounce -> restart -> deep-compare) ==="
#################################################################################
# Every cycle adds one rule, lets the auto-persist debounce write it
# through, and requires the post-restart dump to be identical to the
# pre-restart dump. Drift that is invisible on one cycle (a default
# re-applied, a null list normalized to empty) accumulates here.
sk01_ok=1
sk01_expected=$(fw_count)
for i in $(seq 1 "$CYCLES"); do
    rc=$(add_fw 1 "$i")
    if [[ "$rc" != "200" && "$rc" != "204" ]]; then
        fail "SK-01 cycle $i: mutation refused (HTTP $rc)"; sk01_ok=0; break
    fi
    sk01_expected=$((sk01_expected + 1))
    sleep 5   # the 3s debounce plus margin: the write-through must have run
    canonical_get_all llb1 "$PLIB_ARTIFACTS/sk01-$i-before" || { fail "SK-01 cycle $i: pre-restart dump"; sk01_ok=0; break; }
    restart_inplace_keep llb1 || { fail "SK-01 cycle $i: gateway did not come back"; sk01_ok=0; break; }
    canonical_get_all llb1 "$PLIB_ARTIFACTS/sk01-$i-after" || { fail "SK-01 cycle $i: post-restart dump"; sk01_ok=0; break; }
    if ! deep_diff "$PLIB_ARTIFACTS/sk01-$i-before" "$PLIB_ARTIFACTS/sk01-$i-after" "sk01-$i"; then
        fail "SK-01 cycle $i: configuration drifted across the restart"; sk01_ok=0; break
    fi
    if [[ "$(fw_count)" != "$sk01_expected" ]]; then
        fail "SK-01 cycle $i: firewall rules $(fw_count), want $sk01_expected (a mutation did not survive)"
        sk01_ok=0; break
    fi
    rm -rf "$PLIB_ARTIFACTS/sk01-$i-before" "$PLIB_ARTIFACTS/sk01-$i-after"
done
[[ "$sk01_ok" == 1 ]] \
    && pass "SK-01: $CYCLES mutate/restart cycles with zero drift, all $sk01_expected rules intact" \
    || fail "SK-01: drift or loss inside $CYCLES cycles"
assert_traffic "SK-01"

#################################################################################
echo "=== SK-02: $IDLE_CYCLES idle restarts — document stability and fd growth ==="
#################################################################################
# Nothing is mutated: the persisted desired state must be byte-identical
# every cycle (only the timestamp, generation and checksum may move), and
# the gateway's open descriptors must not creep restart over restart --
# the historical restart fd-leak class.
persist_and_verify llb1 || fail "SK-02: baseline persist"
fp0=$(doc_fingerprint)
fd0=$(gw_fds)
sk02_ok=1
for i in $(seq 1 "$IDLE_CYCLES"); do
    restart_inplace_keep llb1 || { fail "SK-02 cycle $i: gateway did not come back"; sk02_ok=0; break; }
    fp=$(doc_fingerprint)
    if [[ "$fp" != "$fp0" ]]; then
        fail "SK-02 cycle $i: the idle document changed (fingerprint $fp != $fp0)"
        sudo cp "$CFG/snapshot.json" "$PLIB_ARTIFACTS/sk02-drifted-$i.json" 2>/dev/null
        sk02_ok=0; break
    fi
done
fdN=$(gw_fds)
[[ "$sk02_ok" == 1 ]] \
    && pass "SK-02: $IDLE_CYCLES idle restarts left the persisted desired state byte-stable" \
    || fail "SK-02: the idle document churned across restarts"
if [[ -n "$fd0" && -n "$fdN" ]] && [[ "$fdN" -le $((fd0 + 10)) ]]; then
    pass "SK-02: open descriptors bounded across $IDLE_CYCLES restarts ($fd0 -> $fdN)"
else
    fail "SK-02: descriptor growth across restarts: $fd0 -> $fdN"
fi

#################################################################################
echo "=== SK-03: $STORM_MUTATIONS-mutation storm through the debounce ==="
#################################################################################
# A real config push: hundreds of mutations back to back. The debounce
# exists so that becomes a handful of disk writes, not one per call; the
# final state must still be exactly what a restart brings back.
plib_curl llb1 -o /dev/null -X POST "$PLIB_API/config/metrics" >/dev/null 2>&1
p0=$(metric_val 'loxilb_persist_total{result="ok"}')
fd_before=$(gw_fds)
rss_before=$(gw_rss_kb)
fw_before=$(fw_count)
storm_bad=0
for i in $(seq 1 "$STORM_MUTATIONS"); do
    rc=$(add_fw 2 "$i")
    [[ "$rc" == "200" || "$rc" == "204" ]] || { storm_bad=$((storm_bad + 1)); }
done
[[ "$storm_bad" == 0 ]] \
    && pass "SK-03: all $STORM_MUTATIONS mutations accepted during the storm" \
    || fail "SK-03: $storm_bad of $STORM_MUTATIONS mutations were refused"
sleep 8   # the debounce must fire and settle after the last call
fw_after=$(fw_count)
[[ "$fw_after" == "$((fw_before + STORM_MUTATIONS - storm_bad))" ]] \
    && pass "SK-03: every accepted mutation is present ($fw_after rules)" \
    || fail "SK-03: firewall rules $fw_after, want $((fw_before + STORM_MUTATIONS - storm_bad))"
p1=$(metric_val 'loxilb_persist_total{result="ok"}')
if [[ -n "$p0" && -n "$p1" ]]; then
    writes=$(awk -v a="$p0" -v b="$p1" 'BEGIN{printf "%d", b - a}')
    if [[ "$writes" -lt $((STORM_MUTATIONS / 4)) ]]; then
        pass "SK-03: the debounce collapsed $STORM_MUTATIONS mutations into $writes persists"
    else
        fail "SK-03: $writes persists for $STORM_MUTATIONS mutations — the debounce is not collapsing the burst"
    fi
else
    fail "SK-03: persist counter unreadable (metrics endpoint p0=$p0 p1=$p1)"
fi
fd_after=$(gw_fds)
rss_after=$(gw_rss_kb)
if [[ -n "$fd_before" && -n "$fd_after" ]] && [[ "$fd_after" -le $((fd_before + 20)) ]]; then
    pass "SK-03: descriptors bounded across the storm ($fd_before -> $fd_after)"
else
    fail "SK-03: descriptor growth across the storm: $fd_before -> $fd_after"
fi
if [[ -n "$rss_before" && -n "$rss_after" ]] && [[ "$rss_after" -le $((rss_before * 2 + 65536)) ]]; then
    pass "SK-03: RSS bounded across the storm (${rss_before}kB -> ${rss_after}kB)"
else
    fail "SK-03: RSS growth across the storm: ${rss_before}kB -> ${rss_after}kB"
fi
canonical_get_all llb1 "$PLIB_ARTIFACTS/sk03-before" || fail "SK-03: pre-restart dump"
restart_inplace_keep llb1 || fail "SK-03: gateway did not come back"
canonical_get_all llb1 "$PLIB_ARTIFACTS/sk03-after" || fail "SK-03: post-restart dump"
deep_diff "$PLIB_ARTIFACTS/sk03-before" "$PLIB_ARTIFACTS/sk03-after" sk03 \
    && pass "SK-03: the storm's final state survives a restart deep-equal" \
    || fail "SK-03: the storm's final state did not survive the restart"
assert_traffic "SK-03"

#################################################################################
echo "=== SK-04: $CONC_ROUNDS concurrent persist / dry-run restore / mutation rounds ==="
#################################################################################
# The gate contract under repetition: snapshot endpoints answer 200 or
# 409, mutations answer 200/204 or 503, the document stays valid after
# every round, and idle captures stay identical (a torn capture would
# differ between two back-to-back GETs).
sk04_ok=1
sk04_rejections=0
for r in $(seq 1 "$CONC_ROUNDS"); do
    ( plib_curl llb1 -o /dev/null -w "%{http_code}" -X POST "$PLIB_API/config/persist" \
        > "$PLIB_ARTIFACTS/sk04-$r-persist.code" ) &
    ( plib_curl llb1 -o /dev/null -w "%{http_code}" -X POST "$PLIB_API/config/restore?mode=dry-run" \
        -H 'Content-Type: application/json' --data-binary @"$PLIB_ARTIFACTS/good.json" \
        > "$PLIB_ARTIFACTS/sk04-$r-restore.code" ) &
    ( plib_curl llb1 -o /dev/null -w "%{http_code}" "$PLIB_API/config/snapshot" \
        > "$PLIB_ARTIFACTS/sk04-$r-capture.code" ) &
    ( add_fw 3 "$r" > "$PLIB_ARTIFACTS/sk04-$r-mutate.code" ) &
    wait
    for f in "$PLIB_ARTIFACTS/sk04-$r-persist.code" "$PLIB_ARTIFACTS/sk04-$r-restore.code" "$PLIB_ARTIFACTS/sk04-$r-capture.code"; do
        c=$(cat "$f" 2>/dev/null)
        case "$c" in
        200) ;;
        409) sk04_rejections=$((sk04_rejections + 1)) ;;
        *)  fail "SK-04 round $r: $(basename "$f" .code) answered HTTP $c (contract: 200 or 409)"; sk04_ok=0 ;;
        esac
    done
    c=$(cat "$PLIB_ARTIFACTS/sk04-$r-mutate.code" 2>/dev/null)
    case "$c" in
    200|204) ;;
    503) sk04_rejections=$((sk04_rejections + 1)) ;;
    *)  fail "SK-04 round $r: mutation answered HTTP $c (contract: 200/204 or 503)"; sk04_ok=0 ;;
    esac
    sleep 5   # let the round's debounce drain before reading the document
    if ! ondisk_doc_valid "sk04-$r"; then
        fail "SK-04 round $r: the persisted document is not valid after the round"; sk04_ok=0; break
    fi
    plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/sk04-$r-cap1.json"
    plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/sk04-$r-cap2.json"
    if ! diff -q \
        <(jq -S 'del(.created_at,.checksum,.trigger)' "$PLIB_ARTIFACTS/sk04-$r-cap1.json") \
        <(jq -S 'del(.created_at,.checksum,.trigger)' "$PLIB_ARTIFACTS/sk04-$r-cap2.json") >/dev/null 2>&1; then
        fail "SK-04 round $r: two back-to-back captures of an idle node differ (torn capture)"; sk04_ok=0; break
    fi
    rm -f "$PLIB_ARTIFACTS/sk04-$r-cap1.json" "$PLIB_ARTIFACTS/sk04-$r-cap2.json"
done
[[ "$sk04_ok" == 1 ]] \
    && pass "SK-04: $CONC_ROUNDS concurrent rounds held the gate contract and left a valid document each time" \
    || fail "SK-04: the concurrency rounds broke the contract"
echo "  (gate rejections observed across the rounds: $sk04_rejections)"
canonical_get_all llb1 "$PLIB_ARTIFACTS/sk04-before" || fail "SK-04: pre-restart dump"
restart_inplace_keep llb1 || fail "SK-04: gateway did not come back"
canonical_get_all llb1 "$PLIB_ARTIFACTS/sk04-after" || fail "SK-04: post-restart dump"
deep_diff "$PLIB_ARTIFACTS/sk04-before" "$PLIB_ARTIFACTS/sk04-after" sk04 \
    && pass "SK-04: the post-concurrency state survives a restart deep-equal" \
    || fail "SK-04: state changed across the post-concurrency restart"
assert_traffic "SK-04"

plib_collect_logs llb1
exit $code
