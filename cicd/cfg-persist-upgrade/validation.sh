#!/bin/bash
# validation.sh — cfg-persist-upgrade: the version matrix, live. One
# config volume, two gateway images, handed back and forth.
#
#   UP-04  a legacy-only volume (*.txt, no snapshot.json) written by the
#          old image must be replayed by the new one, classified as the
#          legacy path (never as a snapshot recovery), migrated forward
#          by the boot write-through, and the NEXT boot must come up
#          through the snapshot path
#   UP-01  a document persisted by the old image must migrate forward and
#          restore deep-equal on the new one
#   UP-03  the migrated volume round-trips again on the new image: the
#          migration is idempotent, the second boot changes nothing
#   UP-02  a document persisted by the NEW image handed back to the old
#          one must FAIL CLOSED (newer-schema gate) — quarantined, never
#          partially applied
#
# UP-01/02/03 need an old image that already speaks the snapshot API. The
# suite detects that and SKIPS them loudly rather than passing them
# vacuously; set UP_REQUIRE_SNAPSHOT_OLD=1 to turn a skip into a failure
# once a persistence-capable release exists.

source ../common.sh
source ../common/persist_lib.sh
echo SCENARIO-cfg-persist-upgrade

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }
skip() { echo "  [SKIPPED] $1"; }

VIP=20.20.20.1
CFG=llb1_config
CFGDIR="$(cd "$(dirname "$0")" && pwd)"

UP_NEW_IMAGE="${UP_NEW_IMAGE:-${LOXILB_DOCKER_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}}"
UP_OLD_IMAGE="${UP_OLD_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:v0.9.8.9-rc.1-u24}"
[[ "$UP_NEW_IMAGE" != *"/"* && "$UP_NEW_IMAGE" != *":"* ]] && UP_NEW_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$UP_NEW_IMAGE"
[[ "$UP_OLD_IMAGE" != *"/"* && "$UP_OLD_IMAGE" != *":"* ]] && UP_OLD_IMAGE="ghcr.io/loxilb-io/loxilb-inference-gateway:$UP_OLD_IMAGE"

echo "  old side: $UP_OLD_IMAGE"
echo "  new side: $UP_NEW_IMAGE"
if [[ "$UP_OLD_IMAGE" == "$UP_NEW_IMAGE" ]]; then
    echo "  [FAILED] the upgrade matrix needs two DISTINCT images; both sides resolved to $UP_NEW_IMAGE"
    echo "           set UP_OLD_IMAGE / UP_NEW_IMAGE (or LOXILB_DOCKER_IMAGE) and re-run"
    exit 1
fi

lb_count() {
    plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]?] | length'
}
fw_count() {
    plib_curl llb1 "$PLIB_API/config/firewall/all" | jq '[.fwAttr[]?] | length'
}
quarantine_count() {
    sudo sh -c "ls -d $CFG/snapshot.json.failed-* 2>/dev/null | wc -l"
}
assert_traffic() { # assert_traffic <label>
    local resp
    resp=$($hexec l3h1 curl -s -m 5 "http://${VIP}:2020/" 2>/dev/null | head -3)
    echo "$resp" | grep -q 'X-Echo-Backend' \
        && pass "$1: the VIP serves traffic" \
        || fail "$1: VIP probe returned: $resp"
}

# swap_image <image> — replace llb1's container with one running <image>,
# keeping the host-mounted config volume exactly as it is. The veths die
# with the old container, so both pairs are rebuilt and re-addressed.
swap_image() {
    local image=$1
    disconnect_docker_hosts l3h1  llb1
    disconnect_docker_hosts l3ep1 llb1
    delete_docker_host llb1
    pick_config="yes"
    lxdocker="$image"
    spawn_docker_host --dock-type loxilb --dock-name llb1
    pick_config=""
    connect_docker_hosts l3h1  llb1
    connect_docker_hosts l3ep1 llb1
    sleep 3
    config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
    config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
    config_docker_host --host1 llb1 --host2 l3h1  --ptype phy --addr 10.10.10.254/24
    config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
    plib_wait_api llb1
}

# snapshot_api_present — does the running gateway speak the snapshot API?
snapshot_api_present() {
    local rc
    rc=$(plib_curl llb1 -o /dev/null -w "%{http_code}" "$PLIB_API/config/snapshot")
    [[ "$rc" == "200" ]]
}

#################################################################################
echo "=== old side: capability probe and legacy artifact ==="
#################################################################################
plib_wait_api llb1 || fail "old image API never came up"
[[ "$(lb_count)" == "1" && "$(fw_count)" == "1" ]] \
    && pass "fixture is live on the old image" \
    || fail "old-side fixture: lb=$(lb_count) fw=$(fw_count)"
OLD_HAS_SNAPSHOT=0
if snapshot_api_present; then
    OLD_HAS_SNAPSHOT=1
    plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/old-capture.json"
    OLD_SCHEMA=$(jq -r '.schema_version' < "$PLIB_ARTIFACTS/old-capture.json")
    pass "the old image speaks the snapshot API (schema $OLD_SCHEMA)"
else
    if [[ "${UP_REQUIRE_SNAPSHOT_OLD:-0}" == "1" ]]; then
        fail "the old image has no snapshot API and UP_REQUIRE_SNAPSHOT_OLD=1"
    else
        skip "the old image predates the snapshot API: UP-01/02/03 cannot run against it"
    fi
fi
# The legacy artifact the old image DOES write, whatever its vintage.
$dexec llb1 loxicmd save --all >/dev/null 2>&1
sudo test -s "$CFG/lbconfig.txt" \
    && pass "old image wrote a legacy lbconfig.txt to the volume" \
    || fail "no legacy lbconfig.txt after loxicmd save --all on the old image"

#################################################################################
echo "=== UP-04: a legacy-only volume taken over by the new image ==="
#################################################################################
# The upgrade path of every node that has never persisted a document:
# *.txt only. The new image must replay it, classify it as the LEGACY
# path (a legacy replay is not a snapshot recovery and must never be
# reported as one) and migrate the volume forward via the boot
# write-through.
sudo rm -f "$CFG/snapshot.json"
swap_image "$UP_NEW_IMAGE" || fail "new image did not come up on the legacy volume"
f="$PLIB_ARTIFACTS/ready-up04.json"
plib_curl llb1 -o "$f" -w "%{http_code}" "$PLIB_API/status/ready" >/dev/null
bfound=$(jq -r '.boot.snapshot_found' < "$f")
bok=$(jq -r '.boot.succeeded' < "$f")
[[ "$bfound" == "false" && "$bok" == "false" ]] \
    && pass "UP-04: the boot reports the legacy path, not a snapshot recovery" \
    || fail "UP-04: boot surface snapshot_found=$bfound succeeded=$bok on a legacy-only volume"
[[ "$(lb_count)" == "1" ]] \
    && pass "UP-04: the legacy configuration was replayed by the new image" \
    || fail "UP-04: lb=$(lb_count) after the legacy replay"
assert_traffic "UP-04"
# The boot write-through migrates the volume: a current-schema document
# must now exist, and the NEXT boot must come up through the snapshot
# path instead of the legacy one.
sudo test -s "$CFG/snapshot.json" \
    && pass "UP-04: the boot write-through produced a snapshot document" \
    || fail "UP-04: no snapshot.json after the legacy replay (the volume was not migrated)"
plib_curl llb1 "$PLIB_API/config/snapshot" -o "$PLIB_ARTIFACTS/new-capture.json"
NEW_SCHEMA=$(jq -r '.schema_version' < "$PLIB_ARTIFACTS/new-capture.json")
DISK_SCHEMA=$(sudo jq -r '.schema_version' "$CFG/snapshot.json")
[[ -n "$NEW_SCHEMA" && "$DISK_SCHEMA" == "$NEW_SCHEMA" ]] \
    && pass "UP-04: the migrated document carries the running schema ($DISK_SCHEMA)" \
    || fail "UP-04: on-disk schema $DISK_SCHEMA, running schema $NEW_SCHEMA"
canonical_get_all llb1 "$PLIB_ARTIFACTS/up04-before" || fail "UP-04 pre-restart dump"
restart_inplace_keep llb1 || fail "UP-04: gateway did not come back"
canonical_get_all llb1 "$PLIB_ARTIFACTS/up04-after" || fail "UP-04 post-restart dump"
deep_diff "$PLIB_ARTIFACTS/up04-before" "$PLIB_ARTIFACTS/up04-after" up04 \
    && pass "UP-04: the migrated volume boots deep-equal through the snapshot path" \
    || fail "UP-04: the migrated volume did not round-trip"

if [[ "$OLD_HAS_SNAPSHOT" != "1" ]]; then
    skip "UP-01/UP-02/UP-03 (old image has no snapshot API)"
    plib_collect_logs llb1
    exit $code
fi

#################################################################################
echo "=== UP-01: a document persisted by the old image, restored by the new ==="
#################################################################################
# Back to the old side, persist there, then hand the volume forward.
sudo rm -f "$CFG/snapshot.json" "$CFG"/*.txt
swap_image "$UP_OLD_IMAGE" || fail "old image did not come back"
persist_and_verify llb1 || fail "UP-01: persist on the old image"
OLD_DISK_SCHEMA=$(sudo jq -r '.schema_version' "$CFG/snapshot.json")
canonical_get_all llb1 "$PLIB_ARTIFACTS/up01-old" || fail "UP-01 old-side dump"
swap_image "$UP_NEW_IMAGE" || fail "new image did not come up on the old document"
wait_replay_receipt llb1 || fail "UP-01: the new image never replayed the old document"
f="$PLIB_ARTIFACTS/ready-up01.json"
plib_curl llb1 -o "$f" -w "%{http_code}" "$PLIB_API/status/ready" >/dev/null
[[ "$(jq -r '.boot.succeeded' < "$f")" == "true" ]] \
    && pass "UP-01: the new image replayed the old image's document" \
    || fail "UP-01: boot did not succeed on the migrated document"
canonical_get_all llb1 "$PLIB_ARTIFACTS/up01-new" || fail "UP-01 new-side dump"
deep_diff "$PLIB_ARTIFACTS/up01-old" "$PLIB_ARTIFACTS/up01-new" up01 \
    && pass "UP-01: the configuration is deep-equal across the version step" \
    || fail "UP-01: configuration changed across the version step (see the diff artifacts)"
assert_traffic "UP-01"
MIGRATED_SCHEMA=$(sudo jq -r '.schema_version' "$CFG/snapshot.json")
[[ "$OLD_DISK_SCHEMA" != "$MIGRATED_SCHEMA" ]] \
    && pass "UP-01: the document was migrated forward ($OLD_DISK_SCHEMA -> $MIGRATED_SCHEMA)" \
    || pass "UP-01: both sides share schema $MIGRATED_SCHEMA (no migration was due)"

#################################################################################
echo "=== UP-03: the migration is idempotent ==="
#################################################################################
sudo cp "$CFG/snapshot.json" "$PLIB_ARTIFACTS/up03-first.json"
restart_inplace_keep llb1 || fail "UP-03: gateway did not come back"
sudo cp "$CFG/snapshot.json" "$PLIB_ARTIFACTS/up03-second.json"
if diff -q \
    <(sudo jq -S 'del(.created_at,.checksum,.generation,.trigger)' "$PLIB_ARTIFACTS/up03-first.json") \
    <(sudo jq -S 'del(.created_at,.checksum,.generation,.trigger)' "$PLIB_ARTIFACTS/up03-second.json") >/dev/null 2>&1; then
    pass "UP-03: the second boot re-migrated nothing (byte-stable desired state)"
else
    fail "UP-03: the document changed on a second boot — the migration is not idempotent"
fi

#################################################################################
echo "=== UP-02: a NEW-schema document handed back to the old image ==="
#################################################################################
# Downgrade, or a volume attached to a node that was not upgraded yet.
# The old gateway must fail CLOSED on a document it cannot understand:
# quarantine and an empty boot, never a partial apply that leaves the
# node half-configured while looking healthy.
persist_and_verify llb1 || fail "UP-02: persist on the new image"
q_before=$(quarantine_count)
swap_image "$UP_OLD_IMAGE" || fail "old image did not come up on the new document"
lb_old=$(lb_count)
q_after=$(quarantine_count)
if [[ "$q_after" -gt "$q_before" ]]; then
    pass "UP-02: the old image quarantined the newer-schema document ($q_before -> $q_after)"
    [[ "$lb_old" == "0" ]] \
        && pass "UP-02: the old image booted empty rather than partially applying" \
        || fail "UP-02: lb=$lb_old after quarantining — something was applied anyway"
else
    # An old image that predates the schema gate must at least leave the
    # document alone and not invent state from it.
    [[ "$lb_old" == "0" ]] \
        && pass "UP-02: the old image applied nothing from the newer document" \
        || fail "UP-02: the old image applied $lb_old rules from a document it cannot validate"
    sudo test -s "$CFG/snapshot.json" \
        && pass "UP-02: the newer document is still on the volume, unconsumed" \
        || fail "UP-02: the old image destroyed the newer document"
fi
# The upgrade back must recover the node exactly.
swap_image "$UP_NEW_IMAGE" || fail "new image did not come back after the downgrade leg"
if sudo test -s "$CFG/snapshot.json"; then
    wait_replay_receipt llb1 || fail "UP-02: the new image did not replay after the downgrade leg"
    [[ "$(lb_count)" == "1" ]] \
        && pass "UP-02: upgrading back restores the node from its own document" \
        || fail "UP-02: lb=$(lb_count) after upgrading back"
    assert_traffic "UP-02 recovery"
else
    # The old image quarantined it: the operator path is the recovery.
    rc=$(restore_commit llb1 "$PLIB_ARTIFACTS/up03-second.json")
    [[ "$rc" == "200" ]] \
        && pass "UP-02: the quarantined document restores through the operator path" \
        || fail "UP-02: operator recovery HTTP $rc"
fi

plib_collect_logs llb1
exit $code
