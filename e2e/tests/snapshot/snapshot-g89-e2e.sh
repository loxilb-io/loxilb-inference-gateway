#!/bin/bash
# G-8/G-9 E2E — metrics, /config/persist, auto-persist debounce, §6.2 boot
# arbitration, pre-restore pruning (SNAPSHOT-DESIGN.md §6/§7 scenarios).
# Runs ON the gateway node (needs docker + host /opt/loxilb/config mount).
# MUTATES live config and RESTARTS the loxilb container twice.
#
# Boot is ASYNCHRONOUS: the REST API answers while the nlp boot replay is
# still applying config, so after every restart this suite waits for the
# boot-path COMPLETION marker in the container log (scoped with
# `docker logs --since` to this restart), never just for /version.
set -u
B=http://127.0.0.1:11111/netlox/v1
D=/tmp/snap-g89-e2e
H=/opt/loxilb/config   # host side of the container's /etc/loxilb volume
mkdir -p $D
pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }
jqok() { jq -e "$2" >/dev/null 2>&1 <<<"$1"; }
metric() { curl -s $B/metrics | awk -v m="$1" '$1 ~ m {print $2; exit}'; }

# logsince <unix-epoch> — container log scoped to the current boot only.
# Unix timestamps are timezone-unambiguous; an ISO stamp without a zone
# suffix is parsed as DAEMON-LOCAL time and silently unscopes the grep.
logsince() { docker logs --since "$1" loxilb 2>&1; }

# restart_and_wait <marker-regex> — restart the container, then block until
# the given boot-completion marker appears in THIS boot's log (max 120s)
# AND the REST API answers (the marker can precede the listener).
# Snapshot-path marker: "boot config restored from snapshot.json"
# Legacy-path marker:   "legacy config persisted to" (post-replay write-through)
restart_and_wait() {
  T0=$(date +%s)
  docker restart loxilb > /dev/null
  seen=0
  for i in $(seq 1 60); do
    logsince "$T0" | grep -qE "$1" && { seen=1; break; }
    sleep 2
  done
  for i in $(seq 1 30); do
    curl -s -m 2 $B/version >/dev/null 2>&1 && break
    sleep 2
  done
  sleep 2
  [ $seen -eq 1 ]
}

wipe_lbs() {
  curl -s $B/config/loadbalancer/all | jq -r '.lbAttr[]?.serviceArguments | "\(.externalIP) \(.port) \(.protocol)"' |
  while read ip port proto; do
    curl -s -X DELETE "$B/config/loadbalancer/externalipaddress/$ip/port/$port/protocol/$proto" > /dev/null
  done
}

echo "=== S-pre: clean LB baseline ==="
# Loop until stable: an earlier (possibly interrupted) boot replay may still
# be applying rules asynchronously while we wipe.
for i in $(seq 1 10); do
  wipe_lbs
  sleep 3
  N=$(curl -s $B/config/loadbalancer/all | jq '.lbAttr | length')
  [ "$N" = "0" ] && break
done
rm -f $H/lbconfig.txt
sleep 5
curl -s -X POST $B/config/persist > /dev/null
N=$(curl -s $B/config/loadbalancer/all | jq '.lbAttr | length')
[ "$N" = "0" ] && ok "S-pre LB baseline clean" || bad "S-pre $N LBs left"

echo "=== M0 metric series exist ==="
MET=$(curl -s $B/metrics)
for s in loxilb_restore_total loxilb_restore_duration_seconds_count loxilb_last_restore_timestamp_seconds loxilb_boot_config_conflict_total; do
  grep -q "^$s" <<<"$MET" || grep -q "^# TYPE $s" <<<"$MET" && ok "M0 $s present" || bad "M0 $s missing"
done

echo "=== P1 POST /config/persist ==="
BEFORE_MT=$(stat -c %Y $H/snapshot.json 2>/dev/null || echo 0)
sleep 1
R=$(curl -s -X POST $B/config/persist)
jqok "$R" '.result=="ok" and (.path|test("snapshot.json")) and (.checksum|test("^sha256:"))' && ok "P1 persist ok+path+checksum" || bad "P1 persist: $R"
AFTER_MT=$(stat -c %Y $H/snapshot.json 2>/dev/null || echo 0)
[ "$AFTER_MT" -gt "$BEFORE_MT" ] && ok "P1 snapshot.json rewritten" || bad "P1 snapshot.json mtime unchanged ($BEFORE_MT -> $AFTER_MT)"

echo "=== A1 auto-persist picks up a mutation (no explicit save) ==="
curl -s -X POST $B/config/loadbalancer -H 'Content-Type: application/json' -d '{"serviceArguments":{"externalIP":"21.21.21.1","port":2121,"protocol":"tcp","sel":0,"mode":0,"BGP":false,"monitor":false,"inactiveTimeOut":240},"endpoints":[{"endpointIP":"10.0.0.12","weight":1,"targetPort":5001,"state":"active"}]}' > $D/lb.out
sleep 5
grep -q "21.21.21.1" $H/snapshot.json && ok "A1 auto-persisted LB in snapshot.json" || bad "A1 LB missing from snapshot.json after quiet period: $(cat $D/lb.out)"

echo "=== A2 burst debounces to one write ==="
TA=$(date +%s)
for i in 2 3 4; do
  curl -s -X POST $B/config/loadbalancer -H 'Content-Type: application/json' -d "{\"serviceArguments\":{\"externalIP\":\"21.21.21.$i\",\"port\":2121,\"protocol\":\"tcp\",\"sel\":0,\"mode\":0,\"BGP\":false,\"monitor\":false,\"inactiveTimeOut\":240},\"endpoints\":[{\"endpointIP\":\"10.0.0.12\",\"weight\":1,\"targetPort\":5001,\"state\":\"active\"}]}" > /dev/null
done
sleep 5
NW=$(logsince "$TA" | grep -c "auto-persist: running config persisted")
[ "$NW" -eq 1 ] && ok "A2 3-mutation burst -> 1 write" || bad "A2 burst produced $NW writes"

echo "=== B1 arbitration: legacy *.txt NEWER wins, then migrates ==="
docker exec loxilb loxicmd save --lb > /dev/null 2>&1
# diverge: drop one LB so snapshot (auto-persisted) != txt, then age snapshot
curl -s -X DELETE "$B/config/loadbalancer/externalipaddress/21.21.21.4/port/2121/protocol/tcp" > /dev/null
sleep 5
touch $H/lbconfig.txt
T1=$(date +%s)
restart_and_wait "legacy config persisted to" || bad "B1 boot did not reach post-legacy write-through in 120s"
logsince "$T1" | grep -q "loading the newer: legacy" && ok "B1 arbitration chose newer txt" || bad "B1 no arbitration-chose-txt log"
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '[.lbAttr[].serviceArguments.externalIP] | index("21.21.21.4") != null' && ok "B1 txt-only LB replayed" || bad "B1 21.21.21.4 not restored from txt: $LBS"
logsince "$T1" | grep -q "legacy config persisted to /etc/loxilb/snapshot.json" && ok "B1 post-legacy write-through" || bad "B1 no migration write-through log"
C=$(metric '^loxilb_boot_config_conflict_total')
[ "$C" = "1" ] && ok "B1 conflict metric 1" || bad "B1 conflict metric = $C"

echo "=== B2 arbitration: snapshot.json NEWER wins (rule-managed-only LB doc must validate) ==="
T2=$(date +%s)
restart_and_wait "boot config restored from snapshot.json" || bad "B2 boot did not restore from snapshot.json in 120s"
logsince "$T2" | grep -q "loading the newer: snapshot.json" && ok "B2 arbitration chose newer snapshot" || bad "B2 no arbitration-chose-snapshot log"
logsince "$T2" | grep -q "boot config restored from snapshot.json" && ok "B2 snapshot boot restore ok" || bad "B2 snapshot boot restore did not succeed (regression: LB w/ rule-managed eps rejected?)"
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '[.lbAttr[].serviceArguments.externalIP] | index("21.21.21.1") != null' && ok "B2 LBs live after snapshot boot" || bad "B2 LBs missing: $LBS"

echo "=== C1 pre-restore backlog bounded ==="
N=$(ls $H | grep -c '^pre-restore-')
[ "$N" -le 5 ] && ok "C1 pre-restore files bounded ($N <= 5)" || bad "C1 $N pre-restore files (> 5)"

echo "=== CLEANUP ==="
wipe_lbs
rm -f $H/lbconfig.txt
sleep 5
curl -s -X POST $B/config/persist > /dev/null
grep -q "21.21.21" $H/snapshot.json && bad "CLEANUP snapshot still carries test LBs" || ok "CLEANUP snapshot clean"

echo
echo "RESULT: $pass passed, $fail failed"
[ $fail -eq 0 ]
