#!/bin/bash
# validation.sh — ai-ha-failover-bfd
#
# Reports what a client that only knows the shared VIP sees while the BFD
# pair fails over. Every case ends as PASS, FAIL, RECORDED (a measurement
# with no threshold yet) or NOT_RUN (the check could not run). The scenario
# never downgrades a verdict: an unhealthy precondition is NOT_RUN for every
# case that depends on it and a non-zero exit.
#
# Exit status: 0 no FAIL and no NOT_RUN; 1 at least one FAIL; 2 at least one
# NOT_RUN (a precondition or the harness itself failed).
#
# usage: ./validation.sh [--cases FAILOVER-0,BED]   (default: every case)
# Case selectors: FAILOVER-0 BED FAILOVER-1 FAILOVER-2-4 FAILOVER-5-8 FAILOVER-6-7 FAILOVER-9 FAILOVER-10 FAILOVER-11 FAILOVER-11r FAILOVER-12 FAILOVER-13 FAILOVER-FRONTEND

source ../common.sh >/dev/null
source ./lib.sh
CFGDIR="$HAFO_DIR"
ALL_CASES="FAILOVER-0 BED-1 BED-2 FAILOVER-1 FAILOVER-2 FAILOVER-3 FAILOVER-4 FAILOVER-5 FAILOVER-6 FAILOVER-7 FAILOVER-8a FAILOVER-8b FAILOVER-9 FAILOVER-10 FAILOVER-11 FAILOVER-11r FAILOVER-12 FAILOVER-13 FAILOVER-FRONTEND"
if [ ! -f "${CFGDIR}/.unhealthy" ]; then
  [ -s "${CFGDIR}/.keys" ] && [ -f "${CFGDIR}/.env" ] || { echo "FATAL: run config.sh first"; exit 2; }
  . "${CFGDIR}/.env"
fi

CASES_WANTED="FAILOVER-0,BED,FAILOVER-1,FAILOVER-2-4,FAILOVER-5-8,FAILOVER-6-7,FAILOVER-9,FAILOVER-10,FAILOVER-11,FAILOVER-11r,FAILOVER-12,FAILOVER-13,FAILOVER-FRONTEND"
while [ $# -gt 0 ]; do
  case "$1" in
    --cases) CASES_WANTED=$2; shift 2 ;;
    --cases=*) CASES_WANTED=${1#--cases=}; shift ;;
    *) echo "unknown argument $1"; exit 2 ;;
  esac
done
want() { case ",$CASES_WANTED," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

OUT=${HAFO_OUT:-${CFGDIR}/out/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"
: > "$OUT/verdicts.tsv"
nonce_init
trap 'rm -f "$NONCE_FILE"' EXIT
echo "evidence directory: $OUT"

finish() {
  echo
  echo "================ verdicts ================"
  column -t -s $'\t' "$OUT/verdicts.tsv" | cut -c1-200
  local f n
  f=$(awk -F'\t' '$2=="FAIL"' "$OUT/verdicts.tsv" | wc -l)
  n=$(awk -F'\t' '$2=="NOT_RUN"' "$OUT/verdicts.tsv" | wc -l)
  echo "PASS=$(awk -F'\t' '$2=="PASS"' "$OUT/verdicts.tsv" | wc -l) FAIL=$f RECORDED=$(awk -F'\t' '$2=="RECORDED"' "$OUT/verdicts.tsv" | wc -l) NOT_RUN=$n"
  [ "$n" -gt 0 ] && exit 2
  [ "$f" -gt 0 ] && exit 1
  exit 0
}

# node_log <node> -> path of the gateway's own log inside the container
node_log() { echo "/var/log/loxilb$(docker exec "$1" hostname 2>/dev/null).log"; }

# vip_state <node> -> "vip_on_lo=<0|1> listeners=<list or none>"
vip_state() {
  local n=$1 v l
  v=$($hexec "$n" ip -4 -o addr show dev lo 2>/dev/null | grep -c " $VIP/")
  l=$($hexec "$n" ss -Hltn 2>/dev/null | awk '{print $4}' | grep "^$VIP:" | LC_ALL=C sort | tr '\n' ' ')
  echo "vip_on_lo=$v listeners=${l:-none}"
}

# snapshot_readbacks <tag>: every configuration read-back from both nodes,
# raw and normalised, under $OUT/readback-<tag>/<node>/.
snapshot_readbacks() {
  local tag=$1 n d t
  for n in $NODES; do
    d="$OUT/readback-$tag/$n"; mkdir -p "$d"
    api_get "$n" /config/loadbalancer/all > "$d/loadbalancer.raw.json"
    python3 "$CFGDIR/readback_norm.py" loadbalancer < "$d/loadbalancer.raw.json" > "$d/loadbalancer.json" 2>"$d/loadbalancer.err"
    python3 "$CFGDIR/readback_norm.py" fc_effective < "$d/loadbalancer.raw.json" > "$d/fc_effective.json" 2>/dev/null
    api_get "$n" /config/ai/jwtauthprofile | python3 -m json.tool --sort-keys > "$d/jwtauthprofile.json" 2>&1
    api_get "$n" /config/ai/apikey > "$d/apikey.raw.json"
    python3 "$CFGDIR/readback_norm.py" apikey < "$d/apikey.raw.json" > "$d/apikey.json" 2>&1
    : > "$d/tenant-ratelimit.json"
    for t in $(sed -n 's/.*\/config\/ai\/tenant\/ratelimit\t.*"tenant_id":"\([^"]*\)".*/\1/p' "$CFGDIR/.cfg-list"); do
      echo "## $t" >> "$d/tenant-ratelimit.json"
      api_get "$n" "/config/ai/tenant/ratelimit/$t" | python3 -m json.tool --sort-keys >> "$d/tenant-ratelimit.json" 2>&1
    done
  done
}
# readbacks_equal <tag> -> prints the names that differ; returns 0 when none.
readbacks_equal() {
  local tag=$1 f bad=""
  for f in loadbalancer jwtauthprofile apikey tenant-ratelimit; do
    [ -s "$OUT/readback-$tag/llb1/$f.json" ] || { bad="$bad $f(empty)"; continue; }
    diff -u "$OUT/readback-$tag/llb1/$f.json" "$OUT/readback-$tag/llb2/$f.json" > "$OUT/readback-$tag/$f.diff" 2>&1 || bad="$bad $f"
  done
  echo "$bad"; [ -z "$bad" ]
}

# config.sh found the pair unusable and configured nothing.
if [ -f "${CFGDIR}/.unhealthy" ]; then
  cp "${CFGDIR}/.startup-times" "$OUT/startup-times.txt" 2>/dev/null
  for n in $NODES; do
    docker exec "$n" sh -c 'tail -n 200 /var/log/loxilb$(hostname).log' > "$OUT/$n-log-tail.txt" 2>&1
    echo "$n role=$(role "$n")" >> "$OUT/unhealthy-roles.txt"
  done
  for c in $ALL_CASES; do
    verdict "$c" NOT_RUN "config.sh: $(cat "${CFGDIR}/.unhealthy")"
  done
  finish
fi

##############################################################################
echo "Provenance"
##############################################################################
{
  echo "date=$(iso)"
  echo "host_kernel=$(uname -r)"
  echo "gateway_commit=${HAFO_GW_COMMIT:-$(git -C "$CFGDIR" rev-parse HEAD 2>/dev/null || echo unknown)}"
  echo "loxilb_ebpf_pin=${HAFO_EBPF_PIN:-$(git -C "$CFGDIR/../../loxilb-ebpf" rev-parse HEAD 2>/dev/null || echo unknown)}"
  for n in $NODES; do
    echo "$n.image=$(docker inspect -f '{{.Config.Image}}' "$n" 2>/dev/null)"
    echo "$n.image_id=$(docker inspect -f '{{.Image}}' "$n" 2>/dev/null)"
    p=$(loxilb_pid "$n")
    echo "$n.binary_sha256=$(sudo sha256sum "/proc/$p/exe" 2>/dev/null | cut -d' ' -f1)"
    echo "$n.build_identity=$(api_get "$n" /version | tr -d '\n')"
    echo "$n.cmdline=$(cat "$CFGDIR/.${n}-cmdline")"
  done
} > "$OUT/provenance.txt"
cat "$OUT/provenance.txt"
cp "$CFGDIR/.startup-times" "$OUT/startup-times.txt"

##############################################################################
echo; echo "Preconditions: both REST APIs answer, one MASTER and one BACKUP hold"
##############################################################################
PRE_OK=1
for n in $NODES; do
  ms=$(wait_api "$n" 30) || { PRE_OK=0; note "precondition: $n REST API did not answer within ${ms} ms"; }
done
if [ "$PRE_OK" = 1 ] && wait_roles 60 6; then
  note "precondition: roles held for 6 consecutive samples: master=$MASTER_NODE backup=$BACKUP_NODE (waited ${ROLE_WAIT_MS} ms)"
else
  PRE_OK=0
  note "precondition: roles did not converge: $ROLE_LAST"
fi
if [ "$PRE_OK" != 1 ]; then
  for n in $NODES; do
    docker exec "$n" sh -c 'tail -n 200 /var/log/loxilb$(hostname).log' > "$OUT/$n-log-tail.txt" 2>&1
  done
  for c in $ALL_CASES; do
    verdict "$c" NOT_RUN "the pair is not healthy ($ROLE_LAST); see notes.log and the log tails"
  done
  finish
fi

##############################################################################
if want FAILOVER-0; then
echo; echo "FAILOVER-0  Is the pair healthy before any fault?"
##############################################################################
r1=$(role llb1); r2=$(role llb2)
if { [ "$r1" = MASTER ] && [ "$r2" = BACKUP ]; } || { [ "$r1" = BACKUP ] && [ "$r2" = MASTER ]; }; then
  verdict FAILOVER-0.roles PASS "llb1=$r1 llb2=$r2"
else
  verdict FAILOVER-0.roles FAIL "llb1=$r1 llb2=$r2"
fi

# The service answers through the VIP, and the request reached a backend.
new_nonce
code=$(req $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)")
got=$(receipts "$LAST_NONCE")
if [ "$code" = 200 ] && [ "$got" = 1 ]; then
  verdict FAILOVER-0.vip-serves PASS "HTTP 200 through $VIP:$PORT_KEY, backend receipts=1"
else
  verdict FAILOVER-0.vip-serves FAIL "HTTP $code, backend receipts=$got (want 200 and 1)"
fi
new_nonce
code=$(req $PORT_KEY $MODEL_KEY "X-Api-Key: not-a-key")
got=$(receipts "$LAST_NONCE")
if [ "$code" = 401 ] && [ "$got" = 0 ]; then
  verdict FAILOVER-0.vip-refuses PASS "an unknown key is answered 401 with receipts=0 (the 200 above is not a gateway that admits everything)"
else
  verdict FAILOVER-0.vip-refuses FAIL "unknown key: HTTP $code, receipts=$got (want 401 and 0)"
fi

# A completed RateLimiterSync push, observed AFTER state exists to carry.
mark=$(metric "$MASTER_NODE" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
new_nonce; req $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" >/dev/null
adv=""
for _ in $(seq 1 50); do
  cur=$(metric "$MASTER_NODE" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  if [ "$mark" != unreadable ] && [ "$cur" != unreadable ] && awk "BEGIN{exit !($cur > $mark)}"; then adv=$cur; break; fi
  sleep 0.2
done
if [ -n "$adv" ]; then
  verdict FAILOVER-0.sync-push PASS "RateLimiterSync push count on $MASTER_NODE advanced $mark -> $adv after a charged request"
else
  verdict FAILOVER-0.sync-push FAIL "RateLimiterSync push count on $MASTER_NODE stayed at $mark for 10 s after a charged request"
fi

# Identical read-backs.
snapshot_readbacks fo0
if differ=$(readbacks_equal fo0); then
  verdict FAILOVER-0.readback PASS "rule, profile, key and limit read-backs are equal on both nodes (dropped fields: see readback_norm.py)"
else
  verdict FAILOVER-0.readback FAIL "read-backs differ:$differ (see readback-fo0/*.diff)"
fi
if diff -u "$OUT/readback-fo0/llb1/fc_effective.json" "$OUT/readback-fo0/llb2/fc_effective.json" > "$OUT/readback-fo0/fc_effective.diff" 2>&1; then
  verdict FAILOVER-0.fc-effective RECORDED "fc_effective is equal on both nodes"
else
  verdict FAILOVER-0.fc-effective RECORDED "fc_effective differs between MASTER and BACKUP ($(grep -c '^[-+] ' "$OUT/readback-fo0/fc_effective.diff") lines; readback-fo0/fc_effective.diff)"
fi

# Key store reachable and JWKS usable, on both nodes.
bad=""
kid=$(key_id fo-seed-key)
for n in $NODES; do
  rc=$($hexec "$n" curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:11111/netlox/v1/config/ai/apikey/$kid")
  co=$(metric "$n" loxilb_ai_key_store_circuit_open)
  ju=$(metric "$n" loxilb_ai_jwks_usable 'profile="kc"')
  echo "$n key_readback_http=$rc key_store_circuit_open=$co jwks_usable=$ju jwks_refresh_success=$(metric "$n" loxilb_ai_jwks_refresh_total 'outcome="success"')" | tee -a "$OUT/fo0-store-jwks.txt"
  [ "$rc" = 200 ] && [ "$co" = "0.000000" -o "$co" = 0 ] || bad="$bad $n:store(http=$rc,circuit=$co)"
  [ "$ju" = "1.000000" ] || bad="$bad $n:jwks_usable=$ju"
done
if [ -z "$bad" ]; then
  verdict FAILOVER-0.store-jwks PASS "both nodes read a key from the store and report a usable JWKS"
else
  verdict FAILOVER-0.store-jwks FAIL "$bad"
fi

# RECORDED observations.
for n in $NODES; do
  echo "$n role=$(role "$n") $(vip_state "$n")" | tee -a "$OUT/fo0-vip-state.txt"
done
forced=$(api "$BACKUP_NODE" POST /config/cistate '{"instance":"llb-inst0","state":"MASTER","vip":"0.0.0.0"}')
forced_code=$(printf '%s\n' "$forced" | sed -n 's/^http_code=//p')
if [[ "$forced_code" =~ ^[45][0-9][0-9]$ ]] &&
   [ "$(role "$BACKUP_NODE")" = BACKUP ] && [ "$(role "$MASTER_NODE")" = MASTER ]; then
  verdict FAILOVER-0.cistate-gate PASS "the BFD BACKUP refused a forced MASTER request and the incumbent stayed active"
else
  verdict FAILOVER-0.cistate-gate FAIL "HTTP ${forced_code:-none}; roles: $(role "$BACKUP_NODE") / $(role "$MASTER_NODE")"
fi

verdict FAILOVER-0.standby-listener RECORDED "$BACKUP_NODE (BACKUP): $(vip_state "$BACKUP_NODE"); $MASTER_NODE (MASTER): $(vip_state "$MASTER_NODE")"
for n in $NODES; do
  docker exec "$n" sh -c 'grep -h -E "Added BFD|using bfd bind|BFD State|HA stage=ka-gate|kept without a listener|ci-change instance" /var/log/loxilb$(hostname).log' 2>/dev/null | sed "s/^/$n: /"
done > "$OUT/fo0-ha-log-lines.txt"
for n in $NODES; do
  verdict "FAILOVER-0.bfd-line.$n" RECORDED "$(grep "^$n: .*Added BFD" "$OUT/fo0-ha-log-lines.txt" | tail -1 | sed 's/^[^:]*: //' | cut -c1-140)"
done
verdict FAILOVER-0.kept-rules RECORDED "'kept without a listener' lines: llb1=$(grep -c '^llb1: .*kept without' "$OUT/fo0-ha-log-lines.txt") llb2=$(grep -c '^llb2: .*kept without' "$OUT/fo0-ha-log-lines.txt")"
{
  echo "client neighbour table:"; $hexec $CLIENT ip neigh
  for n in $NODES; do echo "$n client-side MAC: $($hexec "$n" cat /sys/class/net/e${n}${SW_C}/address)"; done
} > "$OUT/fo0-neigh.txt"
vmac=$($hexec $CLIENT ip neigh show "$VIP" | awk '{print $5}')
mmac=$($hexec "$MASTER_NODE" cat "/sys/class/net/e${MASTER_NODE}${SW_C}/address")
verdict FAILOVER-0.client-neigh RECORDED "the client resolves $VIP to $vmac; the MASTER's ($MASTER_NODE) MAC is $mmac"
verdict FAILOVER-0.cold-open RECORDED "loxilb_ai_token_quota_cold_open_total at FAILOVER-0: llb1=$(metric llb1 loxilb_ai_token_quota_cold_open_total) llb2=$(metric llb2 loxilb_ai_token_quota_cold_open_total) (later readings are deltas from these)"
verdict FAILOVER-0.startup RECORDED "$(tr '\n' ' ' < "$OUT/startup-times.txt")"

# Where the state under test lives (bpffs sharing on a single host).
{
  for n in $NODES; do
    echo "## $n bpffs mount (device as the container sees it)"
    docker exec "$n" sh -c 'grep " - bpf " /proc/self/mountinfo'
    echo "## $n pinned maps: name -> kernel map id"
    docker exec "$n" sh -c 'for f in /opt/loxilb/dp/bpf/*; do echo "$(basename $f) $(bpftool map show pinned $f 2>/dev/null | head -1 | cut -d: -f1)"; done' | LC_ALL=C sort
    echo "## $n attached programs"
    docker exec "$n" bpftool net 2>/dev/null
  done
  echo "## host: programs attached to cgroups (a cgroup-attached socket program would be host-wide)"
  sudo bpftool cgroup tree 2>/dev/null | grep -v -E "cgroup_device|sd_fw_|sd_devices"
} > "$OUT/fo0-bpffs.txt" 2>&1
ids1=$(awk '/^## llb1 pinned/{f=1;next} /^## /{f=0} f&&$2{print $2}' "$OUT/fo0-bpffs.txt" | LC_ALL=C sort -u)
ids2=$(awk '/^## llb2 pinned/{f=1;next} /^## /{f=0} f&&$2{print $2}' "$OUT/fo0-bpffs.txt" | LC_ALL=C sort -u)
shared=$(LC_ALL=C comm -12 <(echo "$ids1") <(echo "$ids2") | grep -c .)
dev1=$(docker exec llb1 sh -c 'grep " - bpf " /proc/self/mountinfo' | awk '{print $3}' | tr '\n' ' ')
dev2=$(docker exec llb2 sh -c 'grep " - bpf " /proc/self/mountinfo' | awk '{print $3}' | tr '\n' ' ')
sockprogs=$(sudo bpftool cgroup tree 2>/dev/null | grep -c -E "sock_ops|cgroup_sock|connect4|sk_msg")
verdict FAILOVER-0.bpffs RECORDED "bpffs devices llb1=[$dev1] llb2=[$dev2]; pinned maps llb1=$(echo "$ids1" | grep -c .) llb2=$(echo "$ids2" | grep -c .), kernel map ids in common=$shared; cgroup-attached socket programs on the host=$sockprogs"
fi

##############################################################################
if want BED; then
echo; echo "BED   Harness checks: no automatic restart after a kill; a dead node returns"
##############################################################################
VICTIM=$BACKUP_NODE
before_start=$(docker inspect -f '{{.State.StartedAt}}' "$VICTIM")
t0=$(node_death "$VICTIM")
note "BED: node_death $VICTIM (BACKUP) at t0=$t0; watching 30 s for an automatic restart"
restarted=0
: > "$OUT/bed-restart-watch.txt"
for i in $(seq 1 60); do
  st=$(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}} started={{.State.StartedAt}}' "$VICTIM" 2>&1)
  echo "$(iso) $st survivor_role=$(role "$(other_node "$VICTIM")")" >> "$OUT/bed-restart-watch.txt"
  case "$st" in exited*) ;; *) restarted=1 ;; esac
  sleep 0.5
done
if [ "$restarted" = 0 ] && [ "$(docker inspect -f '{{.State.StartedAt}}' "$VICTIM")" = "$before_start" ]; then
  verdict BED-1 PASS "docker did not restart $VICTIM in 30 s after docker kill (restart policy unless-stopped); state: $(tail -1 "$OUT/bed-restart-watch.txt" | cut -d' ' -f2-)"
else
  verdict BED-1 FAIL "docker restarted $VICTIM by itself after docker kill; see bed-restart-watch.txt"
fi
echo "after the kill: $(other_node "$VICTIM") role=$(role "$(other_node "$VICTIM")") $(vip_state "$(other_node "$VICTIM")")" | tee -a "$OUT/bed-restart-watch.txt"

ret_t0=$(now_ms)
if ret=$(node_return "$VICTIM" 2>"$OUT/bed-node-return.err"); then
  pre_rules=$(api_get "$VICTIM" /config/loadbalancer/all | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('lbAttr') or []))" 2>/dev/null)
  pre_prof=$(api_get "$VICTIM" /config/ai/jwtauthprofile | grep -c '"name"')
  note "BED: $VICTIM returned ($ret); before re-applying the list it reads back rules=${pre_rules:-?} jwt-profiles=$pre_prof"
  if apply_cfg "$VICTIM" "" returning 2>>"$OUT/bed-node-return.err" && wait_roles 240 6; then
    note "BED: re-applied the list on $VICTIM: $APPLY_NEW writes created something, $APPLY_HELD were already held (409)"
    snapshot_readbacks bed
    differ=$(readbacks_equal bed) && same=equal || same="differ:$differ"
    verdict BED-2 PASS "$VICTIM returned after reboot emulation: $ret, roles held again after $(( $(now_ms) - ret_t0 )) ms (master=$MASTER_NODE backup=$BACKUP_NODE), read-backs $same"
    verdict BED-2.persisted-config RECORDED "before the harness re-applied the list the returned node read back rules=${pre_rules:-?} jwt-profiles=$pre_prof; of the list's writes $APPLY_NEW created something and $APPLY_HELD were already held"
    verdict BED-2.returned-listener RECORDED "$VICTIM role=$(role "$VICTIM") $(vip_state "$VICTIM")"
  else
    verdict BED-2 NOT_RUN "$VICTIM returned but the pair did not become healthy again ($ROLE_LAST); see bed-node-return.err"
  fi
else
  verdict BED-2 NOT_RUN "node_return $VICTIM failed: $(tr '\n' ' ' < "$OUT/bed-node-return.err" | cut -c1-200)"
fi
fi

if want FAILOVER-1; then . "$CFGDIR/cases/fo1.sh"; fi
if want FAILOVER-2-4; then . "$CFGDIR/cases/fo2-4.sh"; fi
if want FAILOVER-5-8; then . "$CFGDIR/cases/fo5-8.sh"; fi
if want FAILOVER-6-7; then . "$CFGDIR/cases/fo6-7.sh"; fi
if want FAILOVER-9; then . "$CFGDIR/cases/fo9.sh"; fi
if want FAILOVER-10; then . "$CFGDIR/cases/fo10.sh"; fi
if want FAILOVER-11; then F11_ID=FAILOVER-11; . "$CFGDIR/cases/fo11.sh"; fi
if want FAILOVER-11r; then F11_ID=FAILOVER-11r; . "$CFGDIR/cases/fo11.sh"; fi
# The two record-only cases go last: FAILOVER-13 changes a node's configuration.
if want FAILOVER-12 || want FAILOVER-13; then . "$CFGDIR/cases/fo12-13.sh"; fi
if want FAILOVER-FRONTEND; then . "$CFGDIR/cases/frontend.sh"; fi
wait_roles 60 6 || note "end of run: roles did not hold ($ROLE_LAST)"

finish
