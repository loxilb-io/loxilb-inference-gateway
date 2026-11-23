#!/bin/bash
# lib.sh — shared by config.sh, validation.sh and rmconfig.sh of
# ai-ha-failover-bfd. Source it AFTER ../common.sh.
#
# The request/receipt/metric helpers are copied from
# cicd/ai-qos-ha-sync/validation.sh (they live inside that script and cannot
# be sourced without running it). Keep the two in step by hand.

HAFO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------- the bed
CLIENT=hfc1
SW_C=hfsw1            # client-side L2 segment (a bridge in its own netns)
SW_B=hfsw2            # backend-side L2 segment
BACKENDS="hfe1 hfe2 hfe3 hfe4"
NODES="llb1 llb2"
PG_NAME=pg-ha-fo
KC_NAME=kc-ha-fo

VIP=10.10.10.254
CLIENT_IP=10.10.10.1
PORT_KEY=2020         # api_key_auth: required
PORT_JWT=2021         # jwt_auth_profile
PORT_FC=2022          # flow control, enforce
PORT_WIT=2023         # api_key_auth: required, served by the witness backend
PORT_AFF=2024         # conversation affinity (session_header_name)
NPORTS=5
WITNESS_HOST=hfe1     # hafo_backend.py: paced streams, held requests, in-flight count
WITNESS_PORT=8081
MODEL_KEY=ha-fo-key
MODEL_JWT=llama-70b   # the realm's role is model:llama-70b
MODEL_FC=ha-fo-fc
MODEL_AFF=ha-fo-aff
MODEL_WIT=ha-fo-wit

node_cip() { [ "$1" = llb1 ] && echo 10.10.10.11 || echo 10.10.10.12; }
node_bip() { [ "$1" = llb1 ] && echo 31.31.31.11 || echo 31.31.31.12; }
be_ip()    { echo "31.31.31.${1#hfe}"; }
other_node() { [ "$1" = llb1 ] && echo llb2 || echo llb1; }

now_ms() { date +%s%3N; }
iso()    { date -u +%FT%T.%3NZ; }

# ---------------------------------------------------------------- verdicts
# A case ends as PASS, FAIL, RECORDED (a measurement with no threshold) or
# NOT_RUN (the check could not run). Nothing here ever turns one into another.
OUT=${HAFO_OUT:-}
verdict() { # <case> <PASS|FAIL|RECORDED|NOT_RUN> <text>
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$OUT/verdicts.tsv"
  printf '  [%s] %s — %s\n' "$2" "$1" "$3"
}
note() { printf '%s %s\n' "$(iso)" "$*" | tee -a "$OUT/notes.log"; }

# ---------------------------------------------------------------- node API
# api <node> <method> <path> [json] -> body, then a last line http_code=NNN
api() {
  local n=$1 m=$2 p=$3 b=${4:-}
  if [ -n "$b" ]; then
    $hexec "$n" curl -s -m 8 -w '\nhttp_code=%{http_code}' -X "$m" \
      "http://127.0.0.1:11111/netlox/v1$p" -H 'Content-Type: application/json' -d "$b" 2>/dev/null
  else
    $hexec "$n" curl -s -m 8 -w '\nhttp_code=%{http_code}' -X "$m" \
      "http://127.0.0.1:11111/netlox/v1$p" 2>/dev/null
  fi
}
api_get() { $hexec "$1" curl -s -m 8 "http://127.0.0.1:11111/netlox/v1$2" 2>/dev/null; }

# role <node> -> MASTER | BACKUP | NOT_DEFINED | ... | UNREACHABLE
role() {
  local out
  out=$($hexec "$1" curl -s -m 1 "http://127.0.0.1:11111/netlox/v1/config/cistate/all" 2>/dev/null)
  out=$(printf '%s' "$out" | sed -n 's/.*"state":[ ]*"\([A-Z_]*\)".*/\1/p')
  echo "${out:-UNREACHABLE}"
}

# wait_api <node> <timeout-s> -> prints ms until the REST API answered and
# the boot-config freeze lifted; returns 1 on timeout. No fixed sleep.
wait_api() {
  local n=$1 max=$2 t0 rc
  t0=$(now_ms)
  while :; do
    rc=$($hexec "$n" curl -s -m 2 -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
    if [ "$rc" = 200 ]; then
      # The listener answers before the boot config replay settles; until
      # then every mutation is refused. An empty body can never apply.
      if ! $hexec "$n" curl -s -m 3 -X POST "http://127.0.0.1:11111/netlox/v1/config/loadbalancer" \
            -H 'Content-Type: application/json' -d '{}' 2>/dev/null |
           grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
        echo $(( $(now_ms) - t0 )); return 0
      fi
    fi
    [ $(( $(now_ms) - t0 )) -ge $(( max * 1000 )) ] && { echo $(( $(now_ms) - t0 )); return 1; }
    sleep 0.2
  done
}

# wait_roles <timeout-s> [stable-samples] -> sets MASTER_NODE / BACKUP_NODE and
# ROLE_WAIT_MS. Requires exactly one MASTER and one BACKUP for N consecutive
# samples 0.5 s apart. Returns 1 on timeout with the last pair in ROLE_LAST.
wait_roles() {
  local max=$1 need=${2:-6} t0 r1 r2 streak=0
  t0=$(now_ms); MASTER_NODE=""; BACKUP_NODE=""
  while :; do
    r1=$(role llb1); r2=$(role llb2); ROLE_LAST="llb1=$r1 llb2=$r2"
    if { [ "$r1" = MASTER ] && [ "$r2" = BACKUP ]; } || { [ "$r1" = BACKUP ] && [ "$r2" = MASTER ]; }; then
      streak=$((streak + 1))
      if [ "$streak" -ge "$need" ]; then
        [ "$r1" = MASTER ] && { MASTER_NODE=llb1; BACKUP_NODE=llb2; } || { MASTER_NODE=llb2; BACKUP_NODE=llb1; }
        ROLE_WAIT_MS=$(( $(now_ms) - t0 )); return 0
      fi
    else
      streak=0
    fi
    [ $(( $(now_ms) - t0 )) -ge $(( max * 1000 )) ] && { ROLE_WAIT_MS=$(( $(now_ms) - t0 )); return 1; }
    sleep 0.5
  done
}

# metric <node> <family> [label-substring] — summed value, "0" when the family
# is absent, "unreadable" when the scrape itself returned nothing.
metric() {
  local node=$1 fam=$2 lab=${3:-} page
  page=$($hexec "$node" curl -s --max-time 8 "http://127.0.0.1:11111/netlox/v1/metrics" 2>/dev/null)
  [ -z "$page" ] && { echo unreadable; return; }
  printf '%s\n' "$page" | awk -v fam="$fam" -v lab="$lab" '
    $0 ~ "^" fam "([{ ]|$)" {
      if (lab != "" && index($0, lab) == 0) next
      v = $NF; if (v + 0 == v) { s += v; n++ }
    }
    END { if (n > 0) printf "%.6f\n", s; else print "0" }'
}

# ---------------------------------------------------------------- wiring
# node_wire <node>: the node's two links, their bridge ports and addresses.
node_wire() {
  local n=$1 sw i
  # A namespace that just lost its last process is freed by the kernel a
  # moment later, and until then its veth peers still sit on the bridges.
  # Wait for them to go; a port that outlives 5 s is removed here (re-cabling
  # a returning node, never part of a failover).
  for sw in $SW_C $SW_B; do
    for i in $(seq 1 50); do
      sudo ip -n "$sw" link show "e${sw}${n}" >/dev/null 2>&1 || break
      sleep 0.1
      [ "$i" = 50 ] && sudo ip -n "$sw" link del "e${sw}${n}" >/dev/null 2>&1
    done
  done
  connect_docker_hosts "$n" $SW_C
  connect_docker_hosts "$n" $SW_B
  sudo ip -n $SW_C link set "e${SW_C}${n}" master br0
  sudo ip -n $SW_B link set "e${SW_B}${n}" master br0
  sudo ip -n "$n" addr add "$(node_cip "$n")/24" dev "e${n}${SW_C}"
  sudo ip -n "$n" addr add "$(node_bip "$n")/24" dev "e${n}${SW_B}"
}

# node_links <node> -> every non-loopback link in the node's namespace
node_links() { sudo ip -n "$1" -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$'; }

# loxilb_pid <node> -> host pid of the gateway process in that namespace
loxilb_pid() {
  local p
  for p in $(sudo ip netns pids "$1" 2>/dev/null); do
    [ "$(cat /proc/$p/comm 2>/dev/null)" = loxilb ] && { echo "$p"; return; }
  done
}

# node_death <node>: emulates a node that loses power.
#   1. every link in the node's namespace goes down (t0, printed in ms)
#   2. the container is killed with SIGKILL
# The order matters on this bed: the harness bind-mounts the namespace, so it
# outlives the container with its addresses up, and a kernel left like that
# keeps answering ARP for the VIP and resetting connections. Acts on the dead
# node only.
node_death() {
  local n=$1 l batch t0
  batch=$(for l in $(node_links "$n"); do echo "link set dev $l down"; done)
  t0=$(now_ms)
  printf '%s\n' "$batch" | sudo ip -n "$n" -batch - 2>/dev/null
  docker kill "$n" >/dev/null 2>&1
  echo "$t0"
}

# Docker can swap the dynamic peer IPs if both default-bridge endpoints
# start concurrently. Allocate in setup order before launching the gateways.
node_start_pair() {
  local n
  for n in $NODES; do
    docker start "$n" >/dev/null || return 1
  done
}

# node_return <node>: emulates the reboot of a dead node, then starts the
# gateway with the flags it had and re-applies the configuration list.
# What is cleared before the gateway starts: the whole old network namespace
# (every address including a VIP left on lo, every neighbour entry, every
# route, both veths and their bridge ports) and, because the container's
# processes are gone, the node's bpffs mount and everything pinned in it.
# What is kept: the container's filesystem (logs, /etc/loxilb, audit trail),
# as a disk survives a reboot. Prints "api_ms=<n>".
node_return() {
  local n=$1 pid ip want cmd ms
  if [ -e "/var/run/netns/$n" ]; then
    sudo ip netns del "$n" >/dev/null 2>&1 || true
    sudo rm -f "/var/run/netns/$n" >/dev/null 2>&1
  fi
  docker start "$n" >/dev/null 2>&1 || { echo "node_return: docker start $n failed" >&2; return 1; }
  pid=$(docker inspect -f '{{.State.Pid}}' "$n")
  sudo touch "/var/run/netns/$n"
  sudo mount -o bind "/proc/$pid/ns/net" "/var/run/netns/$n"
  # The same per-namespace settings spawn_docker_host applies.
  $hexec "$n" ip link set lo up
  $hexec "$n" sysctl net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
  $hexec "$n" sysctl net.ipv4.conf.eth0.arp_ignore=2 >/dev/null 2>&1
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$n")
  want=$(cat "$HAFO_DIR/.${n}-bridge-ip")
  if [ "$ip" != "$want" ]; then
    echo "node_return: $n came back on $ip, cluster flags name $want" >&2; return 1
  fi
  node_wire "$n"
  # A case may start an observer in the new namespace before the gateway runs.
  [ -n "${NODE_RETURN_HOOK:-}" ] && "$NODE_RETURN_HOOK" "$n"
  cmd=$(cat "$HAFO_DIR/.${n}-cmdline")
  docker exec -d "$n" bash -c "$cmd >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  ms=$(wait_api "$n" 120) || { echo "node_return: $n REST API not ready after ${ms} ms" >&2; return 1; }
  echo "api_ms=$ms"
}

# apply_cfg <node> [list-file] [returning]: every write in the configuration
# list, in order. Returns 1 on the first write that is not answered 2xx.
# With "returning", a 409 is counted instead of failing: the gateway restores
# its own saved configuration at start, so a returning node already holds
# what the list would create. APPLY_NEW / APPLY_HELD carry the two counts,
# and the caller still compares the read-backs afterwards.
apply_cfg() {
  local n=$1 list=${2:-$HAFO_DIR/.cfg-list} mode=${3:-} m p b resp code
  APPLY_NEW=0; APPLY_HELD=0
  while IFS=$'\t' read -r m p b; do
    [ -z "$m" ] && continue
    resp=$(api "$n" "$m" "$p" "$b")
    code=$(printf '%s\n' "$resp" | sed -n 's/^http_code=//p')
    case "$code" in
      2*) APPLY_NEW=$((APPLY_NEW + 1)) ;;
      409) if [ "$mode" = returning ]; then APPLY_HELD=$((APPLY_HELD + 1)); else
             echo "apply_cfg: $n $m $p -> 409: $(printf '%s' "$resp" | head -c 300)" >&2; return 1; fi ;;
      *) echo "apply_cfg: $n $m $p -> ${code:-none}: $(printf '%s' "$resp" | head -c 300)" >&2; return 1 ;;
    esac
  done < "$list"
}

# ---------------------------------------------------------------- client
key_raw() { awk -F: -v n="$1" '$1==n{print $3}' "$HAFO_DIR/.keys"; }
key_id()  { awk -F: -v n="$1" '$1==n{print $2}' "$HAFO_DIR/.keys"; }

NONCE_FILE=""
LAST_NONCE=""
nonce_init() { NONCE_FILE=$(mktemp -t hafo-nonce.XXXXXX); echo 0 > "$NONCE_FILE"; }
new_nonce() {
  local n; n=$(( $(cat "$NONCE_FILE") + 1 )); echo "$n" > "$NONCE_FILE"
  LAST_NONCE="hafo-$$-$n"
}

# req <port> <model> <header|-> [extra curl args...] -> HTTP status.
# The client only ever addresses the VIP.
req() {
  local port=$1 model=$2 hdr=$3; shift 3
  local auth=()
  [ -z "$LAST_NONCE" ] && { echo 000; return; }
  [ "$hdr" != "-" ] && auth=(-H "$hdr")
  $hexec $CLIENT curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 10 -X POST \
    -H 'Content-Type: application/json' -H "X-Test-Nonce: $LAST_NONCE" "${auth[@]}" "$@" \
    --data '{"model":"'"$model"'","messages":[{"role":"user","content":"hi"}]}' \
    "http://$VIP:$port/v1/chat/completions" 2>/dev/null
}

# receipts <nonce> — how many requests carrying this nonce reached ANY
# backend, read inside each backend's namespace, never through a gateway.
receipts() {
  local b out sum=0
  for b in $BACKENDS; do
    out=$($hexec "$b" curl -s --max-time 5 "http://127.0.0.1:8080/__receipts/$1" 2>/dev/null)
    case "$out" in ''|*[!0-9]*) echo unreadable; return ;; esac
    sum=$((sum + out))
  done
  out=$($hexec $WITNESS_HOST curl -s --max-time 5 "http://127.0.0.1:$WITNESS_PORT/__receipts/$1" 2>/dev/null)
  case "$out" in ''|*[!0-9]*) echo unreadable; return ;; esac
  echo $((sum + out))
}
# witness_state -> the witness backend's own view, one JSON object
witness_state() { $hexec $WITNESS_HOST curl -s --max-time 5 "http://127.0.0.1:$WITNESS_PORT/__state" 2>/dev/null; }
witness_reset_peak() { $hexec $WITNESS_HOST curl -s --max-time 5 -X POST "http://127.0.0.1:$WITNESS_PORT/__reset-peak" >/dev/null 2>&1; }

# fc_effective_of <node> -> the fc_effective object of the flow-control rule
# as that node reads it back: JSON, null, no-rule or unreadable.
fc_effective_of() {
  api_get "$1" /config/loadbalancer/all | python3 -c "
import json, sys
try:
    rules = json.load(sys.stdin).get('lbAttr') or []
except ValueError:
    print('unreadable'); sys.exit()
for r in rules:
    a = r.get('serviceArguments', {})
    if a.get('port') == $PORT_FC:
        print(json.dumps(a.get('fc_effective'), sort_keys=True)); break
else:
    print('no-rule')"
}
# fc_configured <node> -> fc_max_outstanding of the flow-control rule as read back
fc_configured() {
  api_get "$1" /config/loadbalancer/all | python3 -c "
import json, sys
try:
    rules = json.load(sys.stdin).get('lbAttr') or []
except ValueError:
    print('unreadable'); sys.exit()
print(next((r['serviceArguments'].get('fc_max_outstanding') for r in rules if r.get('serviceArguments', {}).get('port') == $PORT_FC), 'no-rule'))"
}
# lb_delete <node> <port> <model> -> HTTP status of the delete. A rule that
# names a model is only deleted by the path that names it too; the short path
# answers 404 and leaves the rule serving. rule_present re-reads the list.
lb_delete() {
  $hexec "$1" curl -s -m 8 -o /dev/null -w '%{http_code}' -X DELETE \
    "http://127.0.0.1:11111/netlox/v1/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$2/protocol/tcp?path_prefix=%2F&path_match_mode=prefix&model_name=$3" 2>/dev/null
}
rule_present() { # <node> <port> -> 0 when the node reads the rule back
  api_get "$1" /config/loadbalancer/all | grep -q "\"port\":[ ]*$2[,}]"
}

# mint_key_now <node> <name> <tenant> -> "<key id> <raw key>", minted through
# that node's API into the shared store.
mint_key_now() {
  $hexec "$1" curl -s -m 5 -X POST http://127.0.0.1:11111/netlox/v1/config/ai/apikey \
    -H 'Content-Type: application/json' -d '{"tenant_id":"'"$3"'","name":"'"$2"'","tokens_per_min":0}' |
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key_id',''), d.get('raw_key',''))" 2>/dev/null
}

# ---------------------------------------------------------------- monitors
MON=hfmon             # observer on the client segment (ARP only)
MON_IP=10.10.10.2
PROBE_RATE=${HAFO_PROBE_RATE:-20}        # requests per second, open loop
PROBE_CONNECT_TIMEOUT=0.3                # seconds
PROBE_TIMEOUT=2.0                        # seconds, whole request
SAMPLE_INTERVAL=0.025                    # seconds, per-node sampler
node_mac() { $hexec "$1" cat "/sys/class/net/e${1}${SW_C}/address" 2>/dev/null; }
node_eth0() { cat "$HAFO_DIR/.${1}-bridge-ip"; }

# monitors_start <dir> [pidfile-node pid]: probe, both node samplers, the
# client's neighbour entry, the ARP observer and a BFD capture, all writing
# into <dir>. Everything here only reads.
monitors_start() {
  local d=$1 n
  mkdir -p "$d"; rm -f "$d"/*.stop
  for n in $NODES; do
    sudo ip netns exec "$n" python3 "$HAFO_DIR/hafo_tools.py" node --vip $VIP \
      --interval $SAMPLE_INTERVAL --pidfile "$d/pid-$n" --out "$d/node-$n.jsonl" >/dev/null 2>&1 &
  done
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" neigh --vip $VIP --out "$d/neigh.jsonl" >/dev/null 2>&1 &
  sudo ip netns exec $MON python3 "$HAFO_DIR/hafo_tools.py" arp --vip $VIP --src $MON_IP \
    --iface "e${MON}${SW_C}" --out "$d/arp.jsonl" >/dev/null 2>&1 &
  sudo tcpdump -i docker0 -nn -tt -l udp port 3784 > "$d/bfd.txt" 2>/dev/null &
  echo $! > "$d/tcpdump.pid"
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" probe --vip $VIP --port $PORT_KEY \
    --model $MODEL_KEY --header "X-Api-Key: $(key_raw fo-probe-key)" --rate $PROBE_RATE \
    --connect-timeout $PROBE_CONNECT_TIMEOUT --timeout $PROBE_TIMEOUT --tag "$(basename "$d")" \
    --out "$d/probe.jsonl" >/dev/null 2>&1 &
}
monitors_stop() {
  local d=$1 f
  for f in probe node-llb1 node-llb2 neigh arp; do sudo touch "$d/$f.jsonl.stop"; done
  sleep $(awk "BEGIN{print $PROBE_TIMEOUT + $PROBE_CONNECT_TIMEOUT + 0.5}")
  sudo kill "$(cat "$d/tcpdump.pid" 2>/dev/null)" 2>/dev/null
  sudo pkill -x tcpdump -P "$(cat "$d/tcpdump.pid" 2>/dev/null)" 2>/dev/null
  wait 2>/dev/null
  sudo rm -f "$d"/*.stop "$d/tcpdump.pid"
  sudo chown -R "$(id -u):$(id -g)" "$d" 2>/dev/null
}

# probe_control <dir> [max-s]: the control before a fault. Returns 0 once the
# probe has answered 200 for 3 s without exception, 1 if that does not happen
# within max-s (default 30). The requirement is never relaxed; what changes
# is that the wait is measured. PROBE_SETTLE_MS is how long it took, and
# PROBE_PRE_HIST what the probe got that was not a 200 on the way (a pair
# whose roles hold can still be refusing: see the README, "Before a fault").
probe_control() {
  local d=$1 max=${2:-30} t0 ok=1
  t0=$(now_ms)
  sleep 3.5
  while ! probe_tail_ok "$d" 3; do
    [ $(( $(now_ms) - t0 )) -ge $(( max * 1000 )) ] && { ok=0; break; }
    sleep 0.5
  done
  PROBE_SETTLE_MS=$(( $(now_ms) - t0 ))
  PROBE_PRE_HIST=$(python3 - "$d/probe.jsonl" <<'PY2'
import json, sys
h = {}
try:
    for ln in open(sys.argv[1]):
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r["cls"] != "ok":
            lab = r["cls"] if r["cls"] != "refusal" else "refusal:%s:%s" % (r.get("status"), r.get("error", ""))
            h[lab] = h.get(lab, 0) + 1
except OSError:
    pass
print(", ".join("%s=%d" % kv for kv in sorted(h.items())))
PY2
)
  [ "$ok" = 1 ]
}

# probe_wait_settled <dir> <t0> <max-s>: until the probe has answered 200 for
# 3 s, or the bound passes.
probe_wait_settled() {
  sleep 3
  while [ $(( $(now_ms) - $2 )) -lt $(( $3 * 1000 )) ]; do
    probe_tail_ok "$1" 3 && return 0
    sleep 0.5
  done
  return 1
}

# probe_tail_ok <dir> <seconds>: 0 when every probe sent in the last N seconds
# that has finished answered 200, and there are some.
probe_tail_ok() {
  python3 - "$1/probe.jsonl" "$2" <<'PY'
import json, sys, time
rows = []
try:
    for ln in open(sys.argv[1]):
        try: rows.append(json.loads(ln))
        except ValueError: pass
except OSError:
    sys.exit(1)
lo = time.time() * 1000 - float(sys.argv[2]) * 1000
tail = [r for r in rows if r["t_send"] >= lo]
sys.exit(0 if len(tail) >= 5 and all(r["cls"] == "ok" for r in tail) else 1)
PY
}

# ----------------------------------------------------------- frontend health
frontend_vip() {
  $hexec "$1" ip -o -4 addr show | grep -q " $VIP/"
}

frontend_bfd_up() {
  api_get "$1" /config/bfd/all | grep -q '"BFDUp"'
}

frontend_owned() {
  local m=$1 b=$2
  [ "$(role "$m")" = MASTER ] && [ "$(role "$b")" = BACKUP ] &&
    frontend_vip "$m" && ! frontend_vip "$b"
}

frontend_wait() {
  local duration=$1 deadline
  shift
  deadline=$(( $(now_ms) + duration ))
  while [ "$(now_ms)" -lt "$deadline" ]; do
    "$@" && return 0
    sleep 0.1
  done
  return 1
}

frontend_no_owner() {
  local n
  for n in $NODES; do
    [ "$(role "$n")" = BACKUP ] && ! frontend_vip "$n" || return 1
  done
}

frontend_start_pair() {
  local dir=$1 n m b p1 p2 rc1=0 rc2=0
  for n in $NODES; do
    cp "$HAFO_DIR/.${n}-cmdline" "$dir/$n-command"
    printf '%s --ha-frontend-interface=e%s%s\n' "$(cat "$dir/$n-command")" "$n" "$SW_C" > "$HAFO_DIR/.${n}-cmdline"
    node_death "$n" >/dev/null
  done
  if ! node_start_pair > "$dir/pair-start.log" 2>&1; then
    return 1
  fi
  read -r m b <<< "$NODES"
  node_return "$m" > "$dir/$m-start.log" 2>&1 & pid1=$!
  node_return "$b" > "$dir/$b-start.log" 2>&1 & pid2=$!
  wait "$pid1" || rc1=$?
  wait "$pid2" || rc2=$?
  if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ] || ! apply_cfg "$m" "" returning ||
     ! apply_cfg "$b" "" returning || ! wait_roles 100 6 ||
     ! frontend_wait 10000 frontend_owned "$MASTER_NODE" "$BACKUP_NODE"; then
    return 1
  fi
}

# ---------------------------------------------------------------- failover
# The state cases share one shape: build state through the VIP, prove the
# sync channel carried something, take the MASTER away, ask again through
# the VIP, bring the node back.
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1" 2>/dev/null; }

# vretry <port> <model> <header> <max-s> <tag> -> one JSON object: the same
# request retried every 0.2 s from the client until it answers 200.
vretry() { # <port> <model> <header> <max-s> <tag> [interval-s]
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" retry --vip $VIP --port "$1" \
    --model "$2" --header "$3" --max "$4" --tag "$5-$$" --interval "${6:-0.2}"
}
# vconv <port> <model> <prefix> [n] -> {conversation id: backend label}
vconv() {
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" conv --vip $VIP --port "$1" \
    --model "$2" --prefix "$3" --n "${4:-100}"
}
# conv_share <before.json> <after.json> -> "<same> <total> <share> <distinct-backends-before>"
conv_share() {
  python3 - "$1" "$2" <<'PY'
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
same = sum(1 for k, v in a.items() if not v.startswith("!") and b.get(k) == v)
print(same, len(a), "%.2f" % (same / max(len(a), 1)), len(set(v for v in a.values() if not v.startswith("!"))))
PY
}

# xsync_cut / xsync_restore: drop the sync channel (TCP 22222/22223) between
# the two nodes, both directions, on both nodes. xsync_dropped prints how
# many packets the rules dropped, so a cut that intercepted nothing shows.
XSYNC_CHAIN=HAFAILOVER-XSYNC
xsync_cut() {
  local n peer p
  for n in $NODES; do
    peer=$(node_eth0 "$(other_node "$n")")
    $hexec "$n" iptables -N $XSYNC_CHAIN >/dev/null 2>&1
    $hexec "$n" iptables -F $XSYNC_CHAIN >/dev/null 2>&1
    for p in 22222 22223; do
      $hexec "$n" iptables -A $XSYNC_CHAIN -p tcp -s "$peer" --dport $p -j DROP
      $hexec "$n" iptables -A $XSYNC_CHAIN -p tcp -d "$peer" --dport $p -j DROP
      $hexec "$n" iptables -A $XSYNC_CHAIN -p tcp -s "$peer" --sport $p -j DROP
      $hexec "$n" iptables -A $XSYNC_CHAIN -p tcp -d "$peer" --sport $p -j DROP
    done
    $hexec "$n" iptables -I INPUT 1 -j $XSYNC_CHAIN
    $hexec "$n" iptables -I OUTPUT 1 -j $XSYNC_CHAIN
  done
}
xsync_dropped() {
  local n t=0 d
  for n in $NODES; do
    d=$($hexec "$n" iptables -L $XSYNC_CHAIN -v -n -x 2>/dev/null | awk '$3=="DROP"{s+=$1} END{print s+0}')
    t=$((t + d))
  done
  echo "$t"
}
xsync_restore() {
  local n
  for n in $NODES; do
    $hexec "$n" iptables -D INPUT -j $XSYNC_CHAIN >/dev/null 2>&1
    $hexec "$n" iptables -D OUTPUT -j $XSYNC_CHAIN >/dev/null 2>&1
    $hexec "$n" iptables -F $XSYNC_CHAIN >/dev/null 2>&1
    $hexec "$n" iptables -X $XSYNC_CHAIN >/dev/null 2>&1
  done
}
# vreq <port> <model> <header> <tag> [more headers...]: one request. Sets
# VREQ_OUT ("status error-code"), VREQ_NONCE (for its receipt) and VREQ_JSON.
# It prints nothing: called inside $( ) the three would be lost.
vreq() {
  local out port=$1 model=$2 tag=$4 h hs=(--header "$3")
  shift 4
  for h in "$@"; do hs+=(--header "$h"); done
  VREQ_NONCE="$tag-$$-$(now_ms)"
  out=$(sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" retry --vip $VIP --port "$port" \
    --model "$model" "${hs[@]}" --max 0 --timeout "${VREQ_TIMEOUT:-5}" --tag "$VREQ_NONCE")
  VREQ_NONCE="$VREQ_NONCE-0"
  VREQ_JSON=$out
  VREQ_OUT="$(echo "$out" | jget "d['first_attempt'].get('status', d['first_attempt']['cls'])") $(echo "$out" | jget "d['first_attempt'].get('error','')")"
  VREQ_OUT=${VREQ_OUT% }
}

# ---- quota debt
# A debt tenant has a bound of 10 tokens/min. debt_spend sends one request
# whose answer reports 60 tokens (the witness backend), then asks again.
# Sets DEBT_A1, DEBT_A2 ("status code"), DEBT_G2 (receipts of the second ask)
# and DEBT_HORIZON: the epoch ms before which, by the Retry-After of that
# refusal, no request of the tenant can be admitted. 0 when none was sent.
DEBT_TOKENS=60
debt_spend() { # <raw key> <tag>
  local ra t
  vreq $PORT_WIT $MODEL_WIT "X-Api-Key: $1" "$2-spend" "X-Test-Usage-Tokens: $DEBT_TOKENS"; DEBT_A1=$VREQ_OUT
  sleep 0.3
  vreq $PORT_WIT $MODEL_WIT "X-Api-Key: $1" "$2-refused" "X-Test-Usage-Tokens: $DEBT_TOKENS"; DEBT_A2=$VREQ_OUT
  DEBT_G2=$(receipts "$VREQ_NONCE")
  ra=$(echo "$VREQ_JSON" | jget "d['first_attempt'].get('retry_after','')")
  t=$(echo "$VREQ_JSON" | jget "d['first_attempt']['t_send']")
  DEBT_RETRY_AFTER=$ra; DEBT_HORIZON=0
  case "$ra" in ''|*[!0-9]*) ;; *) DEBT_HORIZON=$(( t + ra * 1000 )) ;; esac
}
# debt_refresh <raw key> <tag>: asks once more so DEBT_HORIZON comes from a
# refusal that is recent. If the tenant is admitted instead (the debt had
# drained), that answer is a new 60-token debt and the next ask is refused.
# Sets DEBT_REFRESH to what was seen.
debt_refresh() {
  local a ra t k
  DEBT_REFRESH=""
  for k in 1 2 3; do
    vreq $PORT_WIT $MODEL_WIT "X-Api-Key: $1" "$2-refresh$k" "X-Test-Usage-Tokens: $DEBT_TOKENS"; a=$VREQ_OUT
    DEBT_REFRESH="${DEBT_REFRESH}[$a]"
    ra=$(echo "$VREQ_JSON" | jget "d['first_attempt'].get('retry_after','')")
    t=$(echo "$VREQ_JSON" | jget "d['first_attempt']['t_send']")
    if [ "${a%% *}" = 429 ]; then
      case "$ra" in ''|*[!0-9]*) return 1 ;; *) DEBT_HORIZON=$(( t + ra * 1000 )); DEBT_RETRY_AFTER=$ra; return 0 ;; esac
    fi
    sleep 0.3
  done
  return 1
}
# debt_watch <raw key> <seconds> <tag> <out.jsonl> <horizon> <mark-ms> [interval]
# -> one JSON object (see hafo_tools.py debtwatch).
debt_watch() {
  sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" debtwatch --vip $VIP --port $PORT_WIT \
    --model $MODEL_WIT --header "X-Api-Key: $1" --header "X-Test-Usage-Tokens: $DEBT_TOKENS" \
    --max "$2" --tag "$3-$$" --out "$4" --horizon "$5" --mark "$6" --interval "${7:-0.5}"
}
# debt_receipts <debtwatch json> -> "<refused attempts that reached a backend> <admitted attempts>"
debt_receipts() {
  local n leak=0 ok=0 g
  for n in $(echo "$1" | jget "' '.join(d['not_ok_nonces'])"); do
    g=$(receipts "$n"); [ "$g" = 0 ] || leak=$((leak + 1))
  done
  ok=$(echo "$1" | jget "len(d['ok_nonces'])")
  echo "$leak $ok"
}

# fo_begin: roles must hold; sets M (MASTER) and S (BACKUP).
fo_begin() { wait_roles 240 6 || return 1; M=$MASTER_NODE; S=$BACKUP_NODE; }

# Sync liveness (guard 3): the push count on the MASTER must advance after
# the state exists and BEFORE the fault; after a kill it cannot.
sync_mark() { SYNC_MARK=$(metric "$M" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"'); }
sync_advanced() {
  local cur i
  for i in $(seq 1 25); do
    cur=$(metric "$M" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
    if [ "$SYNC_MARK" != unreadable ] && [ "$cur" != unreadable ] && awk "BEGIN{exit !($cur > $SYNC_MARK)}"; then
      SYNC_NOW=$cur; return 0
    fi
    sleep 0.2
  done
  SYNC_NOW=$cur; return 1
}

# fo_fault: node death of M. Sets T0, and LISTEN_MS when the survivor holds a
# listener on the key rule's port (read from its namespace, no API call).
fo_fault() {
  T0=$(node_death "$M"); LISTEN_MS=""
  while [ $(( $(now_ms) - T0 )) -lt 60000 ]; do
    if $hexec "$S" ss -Hltn 2>/dev/null | awk '{print $4}' | grep -q "^$VIP:$PORT_KEY\$"; then
      LISTEN_MS=$(( $(now_ms) - T0 )); return 0
    fi
    sleep 0.1
  done
  return 1
}

# fo_restore: the dead node returns (reboot emulation) and the list is
# re-applied; the 409 count stays in the output.
fo_restore() {
  local ret
  if ret=$(node_return "$M" 2>>"$OUT/restore.err") && apply_cfg "$M" "" returning 2>>"$OUT/restore.err"; then
    note "restore: $M returned ($ret); list re-applied: created=$APPLY_NEW already-held(409)=$APPLY_HELD"
  else
    note "restore: $M did not return cleanly: $(tail -2 "$OUT/restore.err" | tr '\n' ' ' | cut -c1-200)"
    return 1
  fi
}

# kc_mint <client> <user> <password> -> access token, minted by the harness
# from the host. The client namespace has no route to the IdP.
kc_mint() {
  curl -s --max-time 10 -X POST -d "client_id=$1" -d "username=$2" -d "password=$3" \
    -d "grant_type=password" "$KC_ISSUER/protocol/openid-connect/token" |
    python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}
