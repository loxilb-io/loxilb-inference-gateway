#!/bin/bash
#
# sockmap_common.sh - shared helpers used only by the sockmap-fullproxy tests.
# The existing cicd/common.sh is left untouched.
#
# Depends on cicd/common.sh already being sourced, so $dexec, $hexec and friends exist.

SOCKMAP_ARTIFACTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/artifacts"

# Map names as truncated by the BPF object name limit (16 minus the null byte).
SOCKMAP_VIP_NAME="sockmap_vip_por"
SOCKMAP_EP_NAME="sockmap_ep_port"
SOCKMAP_PROXY_NAME="sock_proxy_map"
SOCKMAP_VERDICT_NAME="sock_verdict_ma"
SOCKMAP_PEER_NAME="peer_map"
SOCKMAP_STATS_NAME="sockmap_stats"

# sockmap_stats PERCPU_ARRAY index (kernel: llb_sockmap.h SOCKMAP_STAT_*)
SOCKMAP_STAT_REDIRECT_OK=0
SOCKMAP_STAT_PEER_MISS=1
SOCKMAP_STAT_INELIGIBLE=2
SOCKMAP_STAT_REDIRECT_REQ=3
SOCKMAP_STAT_REDIRECT_RESP=4

# result tracking
SOCKMAP_FAIL_COUNT=0

sockmap_init_artifacts() {
  mkdir -p "$SOCKMAP_ARTIFACTS_DIR"
}

sockmap_clear_artifacts() {
  if [[ -d "$SOCKMAP_ARTIFACTS_DIR" ]]; then
    rm -rf "$SOCKMAP_ARTIFACTS_DIR"
  fi
}

# Backend ports used by the sockmap scenarios (validation: 8080, perf: 9080/9090,
# directional: 9090/9091, request path: 9092/9093). All of them are killed on
# cleanup; otherwise the EXIT trap's `wait` on the node servers never returns.
SOCKMAP_BACKEND_PORTS="8080 9080 9090 9091 9092 9093"

sockmap_listener_pids() {
  local host=$1
  local port filter=""
  for port in $SOCKMAP_BACKEND_PORTS; do
    filter+="${filter:+ or }sport = :$port"
  done
  $hexec "$host" sh -c "ss -ltnp '( $filter )' 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p'" 2>/dev/null \
    | sort -u
}

sockmap_kill_tcp_servers() {
  local host pid pids

  for host in l3ep1 l3ep2; do
    pids=$(sockmap_listener_pids "$host")
    if [[ -z "$pids" ]]; then
      continue
    fi

    while IFS= read -r pid; do
      [[ -n "$pid" ]] || continue
      $hexec "$host" kill "$pid" >/dev/null 2>&1 || true
    done <<< "$pids"

    pids=$(sockmap_listener_pids "$host")
    while IFS= read -r pid; do
      [[ -n "$pid" ]] || continue
      $hexec "$host" kill -9 "$pid" >/dev/null 2>&1 || true
    done <<< "$pids"
  done
}

# Runs a command via docker exec from the host, capturing stderr as well.
_sm_dexec() {
  local llb=$1; shift
  sudo docker exec -i "$llb" "$@" 2>&1
}

# Checks whether bpftool exists inside the llb1 container and tries to install it.
sockmap_ensure_bpftool() {
  local llb=$1
  if _sm_dexec "$llb" sh -c 'command -v bpftool' >/dev/null 2>&1; then
    return 0
  fi
  echo "[sockmap] bpftool not found in $llb, attempting fallback install..."
  _sm_dexec "$llb" sh -c '
    set -e
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq >/dev/null
      apt-get install -y --no-install-recommends bpftool >/dev/null 2>&1 \
        || apt-get install -y --no-install-recommends linux-tools-common linux-tools-generic >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y bpftool >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
      yum install -y bpftool >/dev/null 2>&1
    else
      echo "no supported package manager" >&2
      exit 1
    fi
  '
  if _sm_dexec "$llb" sh -c 'command -v bpftool' >/dev/null 2>&1; then
    echo "[sockmap] bpftool installed via fallback."
    return 0
  fi
  echo "[sockmap] ERROR: bpftool unavailable in $llb and install fallback failed." >&2
  return 1
}

# Polls until llb1's REST API responds.
sockmap_wait_api_ready() {
  local llb=$1
  local tries=${2:-30}
  local i=0
  while (( i < tries )); do
    if _sm_dexec "$llb" curl -sf -o /dev/null \
         "http://localhost:11111/netlox/v1/config/loadbalancer/all"; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "[sockmap] ERROR: $llb REST API not ready after $tries seconds" >&2
  return 1
}

# Creates a fullproxy LB rule with sockmap acceleration through the REST API.
#   $1: llb name
#   $2: VIP
#   $3: VIP port
#   $4: backend port (targetPort of the endpoints)
#   $5: endpoint csv, e.g. "31.31.31.1,32.32.32.1"
#   $6: sockmap_en (true|false)
#   $7: service name
sockmap_create_lb_via_api() {
  local llb=$1
  local vip=$2
  local vport=$3
  local bport=$4
  local eps_csv=$5
  local sockmap_en=$6
  local name=$7

  # $6 accepts both legacy booleans (true/false) and the new directional mode
  # strings (off/both/request/response).
  local sockmap_mode
  case "$sockmap_en" in
    true|TRUE|1)        sockmap_mode="both" ;;
    false|FALSE|0|"")   sockmap_mode="off" ;;
    off|both|request|response) sockmap_mode="$sockmap_en" ;;
    *)
      echo "[sockmap] ERROR: invalid sockmap mode '$sockmap_en' (off|both|request|response)"
      return 1
      ;;
  esac

  local eps_json=""
  local first=1
  IFS=',' read -ra eps <<< "$eps_csv"
  for ep in "${eps[@]}"; do
    if [[ $first -eq 0 ]]; then eps_json+=","; fi
    eps_json+="{\"endpointIP\":\"$ep\",\"targetPort\":$bport,\"weight\":1}"
    first=0
  done

  local body
  body=$(cat <<EOF
{
  "serviceArguments": {
    "externalIP": "$vip",
    "port": $vport,
    "protocol": "tcp",
    "mode": 4,
    "name": "$name",
    "sockMapMode": "$sockmap_mode"
  },
  "endpoints": [ $eps_json ]
}
EOF
)

  echo "[sockmap] create LB: $name vip=$vip:$vport sockMapMode=$sockmap_mode"
  local resp
  resp=$(_sm_dexec "$llb" curl -sS -w '\nHTTP %{http_code}\n' \
           -X POST -H 'Content-Type: application/json' \
           -d "$body" \
           "http://localhost:11111/netlox/v1/config/loadbalancer")
  echo "$resp" >> "$SOCKMAP_ARTIFACTS_DIR/api_responses.log"
  if ! echo "$resp" | grep -q "HTTP 20"; then
    echo "[sockmap] ERROR: LB rule create failed for $name"
    echo "$resp"
    return 1
  fi
  return 0
}

# Deletes an LB rule through the REST API. TCP only.
sockmap_delete_lb_via_api() {
  local llb=$1
  local vip=$2
  local vport=$3
  local url="http://localhost:11111/netlox/v1/config/loadbalancer/externalipaddress/${vip}/port/${vport}/protocol/tcp"
  echo "[sockmap] delete LB: $vip:$vport"
  local resp
  resp=$(_sm_dexec "$llb" curl -sS -w '\nHTTP %{http_code}\n' -X DELETE "$url")
  echo "$resp" >> "$SOCKMAP_ARTIFACTS_DIR/api_responses.log"
  if ! echo "$resp" | grep -q "HTTP 20"; then
    echo "[sockmap] ERROR: LB rule delete failed for $vip:$vport"
    echo "$resp"
    return 1
  fi
  return 0
}

# Returns the id of the first map matching the truncated name, or an empty string.
sockmap_map_id() {
  local llb=$1
  local name=$2
  _sm_dexec "$llb" bpftool map show 2>/dev/null \
    | grep " name $name " \
    | head -1 \
    | awk -F: '{print $1}' \
    | tr -d ' '
}

# Portset key bytes as the kernel stores struct llb_sockmap_portset_key:
# IPv4 address (4 bytes, network order), port (2 bytes, network order), 2 bytes pad.
sockmap_portset_key_hex() {
  local ip=$1 port=$2 a b c d
  IFS=. read -r a b c d <<< "$ip"
  printf '%02x %02x %02x %02x %02x %02x 00 00' "$a" "$b" "$c" "$d" $((port >> 8)) $((port & 0xff))
}

# Checks whether a portset holds an entry.
#   $1 llb, $2 portset map name, $3 port, $4 IPv4 address (optional)
# With an address the exact (address, port) entry is looked up. Without one, any entry
# with that port matches, whatever its address.
# Returns 0 if present, 1 if absent or the map does not exist.
sockmap_portset_has() {
  local llb=$1
  local map_name=$2
  local port=$3
  local ip=${4:-}
  local id
  id=$(sockmap_map_id "$llb" "$map_name")
  if [[ -z "$id" ]]; then
    return 1
  fi
  if [[ -n "$ip" ]]; then
    local hex
    hex=$(sockmap_portset_key_hex "$ip" "$port")
    _sm_dexec "$llb" bash -c "bpftool -j map lookup id $id key hex $hex 2>/dev/null" \
      | grep -q '"value":'
    return $?
  fi
  local phex
  phex=$(printf '"0x%02x","0x%02x"' $((port >> 8)) $((port & 0xff)))
  _sm_dexec "$llb" bash -c "bpftool -j map dump id $id 2>/dev/null" \
    | grep -oE '"key":\["0x[0-9a-f]{2}","0x[0-9a-f]{2}","0x[0-9a-f]{2}","0x[0-9a-f]{2}","0x[0-9a-f]{2}","0x[0-9a-f]{2}"' \
    | grep -q "${phex}\$"
}

# verdict_refs of one portset entry: how many enabled rules accelerate the direction in
# which a matching socket receives. Prints nothing if the entry is absent.
#   $1 llb, $2 portset map name, $3 IPv4 address, $4 port
sockmap_portset_verdict_refs() {
  local llb=$1 map_name=$2 ip=$3 port=$4 id hex
  id=$(sockmap_map_id "$llb" "$map_name")
  [[ -n "$id" ]] || return 0
  hex=$(sockmap_portset_key_hex "$ip" "$port")
  _sm_dexec "$llb" bash -c "bpftool -j map lookup id $id key hex $hex 2>/dev/null" \
    | grep -oE '"verdict_refs":[[:space:]]*[0-9]+' \
    | grep -oE '[0-9]+$' \
    | head -1
}

# Current number of entries in sock_proxy_map.
# sock_proxy_map is a SOCKHASH. With an 8-byte value bpftool prints each socket's cookie
# as a normal JSON '"key"' entry; with the older 4-byte value it could not read the value
# and printed plain-text 'key: <hex>...' lines with "value: No space left on device"
# and "Found 0 elements". Both forms are counted so either image reads correctly.
sockmap_sockhash_count() {
  local llb=$1
  local id
  id=$(sockmap_map_id "$llb" "$SOCKMAP_PROXY_NAME")
  if [[ -z "$id" ]]; then
    echo 0
    return 0
  fi
  _sm_dexec "$llb" bash -c "bpftool map dump id $id 2>/dev/null" \
    | grep -cE '"key"|^key:'
}

# Current number of entries in sock_verdict_map, the subset of sock_proxy_map whose
# ingress runs the sk_skb verdict (same bpftool caveats as above).
sockmap_verdict_sockhash_count() {
  local llb=$1
  local id
  id=$(sockmap_map_id "$llb" "$SOCKMAP_VERDICT_NAME")
  if [[ -z "$id" ]]; then
    echo 0
    return 0
  fi
  _sm_dexec "$llb" bash -c "bpftool map dump id $id 2>/dev/null" \
    | grep -cE '"key"|^key:'
}

# Current number of entries in peer_map.
sockmap_peer_map_count() {
  local llb=$1
  local id
  id=$(sockmap_map_id "$llb" "$SOCKMAP_PEER_NAME")
  if [[ -z "$id" ]]; then
    echo 0
    return 0
  fi
  _sm_dexec "$llb" bash -c "bpftool map dump id $id 2>/dev/null" \
    | grep -c '"key"'
}

# Sums one index of sockmap_stats (PERCPU_ARRAY of __u64) across all CPUs.
# With BTF present, `bpftool map lookup` renders a __u64 percpu value as per-CPU JSON
# `"value": N` in decimal, so those numbers are simply added up. The result is
# monotonically increasing.
#   $1 llb, $2 index (0=REDIRECT_OK, 1=PEER_MISS, 2=INELIGIBLE)
sockmap_stat_sum() {
  local llb=$1
  local idx=$2
  local id
  id=$(sockmap_map_id "$llb" "$SOCKMAP_STATS_NAME")
  if [[ -z "$id" ]]; then
    echo 0
    return 0
  fi
  # u32 key (little-endian): indices 0..255 only use the first byte.
  local keyhex
  keyhex=$(printf '%02x 00 00 00' "$idx")
  _sm_dexec "$llb" bash -c "bpftool map lookup id $id key hex $keyhex 2>/dev/null" \
    | grep -oE '"value":[[:space:]]*[0-9]+' \
    | grep -oE '[0-9]+$' \
    | awk '{s+=$1} END{print s+0}'
}

# Cumulative redirects issued by the sk_skb verdict - the sockmap engagement signal.
sockmap_redirect_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_REDIRECT_OK"
}

# Cumulative SK_PASS results of the stream verdict (peer_map miss). Must not grow:
# the proxy adds a socket to sock_verdict_map only after its peer_map entry, and
# SK_PASS data on a strparser socket can stall the reader (kernel defect, see
# loxilb-ebpf kernel/llb_kern_sockmap.c).
sockmap_peer_miss_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_PEER_MISS"
}

# Retired: the stream verdict no longer consults the portset. Always 0.
sockmap_ineligible_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_INELIGIBLE"
}

# Records a result line asserting that the verdict passed nothing up since
# $2 (a sockmap_peer_miss_count taken earlier).
#   $1 llb, $2 PEER_MISS before, $3 label
# Close the measurement window before connections are torn down: during teardown
# a verdict already running when the proxy removes the pair can still miss the
# peer, which is harmless but would read as a failure here.
sockmap_assert_no_pass() {
  local llb=$1 before=$2 label=$3
  local delta=$(( $(sockmap_peer_miss_count "$llb") - before ))
  if (( delta == 0 )); then
    sockmap_result "$label" "OK"
  else
    sockmap_result "$label" "FAILED" "PEER_MISS +$delta; a socket ran the verdict without a peer"
  fi
}

# Polls until a portset reaches the wanted state, waiting for asynchronous dp work.
#   $1 llb, $2 portset map name, $3 port, $4 want (present|absent),
#   $5 tries (default 16, at 0.5s intervals), $6 IPv4 address (optional, see
#   sockmap_portset_has)
# Returns 0 once the wanted state is reached, 1 on timeout.
sockmap_portset_wait() {
  local llb=$1 name=$2 port=$3 want=$4 tries=${5:-16} ip=${6:-}
  local i
  for ((i=0; i<tries; i++)); do
    if sockmap_portset_has "$llb" "$name" "$port" "$ip"; then
      [[ "$want" == "present" ]] && return 0
    else
      [[ "$want" == "absent" ]] && return 0
    fi
    sleep 0.5
  done
  return 1
}

# Cumulative redirects in the request direction (client->backend).
# Increases only in request/both mode; must stay 0 in response-only mode.
sockmap_redirect_req_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_REDIRECT_REQ"
}

# Cumulative redirects in the response direction (backend->client).
# Increases only in response/both mode; must stay 0 in request-only mode.
sockmap_redirect_resp_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_REDIRECT_RESP"
}

# Counts sockmap failure messages in docker logs.
sockmap_log_failure_count() {
  local llb=$1
  sudo docker logs "$llb" 2>&1 \
    | grep -cE "Sockmap: Registration failed!|Sockmap: peer_map registration failed!|Sockmap: peer_map delete failed|Sockmap: sock_verdict_map (add|delete) failed|sockmap: load failed|sockmap: attach failed|sockmap: portset map get failed|sockmap: portset fd get failed|sockmap: skmsg helper load failed|sockmap: skstream helper load failed|sockmap: portset update failed|sockmap: failed to (add|delete|remove)|sockmap: rule [0-9]+: failed|sockmap: rule id [0-9]+ out of range|sockmap: --sockmapsupport requires"
}

# Checks that the required sockmap BPF assets (sockops prog and 6 maps) are attached.
sockmap_assert_bpf_assets() {
  local llb=$1
  local ok=1

  local vip_id ep_id proxy_id verdict_id peer_id stats_id
  vip_id=$(sockmap_map_id "$llb" "$SOCKMAP_VIP_NAME")
  ep_id=$(sockmap_map_id "$llb" "$SOCKMAP_EP_NAME")
  proxy_id=$(sockmap_map_id "$llb" "$SOCKMAP_PROXY_NAME")
  verdict_id=$(sockmap_map_id "$llb" "$SOCKMAP_VERDICT_NAME")
  peer_id=$(sockmap_map_id "$llb" "$SOCKMAP_PEER_NAME")
  stats_id=$(sockmap_map_id "$llb" "$SOCKMAP_STATS_NAME")

  [[ -n "$vip_id"  ]] || ok=0
  [[ -n "$ep_id"   ]] || ok=0
  [[ -n "$proxy_id" ]] || ok=0
  [[ -n "$verdict_id" ]] || ok=0
  [[ -n "$peer_id"  ]] || ok=0
  [[ -n "$stats_id" ]] || ok=0

  local sockops_count
  sockops_count=$(_sm_dexec "$llb" bpftool prog show 2>/dev/null \
                   | grep -cE 'type[[:space:]]+sock_ops|sockops|sock_ops')
  if [[ $sockops_count -eq 0 ]]; then
    ok=0
  fi

  if [[ $ok -eq 1 ]]; then
    return 0
  fi

  echo "[sockmap] BPF assets missing: vip_id='$vip_id' ep_id='$ep_id' proxy_id='$proxy_id' verdict_id='$verdict_id' peer_id='$peer_id' stats_id='$stats_id' sockops_progs=$sockops_count" >&2
  return 1
}

# Helper for printing the result table.
sockmap_section() {
  echo
  echo "[$1] $2"
}

sockmap_result() {
  local label=$1
  local status=$2
  local detail=${3:-}
  if [[ "$status" == "OK" ]]; then
    printf "    %-48s : %s%s\n" "$label" "OK" "${detail:+ ($detail)}"
  else
    printf "    %-48s : %s%s\n" "$label" "FAILED" "${detail:+ ($detail)}"
    SOCKMAP_FAIL_COUNT=$((SOCKMAP_FAIL_COUNT + 1))
  fi
}
