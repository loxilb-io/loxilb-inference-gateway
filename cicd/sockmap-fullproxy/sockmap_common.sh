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
# directional: 9090/9091). All of them are killed on cleanup; otherwise the EXIT
# trap's `wait` on the node servers never returns.
SOCKMAP_BACKEND_PORTS="8080 9080 9090 9091"

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

# Converts a port integer to "<low_byte_hex> <high_byte_hex>", the bytes as the kernel
# stores them in memory. This assumes little-endian x86_64: the htons'd value is stored
# as-is, so a bpftool lookup is given network byte order (high, low) directly.
sockmap_port_to_hex() {
  local port=$1
  printf '%02x %02x' $((port >> 8)) $((port & 0xff))
}

# Checks whether a port is present in a portset map.
# Returns 0 if present, 1 if absent or the map does not exist.
sockmap_portset_has() {
  local llb=$1
  local map_name=$2
  local port=$3
  local id
  id=$(sockmap_map_id "$llb" "$map_name")
  if [[ -z "$id" ]]; then
    return 1
  fi
  local hex
  hex=$(sockmap_port_to_hex "$port")
  if _sm_dexec "$llb" bash -c "bpftool map lookup id $id key hex $hex 2>/dev/null" \
       | grep -q '"value":'; then
    return 0
  fi
  return 1
}

# Current number of entries in sock_proxy_map.
# sock_proxy_map is a SOCKHASH. bpftool cannot read a sockhash value (a socket) from
# userspace, so it prints "value: No space left on device" and finishes with
# "Found 0 elements" - but the key lines still print correctly, in the plain-text form
# 'key: <hex>...' rather than the JSON '"key"' a HASH would emit. Both forms must
# therefore be counted. Counting only JSON '"key"' yields a false negative: always 0
# even when the SOCKHASH is populated.
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

# Cumulative SK_PASS results that were eligible but missed peer_map (diagnostic).
sockmap_peer_miss_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_PEER_MISS"
}

# Cumulative SK_PASS results caused by a portset mismatch (diagnostic).
sockmap_ineligible_count() {
  sockmap_stat_sum "$1" "$SOCKMAP_STAT_INELIGIBLE"
}

# Polls until a portset reaches the wanted state, waiting for asynchronous dp work.
#   $1 llb, $2 portset map name, $3 port, $4 want (present|absent),
#   $5 tries (default 16, at 0.5s intervals)
# Returns 0 once the wanted state is reached, 1 on timeout.
sockmap_portset_wait() {
  local llb=$1 name=$2 port=$3 want=$4 tries=${5:-16}
  local i
  for ((i=0; i<tries; i++)); do
    if sockmap_portset_has "$llb" "$name" "$port"; then
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
    | grep -cE "Sockmap: Registration failed!|Sockmap: peer_map registration failed!|Sockmap: peer_map delete failed|sockmap: load failed|sockmap: attach failed|sockmap: portset map get failed|sockmap: portset fd get failed|sockmap: skmsg helper load failed|sockmap: skstream helper load failed|sockmap: portset update failed|sockmap: failed to (add|delete|remove)|sockmap: rule [0-9]+: failed|sockmap: rule id [0-9]+ out of range|sockmap: --sockmapsupport requires"
}

# Checks that the required sockmap BPF assets (sockops prog and 4 maps) are attached.
sockmap_assert_bpf_assets() {
  local llb=$1
  local ok=1

  local vip_id ep_id proxy_id peer_id stats_id
  vip_id=$(sockmap_map_id "$llb" "$SOCKMAP_VIP_NAME")
  ep_id=$(sockmap_map_id "$llb" "$SOCKMAP_EP_NAME")
  proxy_id=$(sockmap_map_id "$llb" "$SOCKMAP_PROXY_NAME")
  peer_id=$(sockmap_map_id "$llb" "$SOCKMAP_PEER_NAME")
  stats_id=$(sockmap_map_id "$llb" "$SOCKMAP_STATS_NAME")

  [[ -n "$vip_id"  ]] || ok=0
  [[ -n "$ep_id"   ]] || ok=0
  [[ -n "$proxy_id" ]] || ok=0
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

  echo "[sockmap] BPF assets missing: vip_id='$vip_id' ep_id='$ep_id' proxy_id='$proxy_id' peer_id='$peer_id' stats_id='$stats_id' sockops_progs=$sockops_count" >&2
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
