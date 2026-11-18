# FAILOVER-9: independently gate customer responses during a PostgreSQL outage
# and after it accepts connections again. Run the same case in both directions.

f9_pair_up() {
  frontend_owned "$1" "$2" && frontend_bfd_up "$1" && frontend_bfd_up "$2"
}

# Transfer the VIP with PostgreSQL healthy and both processes kept alive. A
# key or policy is warm only if that very process served it while it was MASTER.
f9_move_vip() {
  local from=$1 to=$2 iface="e${1}${SW_C}"
  $hexec "$from" ip link set "$iface" down || return 1
  local result=0
  frontend_wait 5000 f9_pair_up "$to" "$from" || result=1
  $hexec "$from" ip link set "$iface" up || return 1
  [ "$result" = 0 ] || return 1
  sleep 5.5 # The restored frontend has a 5 s eligibility hold.
  f9_pair_up "$to" "$from"
}

f9_expect() {
  local port=$1 model=$2 header=$3 tag=$4 expected=$5 count=$6 actual
  vreq "$port" "$model" "$header" "$tag"
  actual=$(receipts "$VREQ_NONCE")
  printf '%s: %s, Retry-After=%s, receipts=%s\n' "$tag" "$VREQ_OUT" \
    "$(jget "d['first_attempt'].get('retry_after','')" <<< "$VREQ_JSON")" "$actual" >> "$dir/requests.txt"
  [ "$VREQ_OUT" = "$expected" ] && [ "$actual" = "$count" ]
}

f9_probe() {
  local lane=$1 port=$2 model=$3 header=$4
  sudo ip netns exec "$CLIENT" python3 "$HAFO_DIR/hafo_tools.py" probe --vip "$VIP" \
    --port "$port" --model "$model" --header "$header" --rate 10 --duration 45 \
    --connect-timeout 0.3 --timeout 0.6 --require-content-length \
    --tag "$tag-$lane" --out "$dir/$lane.jsonl" &
  probe_pids+=("$!")
}

f9_stop_probes() {
  local pid
  touch "$dir/"{warm-key,warm-jwt,recovery-key,recovery-jwt,survivor}.jsonl.stop
  for pid in "${probe_pids[@]}"; do wait "$pid" || return 1; done
  probe_pids=()
}

f9_pg_ready() {
  docker exec "$PG_NAME" pg_isready -h "$PG_IP" -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1
}

f9_cycle() (
  local id=$1 cold_user=$2 dir="$OUT/fo9/$1" tag="fo9-$1-$$" rc=0 dead=0
  local warm_key warm_jwt cold_key cold_jwt old_key expired_key deleted_id deleted_key survivor_pid
  local fault outage_end pg_ready timing k_seq j_seq key_ms jwt_ms role_ms vip_ms bind_ms pg_started
  local unavailable='503 policy_store_unavailable'
  local -a probe_pids=()
  mkdir -p "$dir"
  # Always restore the dedicated PostgreSQL container before the dead peer.
  trap 'f9_stop_probes; if [ "$dead" = 1 ]; then
    docker start "$PG_NAME" >/dev/null && frontend_wait 12000 f9_pg_ready && fo_restore
  fi' EXIT

  if ! fo_begin || ! frontend_wait 5000 f9_pair_up "$M" "$S" || ! f9_move_vip "$M" "$S"; then
    verdict "$id" NOT_RUN "could not promote the intended survivor for cache priming"
    return 1
  fi
  printf 'victim=%s survivor=%s\n' "$M" "$S" > "$dir/nodes.txt"
  survivor_pid=$(loxilb_pid "$S")
  read -r _ warm_key <<< "$(mint_key_now "$S" "$tag-warm" "$tag-warm")"
  read -r deleted_id deleted_key <<< "$(mint_key_now "$S" "$tag-deleted" "$tag-deleted")"
  expired_key=$(api "$S" POST /config/ai/apikey \
    "{\"tenant_id\":\"$tag-expired\",\"name\":\"$tag-expired\",\"expires_at\":\"2000-01-01T00:00:00Z\"}" |
    sed '$d' | jget "d.get('raw_key', '')")
  warm_jwt=$(kc_mint aigw-client alice alicepw)
  cold_jwt=$(kc_mint aigw-client "$cold_user" "${cold_user}pw")
  if [ -z "$survivor_pid" ] || [ -z "$warm_key" ] || [ -z "$warm_jwt" ] || [ -z "$cold_jwt" ] ||
     [ -z "$expired_key" ] || [ -z "$deleted_key" ] ||
     ! f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $warm_key" "$tag-key-prime" 200 1 ||
     ! f9_expect "$PORT_JWT" "$MODEL_JWT" "Authorization: Bearer $warm_jwt" "$tag-jwt-prime" 200 1 ||
     ! f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $expired_key" "$tag-expired-prime" '401 invalid_api_key' 0 ||
     ! f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $deleted_key" "$tag-deleted-prime" 200 1 ||
     ! f9_move_vip "$S" "$M" || [ "$(loxilb_pid "$S")" != "$survivor_pid" ]; then
    verdict "$id" NOT_RUN "could not prime the survivor or return the VIP to the victim; see requests.txt"
    return 1
  fi

  read -r _ cold_key <<< "$(mint_key_now "$M" "$tag-cold" "$tag-cold")"
  read -r _ old_key <<< "$(mint_key_now "$M" "$tag-old" "$tag-old")"
  if [ -z "$cold_key" ] || [ -z "$old_key" ] ||
     ! f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $old_key" "$tag-victim-only" 200 1 ||
     ! f9_expect "$PORT_JWT" "$MODEL_JWT" "Authorization: Bearer $cold_jwt" "$tag-victim-jwt" 200 1 ||
     ! api "$M" DELETE "/config/ai/apikey/$deleted_id" | grep -qx 'http_code=204' ||
     ! f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $deleted_key" "$tag-deleted-before" '401 invalid_api_key' 0; then
    verdict "$id" NOT_RUN "could not establish victim-only credentials and a confirmed delete"
    return 1
  fi

  f9_probe warm-key "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $warm_key"
  f9_probe warm-jwt "$PORT_JWT" "$MODEL_JWT" "Authorization: Bearer $warm_jwt"
  sudo ip netns exec "$S" python3 "$HAFO_DIR/hafo_tools.py" node --vip "$VIP" \
    --interval 0.05 --out "$dir/survivor.jsonl" &
  probe_pids+=("$!")
  sleep 1
  if ! docker stop -t 5 "$PG_NAME" >/dev/null ||
     [ "$(docker inspect -f '{{.State.Running}}' "$PG_NAME")" != false ]; then
    docker start "$PG_NAME" >/dev/null 2>&1
    verdict "$id" NOT_RUN "could not stop PostgreSQL"
    return 1
  fi
  printf 'pg_down=%s\n' "$(now_ms)" > "$dir/times.txt"
  dead=1
  fault=$(node_death "$M")
  printf 'fault=%s\n' "$fault" >> "$dir/times.txt"
  if ! frontend_wait 5000 f9_promoted "$S"; then
    verdict "$id" FAIL "the survivor did not acquire the VIP"
    return 1
  fi
  # Avoid scoring a connect timeout before L2 convergence as a store verdict.
  sleep 2
  f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $cold_key" "$tag-cold-down" "$unavailable" 0 || rc=1
  f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $old_key" "$tag-victim-only-down" "$unavailable" 0 || rc=1
  f9_expect "$PORT_JWT" "$MODEL_JWT" "Authorization: Bearer $cold_jwt" "$tag-cold-jwt-down" "$unavailable" 0 || rc=1
  f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $expired_key" "$tag-expired-down" '401 invalid_api_key' 0 || rc=1
  # Peer deletion evicts the entry. During the outage either a cached denial
  # or an unavailable-store refusal is valid. Backend delivery is never valid.
  vreq "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $deleted_key" "$tag-deleted-down"
  local deleted_receipts
  deleted_receipts=$(receipts "$VREQ_NONCE")
  printf '%s: %s, receipts=%s\n' "$tag-deleted-down" "$VREQ_OUT" "$deleted_receipts" >> "$dir/requests.txt"
  if { [ "$VREQ_OUT" != '401 invalid_api_key' ] && [ "$VREQ_OUT" != "$unavailable" ]; } ||
     [ "$deleted_receipts" != 0 ]; then rc=1; fi

  while [ "$(now_ms)" -lt "$((fault + 5600))" ]; do sleep 0.1; done
  outage_end=$(now_ms)
  printf 'outage_end=%s\n' "$outage_end" >> "$dir/times.txt"
  f9_stop_probes || rc=1
  if timing=$(python3 "$HAFO_DIR/fo9_oracle.py" outage "$dir" "$fault" "$outage_end" "$PORT_KEY" "$PORT_JWT" 2> "$dir/outage.err"); then
    read -r k_seq j_seq key_ms jwt_ms role_ms vip_ms bind_ms <<< "$timing"
    [ "$(receipts "$tag-warm-key-$k_seq")" = 1 ] && [ "$(receipts "$tag-warm-jwt-$j_seq")" = 1 ] || rc=1
  else
    rc=1
  fi
  if [ "$rc" = 0 ]; then
    verdict "$id.outage" PASS "${M}->${S} stable key=${key_ms}ms JWT=${jwt_ms}ms MASTER=${role_ms}ms VIP=${vip_ms}ms VIP-to-listeners=${bind_ms}ms; refused requests reached no backend"
  else
    verdict "$id.outage" FAIL "${M}->${S} outage contract failed; timing=[$timing]; see requests.txt and outage.err"
  fi

  rm -f "$dir/"recovery-{key,jwt}.jsonl.stop
  f9_probe recovery-key "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $cold_key"
  f9_probe recovery-jwt "$PORT_JWT" "$MODEL_JWT" "Authorization: Bearer $cold_jwt"
  pg_started=$(now_ms)
  if [ "${HAFO_MUTATE:-}" != fo9-skip-pg-start ]; then
    docker start "$PG_NAME" >/dev/null
  fi
  if ! frontend_wait 12000 f9_pg_ready; then
    verdict "$id.recovery" FAIL "PostgreSQL never became ready on its configured TCP endpoint"
    return 1
  fi
  pg_ready=$(now_ms)
  printf 'pg_start=%s\npg_ready=%s\n' "$pg_started" "$pg_ready" >> "$dir/times.txt"
  sleep 6.3
  f9_stop_probes || rc=1
  if timing=$(python3 "$HAFO_DIR/fo9_oracle.py" recovery "$dir" "$pg_ready" 0 2> "$dir/recovery.err"); then
    read -r k_seq j_seq key_ms jwt_ms <<< "$timing"
    if [ "$(receipts "$tag-recovery-key-$k_seq")" = 1 ] && [ "$(receipts "$tag-recovery-jwt-$j_seq")" = 1 ] &&
       [ "$(loxilb_pid "$S")" = "$survivor_pid" ] &&
       f9_expect "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $deleted_key" "$tag-deleted-after" '401 invalid_api_key' 0; then
      verdict "$id.recovery" PASS "key=${key_ms}ms JWT=${jwt_ms}ms after PostgreSQL was ready; survivor PID unchanged"
      return "$rc"
    fi
  fi
  verdict "$id.recovery" FAIL "6 s recovery, unchanged PID or delete isolation failed; timing=[$timing]"
  return 1
)

f9_promoted() {
  [ "$(role "$1")" = MASTER ] && frontend_vip "$1"
}

f9_case() (
  local dir="$OUT/fo9" first second ok=0
  mkdir -p "$dir"
  trap 'for n in $NODES; do [ ! -f "$dir/$n-command" ] || cp "$dir/$n-command" "$HAFO_DIR/.${n}-cmdline"; done' EXIT
  if ! fo_begin || ! frontend_start_pair "$dir" || ! fo_begin; then
    verdict FAILOVER-9 NOT_RUN "frontend-enabled pair could not establish roles"
    return
  fi
  first=$M; second=$S
  f9_cycle FAILOVER-9.first m1 || ok=1
  if fo_begin && [ "$M" = "$second" ] && [ "$S" = "$first" ]; then
    f9_cycle FAILOVER-9.reverse n1 || ok=1
  else
    verdict FAILOVER-9.reverse NOT_RUN "the testbed did not finish the first fault in the opposite direction"
    ok=1
  fi
  if [ "$ok" = 0 ]; then
    verdict FAILOVER-9 PASS "both outage and recovery gates passed in both directions"
  else
    verdict FAILOVER-9 FAIL "an outage, recovery, or direction gate failed; see fo9/"
  fi
)

f9_case
