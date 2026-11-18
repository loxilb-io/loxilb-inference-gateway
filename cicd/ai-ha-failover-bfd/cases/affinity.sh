# Exercise learned bindings whose endpoints differ from the header hash.

f8_requests() {
  local ids=$1 tag=$2
  $hexec "$CLIENT" python3 "$HAFO_DIR/hafo_tools.py" conv --vip "$VIP" --port "$PORT_AFF" \
    --model "$MODEL_AFF" --ids-file "$ids" --tag "$tag" --require-content-length
}

f8_backend_label() {
  local body
  body=$($hexec "$1" curl -sf --max-time 2 http://127.0.0.1:8080) || return 1
  printf '%s\n' "${body%%|*}"
}

f8_install_count() {
  docker exec "$1" sh -c 'cat /var/log/loxilb*.log' 2>/dev/null |
    python3 "$HAFO_DIR/affinity_oracle.py" installed "$2"
}

f8_install_ready() {
  [ "$(f8_install_count "$1" "$2")" = 100 ]
}

f8_listener_ready() {
  $hexec "$1" ss -Hltn | awk -v a="$VIP:$PORT_AFF" '$4==a {found=1} END {exit !found}'
}

f8_backend_block() {
  local operation=$1 backend
  shift
  for backend in "$@"; do
    $hexec "$backend" iptables "$operation" INPUT -p tcp --dport 8080 \
      -j REJECT --reject-with tcp-reset || return 1
  done
}

# Count dataplane health transitions for the fixture endpoint. This endpoint
# appears only in the affinity rule, so a transition cannot name another pool.
f8_down_count() {
  local node=$1 address=$2
  docker exec "$node" cat /var/log/loxilbdp.log 2>/dev/null |
    grep -Fc "EP health - $address:8080 -> inactive=1 applied to"
}

f8_marked_down() {
  [ "$(f8_down_count "$1" "$2")" -gt "$3" ]
}

f8_direct_guard() (
  local backup=$1 tag=$2 dev="e${MON}${SW_C}" code
  trap '$hexec "$MON" ip neigh del "$VIP" dev "$dev" 2>/dev/null || true' EXIT
  $hexec "$MON" ip neigh replace "$VIP" lladdr "$(node_mac "$backup")" nud permanent dev "$dev" || return 1
  code=$($hexec "$MON" curl -s --connect-timeout .7 --max-time 1.5 -o /dev/null -w '%{http_code}' \
    -H "X-Test-Nonce: $tag" -H 'Content-Type: application/json' \
    --data '{"model":"'"$MODEL_AFF"'","messages":[{"role":"user","content":"hi"}]}' \
    "http://$VIP:$PORT_AFF/v1/chat/completions") || true
  printf 'direct_http=%s receipts=%s\n' "$code" "$(receipts "$tag")"
  [ "$code" != 200 ] && [ "$(receipts "$tag")" = 0 ]
)

f8_phase() (
  local mode=$1 order=$2 dir="$OUT/affinity/$2-$1" tag="aff-$2-$1-$$"
  local ep1 ep2 ep3 ep4 a b c d ids ref result matched bad installed cut=0 dead=0 wait_start probe_tag
  local -a blocked=()
  mkdir -p "$dir"
  trap 'if [ "${#blocked[@]}" -gt 0 ]; then f8_backend_block -D "${blocked[@]}"; fi
    if [ "$cut" = 1 ]; then xsync_restore; fi
    if [ "$dead" = 1 ]; then fo_restore; fi' EXIT
  fo_begin || return 1
  printf 'master=%s backup=%s\n' "$M" "$S" > "$dir/direction.txt"
  read -r ep1 ep2 ep3 ep4 <<< "$BACKENDS"
  a=$(f8_backend_label "$ep1") && b=$(f8_backend_label "$ep2") &&
    c=$(f8_backend_label "$ep3") && d=$(f8_backend_label "$ep4") || return 1
  if ! f8_listener_ready "$S" || frontend_vip "$S" ||
     ! f8_direct_guard "$S" "$tag-direct" > "$dir/direct.txt"; then
    echo "standby listener, VIP ownership or ingress guard is inconsistent" > "$dir/failure.txt"
    return 1
  fi
  ids="$dir/ids.txt"; ref="$dir/hash-ids.txt"
  python3 "$HAFO_DIR/affinity_oracle.py" cohort "$tag" > "$ids"
  python3 "$HAFO_DIR/affinity_oracle.py" cohort "$tag-hash" > "$ref"
  f8_requests "$ref" "$tag-hash" > "$dir/hash.json" || return 1
  result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ref" "$dir/hash.json" "$dir/hash.json" "$b" "$d") || return 1
  read -r matched bad _ <<< "$result"
  [ "$matched" = 100 ] && [ "$bad" = 0 ] || { echo "hash control: $result" > "$dir/failure.txt"; return 1; }
  if [ "$mode" = off ]; then xsync_cut; cut=1; fi

  blocked=("$ep2" "$ep4")
  f8_backend_block -I "${blocked[@]}" || return 1
  # Wait for the health checks through successful fresh requests. Never reuse
  # a trial ID that could already have learned an endpoint during the transition.
  wait_start=$(now_ms)
  while :; do
    probe_tag="$tag-probe-$(now_ms)"
    python3 "$HAFO_DIR/affinity_oracle.py" cohort "$probe_tag" | head -8 > "$dir/probe-ids.txt"
    f8_requests "$dir/probe-ids.txt" "$probe_tag" > "$dir/probe.json" || return 1
    if python3 - "$dir/probe.json" "$a" "$c" <<'PY'
import json,sys
rows = json.load(open(sys.argv[1]))
sys.exit(not (len(rows) == 8 and set(rows.values()) <= set(sys.argv[2:])))
PY
    then break; fi
    [ "$(( $(now_ms) - wait_start ))" -lt 45000 ] || return 1
    sleep 1
  done
  f8_requests "$ids" "$tag-learn" > "$dir/learn.json" || return 1
  result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ids" "$dir/learn.json" "$dir/learn.json" "$a" "$c") || return 1
  read -r matched bad _ <<< "$result"
  [ "$matched" = 100 ] && [ "$bad" = 0 ] || { echo "learn control: $result" > "$dir/failure.txt"; return 1; }
  f8_backend_block -D "${blocked[@]}" || return 1
  blocked=()
  sleep 5
  if [ "$mode" = on ]; then
    frontend_wait 10000 f8_install_ready "$S" "$ids" || return 1
  else
    [ "$(xsync_dropped)" -gt 0 ] || return 1
  fi
  installed=$(f8_install_count "$S" "$ids")
  printf 'installed_before_fault=%s\n' "$installed" > "$dir/install.txt"
  [ "$mode" = on ] || [ "$installed" = 0 ] || return 1
  f8_requests "$ids" "$tag-before" > "$dir/before.json" || return 1
  result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ids" "$dir/learn.json" "$dir/before.json" "$a" "$c") || return 1
  read -r matched bad _ <<< "$result"
  [ "$matched" = 100 ] && [ "$bad" = 0 ] || return 1
  # New keys with the same two hash buckets prove that both normal hash
  # targets are usable again before the gateway fault.
  python3 "$HAFO_DIR/affinity_oracle.py" cohort "$tag-restored" > "$ref"
  f8_requests "$ref" "$tag-restored" > "$dir/restored.json" || return 1
  result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ref" "$dir/restored.json" "$dir/restored.json" "$b" "$d") || return 1
  read -r matched bad _ <<< "$result"
  [ "$matched" = 100 ] && [ "$bad" = 0 ] || { echo "restored hash control: $result" > "$dir/failure.txt"; return 1; }

  dead=1
  fo_fault || return 1
  local control
  control=$(vretry "$PORT_KEY" "$MODEL_KEY" "X-Api-Key: $(key_raw fo-seed-key)" 12 "$tag-ready")
  [ "$(jget "d['ok']" <<< "$control")" = True ] || return 1
  f8_requests "$ids" "$tag-after" > "$dir/after.json" || return 1
  result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ids" "$dir/before.json" "$dir/after.json" "$a" "$b" "$c" "$d") || return 1
  echo "$result" > "$dir/score.txt"
  read -r matched bad _ <<< "$result"
  [ "$bad" = 0 ] || return 1
  if [ "$mode" = off ]; then
    # The original two hash members are known good in this arm. Require the
    # complete, unreplicated cohort to use them, with no learned-member hit.
    result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ids" "$dir/before.json" "$dir/after.json" "$b" "$d") || return 1
    read -r matched bad _ <<< "$result"
    [ "$matched" = 0 ] && [ "$bad" = 0 ]
    return
  fi
  [ "$matched" -ge 90 ] || return 1
  if [ "$order" = 4 ]; then
    local address prior health_start
    address=$(be_ip "$ep3")
    prior=$(f8_down_count "$S" "$address")
    blocked=("$ep3")
    f8_backend_block -I "${blocked[@]}" || return 1
    health_start=$(now_ms)
    if ! frontend_wait 45000 f8_marked_down "$S" "$address" "$prior"; then
      echo "dataplane did not mark $address down within the harness observation window" > "$dir/failure.txt"
      return 1
    fi
    echo "$(( $(now_ms) - health_start ))" > "$dir/health-mark-ms.txt"
    f8_requests "$ids" "$tag-unhealthy" > "$dir/unhealthy.json" || return 1
    result=$(python3 "$HAFO_DIR/affinity_oracle.py" compare "$ids" "$dir/after.json" "$dir/unhealthy.json" "$a" "$b" "$d") || return 1
    echo "$result" > "$dir/unhealthy-score.txt"
    read -r _ bad _ <<< "$result"
    [ "$bad" = 0 ] || return 1
    f8_backend_block -D "${blocked[@]}" || return 1
    blocked=()
  fi
)

f8_case() (
  local mode index=0 first second
  if ! fo_begin; then
    verdict FAILOVER-8b NOT_RUN "roles did not converge"
    return
  fi
  first=$M; second=$S
  for mode in on off off on; do
    index=$((index + 1))
    if ! f8_phase "$mode" "$index"; then
      verdict FAILOVER-8b FAIL "${mode} trial $index failed; see affinity/$index-$mode"
      return
    fi
    if ! fo_begin; then
      verdict FAILOVER-8b FAIL "roles did not recover after trial $index"
      return
    fi
    if { [ "$((index % 2))" = 1 ] && [ "$M" != "$second" ]; } ||
       { [ "$((index % 2))" = 0 ] && [ "$M" != "$first" ]; }; then
      verdict FAILOVER-8b FAIL "trial $index did not reverse the owner"
      return
    fi
    note "affinity test $index, sync=$mode, retained/outside expected backends/backend distribution: $(cat "$OUT/affinity/$index-$mode/score.txt")"
  done
  verdict FAILOVER-8b PASS "100 applied on each standby; learned endpoint retained at least 90%, unlike the sync-cut controls in both directions"
)

f8_case
