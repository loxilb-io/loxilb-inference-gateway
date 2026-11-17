# Run last. The two nodes use --ha-frontend-interface on their existing
# customer veths while BFD continues on the Docker bridge.
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

frontend_case() (
  local dir="$OUT/frontend" n m b t0 elapsed old_index new_index pid1 pid2 rc1=0 rc2=0
  mkdir -p "$dir"
  trap 'for n in $NODES; do [ ! -f "$dir/$n-command" ] || cp "$dir/$n-command" "$HAFO_DIR/.${n}-cmdline"; done' EXIT
  if ! wait_roles 60 6; then
    verdict FAILOVER-FRONTEND NOT_RUN "pair did not converge before frontend validation"
    return
  fi
  for n in $NODES; do
    cp "$HAFO_DIR/.${n}-cmdline" "$dir/$n-command"
    printf '%s --ha-frontend-interface=e%s%s\n' "$(cat "$dir/$n-command")" "$n" "$SW_C" > "$HAFO_DIR/.${n}-cmdline"
    node_death "$n" >/dev/null
  done
  if ! node_start_pair > "$dir/pair-start.log" 2>&1; then
    verdict FAILOVER-FRONTEND NOT_RUN "could not start both frontend test containers"
    return
  fi
  read -r m b <<< "$NODES"
  node_return "$m" > "$dir/$m-start.log" 2>&1 & pid1=$!
  node_return "$b" > "$dir/$b-start.log" 2>&1 & pid2=$!
  wait "$pid1" || rc1=$?
  wait "$pid2" || rc2=$?
  if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ] || ! apply_cfg "$m" "" returning ||
     ! apply_cfg "$b" "" returning || ! wait_roles 100 6 ||
     ! frontend_wait 10000 frontend_owned "$MASTER_NODE" "$BACKUP_NODE"; then
    verdict FAILOVER-FRONTEND NOT_RUN "frontend-enabled pair did not reach a single VIP owner"
    return
  fi
  m=$MASTER_NODE; b=$BACKUP_NODE

  t0=$(now_ms)
  if $hexec "$m" ip link set "e${m}$SW_C" down &&
     frontend_wait 3000 frontend_owned "$b" "$m" &&
     frontend_bfd_up "$m" && frontend_bfd_up "$b"; then
    verdict FAILOVER-FRONTEND.down PASS "customer port down, BFD UP on both, VIP inherited in $(( $(now_ms) - t0 )) ms"
  else
    verdict FAILOVER-FRONTEND.down FAIL "customer port down did not leave the other node as sole VIP owner with BFD UP"
    return
  fi

  if $hexec "$b" ip link set "e${b}$SW_C" down && frontend_wait 3000 frontend_no_owner &&
     frontend_bfd_up "$m" && frontend_bfd_up "$b"; then
    verdict FAILOVER-FRONTEND.both-down PASS "both nodes BACKUP with no VIP and both BFD sessions UP"
  else
    verdict FAILOVER-FRONTEND.both-down FAIL "an ineligible peer retained the VIP or BFD failed"
    return
  fi
  t0=$(now_ms)
  if ! $hexec "$m" ip link set "e${m}$SW_C" up || ! $hexec "$b" ip link set "e${b}$SW_C" up ||
     ! wait_roles 20 1 || ! frontend_wait 4000 frontend_owned "$MASTER_NODE" "$BACKUP_NODE"; then
    verdict FAILOVER-FRONTEND.rejoin FAIL "both frontend ports restored without a single VIP owner"
    return
  fi
  elapsed=$(( $(now_ms) - t0 ))
  if [ "$elapsed" -lt 5000 ]; then
    verdict FAILOVER-FRONTEND.rejoin FAIL "both nodes recovered in ${elapsed} ms, before the 5 s UP hold"
    return
  fi
  verdict FAILOVER-FRONTEND.rejoin PASS "one VIP owner after ${elapsed} ms from restoring both ports"
  m=$MASTER_NODE; b=$BACKUP_NODE

  old_index=$($hexec "$m" ip -o link show "e${m}$SW_C" | cut -d: -f1)
  if ! $hexec "$m" ip link del "e${m}$SW_C" ||
     ! frontend_wait 3000 frontend_owned "$b" "$m" ||
     ! connect_docker_hosts "$m" "$SW_C" ||
     ! sudo ip -n "$SW_C" link set "e${SW_C}$m" master br0 ||
     ! $hexec "$m" ip addr add "$(node_cip "$m")/24" dev "e${m}$SW_C"; then
    verdict FAILOVER-FRONTEND.recreate FAIL "could not transfer ownership and recreate the frontend port"
    return
  fi
  new_index=$($hexec "$m" ip -o link show "e${m}$SW_C" | cut -d: -f1)
  sleep 6
  if [ -n "$old_index" ] && [ -n "$new_index" ] && [ "$old_index" != "$new_index" ] &&
     frontend_owned "$b" "$m" && frontend_bfd_up "$m" && frontend_bfd_up "$b"; then
    verdict FAILOVER-FRONTEND.recreate PASS "frontend ifindex $old_index -> $new_index; current VIP owner retained"
  else
    verdict FAILOVER-FRONTEND.recreate FAIL "same-name frontend replacement did not preserve the elected VIP owner"
  fi
)

frontend_case
