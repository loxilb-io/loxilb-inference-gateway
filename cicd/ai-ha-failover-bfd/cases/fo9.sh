# FO-9  Failover while the key store is down.   (sourced by validation.sh)
#
# PostgreSQL is stopped, then the MASTER dies. Two keys minted for this case:
# one the old master has served (so it is in that node's cache and in no
# other), one no gateway has ever seen. RECORDED: what each key and a JWT get
# on the new master (status, error code, Retry-After). PASS/FAIL: after
# PostgreSQL starts again, the never-seen key and the JWT answer 200 through
# the VIP and the gateway process is the one that was running (no restart).
#
# Mutation: fo9-skip-pg-start leaves the store down for the recovery check,
# which must then FAIL.

echo; echo "FO-9  Failover while the key store is down"
F9_DIR="$OUT/fo9"; mkdir -p "$F9_DIR"
f9_line() { # <label> — prints "status code, Retry-After r, N ms" from the last vreq
  echo "$1: $2, Retry-After '$(echo "$VREQ_JSON" | jget "d['first_attempt'].get('retry_after','')")', $(echo "$VREQ_JSON" | jget "d['first_attempt']['latency_ms']") ms, receipts=$(receipts "$VREQ_NONCE")"
}
store_view() { echo "$1 circuit_open=$(metric "$1" loxilb_ai_key_store_circuit_open) lookup_inflight=$(metric "$1" loxilb_ai_key_store_lookup_inflight)"; }

if ! fo_begin; then
  verdict FO-9 NOT_RUN "roles did not hold before the fault ($ROLE_LAST)"
else
  pre_ok=1
  read -r _ K_USED <<<"$(mint_key_now "$M" "fo9-used-$$" fo9-tenant)"
  read -r _ K_NEW  <<<"$(mint_key_now "$M" "fo9-new-$$" fo9-tenant)"
  read -r _ K_NEW2 <<<"$(mint_key_now "$M" "fo9-new2-$$" fo9-tenant)"
  TOK=$(kc_mint aigw-client alice alicepw)
  [ -n "$K_USED" ] && [ -n "$K_NEW" ] && [ -n "$K_NEW2" ] && [ -n "$TOK" ] || { pre_ok=0; note "FO-9 pre: could not mint the keys or the token"; }
  vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K_USED" fo9-pre-key; a=$VREQ_OUT; [ "${a%% *}" = 200 ] || { pre_ok=0; note "FO-9 pre: the key answered $a with the store up"; }
  vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" fo9-pre-jwt; a=$VREQ_OUT; [ "${a%% *}" = 200 ] || { pre_ok=0; note "FO-9 pre: the token answered $a with the store up"; }
  { store_view "$M"; store_view "$S"; } > "$F9_DIR/store-before.txt"

  if [ "$pre_ok" != 1 ]; then
    verdict FO-9 NOT_RUN "a precondition failed with the store up; see notes.log"
  else
    docker stop -t 5 "$PG_NAME" >/dev/null 2>&1
    pg_down=$(now_ms)
    note "FO-9: PostgreSQL stopped"
    # The old master with the store down, before any failover.
    {
      vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K_USED" fo9-old-used; a=$VREQ_OUT; f9_line "old master $M, key it has served" "$a"
      vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K_NEW2" fo9-old-new; a=$VREQ_OUT; f9_line "old master $M, key no gateway has seen" "$a"
      vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" fo9-old-jwt; a=$VREQ_OUT; f9_line "old master $M, JWT" "$a"
    } > "$F9_DIR/old-master-store-down.txt"
    spid=$(loxilb_pid "$S")
    if ! fo_fault; then
      verdict FO-9 NOT_RUN "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
    else
      note "FO-9: node death of $M at t0=$T0, store down since $(( T0 - pg_down )) ms; $S listener after ${LISTEN_MS} ms"
      # The first answers the new master gives, then what a client that keeps
      # asking for 10 s sees.
      {
        vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K_NEW" fo9-new-new; a=$VREQ_OUT; f9_line "new master $S, key no gateway has seen" "$a"; first_new=$a
        vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K_USED" fo9-new-used; a=$VREQ_OUT; f9_line "new master $S, key only the old master served" "$a"; first_used=$a
        vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" fo9-new-jwt; a=$VREQ_OUT; f9_line "new master $S, JWT" "$a"; first_jwt=$a
      } > "$F9_DIR/new-master-store-down.txt"
      r=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $K_NEW" 10 fo9-down); echo "$r" > "$F9_DIR/key-retry-store-down.json"
      rj=$(vretry $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" 10 fo9-down-jwt); echo "$rj" > "$F9_DIR/jwt-retry-store-down.json"
      store_view "$S" > "$F9_DIR/store-down-on-new-master.txt"
      verdict FO-9.store-down RECORDED "$(tr '\n' ';' < "$F9_DIR/new-master-store-down.txt") over 10 s the unseen key got: $(echo "$r" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])"); the JWT got: $(echo "$rj" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])"); $(cat "$F9_DIR/store-down-on-new-master.txt")"
      verdict FO-9.old-master RECORDED "before the fault, store already down: $(tr '\n' ';' < "$F9_DIR/old-master-store-down.txt")"

      # Recovery.
      if [ "${HAFO_MUTATE:-}" = fo9-skip-pg-start ]; then
        note "FO-9: MUTATION, PostgreSQL is not started before the recovery check"
      else
        docker start "$PG_NAME" >/dev/null 2>&1
      fi
      pg_up=$(now_ms)
      pg_ip_now=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME" 2>/dev/null)
      rk=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $K_NEW" 60 fo9-up 0.5); echo "$rk" > "$F9_DIR/key-retry-store-up.json"
      gk=$(receipts "$(echo "$rk" | jget "d['last_nonce']")")
      rj=$(vretry $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" 10 fo9-up-jwt); echo "$rj" > "$F9_DIR/jwt-retry-store-up.json"
      spid_now=$(loxilb_pid "$S")
      seq=$(echo "$rk" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")
      if [ "${HAFO_MUTATE:-}" != fo9-skip-pg-start ] && [ "$pg_ip_now" != "$(cat "$HAFO_DIR/.pg-ip")" ]; then
        verdict FO-9 NOT_RUN "PostgreSQL came back on $pg_ip_now, the gateways were started with $(cat "$HAFO_DIR/.pg-ip")"
      elif [ "$(echo "$rk" | jget "d['ok']")" = True ] && [ "$gk" = 1 ] && [ "$(echo "$rj" | jget "d['ok']")" = True ] && [ "$spid_now" = "$spid" ]; then
        verdict FO-9 PASS "after PostgreSQL started the unseen key answered 200 in $(echo "$rk" | jget "d['first_200_after_ms']") ms ($seq; receipts=1) and the JWT answered 200; the gateway process on $S is the same one (pid $spid)"
      else
        verdict FO-9 FAIL "after PostgreSQL started: unseen key $seq (receipts=$gk); JWT ok=$(echo "$rj" | jget "d['ok']"); gateway pid on $S $spid -> ${spid_now:-none}"
      fi
      store_view "$S" > "$F9_DIR/store-after.txt"
    fi
    # The store must be up before the dead node returns, whatever happened.
    docker start "$PG_NAME" >/dev/null 2>&1
    for _ in $(seq 1 60); do docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1 && break; sleep 0.5; done
    [ "$(role "$M")" = UNREACHABLE ] && fo_restore
  fi
fi
