# FAILOVER-2, FAILOVER-3, FAILOVER-4  Credentials through one failover.   (sourced by validation.sh)
#
#   FAILOVER-2  the same API key keeps working, with no management call
#   FAILOVER-3  the same JWT keeps working, the client makes no IdP call, and an
#         expired token is refused on the new master
#   FAILOVER-4  a key deleted on the old master is still refused on the new one
#
# The three use separate identities, so one failover serves all of them.
# Mutations: fo2-delete-key (the key is deleted before the fault),
# fo3-wrong-aud (config.sh gives the profile an audience no token carries),
# fo4-skip-delete (the delete is skipped; the oracle must then see a 200).

echo; echo "FAILOVER-2 / FAILOVER-3 / FAILOVER-4  Do the same credentials keep working?"
C_DIR="$OUT/fo2-4"; mkdir -p "$C_DIR"
c_notrun() { for c in FAILOVER-2 FAILOVER-3 FAILOVER-4; do verdict "$c" NOT_RUN "$1"; done; }

if ! fo_begin; then
  c_notrun "roles did not hold before the fault ($ROLE_LAST)"
else
  K2=$(key_raw fo2-key); KDEL=$(key_raw fo4-del-key); KCTL=$(key_raw fo4-ctl-key)
  TOK=$(kc_mint aigw-client alice alicepw)
  TOK_SHORT=$(kc_mint aigw-short alice alicepw)
  pre_ok=1
  [ -n "$TOK" ] && [ -n "$TOK_SHORT" ] || { pre_ok=0; note "FAILOVER-3: the IdP did not mint the tokens"; }
  # "The client makes no IdP call" is observed, not assumed: the client is a
  # container on the docker bridge and could reach the IdP, so every packet
  # between the two is captured from here to the end of FAILOVER-3. The harness
  # mints the tokens from the host, before this point.
  CLIENT_ETH0=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CLIENT)
  sudo tcpdump -i docker0 -nn -tt -l "host $CLIENT_ETH0 and host $KC_IP" > "$C_DIR/client-idp-packets.txt" 2>"$C_DIR/client-idp-capture.log" &
  IDP_CAP=$!
  sleep 1
  if ! grep -q 'listening on ' "$C_DIR/client-idp-capture.log" || ! sudo kill -0 "$IDP_CAP" 2>/dev/null; then
    pre_ok=0
    note "FAILOVER-3: could not start the client-to-IdP packet capture"
  fi

  # Before the fault: every credential is used once on the old master.
  vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K2" fo2-pre; a=$VREQ_OUT;    [ "${a%% *}" = 200 ] || { pre_ok=0; note "FAILOVER-2 pre: key answered $a on the old master"; }
  vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" fo3-pre; a=$VREQ_OUT; [ "${a%% *}" = 200 ] || { [ "${HAFO_MUTATE:-}" = fo3-wrong-aud ] || pre_ok=0; note "FAILOVER-3 pre: token answered $a on the old master"; }
  vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $KDEL" fo4-pre; a=$VREQ_OUT;  [ "${a%% *}" = 200 ] || { pre_ok=0; note "FAILOVER-4 pre: the key answered $a before its delete"; }
  # FAILOVER-4: delete on the master, confirm 401 there.
  if [ "${HAFO_MUTATE:-}" = fo4-skip-delete ]; then
    note "FAILOVER-4: MUTATION, the delete is skipped"
  else
    api "$M" DELETE "/config/ai/apikey/$(key_id fo4-del-key)" > "$C_DIR/fo4-delete.txt"
    vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $KDEL" fo4-pre401; a=$VREQ_OUT
    [ "${a%% *}" = 401 ] || { pre_ok=0; note "FAILOVER-4 pre: the deleted key answered $a on the old master (want 401)"; }
    echo "old master after delete: $a" >> "$C_DIR/fo4-delete.txt"
  fi
  if [ "${HAFO_MUTATE:-}" = fo2-delete-key ]; then
    note "FAILOVER-2: MUTATION, the key is deleted before the fault"
    api "$M" DELETE "/config/ai/apikey/$(key_id fo2-key)" >/dev/null
  fi
  miss_before=$(metric "$S" loxilb_ai_key_store_lookup_seconds_count 'result="miss_found"')
  jwks_before="$M=$(metric "$M" loxilb_ai_jwks_refresh_total 'outcome="success"') $S=$(metric "$S" loxilb_ai_jwks_refresh_total 'outcome="success"')"
  sync_mark
  vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $(key_raw fo-seed-key)" c-seed
  sync_advanced || { pre_ok=0; note "sync liveness: push count on $M did not advance ($SYNC_MARK), seed request answered $VREQ_OUT"; }

  if [ "$pre_ok" != 1 ]; then
    c_notrun "a precondition failed before the fault; see notes.log"
  elif ! fo_fault; then
    c_notrun "the survivor $S held no listener on $VIP:$PORT_KEY within 60 s of the fault"
    fo_restore
  else
    note "FAILOVER-2/3/4: node death of $M at t0=$T0; $S listener after ${LISTEN_MS} ms"
    # ---- FAILOVER-2
    r=$(vretry $PORT_KEY $MODEL_KEY "X-Api-Key: $K2" 60 fo2); echo "$r" > "$C_DIR/fo2-retry.json"
    got=$(receipts "$(echo "$r" | jget "d['last_nonce']")")
    seq=$(echo "$r" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")
    if [ "$(echo "$r" | jget "d['ok']")" = True ] && [ "$got" = 1 ]; then
      verdict FAILOVER-2 PASS "the pre-existing key answered 200 through the VIP with no management call; backend receipts=1"
    else
      verdict FAILOVER-2 FAIL "the pre-existing key did not answer 200 within 60 s (receipts=$got); sequence: $seq"
    fi
    verdict FAILOVER-2.first-request RECORDED "attempts until 200: $(echo "$r" | jget "d['attempts']") over $(echo "$r" | jget "d['first_200_after_ms']") ms; sequence: $seq; the 200 itself took $(echo "$r" | jget "d['first_200_latency_ms']") ms"
    vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $K2" fo2-second; a2=$VREQ_OUT
    miss_after=$(metric "$S" loxilb_ai_key_store_lookup_seconds_count 'result="miss_found"')
    verdict FAILOVER-2.cache RECORDED "second request with the same key: $a2 in $(echo "$VREQ_JSON" | jget "d['first_attempt']['latency_ms']") ms; store lookups (miss_found) on $S: $miss_before before the fault, $miss_after after"
    # 200 distinct keys reconnect at once, released by one barrier.
    b=$(sudo ip netns exec $CLIENT python3 "$HAFO_DIR/hafo_tools.py" burst --vip $VIP --port $PORT_KEY --model $MODEL_KEY \
        --headers-file "$HAFO_DIR/.burst-headers" --timeout 10 --tag fo2-burst --out "$C_DIR/fo2-burst.jsonl")
    echo "$b" > "$C_DIR/fo2-burst.json"
    verdict FAILOVER-2.burst RECORDED "$(echo "$b" | jget "'%d keys at once (send spread %s ms, %s ms after the fault): %s; 200 latency %s; Retry-After %s' % (d['n'], d['send_spread_ms'], d['t_first_send'] - $T0, ', '.join('%s=%d' % kv for kv in sorted(d['counts'].items())), d['ok_latency_ms'], d['retry_after'])")"
    echo "after the burst on $S: inflight=$(metric "$S" loxilb_ai_key_store_lookup_inflight) circuit_open=$(metric "$S" loxilb_ai_key_store_circuit_open) lookups: $($hexec "$S" curl -s -m 5 http://127.0.0.1:11111/netlox/v1/metrics | grep '^loxilb_ai_key_store_lookup_seconds_count' | tr '\n' ' ')" > "$C_DIR/fo2-burst-metrics.txt"

    # ---- FAILOVER-3
    r=$(vretry $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" 60 fo3); echo "$r" > "$C_DIR/fo3-retry.json"
    got=$(receipts "$(echo "$r" | jget "d['last_nonce']")")
    seq=$(echo "$r" | jget "' '.join('%s x%d' % (a, b) for a, b in d['sequence'])")
    vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK_SHORT" fo3-expired; ae=$VREQ_OUT; ge=$(receipts "$VREQ_NONCE")
    vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer not.a.token" fo3-garbage; ag=$VREQ_OUT; gg=$(receipts "$VREQ_NONCE")
    sleep 1; sudo kill "$IDP_CAP" 2>/dev/null; sudo pkill -x tcpdump -P "$IDP_CAP" 2>/dev/null; wait "$IDP_CAP" 2>/dev/null; IDP_CAP=""
    idp_pkts=$(grep -c . "$C_DIR/client-idp-packets.txt")
    if [ "$(echo "$r" | jget "d['ok']")" = True ] && [ "$got" = 1 ] && [ "${ae%% *}" = 401 ] && [ "$ge" = 0 ] && [ "${ag%% *}" = 401 ] && [ "$gg" = 0 ] && [ "$idp_pkts" = 0 ]; then
      verdict FAILOVER-3 PASS "a token minted before the fault answered 200 (receipts=1); no packet passed between the client ($CLIENT_ETH0) and the IdP ($KC_IP) from before the fault to here; the expired token got $ae and a garbage token got $ag, both with receipts=0"
    else
      verdict FAILOVER-3 FAIL "pre-fault token: $seq (receipts=$got); packets between the client and the IdP: $idp_pkts; expired token: $ae (receipts=$ge); garbage token: $ag (receipts=$gg)"
    fi
    verdict FAILOVER-3.first-request RECORDED "attempts until 200: $(echo "$r" | jget "d['attempts']"); sequence: $seq"
    # H6: the new master verifies with its own JWKS while the IdP is unreachable.
    docker pause "$KC_NAME" >/dev/null 2>&1
    vreq $PORT_JWT $MODEL_JWT "Authorization: Bearer $TOK" fo3-idp-paused; ap=$VREQ_OUT
    docker unpause "$KC_NAME" >/dev/null 2>&1
    verdict FAILOVER-3.idp-paused RECORDED "with the IdP paused the pre-fault token answered $ap; JWKS refresh successes before the fault: $jwks_before; on $S now: $(metric "$S" loxilb_ai_jwks_refresh_total 'outcome="success"')"

    # ---- FAILOVER-4
    vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $KDEL" fo4-post; a=$VREQ_OUT; gd=$(receipts "$VREQ_NONCE")
    vreq $PORT_KEY $MODEL_KEY "X-Api-Key: $KCTL" fo4-ctl; c=$VREQ_OUT;  gc=$(receipts "$VREQ_NONCE")
    if [ "${a%% *}" = 401 ] && [ "$gd" = 0 ] && [ "${c%% *}" = 200 ] && [ "$gc" = 1 ]; then
      verdict FAILOVER-4 PASS "the key deleted on the old master answered $a on the new one (receipts=0); the control key answered 200 (receipts=1)"
    else
      verdict FAILOVER-4 FAIL "deleted key on the new master: $a (receipts=$gd, want 401 and 0); control key: $c (receipts=$gc, want 200 and 1)"
    fi
    fo_restore
  fi
  [ -n "${IDP_CAP:-}" ] && { sudo kill "$IDP_CAP" 2>/dev/null; sudo pkill -x tcpdump -P "$IDP_CAP" 2>/dev/null; wait "$IDP_CAP" 2>/dev/null; }
fi
