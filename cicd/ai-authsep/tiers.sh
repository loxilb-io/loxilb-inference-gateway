#!/bin/bash
# tiers.sh — the combination tiers, A through E, against the ai-authsep
# topology. Run AFTER config.sh; leaves the topology in the advertised posture.
#
#   Tier A  independence core: 3 management-auth modes × 3 store states,
#           3 VIPs × 4 credential classes each — the per-COLUMN assertion is
#           the point: verdicts must be byte-identical across all three values
#           of the management axis, or the axis leaked into the data plane.
#           The oauth2 mode is EXCLUDED: OAuth2 management auth is incomplete
#           and unstable (the gateway does not reliably start under --oauth2),
#           so covering it here would assert properties of a feature that is
#           not finished. Reported SKIPPED at the end, loudly, like Tier F.
#   Tier B  streaming independence: policy × streaming crossed as 9 rules in
#           one process; the verdict must depend only on the policy.
#   Tier C  credential semantics: adversarial classes against one required VIP.
#   Tier D  QoS coupling: each limit kind enforces under `required` with its
#           OWN error_code, and configures-but-never-enforces under `disabled`.
#   Tier E  transitions: the defects that live in the change, not the state.
#
# Tier F (HA pair) is not here: it needs a second gateway and cluster peering,
# and a suite that silently covered less than it claims would be worse than
# one that says so. It is reported SKIPPED at the end, loudly.
#
# Rules this file follows: every deny asserts the error_code, not
# just the status; every store-down leg runs with a cold cache (the gateway is
# restarted AFTER the store stops, and snapshot.json is removed so no rule —
# and no warm state — survives); a red leg is a code defect until proven
# otherwise; observed values are printed, not just verdicts.
cd "$(dirname "$0")"
source .state

API=http://localhost:11111/netlox/v1
VIP=10.10.10.254
PASS=0; FAIL=0

chk() { # chk <name> <want> <got>
  if [ "$2" = "$3" ]; then echo "  [PASS] $1 (got $3)"; PASS=$((PASS + 1))
  else echo "  [FAIL] $1 expected=$2 got=$3"; FAIL=$((FAIL + 1)); fi
}
chk_has() {
  case "$3" in *"$2"*) echo "  [PASS] $1"; PASS=$((PASS + 1));;
  *) echo "  [FAIL] $1 — did not find '$2' in: $(echo "$3" | head -c 200)"; FAIL=$((FAIL + 1));; esac
}

# Every management call carries the credential the active mode demands. The
# swagger security block is global, so with --userservice, --oauth2 or
# --manualtoken on, an unauthenticated POST /config/loadbalancer is refused —
# a tokenless harness would read that refusal as a data-plane defect.
AUTH_HDR=""
lcurl() {
  if [ -n "$AUTH_HDR" ]; then
    docker exec llb1 curl -s -m 30 -H "Authorization: $AUTH_HDR" "$@"
  else
    docker exec llb1 curl -s -m 30 "$@"
  fi
}

MGMT_USER=tiersadmin
MGMT_PASS='TiersAdm1n!pass'
mgmt_login() { # mgmt_login <none|usvc|manual> — arms AUTH_HDR for lcurl
  case "$1" in
    none)   AUTH_HDR=""; return 0;;
    manual) AUTH_HDR="tiers-manual-token-1"; return 0;;
  esac
  # usvc validates bearer tokens against the user service, so mint a login
  # token. The first login on an empty user table is preceded by the loopback
  # bootstrap; the setup TRUNCATE makes that state deterministic.
  local tok
  tok=$(docker exec llb1 curl -s -m 10 -X POST $API/auth/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"$MGMT_USER\",\"password\":\"$MGMT_PASS\"}" \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")' 2>/dev/null)
  if [ -z "$tok" ]; then
    docker exec llb1 curl -s -o /dev/null -m 10 -X POST $API/auth/users -H 'Content-Type: application/json' \
      -d "{\"username\":\"$MGMT_USER\",\"password\":\"$MGMT_PASS\",\"role\":\"admin\"}"
    tok=$(docker exec llb1 curl -s -m 10 -X POST $API/auth/login -H 'Content-Type: application/json' \
      -d "{\"username\":\"$MGMT_USER\",\"password\":\"$MGMT_PASS\"}" \
      | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")' 2>/dev/null)
  fi
  if [ -z "$tok" ]; then
    echo "FATAL: management login failed for mode=$1 — a user other than"
    echo "       $MGMT_USER may already exist in aigw_mgmt.users (bootstrap closed)."
    return 1
  fi
  AUTH_HDR="$tok"
}

# probe <port> <extra curl args...> → "<code> <error_code-or-->" on stdout.
# Status AND error code together, because 401 invalid_api_key and 401
# policy_store_unavailable are different defects wearing the same status.
probe() {
  local port="$1"; shift
  local out code body err
  out=$(docker exec l3h1 curl -s -m 20 -w '\n%{http_code}' \
    -X POST "http://$VIP:$port/v1/chat/completions" \
    -H 'Content-Type: application/json' "$@")
  code=$(echo "$out" | tail -1)
  body=$(echo "$out" | sed '$d')
  err=$(echo "$body" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("error","-"))
except Exception: print("-")' 2>/dev/null)
  echo "$code ${err:--}"
}

BODY_OK='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'
BODY_BADMODEL='{"model":"mistral-7b","messages":[{"role":"user","content":"hi"}]}'

restart_gw() { # restart_gw <flags...> — always cold: no snapshot, no cache
  rm -f llb1_config/snapshot.json
  start_gw "$@"
}

# Cold CACHE, but the snapshot stays, so rules replay at startup. The
# store-down cells need this: with --userservice the management credential is
# validated against the same store, so once it is down no rule can be created
# at all — the rules are installed store-up and carried across the restart.
restart_gw_keep() {
  start_gw "$@" || return 1
  # The boot restore RETRIES while late subsystems (ipsec, bgp) come up, and
  # every failed attempt rolls the whole config back to empty — so for tens
  # of seconds after the API answers, the replayed rules flap in and out.
  # Probing inside that window turns replay races into phantom data-plane
  # verdicts. Wait for the restore to settle before returning.
  for _ in $(seq 1 30); do
    docker exec llb1 grep -aq "boot snapshot: snapshot.json applied" /tmp/loxilb.out 2>/dev/null && return 0
    sleep 2
  done
  echo "  boot snapshot never settled; restore lines:"
  docker exec llb1 grep -a "boot snapshot" /tmp/loxilb.out 2>/dev/null | tail -5
  return 1
}

start_gw() {
  docker exec llb1 pkill -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
  for _ in $(seq 1 15); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
  done
  # A survivor keeps the port; the new process dies at bind and every leg
  # that follows silently runs against the OLD flag set. Escalate, and stop
  # the tier rather than measure a process this cell did not configure.
  if docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
    echo "  (old gateway survived SIGTERM for 15s; escalating to SIGKILL)"
    docker exec llb1 pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
    for _ in $(seq 1 10); do
      docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
      sleep 1
    done
  fi
  if docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
    echo "  FATAL: the old gateway process would not die; refusing to run legs against it"
    return 1
  fi
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
  docker exec -d llb1 bash -c "ulimit -l unlimited; /root/loxilb-io/loxilb/loxilb $* > /tmp/loxilb.out 2> /tmp/loxilb.err"
  for _ in $(seq 1 40); do
    if docker exec llb1 curl -sf -m 3 $API/version >/dev/null 2>&1; then
      sleep 25; return 0
    fi
    sleep 2
  done
  echo "  gateway did not come back; stderr tail:"
  docker exec llb1 tail -20 /tmp/loxilb.err
  return 1
}

mk_rule() { # mk_rule <port> <sse:true|false> <pd:true|false> <policy:required|disabled|->
  local pol="" eps
  [ "$4" != "-" ] && pol=",\"api_key_auth\":\"$4\""
  # A P/D rule refuses to install without >=1 prefill and >=1 decode endpoint
  # (dead config fails loudly at create time). Both roles point at LIVE mock
  # instances (config.sh runs count_server on :8080 and :8081); the tier
  # still only ASSERTS gate verdicts on P/D rows — admit mechanics need a
  # real engine and belong to the engine matrix.
  if [ "$3" = "true" ]; then
    eps='[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1,"ep_role":1},{"endpointIP":"31.31.31.1","targetPort":8081,"weight":1,"ep_role":2}]'
  else
    eps='[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]'
  fi
  lcurl -o /dev/null -X POST $API/config/loadbalancer -H 'Content-Type: application/json' \
    -d "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":$1,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":$2,\"pd_disagg_mode\":$3$pol,\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":$eps}"
}

rm_rule() { # rm_rule <port>
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp"
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/externalipaddress/$VIP/port/$1/protocol/tcp"
}

pg_ready() {
  for _ in $(seq 1 30); do
    docker exec -e PGPASSWORD=oampass aisep-pg psql -h 127.0.0.1 -U oamuser -d loxilb -tAc 'SELECT 1' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

mkkey() { # mkkey <tenant> <name> <models-json> <rps> <burst> <tpm> → raw key
  lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$1\",\"name\":\"$2\",\"allowed_models\":$3,\"rate_limit_rps\":$4,\"burst_size\":$5,\"tokens_per_min\":$6,\"enabled\":true}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null
}

################################################################################
echo "===== TIER SETUP: key material minted once, store up, no management ====="
################################################################################
docker start aisep-pg >/dev/null 2>&1; pg_ready
# The usvc cells bootstrap their management user over loopback, which
# only works while the user table is empty — make that state deterministic
# rather than inherited from whatever ran before. (The tables exist once any
# --userservice gateway has started against this store; tolerate their
# absence on a virgin store, where the bootstrap is open anyway.)
docker exec -e PGPASSWORD=oampass aisep-pg psql -h 127.0.0.1 -U oamuser -d loxilb \
  -c 'TRUNCATE aigw_mgmt.users, aigw_mgmt.token' >/dev/null 2>&1 \
  || echo "  (aigw_mgmt tables not present yet — bootstrap is open)"
restart_gw $AIKEY_ARGS || exit 1
K_VAL=$(mkkey tiers-t1 val '[]' 500 1000 0)
K_MODEL=$(mkkey tiers-t1 model '["llama-3"]' 500 1000 0)
K_UNKNOWN="lxb_00000000000000000000000000000000"
[ -n "$K_VAL" ] && [ -n "$K_MODEL" ] || { echo "FATAL: key mint failed"; exit 1; }
echo "  minted: val=${K_VAL:0:12}… model=${K_MODEL:0:12}…"
# The manual-token mode needs its token file where the flag's default looks.
echo "tiers-manual-token-1" > llb1_config/manual_token

################################################################################
echo ""
echo "===== TIER A: independence core (3 modes x 3 stores, 3 VIPs x 4 creds; oauth2 excluded) ====="
################################################################################
# Expected verdicts per (store, policy), from the campaign's decision table.
# The absent-policy VIP behaves as disabled in every cell — a decided
# default, asserted here 48 times rather than assumed.
expected() { # expected <store> <policy> <cred> → "code err"
  case "$2" in
    required)
      case "$1" in
        up)   case "$3" in absent) echo "401 invalid_api_key";; valid) echo "200 -";;
                           invalid) echo "401 invalid_api_key";; badmodel) echo "403 model_not_allowed";; esac;;
        # Store DOWN is an operational outage: every verdict on a PRESENTED
        # key is the store's outage, never a verdict on the key — except the
        # absent-credential case, which is refused without the store being
        # consulted at all: there is no credential to examine, so no keyholder
        # can be misdirected into rotating a healthy key. (Live-verified:
        # absent → 401 with the store stopped.)
        down)   case "$3" in absent) echo "401 invalid_api_key";;
                             *) echo "503 policy_store_unavailable";; esac;;
        # Store NEVER CONFIGURED is an operator error: a required service
        # with no store to enforce against answers 503 for every request,
        # absent credential included — the misconfiguration must be loud,
        # not selectively serviceable. (Live-verified; the presented-key
        # half is also DP-21's row.)
        unconf) echo "503 policy_store_unavailable";;
      esac;;
    disabled|absent)
      echo "200 -";;
  esac
}

declare -A VEC   # VEC[mode,store] = the 12-verdict vector
for STORE in up down unconf; do
  for MODE in none usvc manual; do
    case "$MODE" in
      none)   MARGS="";;
      usvc)   MARGS="$MGMT_ARGS";;
      manual) MARGS="--manualtoken";;
    esac
    echo ""
    echo "--- config mode=$MODE store=$STORE ---"
    if [ "$STORE" = "down" ]; then
      # The rules are installed while the store is up (under usvc the
      # management credential is validated against the same store, so nothing
      # can be configured once it is down), then the store is stopped and the
      # gateway restarted KEEPING the snapshot: the rules replay, the key
      # cache is cold — the state these tiers demand.
      docker start aisep-pg >/dev/null 2>&1; pg_ready; SARGS="$AIKEY_ARGS"
      restart_gw $SARGS $MARGS || exit 1
      mgmt_login $MODE || exit 1
      mk_rule 2020 false false required
      mk_rule 2021 true  false disabled
      mk_rule 2022 true  false -
      sleep 3   # let auto-persist write the snapshot the replay depends on
      ls -l llb1_config/snapshot.json 2>/dev/null | sed 's/^/    snapshot: /' \
        || echo "    snapshot: MISSING — the down cells below will read as dead rules"
      docker stop aisep-pg >/dev/null 2>&1
      restart_gw_keep $SARGS $MARGS || exit 1
    else
      case "$STORE" in
        up)     docker start aisep-pg >/dev/null 2>&1; pg_ready; SARGS="$AIKEY_ARGS";;
        unconf) docker start aisep-pg >/dev/null 2>&1; pg_ready; SARGS="";;
      esac
      restart_gw $SARGS $MARGS || exit 1
      mgmt_login $MODE || exit 1
      mk_rule 2020 false false required
      mk_rule 2021 true  false disabled
      mk_rule 2022 true  false -
    fi
    sleep 3
    V=""
    for PORT in 2020 2021 2022; do
      case "$PORT" in 2020) POL=required;; 2021) POL=disabled;; 2022) POL=absent;; esac
      for CRED in absent valid invalid badmodel; do
        case "$CRED" in
          absent)   GOT=$(probe $PORT -d "$BODY_OK");;
          valid)    GOT=$(probe $PORT -H "X-Api-Key: $K_VAL" -d "$BODY_OK");;
          invalid)  GOT=$(probe $PORT -H "X-Api-Key: $K_UNKNOWN" -d "$BODY_OK");;
          badmodel) GOT=$(probe $PORT -H "X-Api-Key: $K_MODEL" -d "$BODY_BADMODEL");;
        esac
        WANT=$(expected $STORE $POL $CRED)
        # On non-enforcing services the error field is whatever the mock
        # returns; only the code is the contract there.
        if [ "${WANT% *}" = "200" ]; then GOT="${GOT% *} -"; fi
        chk "A[$MODE/$STORE] :$PORT($POL) $CRED" "$WANT" "$GOT"
        V="$V|$GOT"
      done
    done
    VEC[$MODE,$STORE]="$V"
  done
  # The per-column assertion — the actual independence claim. Cell checks
  # above localise a defect; this is the property.
  for MODE in usvc manual; do
    if [ "${VEC[none,$STORE]}" = "${VEC[$MODE,$STORE]}" ]; then
      echo "  [PASS] A-independence store=$STORE: mode=$MODE vector identical to mode=none"; PASS=$((PASS + 1))
    else
      echo "  [FAIL] A-independence store=$STORE: mode=$MODE vector DIFFERS from mode=none:"
      echo "     none:  ${VEC[none,$STORE]}"
      echo "     $MODE: ${VEC[$MODE,$STORE]}"
      FAIL=$((FAIL + 1))
    fi
  done
done
docker start aisep-pg >/dev/null 2>&1; pg_ready
mgmt_login none   # Tiers B-E run without a management mode

################################################################################
echo ""
echo "===== TIER B: streaming independence (9 rules, one process) ====="
################################################################################
# The regression grid for the original defect: enforcement used to be derived
# from the streaming flags. Nine rules cross policy with streaming; the
# verdict must depend only on the policy column. The P/D rows are probed for
# their GATE verdict — a P/D rule pointed at this mock cannot serve a real
# 200 end-to-end, so the admit legs on those rows record what the relay did
# without failing the tier on backend mechanics the engines cover later.
restart_gw $AIKEY_ARGS || exit 1
PORTB=2030
declare -A BPORT
for POL in required disabled -; do
  for D in plain sse pd; do
    case "$D" in
      plain) SSE=false; PD=false;;
      sse)   SSE=true;  PD=false;;
      pd)    SSE=false; PD=true;;
    esac
    mk_rule $PORTB $SSE $PD $POL
    BPORT[$POL,$D]=$PORTB
    PORTB=$((PORTB + 1))
  done
done
sleep 3
for POL in required disabled -; do
  case "$POL" in
    required) WA="401 invalid_api_key";;
    *)        WA="200 -";;
  esac
  for D in plain sse pd; do
    P=${BPORT[$POL,$D]}
    GA=$(probe $P -d "$BODY_OK")
    [ "${WA% *}" = "200" ] && GA="${GA% *} -"
    if [ "$D" = "pd" ] && [ "${WA% *}" = "200" ]; then
      # Deny verdicts on a P/D rule are the gate's and assertable; the admit
      # path needs a real P/D backend. Record, don't assert.
      echo "  [INFO] B :$P($POL/$D) absent → $GA (admit path not assertable on the mock; deny rows are)"
    else
      chk "B :$P($POL/$D) absent" "$WA" "$GA"
    fi
    GV=$(probe $P -H "X-Api-Key: $K_VAL" -d "$BODY_OK")
    if [ "$D" = "pd" ]; then
      echo "  [INFO] B :$P($POL/$D) valid → $GV (recorded; P/D admit mechanics are the engine matrix's)"
    else
      chk "B :$P($POL/$D) valid" "200 -" "${GV% *} -"
    fi
  done
done
for POL in required disabled -; do for D in plain sse pd; do rm_rule ${BPORT[$POL,$D]}; done; done

################################################################################
echo ""
echo "===== TIER C: credential semantics (adversarial classes, one required VIP) ====="
################################################################################
mk_rule 2020 false false required
mk_rule 2021 true false disabled
sleep 3
chk "C absent header"        "401 invalid_api_key" "$(probe 2020 -d "$BODY_OK")"
chk "C empty value"          "401 invalid_api_key" "$(probe 2020 -H 'X-Api-Key;' -d "$BODY_OK")"
chk "C whitespace value"     "401 invalid_api_key" "$(probe 2020 -H 'X-Api-Key:    ' -d "$BODY_OK")"
chk "C unknown key"          "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $K_UNKNOWN" -d "$BODY_OK")"
chk "C well-formed, never issued" "401 invalid_api_key" "$(probe 2020 -H 'X-Api-Key: lxb_deadbeefdeadbeefdeadbeefdeadbeef' -d "$BODY_OK")"

K_OFF=$(mkkey tiers-t1 toggled '[]' 500 1000 0)
KID_OFF=$(lcurl "$API/config/ai/apikey?tenant_id=tiers-t1" | python3 -c 'import sys,json
for k in json.load(sys.stdin):
    if k.get("name")=="toggled": print(k["key_id"]); break' 2>/dev/null)
lcurl -o /dev/null -X PATCH "$API/config/ai/apikey/$KID_OFF" -H 'Content-Type: application/json' -d '{"enabled":false}'
sleep 1
chk "C enabled=0 key"        "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $K_OFF" -d "$BODY_OK")"

K_EXPIRED=$(lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tiers-t1","name":"expired","allowed_models":[],"rate_limit_rps":500,"tokens_per_min":0,"enabled":true,"expires_at":"2020-01-01T00:00:00.000Z"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
chk "C expired key"          "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $K_EXPIRED" -d "$BODY_OK")"

# Revoked one second earlier: revocation invalidates the local cache
# immediately, observed at the VIP.
K_REVOKED=$(mkkey tiers-t1 revoked '[]' 500 1000 0)
probe 2020 -H "X-Api-Key: $K_REVOKED" -d "$BODY_OK" >/dev/null   # warm the cache — revocation must beat it
KID_REV=$(lcurl "$API/config/ai/apikey?tenant_id=tiers-t1" | python3 -c 'import sys,json
for k in json.load(sys.stdin):
    if k.get("name")=="revoked": print(k["key_id"]); break' 2>/dev/null)
lcurl -o /dev/null -X PATCH "$API/config/ai/apikey/$KID_REV" -H 'Content-Type: application/json' -d '{"enabled":false}'
sleep 1
chk "C revoked one second earlier (cache invalidated)" "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $K_REVOKED" -d "$BODY_OK")"

chk "C model outside allow-list" "403 model_not_allowed" "$(probe 2020 -H "X-Api-Key: $K_MODEL" -d "$BODY_BADMODEL")"
chk "C empty allow-list means all" "200" "$(probe 2020 -H "X-Api-Key: $K_VAL" -d "$BODY_BADMODEL" | awk '{print $1}')"
chk "C lower-case header name"   "200" "$(probe 2020 -H "x-api-key: $K_VAL" -d "$BODY_OK" | awk '{print $1}')"

# Duplicate header: deterministic, never a concatenation into a third value.
DUP1=$(probe 2020 -H "X-Api-Key: $K_VAL" -H "X-Api-Key: $K_UNKNOWN" -d "$BODY_OK")
DUP2=$(probe 2020 -H "X-Api-Key: $K_VAL" -H "X-Api-Key: $K_UNKNOWN" -d "$BODY_OK")
DUP3=$(probe 2020 -H "X-Api-Key: $K_VAL" -H "X-Api-Key: $K_UNKNOWN" -d "$BODY_OK")
if [ "$DUP1" = "$DUP2" ] && [ "$DUP2" = "$DUP3" ]; then
  case "${DUP1% *}" in
    200|401) echo "  [PASS] C duplicate header is deterministic and sane ($DUP1 x3)"; PASS=$((PASS + 1));;
    *) echo "  [FAIL] C duplicate header produced $DUP1 — neither the first nor the second value's verdict"; FAIL=$((FAIL + 1));;
  esac
else
  echo "  [FAIL] C duplicate header is nondeterministic: $DUP1 / $DUP2 / $DUP3"; FAIL=$((FAIL + 1))
fi

# Buffer boundary: x_api_key_raw is char[256]. A 255-byte value fits and is
# unknown; anything longer must not truncate into a DIFFERENT valid key or
# crash. The control for silent truncation: a valid key with garbage appended
# must NOT authenticate.
LONG255=$(python3 -c 'print("lxb_" + "a"*251)')
chk "C 255-byte value"       "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $LONG255" -d "$BODY_OK")"
LONG400=$(python3 -c 'print("lxb_" + "a"*396)')
chk "C 400-byte value"       "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $LONG400" -d "$BODY_OK")"
PADDED=$(python3 -c "import sys; print(\"$K_VAL\" + \"z\"*220)")
chk "C valid key + garbage tail does not truncate into the valid key" "401 invalid_api_key" "$(probe 2020 -H "X-Api-Key: $PADDED" -d "$BODY_OK")"

# Cross-VIP replay: valid credential on the disabled service — admitted as
# ordinary traffic, no tenant recorded for it.
chk "C valid key replayed on the disabled VIP" "200" "$(probe 2021 -H "X-Api-Key: $K_VAL" -d "$BODY_OK" | awk '{print $1}')"

# Chunked transfer: the model is parsed from the body, so the verdict must
# not depend on the framing the body arrived in.
CH=$(docker exec l3h1 sh -c "printf '%s' '$BODY_BADMODEL' | curl -s -m 20 -w '\\n%{http_code}' -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' -H 'X-Api-Key: $K_MODEL' --data-binary @-" | tail -1)
chk "C chunked body, disallowed model, same verdict as unchunked" "403" "$CH"

################################################################################
echo ""
echo "===== TIER D: QoS coupling (limit kinds x policy, error codes exact) ====="
################################################################################
# Each limit kind under `required`, each with the error_code that names the
# operator action; then the structural cases.
K_RPS=$(mkkey tiers-rps rpskey '[]' 1 1 0)
sleep 1
CODES=""
for i in 1 2 3 4 5 6; do CODES="$CODES $(probe 2020 -H "X-Api-Key: $K_RPS" -d "$BODY_OK" | awk '{print $1}')"; done
case "$CODES" in
  *429*) echo "  [PASS] D key RPS enforced ($CODES)"; PASS=$((PASS + 1));;
  *) echo "  [FAIL] D key rps=1 never 429'd ($CODES)"; FAIL=$((FAIL + 1));;
esac
R429=$(probe 2020 -H "X-Api-Key: $K_RPS" -d "$BODY_OK")
chk "D key RPS names rate_limit_exceeded" "429 rate_limit_exceeded" "$R429"

# Tenant RPS: a fresh tenant whose KEY is generous but whose TENANT cap is 1.
K_TRPS=$(mkkey tiers-trps trpskey '[]' 500 1000 0)
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tiers-trps","rps":1,"tokens_per_min":0}'
sleep 1
CODES=""
for i in 1 2 3 4 5 6; do CODES="$CODES $(probe 2020 -H "X-Api-Key: $K_TRPS" -d "$BODY_OK")"; done
case "$CODES" in
  *"429 tenant_quota_exceeded"*) echo "  [PASS] D tenant RPS enforced with tenant_quota_exceeded"; PASS=$((PASS + 1));;
  *) echo "  [FAIL] D tenant rps=1 verdicts: $CODES"; FAIL=$((FAIL + 1));;
esac

# Tenant TPM via pre-admission: the declared ceiling exceeds the quota, so the
# request is refused BEFORE dispatch with the token error, not the rate one.
K_TPM=$(mkkey tiers-tpm tpmkey '[]' 500 1000 0)
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tiers-tpm","rps":1000,"tokens_per_min":200}'
sleep 1
BIG='{"model":"test-model","max_tokens":4000,"messages":[{"role":"user","content":"hi"}]}'
T1=$(probe 2020 -H "X-Api-Key: $K_TPM" -d "$BIG")
chk "D tenant TPM pre-admission denies with a token code" "429" "${T1% *}"
chk_has "D tenant TPM error names tokens, not rate" "token_quota" "$T1"

# Model TPM: same shape, keyed to the model.
K_MTPM=$(mkkey tiers-mtpm mtpmkey '[]' 500 1000 0)
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tiers-mtpm","rps":1000,"tokens_per_min":0,"model_limits":[{"model":"test-model","tokens_per_min":200}]}'
sleep 1
M1=$(probe 2020 -H "X-Api-Key: $K_MTPM" -d "$BIG")
chk "D model TPM pre-admission denies" "429" "${M1% *}"
chk_has "D model TPM error names tokens" "token_quota" "$M1"

# Burst narrowing: same quota, narrowed bucket refuses the ceiling the
# default bucket accepts.
K_BURST=$(mkkey tiers-burst burstkey '[]' 500 1000 0)
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tiers-burst","rps":1000,"tokens_per_min":6000,"burst_pct":5}'
K_WIDE=$(mkkey tiers-wide widekey '[]' 500 1000 0)
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tiers-wide","rps":1000,"tokens_per_min":6000}'
sleep 1
MID='{"model":"test-model","max_tokens":1500,"messages":[{"role":"user","content":"hi"}]}'
W1=$(probe 2020 -H "X-Api-Key: $K_WIDE" -d "$MID")
chk "D burst control: default bucket admits the ceiling" "200" "${W1% *}"
B1=$(probe 2020 -H "X-Api-Key: $K_BURST" -d "$MID")
chk "D burst_pct=5 refuses the same ceiling under the same quota" "429" "${B1% *}"

# Structural: disabled policy + configured quota = no enforcement AND no
# accounting, because there is no tenant. The quota tenant above is already
# in debt-shape; the disabled VIP must not care.
D200=$(probe 2021 -H "X-Api-Key: $K_TPM" -d "$BIG")
chk "D disabled VIP ignores the configured quota (no tenant, no accounting)" "200" "${D200% *}"

################################################################################
echo ""
echo "===== TIER E: transitions (the defects that live in the change) ====="
################################################################################
# E1: disabled → required under a live keep-alive connection. The next
# request on the SAME connection must be refused — the accept-time policy
# copy must not outlive the rule change.
mk_rule 2029 false false disabled
sleep 3
docker exec -i l3h1 sh -c 'cat > /tmp/ka_probe.py' <<'PYEOF'
import http.client, json, sys, time
conn = http.client.HTTPConnection("10.10.10.254", 2029, timeout=30)
body = json.dumps({"model":"test-model","messages":[{"role":"user","content":"hi"}]})
conn.request("POST", "/v1/chat/completions", body, {"Content-Type": "application/json"})
r1 = conn.getresponse(); r1.read()
print("first", r1.status, flush=True)
time.sleep(8)   # the rule is flipped out here, connection held open
conn.request("POST", "/v1/chat/completions", body, {"Content-Type": "application/json"})
r2 = conn.getresponse()
print("second", r2.status, r2.read().decode()[:80], flush=True)
PYEOF
docker exec l3h1 python3 /tmp/ka_probe.py > /tmp/e1.out 2>&1 &
E1PID=$!
sleep 4
mk_rule 2029 false false required    # same VIP re-POST = update in place
wait $E1PID
E1=$(cat /tmp/e1.out)
echo "    $E1" | tr '\n' ' '; echo
chk_has "E1 first request on the disabled rule was admitted" "first 200" "$E1"
chk_has "E1 the NEXT request on the same connection is refused after the flip" "second 401" "$E1"

# E2: required → disabled with an SSE stream in flight; the stream completes
# and the next request is admitted keyless.
mk_rule 2029 true false required
sleep 3
docker exec l3h1 curl -s -N -m 30 "http://$VIP:2029/v1/chat/completions?sse=1" \
  -H 'Content-Type: application/json' -H "X-Api-Key: $K_VAL" -d "$BODY_OK" > /tmp/e2.stream 2>&1 &
E2PID=$!
sleep 2
mk_rule 2029 true false disabled
wait $E2PID
chk_has "E2 the in-flight stream completed across the flip" "[DONE]" "$(cat /tmp/e2.stream)"
chk "E2 the next request is admitted keyless" "200" "$(probe 2029 -d "$BODY_OK" | awk '{print $1}')"

# E3: store stopped mid-stream; the stream completes; the next UNCACHED
# verdict is the outage, told truthfully.
mk_rule 2029 true false required
sleep 3
K_E3=$(mkkey tiers-e3 e3cold '[]' 500 1000 0)   # minted now, never presented
docker exec l3h1 curl -s -N -m 30 "http://$VIP:2029/v1/chat/completions?sse=1" \
  -H 'Content-Type: application/json' -H "X-Api-Key: $K_VAL" -d "$BODY_OK" > /tmp/e3.stream 2>&1 &
E3PID=$!
sleep 2
docker stop aisep-pg >/dev/null 2>&1
wait $E3PID
chk_has "E3 the stream survived the store outage" "[DONE]" "$(cat /tmp/e3.stream)"
chk "E3 the next uncached request is the outage, not a key verdict" "503 policy_store_unavailable" "$(probe 2029 -H "X-Api-Key: $K_E3" -d "$BODY_OK")"

# E4: store restarted → enforcement resumes with no gateway restart.
docker start aisep-pg >/dev/null 2>&1; pg_ready
sleep 3
chk "E4 the cold key serves once the store returns (no gateway restart)" "200" "$(probe 2029 -H "X-Api-Key: $K_E3" -d "$BODY_OK" | awk '{print $1}')"
chk "E4 and keyless is still refused (enforcement resumed, not dropped)" "401 invalid_api_key" "$(probe 2029 -d "$BODY_OK")"

# E5: key revoked mid-stream; the stream completes; the next request is 401.
K_E5=$(mkkey tiers-e5 e5key '[]' 500 1000 0)
KID_E5=$(lcurl "$API/config/ai/apikey?tenant_id=tiers-e5" | python3 -c 'import sys,json
for k in json.load(sys.stdin):
    if k.get("name")=="e5key": print(k["key_id"]); break' 2>/dev/null)
docker exec l3h1 curl -s -N -m 30 "http://$VIP:2029/v1/chat/completions?sse=1" \
  -H 'Content-Type: application/json' -H "X-Api-Key: $K_E5" -d "$BODY_OK" > /tmp/e5.stream 2>&1 &
E5PID=$!
sleep 2
lcurl -o /dev/null -X PATCH "$API/config/ai/apikey/$KID_E5" -H 'Content-Type: application/json' -d '{"enabled":false}'
wait $E5PID
chk_has "E5 the stream completed across the revocation" "[DONE]" "$(cat /tmp/e5.stream)"
chk "E5 the next request with the revoked key is refused" "401 invalid_api_key" "$(probe 2029 -H "X-Api-Key: $K_E5" -d "$BODY_OK")"

# E6: management mode changed across a restart — every key, quota and rule
# policy unchanged. (The rules are recreated because rules die with the
# process; what must SURVIVE is the store's contents.)
QB=$(lcurl "$API/config/ai/tenant/ratelimit/tiers-tpm")
restart_gw $AIKEY_ARGS $MGMT_ARGS || exit 1
mgmt_login usvc || exit 1   # the flipped-to mode gates the management API
mk_rule 2020 false false required
sleep 3
QA=$(lcurl "$API/config/ai/tenant/ratelimit/tiers-tpm")
chk "E6 tenant quota row identical across a management-mode flip" "$QB" "$QA"
chk "E6 a key minted before the flip still authenticates" "200" "$(probe 2020 -H "X-Api-Key: $K_VAL" -d "$BODY_OK" | awk '{print $1}')"

# E7: rule deleted and recreated on the same VIP without a policy — the old
# rule's `required` must NOT be inherited.
chk "E7 precondition: the required rule refuses keyless" "401 invalid_api_key" "$(probe 2020 -d "$BODY_OK")"
rm_rule 2020
mk_rule 2020 false false -
sleep 3
chk "E7 the recreated rule carries no ghost of the deleted policy" "200" "$(probe 2020 -d "$BODY_OK" | awk '{print $1}')"

# E8: the E1 property in the other direction — required → disabled on a live
# keep-alive connection admits the NEXT request keyless.
rm_rule 2029; mk_rule 2029 false false required; sleep 3
docker exec -i l3h1 sh -c 'cat > /tmp/ka2_probe.py' <<'PYEOF'
import http.client, json, time
conn = http.client.HTTPConnection("10.10.10.254", 2029, timeout=30)
body = json.dumps({"model":"test-model","messages":[{"role":"user","content":"hi"}]})
conn.request("POST", "/v1/chat/completions", body, {"Content-Type": "application/json"})
r1 = conn.getresponse(); r1.read()
print("first", r1.status, flush=True)
time.sleep(8)
conn.request("POST", "/v1/chat/completions", body, {"Content-Type": "application/json"})
r2 = conn.getresponse()
print("second", r2.status, flush=True)
PYEOF
docker exec l3h1 python3 /tmp/ka2_probe.py > /tmp/e8.out 2>&1 &
E8PID=$!
sleep 4
mk_rule 2029 false false disabled
wait $E8PID
E8=$(cat /tmp/e8.out)
echo "    $E8" | tr '\n' ' '; echo
chk_has "E8 keyless was refused while required" "first 401" "$E8"
chk_has "E8 the next request on the same connection is admitted after the flip" "second 200" "$E8"
rm_rule 2029

################################################################################
echo ""
echo "===== TIER F: SKIPPED — needs an HA pair ====="
################################################################################
echo "  [SKIP] Tier F (revocation propagation, counter sync, cold-cache peer)"
echo "         requires a second gateway with cluster peering; not available in"
echo "         this topology. Skipped LOUDLY by rule — the summary"
echo "         below covers Tiers A-E only."
echo "  [SKIP] Tier A oauth2 column: OAuth2 management auth is incomplete and"
echo "         unstable (the gateway does not reliably start under --oauth2),"
echo "         so the independence claim is asserted for none/usvc/manual only."

# Leave the topology in the advertised posture.
mgmt_login none
restart_gw $AIKEY_ARGS >/dev/null 2>&1
mk_rule 2020 true false required
mk_rule 2021 false false disabled
sleep 3

echo ""
echo "===== TIERS SUMMARY: pass=$PASS fail=$FAIL (Tier F skipped) ====="
if [ "$FAIL" -eq 0 ]; then
  echo "SCENARIO-ai-authsep-tiers [OK]"
  exit 0
fi
echo "SCENARIO-ai-authsep-tiers [FAILED]"
exit 1
