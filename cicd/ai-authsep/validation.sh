#!/bin/bash
# ai-authsep validation.
#
# What this suite is for: the data plane's key decision must not depend on the
# management plane. Every data-plane leg therefore runs in all four
# {--userservice on|off} x {store configured|not} cells, and the suite asserts
# that the two verdict vectors along the --userservice axis are *identical*.
# A cell passing its own expectations is not the property under test; the two
# columns agreeing is.
#
#   Section 1  four-cell matrix + POL-1 / POL-1b / POL-1c / POL-6
#   Section 2  DP-18, DP-19  store role isolation, at the database
#   Section 3  DP-20         the store password is nowhere it should not be
#   Section 4  DP-16, DP-17  verified TLS to the store, and no downgrade
#
# A red leg is a code defect until proven otherwise. Do not soften an assert.
#
# Verdicts marked "PR 2 state" below are the *current* documented behaviour of
# a behaviour-preserving change, not the end state. PR 3 removes the retained
# `nil -> allow` and introduces the per-rule api_key_auth policy, and it must
# edit these expectations deliberately — which is the point of writing them
# down rather than leaving them implicit.
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-ai-authsep

PASS=0
FAIL=0
API=http://localhost:11111/netlox/v1
VIP=10.10.10.254

if [ ! -f .state ]; then
  echo "  FATAL: .state missing — run ./config.sh first"
  echo "SCENARIO-ai-authsep [FAILED]"
  exit 1
fi
# shellcheck disable=SC1091
source .state

chk() { # chk <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  [PASS] $1 (got $3)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 expected=$2 got=$3"; FAIL=$((FAIL + 1))
  fi
}
chk_not() { # chk_not <name> <forbidden> <actual>
  if [ "$2" != "$3" ]; then
    echo "  [PASS] $1 (got $3, not $2)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 must not be $2"; FAIL=$((FAIL + 1))
  fi
}
chk_has() { # chk_has <name> <needle> <haystack>
  if [ "${3#*$2}" != "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — did not find '$2' in: $(echo "$3" | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}
chk_hasnt() { # chk_hasnt <name> <needle> <haystack>
  if [ "${3#*$2}" = "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — found '$2' where it must not appear"; FAIL=$((FAIL + 1))
  fi
}

lcurl() { docker exec llb1 curl -s -m 30 "$@"; }
lcode() { docker exec llb1 curl -s -o /dev/null -m 30 -w '%{http_code}' "$@"; }
vip_code() { docker exec l3h1 curl -s -o /dev/null -m 20 -w '%{http_code}' "$@"; }
psql_as() { # psql_as <container> <role> <password> <sql>
  docker exec -e PGPASSWORD="$3" "$1" psql -h 127.0.0.1 -U "$2" -d loxilb -tAc "$4" 2>&1
}
pg_lines() { docker logs "$1" 2>&1 | wc -l | tr -d '[:space:]'; }
# wait_log waits for a line to appear in the gateway log, bounded. The store
# connect retries with a doubling backoff, so the settled verdict is not
# available the instant the REST API answers; asserting immediately would make
# a real property look flaky and invite someone to weaken it.
wait_log() { # wait_log <needle> <seconds>
  local i
  for i in $(seq 1 "$2"); do
    docker exec llb1 grep -qF "$1" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
pg_since() { docker logs "$1" 2>&1 | tail -n +"$(( $2 + 1 ))"; }

# restart_gw restarts the gateway under a different flag set. The flag set is
# the thing under test, so this runs many times.
#
# A bare kill-and-start always fails on `llb_xh_init: Assertion 0 failed`:
# four pieces of datapath state outlive the process — the persistent llb0 TAP,
# the XDP programs and clsact qdiscs on each interface, and the bpffs pins
# under /opt/loxilb/dp. The TAP is what actually blocks the restart; the rest
# are cleared for the same reason.
restart_gw() { # restart_gw <flags...>
  docker exec llb1 pkill -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
  for _ in $(seq 1 30); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
  done
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1

  # `docker exec` hands the process an 8192K memlock limit, which the eBPF maps
  # do not fit in. stderr is captured because a gateway started with
  # `docker exec -d` and no redirection loses its panic traces entirely.
  docker exec -d llb1 bash -c "ulimit -l unlimited; /root/loxilb-io/loxilb/loxilb $* > /tmp/loxilb.out 2> /tmp/loxilb.err"
  for _ in $(seq 1 40); do
    if docker exec llb1 curl -sf -m 3 $API/version >/dev/null 2>&1; then
      # The earliest answer the key API is capable of giving. Several legs are
      # about the window between the REST listener coming up and the key store
      # being constructed — a window that is over by the time the L7 wait below
      # finishes, so it has to be sampled here or not at all.
      EARLY_KEY_API=$(lcurl -w '\n%{http_code}' -X GET $API/config/ai/apikey)
      # The sockproxy binds on a 10s retry loop, so the L7 listeners are not up
      # when the REST API answers. Judging L7 before then reads as a gateway
      # defect and is really a race in the probe.
      sleep 25
      return 0
    fi
    sleep 2
  done
  echo "  gateway did not come back; stderr tail:"
  docker exec llb1 tail -20 /tmp/loxilb.err
  return 1
}

# Rules do not survive a restart, so both services are recreated each time.
#   :2020  sse_mode=true   — the AI service, where keys are checked today
#   :2021  sse_mode=false  — a plain full-proxy AI service. PR 2 state: keys
#          are NOT checked here at all. The per-service policy field gives it
#          expectation below changes with it.
mk_rules() {
  for spec in "2020 true" "2021 false"; do
    set -- $spec
    lcurl -X POST $API/config/loadbalancer -H 'Content-Type: application/json' \
      -d "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":$1,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":$2,\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}" >/dev/null
  done
  sleep 3
}

# The seven key-lifecycle operations, as <label>|<curl args...> records.
seven_ops() {
  cat <<'OPS'
POST /config/ai/apikey|-X|POST|/config/ai/apikey|-H|Content-Type: application/json|-d|{"tenant_id":"probe-tenant"}
GET /config/ai/apikey|-X|GET|/config/ai/apikey
GET /config/ai/apikey/{id}|-X|GET|/config/ai/apikey/nosuchkey
PATCH /config/ai/apikey/{id}|-X|PATCH|/config/ai/apikey/nosuchkey|-H|Content-Type: application/json|-d|{"enabled":false}
DELETE /config/ai/apikey/{id}|-X|DELETE|/config/ai/apikey/nosuchkey
POST /config/ai/tenant/ratelimit|-X|POST|/config/ai/tenant/ratelimit|-H|Content-Type: application/json|-d|{"tenant_id":"probe-tenant","rps":10}
GET /config/ai/tenant/ratelimit/{id}|-X|GET|/config/ai/tenant/ratelimit/probe-tenant
OPS
}

run_seven() { # run_seven <mode: non501|unconfigured503|unauth401>
  local mode=$1
  while IFS='|' read -r label rest; do
    [ -z "$label" ] && continue
    local -a args=() fields=()
    IFS='|' read -r -a fields <<<"$rest"
    for f in "${fields[@]}"; do
      case "$f" in
        /config/*) args+=("$API$f") ;;
        *)         args+=("$f") ;;
      esac
    done
    local body code
    body=$(lcurl -w '\n%{http_code}' "${args[@]}")
    code=$(echo "$body" | tail -n1)
    case "$mode" in
      non501)          chk_not "POL-1 $label is registered" "501" "$code" ;;
      unconfigured503) chk "POL-1b $label reports the store unconfigured" "503" "$code"
                       chk_has "POL-1b $label names ai_key_store_unconfigured" "ai_key_store_unconfigured" "$body" ;;
      unauth401)       chk "POL-1c unauthenticated $label" "401" "$code" ;;
    esac
  done < <(seven_ops)
}

################################################################################
# Precondition
################################################################################
ROWS=$(psql_as aisep-pg oamuser oampass 'SELECT count(*) FROM aigw.api_keys;' | tr -d '[:space:]')
if [ "$ROWS" != "0" ]; then
  # key_hash is UNIQUE, so a re-run against a store that already holds these
  # keys fails on the create. That is a dirty fixture, not a code defect, and
  # it should say so rather than be read as one. config.sh recreates the store.
  echo "  PRECONDITION NOT MET: aigw.api_keys holds ${ROWS:-?} row(s). Re-run ./config.sh."
  echo "SCENARIO-ai-authsep [FAILED]"
  exit 1
fi

################################################################################
echo ""
echo "===== SECTION 1: the four-cell matrix ====="
################################################################################

# vector_configured / vector_unconfigured print one verdict per line. The
# vectors, not the individual codes, are what the axis-invariance check
# compares.
vector_configured() {
  local body='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'
  echo "keyless:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -d "$body")"
  echo "valid:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_GOOD" -d "$body")"
  echo "unknown:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H 'X-Api-Key: lxb_00000000000000000000000000000000' -d "$body")"
  echo "disabled:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_OFF" -d "$body")"
  echo "badmodel:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_MODEL" -H 'X-Model: mistral-7b' -d "$body")"
  echo "keyless:2021=$(vip_code -X POST http://$VIP:2021/v1/chat/completions -H 'Content-Type: application/json' -d "$body")"
}
vector_unconfigured() {
  local body='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'
  echo "keyless:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -d "$body")"
  echo "unknown:2020=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H 'X-Api-Key: lxb_00000000000000000000000000000000' -d "$body")"
  echo "keyless:2021=$(vip_code -X POST http://$VIP:2021/v1/chat/completions -H 'Content-Type: application/json' -d "$body")"
}

# ── Cell A: --userservice OFF, store configured ────────────────────────────
echo ""
echo "--- cell A: --userservice off, store configured ---"
restart_gw $AIKEY_ARGS || exit 1
mk_rules

mkkey() { # mkkey <name> <models-json> -> raw key on stdout, id on fd 3
  lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"authsep-tenant\",\"name\":\"$1\",\"allowed_models\":$2,\"rate_limit_rps\":200,\"burst_size\":400,\"tokens_per_min\":1000000,\"enabled\":true}"
}
R_GOOD=$(mkkey good '[]')
R_OFF=$(mkkey revoked '[]')
R_MODEL=$(mkkey modelbound '["llama-3"]')
jf() { echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null; }
K_GOOD=$(jf "$R_GOOD" raw_key);   ID_GOOD=$(jf "$R_GOOD" key_id)
K_OFF=$(jf "$R_OFF" raw_key);     ID_OFF=$(jf "$R_OFF" key_id)
K_MODEL=$(jf "$R_MODEL" raw_key); ID_MODEL=$(jf "$R_MODEL" key_id)
if [ -z "$K_GOOD" ] || [ -z "$K_OFF" ] || [ -z "$K_MODEL" ]; then
  echo "  FATAL: could not create the data-plane keys. responses:"
  echo "    $R_GOOD"; echo "    $R_OFF"; echo "    $R_MODEL"
  echo "SCENARIO-ai-authsep [FAILED]"
  exit 1
fi
lcurl -X PATCH $API/config/ai/apikey/$ID_OFF -H 'Content-Type: application/json' \
  -d '{"enabled":false}' >/dev/null
sleep 1

# The first answer the API gave, sampled the instant it started answering and
# well before the store finished connecting. A configured store must never be
# described as unconfigured, not even then: those are different situations and
# an operator acts on them differently.
chk_hasnt "A a configured store is not called unconfigured, even in the API's first answer" "ai_key_store_unconfigured" "$EARLY_KEY_API"

echo "  POL-1: the key lifecycle stands without the management plane"
run_seven non501

VEC_A=$(vector_configured)
echo "$VEC_A" | sed 's/^/    A /'
chk "A keyless :2020 denied"          "keyless:2020=401"  "$(echo "$VEC_A"  | grep '^keyless:2020=')"
chk "A valid key :2020 admitted"      "valid:2020=200"    "$(echo "$VEC_A"  | grep '^valid:2020=')"
chk "A unknown key :2020 denied"      "unknown:2020=401"  "$(echo "$VEC_A"  | grep '^unknown:2020=')"
chk "A revoked key :2020 denied"      "disabled:2020=401" "$(echo "$VEC_A"  | grep '^disabled:2020=')"
chk "A model outside allow-list 403"  "badmodel:2020=403" "$(echo "$VEC_A"  | grep '^badmodel:2020=')"
# PR 2 state: a plain full-proxy AI service never reaches the key check
# at all. The per-service policy field gives :2021 api_key_auth=disabled
# explicitly and this stays
# 200 for a different and defensible reason.
chk "A keyless :2021 admitted"        "keyless:2021=200"  "$(echo "$VEC_A"  | grep '^keyless:2021=')"

KEYROWS_A=$(psql_as aisep-pg oamuser oampass 'SELECT count(*) FROM aigw.api_keys;' | tr -d '[:space:]')

# ── Cell B: --userservice ON, store configured ─────────────────────────────
echo ""
echo "--- cell B: --userservice on, store configured ---"
restart_gw $AIKEY_ARGS $MGMT_ARGS || exit 1
mk_rules

echo "  POL-1c: management auth governs the caller of the key API"
run_seven unauth401

VEC_B=$(vector_configured)
echo "$VEC_B" | sed 's/^/    B /'

echo "  the management database holds no data-plane table"
# The DDL for api_keys, tenant_rate_limits and tenant_model_rate_limits left
# pkg/db with the repoint. If InitDB still created them, a later change could
# quietly start writing there again and nothing on the wire would say so.
DPT=$(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='loxilb_db' AND table_name IN ('api_keys','tenant_rate_limits','tenant_model_rate_limits');" 2>/dev/null | tr -d '[:space:]')
chk "no data-plane tables in the management database" "0" "$DPT"
MGT=$(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='loxilb_db' AND table_name IN ('users','token');" 2>/dev/null | tr -d '[:space:]')
chk "the management tables are still created (the leg above is not vacuous)" "2" "$MGT"

KEYROWS_B=$(psql_as aisep-pg oamuser oampass 'SELECT count(*) FROM aigw.api_keys;' | tr -d '[:space:]')
chk "POL-6 the key rows are unchanged across the --userservice toggle" "$KEYROWS_A" "$KEYROWS_B"

echo ""
echo "  === the axis-invariance check, store configured ==="
if [ "$VEC_A" = "$VEC_B" ]; then
  echo "  [PASS] DP-12/DP-15 verdicts identical with --userservice off and on"; PASS=$((PASS + 1))
else
  echo "  [FAIL] DP-12/DP-15 verdicts MOVED when --userservice was toggled:"
  diff <(echo "$VEC_A") <(echo "$VEC_B") | sed 's/^/        /'
  FAIL=$((FAIL + 1))
fi

# ── Cell C: --userservice OFF, no store ────────────────────────────────────
echo ""
echo "--- cell C: --userservice off, store unconfigured ---"
restart_gw || exit 1
mk_rules

# The control for the leg in cell A: with nothing configured, that same first
# answer does say unconfigured. Without this the assertion above would hold for
# a build that had simply stopped using the word.
chk_has "C with no store configured the first answer does say unconfigured" "ai_key_store_unconfigured" "$EARLY_KEY_API"

echo "  POL-1b: the ops are registered and honestly report no store"
run_seven unconfigured503

VEC_C=$(vector_unconfigured)
echo "$VEC_C" | sed 's/^/    C /'
# PR 2 state: the retained `nil -> allow`. PR 3 deletes this branch and these
# two become 503 policy_store_unavailable (DP-13).
chk "C keyless :2020 admitted (retained nil->allow; PR 3 removes it)" "keyless:2020=200" "$(echo "$VEC_C" | grep '^keyless:2020=')"
chk "C unknown key :2020 admitted (same branch)"                     "unknown:2020=200" "$(echo "$VEC_C" | grep '^unknown:2020=')"
chk "C keyless :2021 admitted"                                       "keyless:2021=200" "$(echo "$VEC_C" | grep '^keyless:2021=')"

LOGC=$(docker exec llb1 cat /tmp/loxilb.err /tmp/loxilb.out 2>/dev/null)
chk_has "the storeless admit is stated in the log, once, at critical severity" "No API-key store configured" "$LOGC"

# ── Cell D: --userservice ON, no store ─────────────────────────────────────
echo ""
echo "--- cell D: --userservice on, store unconfigured ---"
restart_gw $MGMT_ARGS || exit 1
mk_rules
VEC_D=$(vector_unconfigured)
echo "$VEC_D" | sed 's/^/    D /'

echo ""
echo "  === the axis-invariance check, store unconfigured ==="
if [ "$VEC_C" = "$VEC_D" ]; then
  echo "  [PASS] verdicts identical with --userservice off and on"; PASS=$((PASS + 1))
else
  echo "  [FAIL] verdicts MOVED when --userservice was toggled:"
  diff <(echo "$VEC_C") <(echo "$VEC_D") | sed 's/^/        /'
  FAIL=$((FAIL + 1))
fi

# Still open: a denied request can still be dispatched
# upstream, because the C gate returns without an explicit value. The backend
# log is reported here rather than asserted — DP-28 gates PR 3, and the leak
# ratio is nondeterministic, so an assertion either way would be a fiction.
LEAK=$(docker exec l3ep1 wc -l /tmp/backend_reqs.log 2>/dev/null | awk '{print $1}')
echo "  [INFO] backend saw ${LEAK:-?} request(s) across this run; denied requests can still reach it"
echo "         until PR 3; DP-28 asserts the counter, and it gates I-12, not this step."

################################################################################
echo ""
echo "===== SECTION 2: store role isolation (DP-18, DP-19) ====="
################################################################################
# The management tables do not exist in PostgreSQL until PR 2b. Create them
# here as the owner, so the denial below is about privilege and not about the
# table being absent — otherwise the leg passes for the wrong reason and stops
# meaning anything the day the tables arrive.
psql_as aisep-pg oamuser oampass \
  'CREATE TABLE IF NOT EXISTS public.users (id int); CREATE TABLE IF NOT EXISTS public.api_tokens (id int);' >/dev/null

for t in users api_tokens; do
  OUT=$(psql_as aisep-pg aigwuser dp-secret-1 "SELECT count(*) FROM public.$t;")
  chk_has "DP-18 aigwuser cannot read public.$t" "permission denied" "$OUT"
done
OUT=$(psql_as aisep-pg aigwuser dp-secret-1 'SELECT count(*) FROM aigw.api_keys;')
chk_hasnt "DP-18 is not vacuous: aigwuser can read its own schema" "permission denied" "$OUT"

# DP-19 asserts the *known* state, not isolation: oamuser is the initdb
# superuser and bypasses grants. The leg turns red if OAM later moves to a
# non-superuser role and nobody revisits this plan.
OUT=$(psql_as aisep-pg oamuser oampass 'SELECT count(*) FROM aigw.api_keys;')
chk_hasnt "DP-19 oamuser still reads aigw.api_keys (superuser bypass, known)" "permission denied" "$OUT"

################################################################################
echo ""
echo "===== SECTION 3: the store password stays where it was put (DP-20) ====="
################################################################################
PID=$(docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' | head -n1 | tr -d '[:space:]')
CMDLINE=$(docker exec llb1 bash -c "tr '\\0' ' ' < /proc/$PID/cmdline")
chk_hasnt "DP-20 the password is not in the gateway's argv" "dp-secret-1" "$CMDLINE"
chk_has   "DP-20 is not vacuous: argv is populated" "loxilb" "$CMDLINE"

# Read the log from the store-configured cell rather than the current one:
# a cell with no store never builds a DSN, so grepping its log would pass for
# free.
restart_gw $AIKEY_ARGS || exit 1
mk_rules
LOGD=$(docker exec llb1 cat /tmp/loxilb.err /tmp/loxilb.out 2>/dev/null)
chk_hasnt "DP-20 the password is not in the gateway log" "dp-secret-1" "$LOGD"
chk_has   "DP-20 is not vacuous: the log does report the store" "Key store ready" "$LOGD"

################################################################################
echo ""
echo "===== SECTION 4: verified TLS to the store (DP-16, DP-17) ====="
################################################################################
TLS_ARGS_BASE="--aikey-db-port 5432 --aikey-db-user aigwuser --aikey-db-name loxilb --aikey-db-password-file /etc/loxilb/aikey_password --aikey-db-ssl --aikey-db-ssl-client-cert-file /etc/loxilb/client.crt --aikey-db-ssl-client-key-file /etc/loxilb/client.key"

point_store_dns() { # point_store_dns <ip>
  # /etc/hosts is a bind mount, so `sed -i` cannot rename over it. Rewrite
  # through the existing inode.
  docker exec llb1 bash -c "grep -v ' aikey-store\$' /etc/hosts > /tmp/hosts.new; cat /tmp/hosts.new > /etc/hosts; echo '$1 aikey-store' >> /etc/hosts"
}

# A key written straight into the TLS store with psql, never through the
# gateway. A pass at the VIP can then only mean the data plane read *that*
# database over *that* connection. The insert happens after the gateway has
# connected, because `aigw.api_keys` is created by the store preflight rather
# than by the bootstrap script — inserting first fails on a table that does not
# exist yet, and the leg then reads as an authentication failure.
TLS_KEY="sk-tls-store-key-written-by-psql1"
TLS_HASH=$(printf '%s' "$TLS_KEY" | sha256sum | cut -d' ' -f1)
seed_tls_store() {
  local out
  out=$(psql_as aisep-pg-tls oamuser oampass \
    "INSERT INTO aigw.api_keys (key_id, key_hash, tenant_id, name, allowed_models, rate_limit_rps, burst_size, tokens_per_min, created_at, enabled) VALUES ('tlsrow00000000000000000000000001', '$TLS_HASH', 'tls-tenant', 'tls', 'test-model', 200, 400, 1000000, now(), TRUE) ON CONFLICT DO NOTHING;")
  chk_hasnt "DP-16a the seed row really was written to the TLS store" "ERROR" "$out"
}

# ── T1 (DP-16, positive): TLS required, correct CA and client keypair ──────
echo ""
echo "--- DP-16a: --aikey-db-ssl against a TLS-required store ---"
point_store_dns "$PG_TLS_IP"
TLSLOG=$(pg_lines aisep-pg-tls)
restart_gw $TLS_ARGS_BASE --aikey-db-host aikey-store --aikey-db-ssl-ca-cert-file /etc/loxilb/ca.crt || exit 1
mk_rules
chk "DP-16a the key API is live, so the store connected" "200" "$(lcode -X GET $API/config/ai/apikey)"
seed_tls_store

SSLROW=$(psql_as aisep-pg-tls oamuser oampass \
  "SELECT s.ssl || '|' || coalesce(s.client_dn,'') FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.usename='aigwuser' LIMIT 1;" | tr -d '[:space:]')
# `s.ssl || '|'` casts the boolean to text, so the server says "true", not "t".
chk_has "DP-16a the server sees the gateway's session as TLS"        "true|"     "$SSLROW"
# pg_hba's `cert` method authenticates by certificate alone, so a session that
# exists at all proves the client keypair was used and accepted.
chk_has "DP-16a the client certificate is the one that authenticated" "CN=aigwuser" "$SSLROW"

BODY='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'
chk "DP-16a a key present only in the TLS store authenticates at the VIP" "200" \
  "$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $TLS_KEY" -d "$BODY")"

# ── T2 (DP-16, the no-downgrade half) ──────────────────────────────────────
echo ""
echo "--- DP-16b: the same TLS configuration against a plaintext-only store ---"
# Same name, same CA, same keypair. The only thing that changes is that the
# server cannot speak TLS — which isolates the downgrade question from every
# other way a TLS connection can fail.
point_store_dns "$PG_IP"
PLAINLOG=$(pg_lines aisep-pg)
restart_gw $TLS_ARGS_BASE --aikey-db-host aikey-store --aikey-db-ssl-ca-cert-file /etc/loxilb/ca.crt || exit 1
# Asked immediately, before the connect retries have run out. A configured
# store must report itself as unavailable from the first moment, never as
# unconfigured: the service is published before it is dialled precisely so that
# these two conditions cannot be confused while the dial is in flight.
BODY_503=$(lcurl -w '\n%{http_code}' -X GET $API/config/ai/apikey)
# Record whether the dial had already given up when the question was asked.
# Without this the leg still passes once the dial settles, and would stop being
# a regression test for the window it was written for.
SETTLED=$(docker exec llb1 grep -cF "[AIKey] Key store unavailable at" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
chk "DP-16b the question was asked while the dial was still in flight" "0" "$SETTLED"
chk "DP-16b the store is unavailable, not silently connected" "503" "$(echo "$BODY_503" | tail -n1)"
chk_hasnt "DP-16b a configured store is never reported as unconfigured, not even mid-dial" "ai_key_store_unconfigured" "$BODY_503"
chk_hasnt "DP-16b nor in the API's very first answer, before the store block had run" "ai_key_store_unconfigured" "$EARLY_KEY_API"
chk_has "DP-16b it is reported as unavailable" "ai_key_store_unavailable" "$BODY_503"
NEW=$(pg_since aisep-pg "$PLAINLOG")
chk_hasnt "DP-16b no plaintext session was authorized on the plaintext server" "user=aigwuser" "$NEW"

echo "--- DP-16b control: the same server does accept a connection asked for in plaintext ---"
PLAINLOG=$(pg_lines aisep-pg)
restart_gw $AIKEY_ARGS || exit 1
NEW=$(pg_since aisep-pg "$PLAINLOG")
chk_has "DP-16b is not vacuous: without --aikey-db-ssl the same server authorizes aigwuser" "user=aigwuser" "$NEW"

# ── T3 (DP-17a): wrong CA ──────────────────────────────────────────────────
echo ""
echo "--- DP-17a: the store certificate is signed by a CA the gateway does not trust ---"
point_store_dns "$PG_TLS_IP"
TLSLOG=$(pg_lines aisep-pg-tls)
restart_gw $TLS_ARGS_BASE --aikey-db-host aikey-store --aikey-db-ssl-ca-cert-file /etc/loxilb/rogue-ca.crt || exit 1
BODY_503=$(lcurl -w '\n%{http_code}' -X GET $API/config/ai/apikey)
chk "DP-17a the store is unavailable" "503" "$(echo "$BODY_503" | tail -n1)"
chk_hasnt "DP-17a a configured store is never reported as unconfigured" "ai_key_store_unconfigured" "$BODY_503"
chk_hasnt "DP-17a nor in the API's very first answer, before the store block had run" "ai_key_store_unconfigured" "$EARLY_KEY_API"
if wait_log "[AIKey] Key store unavailable at" 120; then
  echo "  [PASS] DP-17a the failure is stated loudly and names the store"; PASS=$((PASS + 1))
else
  echo "  [FAIL] DP-17a nothing in the log says the store could not be reached"; FAIL=$((FAIL + 1))
fi
LOGT=$(docker exec llb1 grep -F "[AIKey]" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null)
chk_has "DP-17a and it names the certificate authority as the reason" "certificate" "$LOGT"
NEW=$(pg_since aisep-pg-tls "$TLSLOG")
chk_hasnt "DP-17a no session was authorized on the store"          "user=aigwuser"         "$NEW"

# ── T4 (DP-17b): hostname mismatch ─────────────────────────────────────────
echo ""
echo "--- DP-17b: the store is addressed by an identity its certificate does not carry ---"
# Same server, same CA, correct client keypair; only the name changes. The
# certificate carries DNS:aikey-store and no IP SAN, so addressing it by
# address is a hostname mismatch and nothing else.
TLSLOG=$(pg_lines aisep-pg-tls)
restart_gw $TLS_ARGS_BASE --aikey-db-host "$PG_TLS_IP" --aikey-db-ssl-ca-cert-file /etc/loxilb/ca.crt || exit 1
BODY_503=$(lcurl -w '\n%{http_code}' -X GET $API/config/ai/apikey)
chk "DP-17b the store is unavailable" "503" "$(echo "$BODY_503" | tail -n1)"
chk_hasnt "DP-17b a configured store is never reported as unconfigured" "ai_key_store_unconfigured" "$BODY_503"
chk_hasnt "DP-17b nor in the API's very first answer, before the store block had run" "ai_key_store_unconfigured" "$EARLY_KEY_API"
if wait_log "[AIKey] Key store unavailable at" 120; then
  echo "  [PASS] DP-17b the failure is stated loudly and names the store"; PASS=$((PASS + 1))
else
  echo "  [FAIL] DP-17b nothing in the log says the store could not be reached"; FAIL=$((FAIL + 1))
fi
LOGT=$(docker exec llb1 grep -F "[AIKey]" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null)
chk_has "DP-17b the failure names the certificate identity" "certificate" "$LOGT"
NEW=$(pg_since aisep-pg-tls "$TLSLOG")
chk_hasnt "DP-17b no session was authorized on the store"   "user=aigwuser" "$NEW"

# Leave the topology in the posture config.sh advertised.
point_store_dns "$PG_TLS_IP"
restart_gw $AIKEY_ARGS >/dev/null 2>&1
mk_rules

echo ""
echo "===== SUMMARY: pass=$PASS fail=$FAIL ====="
if [ "$FAIL" -eq 0 ]; then
  echo SCENARIO-ai-authsep [OK]
  exit 0
fi
echo SCENARIO-ai-authsep [FAILED]
exit 1
