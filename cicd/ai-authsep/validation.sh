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
  for _ in $(seq 1 15); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
  done
  # A survivor here means the new gateway will lose the port bind and die,
  # while the OLD process keeps answering — every leg that follows then runs
  # against the previous flag set and reads as phantom product failures.
  # Escalate, and refuse to continue if even SIGKILL does not clear it.
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
#
#   :2020  sse_mode=true   api_key_auth=required  — the enforcing service
#   :2021  sse_mode=false  api_key_auth=disabled  — the non-enforcing service
#
# Both policies are now stated rather than inferred, and that is the change.
# Enforcement used to be a rider on sse_mode: :2020 checked keys because it
# streamed, and :2021 escaped the check because it did not. Neither service
# said anything about authentication, so neither leg tested a policy — they
# tested a side effect of a streaming flag, and the pair would have kept
# passing if the policy field did nothing at all.
#
# The two axes are deliberately crossed rather than aligned: :2020 streams AND
# enforces, :2021 does neither, so a datapath that had quietly gone back to
# deriving one from the other would still pass here. The cross that would
# catch that (a non-streaming service that enforces) is what DP-22 is for.
mk_rules() {
  for spec in "2020 true required" "2021 false disabled"; do
    set -- $spec
    lcurl -X POST $API/config/loadbalancer -H 'Content-Type: application/json' \
      -d "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":$1,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":$2,\"api_key_auth\":\"$3\",\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}" >/dev/null
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
# Still 200, and now for a reason the service states: api_key_auth=disabled.
# Before the policy field this was 200 because a non-streaming service never
# reached the key check at all — the right answer arrived by accident, and the
# leg could not tell the difference between a working policy and a missing one.
chk "A keyless :2021 admitted (api_key_auth=disabled says so)" "keyless:2021=200"  "$(echo "$VEC_A"  | grep '^keyless:2021=')"

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

echo "  the management schema holds no data-plane table"
# The management plane lives in aigw_mgmt under its own role, on the same
# server as the data plane's aigw. Asking the wrong database is how this leg
# stops meaning anything: it used to query the MariaDB that --userservice once
# needed, and once the management plane moved to PostgreSQL that query returned
# zero tables for the trivial reason that the gateway had stopped writing there
# at all. A zero that means "nothing looked" reads exactly like a zero that
# means "correctly separated", which is why the non-vacuity row below is not
# optional.
DPT=$(psql_as aisep-pg oamuser oampass \
  "SELECT count(*) FROM pg_tables WHERE schemaname='aigw_mgmt' AND tablename IN ('api_keys','tenant_rate_limits','tenant_model_rate_limits');" | tr -d '[:space:]')
chk "no data-plane tables in the management schema" "0" "$DPT"
MGT=$(psql_as aisep-pg oamuser oampass \
  "SELECT count(*) FROM pg_tables WHERE schemaname='aigw_mgmt' AND tablename IN ('users','token');" | tr -d '[:space:]')
chk "the management tables are still created (the leg above is not vacuous)" "2" "$MGT"
# And the converse: the data plane's tables are where they belong. Together
# these three say the planes are separated, rather than that one of them is
# simply absent.
DPOWN=$(psql_as aisep-pg oamuser oampass \
  "SELECT count(*) FROM pg_tables WHERE schemaname='aigw' AND tablename IN ('api_keys','tenant_rate_limits','tenant_model_rate_limits');" | tr -d '[:space:]')
chk "the data-plane tables live in aigw" "3" "$DPOWN"

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
# DP-13. The retained `nil -> allow` is gone: a service whose policy says
# required, on a gateway with no key store, refuses rather than admits.
#
# 503 and not 401 is the load-bearing part. The client has done nothing wrong
# and its key may be perfectly good — the gateway cannot tell. A 401 would say
# "your credential is bad", which is both false and permanent, and a client
# that stopped retrying because of it would stay broken after the operator
# fixed the store.
chk "C keyless :2020 refused, store unavailable"     "keyless:2020=503" "$(echo "$VEC_C" | grep '^keyless:2020=')"
chk "C unknown key :2020 refused, store unavailable" "unknown:2020=503" "$(echo "$VEC_C" | grep '^unknown:2020=')"
# The non-enforcing service is unaffected, which is what makes the two 503s
# above a policy decision rather than a gateway that has simply stopped
# serving. Without this row a build that 503'"'"'d everything would pass.
chk "C keyless :2021 still admitted (policy is disabled, store is irrelevant)" "keyless:2021=200" "$(echo "$VEC_C" | grep '^keyless:2021=')"

LOGC=$(docker exec llb1 cat /tmp/loxilb.err /tmp/loxilb.out 2>/dev/null)
chk_has "the storeless refusal is stated in the log, once, at critical severity" "No API-key store configured" "$LOGC"

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

# DP-28: a denied request must not reach the backend.
#
# This is the leg the whole scenario was built for — the gateway's own counters
# cannot answer it, because from their point of view a denied request was
# denied either way. Only the backend knows whether it was handed the request
# anyway. The defect it gates was real: three deny paths returned from the C
# gate with a bare `return;`, leaving an indeterminate parser status that the
# caller read as "carry on", and the request went upstream after being refused.
#
# Measured as a delta around the denied requests rather than as a total, so a
# backend that legitimately served the admitted traffic earlier in the run does
# not make this look like a leak.
# The path is an ARGUMENT, never `wc -l < path`: the redirection would be
# performed by the host shell against the host's filesystem, the file would be
# missing, and every delta would read zero — which is indistinguishable from a
# perfect result. The control below exists because that failure is silent.
BEFORE_DENY=$(docker exec l3ep1 wc -l /tmp/backend_reqs.log 2>/dev/null | awk '{print $1}')
body='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'
DENY_CODE=$(vip_code -X POST http://$VIP:2020/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: lxb_00000000000000000000000000000000' -d "$body")
AFTER_DENY=$(docker exec l3ep1 wc -l /tmp/backend_reqs.log 2>/dev/null | awk '{print $1}')
DELTA=$(( ${AFTER_DENY:-0} - ${BEFORE_DENY:-0} ))
# Positive control first. A zero delta proves nothing unless an ADMITTED
# request moves this counter — a backend that had stopped logging, or a log
# path that had moved, would otherwise report a perfect result.
BEFORE_OK=$AFTER_DENY
OK_CODE=$(vip_code -X POST http://$VIP:2021/v1/chat/completions \
  -H 'Content-Type: application/json' -d "$body")
AFTER_OK=$(docker exec l3ep1 wc -l /tmp/backend_reqs.log 2>/dev/null | awk '{print $1}')
OK_DELTA=$(( ${AFTER_OK:-0} - ${BEFORE_OK:-0} ))
echo "  denied request -> $DENY_CODE, backend delta $DELTA; admitted -> $OK_CODE, backend delta $OK_DELTA"
if [ "$OK_DELTA" -lt 1 ]; then
  echo "  [FAIL] DP-28 control: an ADMITTED request did not move the backend counter"
  echo "         — the instrument is not reading, so the denied-request result below means nothing"
  FAIL=$((FAIL + 1))
else
  chk "DP-28 a denied request does not reach the backend" "0" "$DELTA"
fi

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

################################################################################
echo ""
echo "===== SECTION 5: enforcement mechanics (DP-4, DP-6, DP-10, DP-11, DP-22, DP-23, DP-27) ====="
################################################################################

# ── DP-23: a quota configured against nothing says so ──────────────────────
# The "no enforcing service" posture is produced by DELETING the rules, never
# by restarting: loxilb replays its rules from snapshot.json on start, so a
# freshly restarted gateway still carries every service the previous one had
# — the first version of this leg leaned on exactly that assumption and went
# red against a product that was behaving correctly. The warning must appear
# for the ruleless write and must NOT appear again once an enforcing rule
# exists — both halves, or the leg would pass against a gateway that always
# warns.
echo ""
echo "--- DP-23: tenant quota with no enforcing service ---"
restart_gw $AIKEY_ARGS || exit 1
for p23 in 2020 2021 2022; do
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$p23/protocol/tcp"
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/externalipaddress/$VIP/port/$p23/protocol/tcp"
done
NRULES=$(lcurl "$API/config/loadbalancer/all" | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("lbAttr",[])))' 2>/dev/null)
chk "DP-23 precondition: the rule table is actually empty" "0" "$NRULES"
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"dp23-tenant","rps":100,"tokens_per_min":50000}'
sleep 1
W1=$(docker exec llb1 grep -c "quota configured but NO service has api_key_auth=required" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null | awk -F: '{n+=$2} END{print n+0}')
chk "DP-23 the write is warned about, out loud" "1" "$W1"
mk_rules
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit -H 'Content-Type: application/json' \
  -d '{"tenant_id":"dp23-tenant","rps":100,"tokens_per_min":50000}'
sleep 1
W2=$(docker exec llb1 grep -c "quota configured but NO service has api_key_auth=required" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null | awk -F: '{n+=$2} END{print n+0}')
chk "DP-23 with an enforcing rule present the same write is NOT warned about" "$W1" "$W2"

# Fresh keys for the rest of the section (the restart above emptied the cache).
R_E=$(mkkey dp4-expired '[]')
K_EXP=$(echo "$R_E" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
# Expired at create time on purpose: expiry is checked at validation, and a
# key that was born expired is the cheapest honest way to exercise it.
R_E2=$(lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d '{"tenant_id":"dp4-tenant","name":"born-expired","allowed_models":[],"rate_limit_rps":200,"tokens_per_min":0,"enabled":true,"expires_at":"2020-01-01T00:00:00.000Z"}')
K_DEAD=$(echo "$R_E2" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
R_S=$(lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d '{"tenant_id":"dp6-tenant","name":"slow","allowed_models":[],"rate_limit_rps":1,"burst_size":1,"tokens_per_min":0,"enabled":true}')
K_SLOW=$(echo "$R_S" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
BODY5='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'

echo ""
echo "--- DP-4: an expired key is a 401, not a served request ---"
# The live half of the expiry check: the store row is present and enabled, so
# only the expires_at comparison can produce the denial.
chk "DP-4 a valid key from the same section serves (control)" "200" \
  "$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_EXP" -d "$BODY5")"
chk "DP-4 the born-expired key is refused" "401" \
  "$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_DEAD" -d "$BODY5")"

echo ""
echo "--- DP-6: per-key RPS exhaustion is a 429 that says when to come back ---"
# rps=1 burst=1: the first request drains the bucket, an immediate burst of
# five must include at least one 429, and that 429 must carry Retry-After —
# a client that is told to slow down without being told for how long will
# guess, and guess wrong in both directions.
CODES6=""
HDR6=""
for i in 1 2 3 4 5 6; do
  OUT6=$(docker exec l3h1 curl -s -D - -o /dev/null -m 20 -X POST "http://$VIP:2020/v1/chat/completions" \
    -H 'Content-Type: application/json' -H "X-Api-Key: $K_SLOW" -d "$BODY5")
  C6=$(echo "$OUT6" | head -1 | awk '{print $2}')
  CODES6="$CODES6 $C6"
  if [ "$C6" = "429" ] && [ -z "$HDR6" ]; then
    HDR6=$(echo "$OUT6" | grep -i '^Retry-After:' | tr -d '\r' | awk '{print $2}')
  fi
done
echo "    codes:$CODES6"
case "$CODES6" in
  *429*) echo "  [PASS] DP-6 the burst was rate-limited"; PASS=$((PASS + 1));;
  *) echo "  [FAIL] DP-6 six burst requests on rps=1 never saw a 429 (codes:$CODES6)"; FAIL=$((FAIL + 1));;
esac
if [ -n "$HDR6" ] && [ "$HDR6" -ge 1 ] 2>/dev/null; then
  echo "  [PASS] DP-6 the 429 carries Retry-After ($HDR6 s)"; PASS=$((PASS + 1))
else
  echo "  [FAIL] DP-6 the 429 carries no usable Retry-After ('$HDR6')"; FAIL=$((FAIL + 1))
fi

echo ""
echo "--- DP-22: enforcement on a service that does not stream ---"
# The crossed cell mk_rules cannot provide: sse_mode=false AND
# api_key_auth=required. Enforcement used to be a rider on the streaming
# flag, so this service — auth without SSE — could not exist at all; a
# datapath that quietly re-derived one from the other would serve :2022
# keyless and never rate-limit it.
lcurl -o /dev/null -X POST $API/config/loadbalancer -H 'Content-Type: application/json' \
  -d "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":2022,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":false,\"api_key_auth\":\"required\",\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}"
sleep 3
chk "DP-22 keyless on the non-streaming enforcing service is denied" "401" \
  "$(vip_code -X POST http://$VIP:2022/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY5")"
chk "DP-22 a valid key serves it (control)" "200" \
  "$(vip_code -X POST http://$VIP:2022/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_EXP" -d "$BODY5")"
CODES22=""
for i in 1 2 3 4 5 6; do
  CODES22="$CODES22 $(vip_code -X POST http://$VIP:2022/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_SLOW" -d "$BODY5")"
done
echo "    codes:$CODES22"
case "$CODES22" in
  *429*) echo "  [PASS] DP-22 RPS enforced on the non-SSE service"; PASS=$((PASS + 1));;
  *) echo "  [FAIL] DP-22 rps=1 key was never rate-limited on the non-SSE service (codes:$CODES22)"; FAIL=$((FAIL + 1));;
esac

echo ""
echo "--- DP-27: the key stays on the client side of the gateway ---"
# The backend's own log decides this: count_server records whether any
# x-api-key material appeared in what actually arrived. Instrument control
# first — a canary that is NOT the credential must register, or an absent
# key proves only that the detector is blind.
docker exec l3ep1 sh -c ': > /tmp/backend_reqs.log'
vip_code -X POST "http://$VIP:2020/v1/chat/completions?probe=dp27-canary" \
  -H 'Content-Type: application/json' -H 'X-Canary: x-api-key-canary' -H "X-Api-Key: $K_EXP" -d "$BODY5" >/dev/null
vip_code -X POST "http://$VIP:2020/v1/chat/completions?probe=dp27-required" \
  -H 'Content-Type: application/json' -H "X-Api-Key: $K_EXP" -d "$BODY5" >/dev/null
vip_code -X POST "http://$VIP:2021/v1/chat/completions?probe=dp27-disabled" \
  -H 'Content-Type: application/json' -H "X-Api-Key: $K_EXP" -d "$BODY5" >/dev/null
sleep 1
L_CANARY=$(docker exec l3ep1 grep "probe=dp27-canary" /tmp/backend_reqs.log 2>/dev/null | head -1)
L_REQ=$(docker exec l3ep1 grep "probe=dp27-required" /tmp/backend_reqs.log 2>/dev/null | head -1)
L_DIS=$(docker exec l3ep1 grep "probe=dp27-disabled" /tmp/backend_reqs.log 2>/dev/null | head -1)
chk_has "DP-27 control: the detector sees x-api-key-shaped bytes when they DO arrive" "x_api_key=True" "$L_CANARY"
chk_has "DP-27 the credential is absent upstream on the enforcing service" "x_api_key=False" "$L_REQ"
chk_has "DP-27 and absent upstream on the disabled service too" "x_api_key=False" "$L_DIS"

echo ""
echo "--- DP-10 / DP-11: the store goes away mid-flight ---"
# K_EXP has validated at the VIP above, so it is cached. K_COLD is minted and
# never presented, so its first appearance requires the store. Stop the store
# and the two keys must part ways: the cached one serves (the documented
# window), the cold one is told the truth — 503, the gateway cannot tell, and
# never 401, which would send the keyholder to rotate a credential that is
# fine.
R_C=$(mkkey dp10-cold '[]')
K_COLD=$(echo "$R_C" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
docker stop aisep-pg >/dev/null 2>&1
sleep 2
CODE10=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_COLD" -d "$BODY5")
chk "DP-10 an uncached key during the outage is a 503, not a verdict on the key" "503" "$CODE10"
BODY10=$(docker exec l3h1 curl -s -m 20 -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_COLD" -d "$BODY5")
chk_has "DP-10 and it names the store, not the credential" "policy_store_unavailable" "$BODY10"
chk "DP-11 the cached key keeps serving through the outage (documented window)" "200" \
  "$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_EXP" -d "$BODY5")"
docker start aisep-pg >/dev/null 2>&1
for i in $(seq 1 30); do
  docker exec -e PGPASSWORD=oampass aisep-pg psql -h 127.0.0.1 -U oamuser -d loxilb -tAc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 1
done
chk "DP-10 aftermath: the cold key serves once the store is back" "200" \
  "$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_COLD" -d "$BODY5")"

# Leave the topology in the posture config.sh advertised.
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
