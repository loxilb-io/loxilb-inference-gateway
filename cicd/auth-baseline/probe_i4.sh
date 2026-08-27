#!/bin/bash
# I-4 gates: the key lifecycle API stands on its own, and the datapath
# validates against the new store.
#
# POL-1   with --userservice off, all seven key-lifecycle ops answer non-501
# POL-1b  with no store configured, all seven answer 503 ai_key_store_unconfigured
# POL-1c  with --userservice on, an unauthenticated call to any of them is 401
# POL-3   POST returns the secret once; GET and list never carry it
# POL-7   a caller-supplied key registers and works end-to-end through the VIP
# DP-REPOINT  the datapath enforces against PostgreSQL with --userservice off,
#             and still admits when no store is configured (the retained
#             nil -> allow, which PR 3 removes)
#
# The gateway is restarted between phases because each phase is a different
# gateway configuration; that is the thing under test, not an artefact.
#
# A red leg is a code defect until proven otherwise. Do not soften an assert.
API=http://localhost:11111/netlox/v1
VIP=10.10.10.254
PASS=0
FAIL=0

chk() { # chk <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  [PASS] $1 (got $3)"
    PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 expected=$2 got=$3"
    FAIL=$((FAIL + 1))
  fi
}
chk_not() { # chk_not <name> <forbidden> <actual>
  if [ "$2" != "$3" ]; then
    echo "  [PASS] $1 (got $3, not $2)"
    PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 must not be $2"
    FAIL=$((FAIL + 1))
  fi
}
code_llb() { docker exec llb1 curl -s -o /dev/null -m 30 -w "%{http_code}" "$@"; }
body_llb() { docker exec llb1 curl -s -m 30 "$@"; }

AIKEY_ARGS=$(cat /root/authsep-i4-aikey-args 2>/dev/null)
if [ -z "$AIKEY_ARGS" ]; then
  echo "PRECONDITION NOT MET: /root/authsep-i4-aikey-args is missing. Run up_i4.sh first."
  exit 2
fi

# restart_gw restarts the gateway with a different flag set.
#
# A bare kill-and-start always fails on `llb_xh_init: Assertion 0 failed`,
# because four pieces of datapath state outlive the process: the persistent
# llb0 TAP, the XDP programs and clsact qdiscs on each interface, and the bpffs
# pins under /opt/loxilb/dp. The TAP is the one that actually blocks the
# restart; the rest are cleared for the same reason.
# The POL-3 and POL-7 legs create keys and then count them, and `key_hash` is
# UNIQUE — so a re-run against a store that already holds them fails on the
# create and on the count. That is a dirty fixture, not a code defect, and it
# should say so rather than be read as one. `up_i4.sh` recreates the store.
PGROWS=$(docker exec aikey-pg psql -h 127.0.0.1 -U oamuser -d loxilb -tAc \
  'SELECT count(*) FROM aigw.api_keys;' 2>/dev/null | tr -d '[:space:]')
if [ "$PGROWS" != "0" ]; then
  echo "PRECONDITION NOT MET: aigw.api_keys holds ${PGROWS:-?} row(s)."
  echo "Re-run cicd/auth-baseline/up_i4.sh first; it recreates the store."
  exit 2
fi

restart_gw() { # restart_gw <extra flags...>
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

  # `docker exec` hands the process an 8192K memlock limit, which the eBPF
  # maps do not fit in. stderr is captured because a gateway started with
  # `docker exec -d` and no redirection loses its panic traces entirely.
  docker exec -d llb1 bash -c "ulimit -l unlimited; /root/loxilb-io/loxilb/loxilb $* > /tmp/loxilb.out 2> /tmp/loxilb.err"
  for i in $(seq 1 40); do
    docker exec llb1 curl -sf -m 3 http://localhost:11111/netlox/v1/version >/dev/null 2>&1 && {
      # The sockproxy binds on a 10s retry loop, so the L7 listeners are not
      # up when the REST API answers. Judging L7 before then reads as a
      # gateway defect and is a race in the probe.
      sleep 25
      return 0
    }
    sleep 2
  done
  echo "  gateway did not come back; stderr tail:"
  docker exec llb1 tail -20 /tmp/loxilb.err
  return 1
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

# run_seven <assert-fn> [extra curl args...]
run_seven() {
  local assert_fn=$1; shift
  while IFS='|' read -r label rest; do
    [ -z "$label" ] && continue
    local -a args=()
    IFS='|' read -r -a fields <<<"$rest"
    for f in "${fields[@]}"; do
      case "$f" in
        /config/*) args+=("$API$f") ;;
        *) args+=("$f") ;;
      esac
    done
    "$assert_fn" "$label" "${args[@]}" "$@"
  done < <(seven_ops)
}

assert_not_501() {
  local label=$1; shift
  chk_not "POL-1 $label registered" "501" "$(code_llb "$@")"
}
assert_401() {
  local label=$1; shift
  chk "POL-1c $label unauthenticated" "401" "$(code_llb "$@")"
}
assert_503_unconfigured() {
  local label=$1; shift
  local code body
  code=$(code_llb "$@")
  body=$(body_llb "$@")
  chk "POL-1b $label status" "503" "$code"
  case "$body" in
    *ai_key_store_unconfigured*)
      echo "  [PASS] POL-1b $label reports ai_key_store_unconfigured"
      PASS=$((PASS + 1)) ;;
    *)
      echo "  [FAIL] POL-1b $label body did not name the condition: $body"
      FAIL=$((FAIL + 1)) ;;
  esac
}

################################################################################
echo "===== PHASE A: store configured, --userservice OFF ====="
################################################################################
restart_gw $AIKEY_ARGS || exit 1

echo "----- POL-1: every key-lifecycle op is registered without --userservice -----"
run_seven assert_not_501

echo "----- POL-3: POST returns the secret once, reads never carry it -----"
KRESP=$(body_llb -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d '{"tenant_id":"pol3-tenant","name":"generated","allowed_models":["test-model"],"rate_limit_rps":100,"burst_size":200,"tokens_per_min":1000000,"enabled":true}')
echo "  create response: $(echo "$KRESP" | sed 's/lxb_[0-9a-f]*/lxb_<redacted>/')"
RAW=$(echo "$KRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
KID=$(echo "$KRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("key_id",""))' 2>/dev/null)
if [ -n "$RAW" ]; then
  echo "  [PASS] POL-3 create returned a secret"; PASS=$((PASS + 1))
else
  echo "  [FAIL] POL-3 create returned no secret"; FAIL=$((FAIL + 1))
fi
GETONE=$(body_llb -X GET $API/config/ai/apikey/$KID)
LIST=$(body_llb -X GET $API/config/ai/apikey)
for pair in "GET/{id}:$GETONE" "list:$LIST"; do
  what=${pair%%:*}; doc=${pair#*:}
  if [ -n "$RAW" ] && [ "${doc#*$RAW}" != "$doc" ]; then
    echo "  [FAIL] POL-3 $what returned the raw key"; FAIL=$((FAIL + 1))
  else
    echo "  [PASS] POL-3 $what does not carry the raw key"; PASS=$((PASS + 1))
  fi
done

echo "----- POL-7: register a caller-supplied key -----"
SUPPLIED="sk-imported-probe-key-0123456789"
SRESP=$(body_llb -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"pol7-tenant\",\"name\":\"imported\",\"api_key\":\"$SUPPLIED\",\"allowed_models\":[\"test-model\"],\"rate_limit_rps\":100,\"burst_size\":200,\"tokens_per_min\":1000000,\"enabled\":true}")
echo "  create response: $SRESP"
SKID=$(echo "$SRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("key_id",""))' 2>/dev/null)
SRAW=$(echo "$SRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
if [ -n "$SKID" ]; then
  echo "  [PASS] POL-7 supplied key registered (key_id=$SKID)"; PASS=$((PASS + 1))
else
  echo "  [FAIL] POL-7 supplied key was not registered"; FAIL=$((FAIL + 1))
fi
if [ -z "$SRAW" ]; then
  echo "  [PASS] POL-7 create does not echo the supplied key"; PASS=$((PASS + 1))
else
  echo "  [FAIL] POL-7 create echoed the supplied key"; FAIL=$((FAIL + 1))
fi
SGET=$(body_llb -X GET $API/config/ai/apikey/$SKID)
SLIST=$(body_llb -X GET $API/config/ai/apikey)
for pair in "GET/{id}:$SGET" "list:$SLIST"; do
  what=${pair%%:*}; doc=${pair#*:}
  if [ "${doc#*$SUPPLIED}" != "$doc" ]; then
    echo "  [FAIL] POL-7 $what returned the supplied key"; FAIL=$((FAIL + 1))
  else
    echo "  [PASS] POL-7 $what does not carry the supplied key"; PASS=$((PASS + 1))
  fi
done

echo "----- the key really is in PostgreSQL, not in MariaDB -----"
ROWS=$(docker exec aikey-pg psql -h 127.0.0.1 -U oamuser -d loxilb -tAc \
  "SELECT count(*) FROM aigw.api_keys WHERE tenant_id IN ('pol3-tenant','pol7-tenant');" 2>/dev/null | tr -d '[:space:]')
chk "both keys are rows in aigw.api_keys" "2" "$ROWS"

echo "----- DP-REPOINT: the datapath validates against the new store -----"
docker exec llb1 curl -s -X POST $API/config/loadbalancer -H 'Content-Type: application/json' \
  -d "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":2020,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":true,\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}" >/dev/null
sleep 3
vip_code() { docker exec l3h1 curl -s -o /dev/null -m 20 -w '%{http_code}' "$@"; }
BODY='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'

R=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -H "X-Api-Key: $SUPPLIED" -d "$BODY")
chk "POL-7 supplied key works end-to-end through the VIP" "200" "$R"

R=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -H "X-Api-Key: $RAW" -d "$BODY")
chk "POL-7 generated key works end-to-end through the VIP" "200" "$R"

R=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")
chk "keyless request denied with --userservice OFF" "401" "$R"

R=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -H 'X-Api-Key: lxb_not-a-real-key-at-all-0000000' -d "$BODY")
chk "unknown key denied" "401" "$R"

echo "----- a row written straight into PostgreSQL authenticates at the VIP -----"
# Written with psql, never through the gateway, so a pass can only mean the
# datapath read that database. Every other leg here would still pass if the
# gateway were serving from its own cache or from somewhere else entirely.
DIRECT="sk-written-by-psql-not-the-api-01"
DIRECT_HASH=$(printf '%s' "$DIRECT" | sha256sum | cut -d' ' -f1)
docker exec aikey-pg psql -h 127.0.0.1 -U oamuser -d loxilb -q -c \
  "INSERT INTO aigw.api_keys (key_id, key_hash, tenant_id, name, allowed_models, rate_limit_rps, burst_size, tokens_per_min, created_at, enabled) VALUES ('directrow0000000000000000000001', '$DIRECT_HASH', 'direct-tenant', 'direct', 'test-model', 100, 200, 1000000, now(), TRUE);" >/dev/null
R=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -H "X-Api-Key: $DIRECT" -d "$BODY")
chk "a key inserted directly into aigw.api_keys authenticates" "200" "$R"

echo "----- revocation takes effect at the VIP -----"
docker exec llb1 curl -s -X PATCH $API/config/ai/apikey/$SKID -H 'Content-Type: application/json' \
  -d '{"enabled":false}' >/dev/null
sleep 1
R=$(vip_code -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -H "X-Api-Key: $SUPPLIED" -d "$BODY")
chk "disabled key rejected at the VIP" "401" "$R"

################################################################################
echo "===== PHASE B: NO store configured ====="
################################################################################
restart_gw || exit 1

echo "----- POL-1b: every op reports the store is unconfigured -----"
run_seven assert_503_unconfigured

echo "----- the retained nil -> allow: keyless traffic is still admitted -----"
docker exec llb1 curl -s -X POST $API/config/loadbalancer -H 'Content-Type: application/json' \
  -d "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":2020,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":true,\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}" >/dev/null
sleep 3
R=$(docker exec l3h1 curl -s -o /dev/null -m 20 -w '%{http_code}' \
  -X POST http://$VIP:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}')
chk "keyless request admitted with no store (PR 2 keeps this; PR 3 removes it)" "200" "$R"
if docker exec llb1 grep -q "No API-key store configured" /tmp/loxilb.err /tmp/loxilb.out 2>/dev/null; then
  echo "  [PASS] the storeless admit is stated in the log"; PASS=$((PASS + 1))
else
  echo "  [FAIL] nothing in the log says requests are being admitted without a key"; FAIL=$((FAIL + 1))
fi

################################################################################
echo "===== PHASE C: store configured, --userservice ON ====="
################################################################################
echo "### MariaDB for the management plane"
docker rm -f mysql-ai >/dev/null 2>&1
docker run --rm -d --name mysql-ai -e MYSQL_ROOT_PASSWORD=loxilb123 \
  -e MYSQL_DATABASE=loxilb_db mariadb:10.11 >/dev/null
for i in $(seq 1 30); do
  docker exec mysql-ai mysqladmin ping -h127.0.0.1 -uroot -ploxilb123 --silent 2>/dev/null && break
  sleep 2
done
MYSQL_IP=$(docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" mysql-ai)
docker exec llb1 bash -c "echo loxilb123 > /etc/loxilb/mysql_password"
# FROZEN at the pre-I-8 flag family, like up.sh and for the same reason: this
# probe targets the authsep-i4 image, which predates the management store's
# move to PostgreSQL, and --databasehost is the correct flag for that build.
restart_gw $AIKEY_ARGS --userservice --databasehost $MYSQL_IP || exit 1

echo "----- POL-1c: unauthenticated calls are refused, not served -----"
run_seven assert_401

echo "----- the management database no longer holds a data-plane key table -----"
# The DDL for api_keys, tenant_rate_limits and tenant_model_rate_limits left
# pkg/db with the repoint. If InitDB still created them, a later change could
# quietly start writing there again and nothing on the wire would say so.
DPTABLES=$(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='loxilb_db' AND table_name IN ('api_keys','tenant_rate_limits','tenant_model_rate_limits');" 2>/dev/null | tr -d '[:space:]')
chk "no data-plane tables in the management database" "0" "$DPTABLES"
MGMTTABLES=$(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='loxilb_db' AND table_name IN ('users','token');" 2>/dev/null | tr -d '[:space:]')
chk "the management tables are still created (the leg above is not vacuous)" "2" "$MGMTTABLES"

echo
echo "===== SUMMARY: pass=$PASS fail=$FAIL ====="
[ "$FAIL" -eq 0 ] || exit 1
