#!/bin/bash
# gw.sh — the gateway half of the ai-admission scenario, shared by config.sh
# (the first boot, enforce mode) and validation.sh (the observe-mode reboot).
# Sourced after ../common.sh.

VIP=10.10.10.254
MODEL=cap-model
FC_MAX_OUT=8          # LLB_FC_MAX_OUTSTANDING: executing requests per pool
FC_EP_CAP=5           # LLB_FC_EP_MAX_INFLIGHT:  executing requests per endpoint
PORT_H1=2021          # plaintext HTTP/1.1 pool, two backends
PORT_H2=2022          # HTTP/2 (h2c) pool, two h2c backends
PORT_TLS=2023         # TLS listener, the same two HTTP/1.1 backends, SSE cap 3 s
PORT_ONE=2024         # one backend: the endpoint ceiling is the binding one
PORT_Q=2025           # the same two backends with a queue: depth 4, wait 30 s
PORT_W=2026           # one backend, depth 65536: the memory warning fires at apply
# (2027 is the port row R13's refused create names; it never exists.)
PORT_P=2028           # the same two backends, the rule's own ceiling (4) under the env's 8
PORT_U=2029           # the same two backends, rule ceiling 2 and a queue: raised at runtime
PORT_AD=2030          # two scraped backends, an adaptive ceiling of 10 on their queue depth
PORT_TT=2031          # the same two, an adaptive ceiling of 8 on their time to first token
PORT_WU=2032          # two backends of its own, per-endpoint ceiling 8, a 20 s warm-up
PORT_TS=2033          # the same two backends, keyed: ceiling 4, tenant share 50 %, no queue
PORT_TQ=2034          # the same two backends, keyed: ceiling 2, tenant share 50 %, a queue
PORT_XH=2035          # the same two backends, ceiling 4, admission headers on admitted responses
PORT_XH2=2036         # the two h2c backends, ceiling 4, admission headers on admitted streams
PORT_DEAD=2037        # one endpoint nothing listens on (l3ep1:8099): the outage a failed connect is answered with
DEAD_TARGET=8099
# Row OBJ creates these three itself and deletes them when it is done: keyed,
# admission headers on, the first two differing only in ai_objective_strict.
PORT_OBJ=2038         # the same two backends: a denied objective is served at the default
PORT_OBJS=2039        # the same, strict: a denied objective is refused 403
PORT_OBJ2=2040        # the two h2c backends, not strict
FC_P_MAX=4
FC_P_STALE_MS=45000
FC_U_MAX=2
FC_AD_MAX=10
FC_AD_FLOOR=2         # a quarter of the ceiling: what fresh backpressure tightens it to
FC_AD_STALE_MS=15000  # the scrape comes every 10 s, so this is one missed scrape
FC_TT_MAX=8
FC_TT_TARGET_MS=300
FC_WU_EP=8
FC_WU_MS=20000
FC_TS_MAX=4
FC_TQ_MAX=2
FC_TS_PCT=50          # half: two units of :PORT_TS a tenant, one of :PORT_TQ and two of its queue
FC_XH_MAX=4
FC_Q_DEPTH=4
# The pool's wait is long enough that a waiter outlives the 10 s metric
# republish the rows poll between parking it and releasing a unit; row T
# shortens it at runtime for the deadline it proves.
FC_Q_WAIT_MS=30000
FC_T_WAIT_MS=4000
SSE_CAP_SEC=3
AUDIT_DIR=/var/log/loxilb/audit
GW_ARGS="--audit-dir $AUDIT_DIR --audit-required"
# The API-key store behind the keyed pools (:PORT_TS, :PORT_TQ): the tenant a
# key resolves to is what the tenant share counts. Its two secrets are files
# in cert/, the one directory mounted into the gateway, so the in-place
# restarts keep them.
PG_NAME=pg-ai-admission
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1
MGMT_PW=mgmt-secret-1
# gw_pg_start: the store, empty and bootstrapped. config.sh starts it; row
# NEG stops it (the outage a cold key meets) and starts it again before the
# observe-mode reboot, which needs it for the two keyed rules. The container
# runs --rm, so a stop removes it and a start is always a new, empty store.
gw_pg_start() {
  local i
  docker rm -f "$PG_NAME" >/dev/null 2>&1
  # --rm hands the previous run's removal to the daemon asynchronously: wait,
  # bounded, until the name is free before reusing it.
  for i in $(seq 1 30); do
    docker inspect "$PG_NAME" >/dev/null 2>&1 || break
    sleep 1
  done
  docker inspect "$PG_NAME" >/dev/null 2>&1 && { echo "FATAL: a previous $PG_NAME is still being removed"; return 1; }
  docker run --rm -d --name "$PG_NAME" -e POSTGRES_USER="$PG_OWNER" -e POSTGRES_PASSWORD="$PG_OWNER_PW" \
    -e POSTGRES_DB="$PG_DB" postgres:18.6 >/dev/null
  for i in $(seq 1 60); do
    # Over TCP: pg_isready answers on the unix socket before the port listens.
    docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null || {
    echo "FATAL: PostgreSQL did not come up"; return 1; }
  docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
  docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
    "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
    echo "FATAL: the store bootstrap failed"; return 1; }
}
# gw_db_args: the store flags, once the PostgreSQL container is up.
gw_db_args() {
  local ip
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME" 2>/dev/null)
  [ -n "$ip" ] || return 0
  echo "--mgmt-db-host $ip --mgmt-db-port 5432 --mgmt-db-user aigw_mgmt_user --mgmt-db-name $PG_DB" \
       "--mgmt-db-password-file /opt/loxilb/cert/mgmt_db_password" \
       "--aikey-db-host $ip --aikey-db-port 5432 --aikey-db-user aigwuser --aikey-db-name $PG_DB" \
       "--aikey-db-password-file /opt/loxilb/cert/aikey_password"
}
API="http://$VIP:11111/netlox/v1"

gw_env() { # gw_env <mode> -> the environment the gate reads at pool creation
  echo "LLB_FC_MODE=$1 LLB_FC_MAX_OUTSTANDING=$FC_MAX_OUT LLB_FC_EP_MAX_INFLIGHT=$FC_EP_CAP${GW_EXTRA_ENV:+ $GW_EXTRA_ENV}"
}

gw_wait_api() {
  local i
  for i in $(seq 1 40); do
    if $hexec l3h1 curl -sf --max-time 3 "$API/version" >/dev/null 2>&1; then
      echo "  loxilb REST API ready (${i})"; return 0
    fi
    sleep 2
  done
  echo "FATAL: the REST API never answered"; return 1
}

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation. Probe the freeze with a
# write that can never apply.
gw_wait_boot() {
  local i
  for i in $(seq 1 40); do
    if ! $hexec l3h1 curl -s -m 3 -X POST "$API/config/loadbalancer" \
         -H 'Content-Type: application/json' -d '{}' \
         | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      echo "  boot config settled (${i})"; return 0
    fi
    sleep 2
  done
  echo "FATAL: boot config replay never settled"; return 1
}

gw_wait_audit() {
  local st
  st=$($hexec l3h1 curl -s -m 5 "$API/audit/status")
  echo "  audit: $(printf '%s' "$st" | cut -c1-160)"
  if ! printf '%s' "$st" | jq -e '.available == true and .running == true' >/dev/null 2>&1; then
    echo "FATAL: the audit writer is not running; the deny records cannot be measured"
    return 1
  fi
}

# gw_add_rule <port> <extra-json> <target-port> [<target-port> ...]
# mode 4 (full proxy) turns on the userspace HTTP path; sse_mode makes the
# service an AI-gateway service, which is what the capacity gate keys on. No
# API key: the gate refuses on capacity alone, and the refusal is recorded
# with no actor, which is the shape a keyless VIP produces.
gw_add_rule() {
  local port=$1 extra=$2 resp eps="" tp; shift 2
  for tp in "$@"; do
    eps="$eps${eps:+, }{\"endpointIP\": \"31.31.31.1\", \"targetPort\": $tp, \"weight\": 1}"
  done
  resp=$($hexec l3h1 curl -s -m 10 -X POST "$API/config/loadbalancer" \
    -H 'Content-Type: application/json' \
    -d "{
      \"serviceArguments\": {
        \"externalIP\":      \"$VIP\",
        \"port\":             $port,
        \"protocol\":        \"tcp\",
        \"sel\":              0,
        \"mode\":             4,
        \"host\":            \"$VIP\",
        \"path_prefix\":     \"/\",
        \"path_match_mode\": \"prefix\",
        \"model_name\":      \"$MODEL\",
        \"sse_mode\":         true,
        \"inactiveTimeOut\":  60$extra
      },
      \"endpoints\": [ $eps ]
    }")
  echo "  rule $VIP:$port -> 31.31.31.1:$*: $(printf '%s' "$resp" | cut -c1-120)"
  case "$resp" in
    *Success*|*exist*) ;;
    *) echo "FATAL: rule $port rejected"; return 1 ;;
  esac
}

# gw_queue_json <depth> <wait-ms>: the two queue fields as rule JSON
gw_queue_json() { echo ", \"fc_max_queue_depth\": $1, \"fc_max_queue_wait_ms\": $2"; }
# gw_p_json [<extra>]: the :PORT_P rule's own gate fields, plus <extra>
gw_p_json() { echo ", \"fc_max_outstanding\": $FC_P_MAX, \"fc_telemetry_stale_ms\": $FC_P_STALE_MS${1:-}"; }
# gw_u_json <ceiling>: the :PORT_U rule's ceiling and queue
gw_u_json() { echo ", \"fc_max_outstanding\": $1$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)"; }
# gw_ad_json <on|off>: the :PORT_AD rule, adaptive on its scraped queue depth
gw_ad_json() { echo ", \"fc_max_outstanding\": $FC_AD_MAX, \"fc_adaptive\": \"$1\", \"fc_telemetry_stale_ms\": $FC_AD_STALE_MS"; }
# gw_tt_json: the :PORT_TT rule, adaptive on its time to first token
gw_tt_json() { echo ", \"fc_max_outstanding\": $FC_TT_MAX, \"fc_adaptive\": \"on\", \"fc_ttft_target_ms\": $FC_TT_TARGET_MS, \"fc_telemetry_stale_ms\": $FC_AD_STALE_MS"; }
# gw_wu_json: the :PORT_WU rule, a per-endpoint ceiling and a warm-up window
gw_wu_json() { echo ", \"fc_ep_max_inflight\": $FC_WU_EP, \"fc_warmup_ms\": $FC_WU_MS"; }
# gw_ts_json: the :PORT_TS rule, keyed, a ceiling shared among tenants
gw_ts_json() { echo ", \"api_key_auth\": \"required\", \"fc_max_outstanding\": $FC_TS_MAX, \"fc_tenant_max_share_pct\": $FC_TS_PCT"; }
# gw_xh_json <on|off>: the :PORT_XH / :PORT_XH2 rules, a ceiling and the admission headers switch
gw_xh_json() { echo ", \"fc_max_outstanding\": $FC_XH_MAX, \"fc_expose_headers\": \"$1\""; }
# gw_tq_json: the :PORT_TQ rule, the same with a queue
gw_tq_json() { echo ", \"api_key_auth\": \"required\", \"fc_max_outstanding\": $FC_TQ_MAX, \"fc_tenant_max_share_pct\": $FC_TS_PCT$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)"; }

# gw_obj_json <true|false>: the row OBJ rules, keyed, the class headers exposed
gw_obj_json() { echo ", \"api_key_auth\": \"required\", \"fc_max_outstanding\": $FC_XH_MAX, \"fc_expose_headers\": \"on\", \"ai_objective_strict\": $1"; }

gw_add_rules() {
  gw_add_rule $PORT_H1  ""                                                       8080 8081 || return 1
  gw_add_rule $PORT_H2  ", \"backend_protocol\": \"http2\""                       8090 8091 || return 1
  gw_add_rule $PORT_TLS ", \"security\": 1, \"max_stream_duration_sec\": $SSE_CAP_SEC" 8080 8081 || return 1
  gw_add_rule $PORT_ONE ""                                                       8080      || return 1
  gw_add_rule $PORT_Q   "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)"             8080 8081 || return 1
  gw_add_rule $PORT_W   "$(gw_queue_json 65536 $FC_Q_WAIT_MS)"                   8080      || return 1
  gw_add_rule $PORT_P   "$(gw_p_json)"                                           8080 8081 || return 1
  gw_add_rule $PORT_U   "$(gw_u_json $FC_U_MAX)"                                 8080 8081 || return 1
  gw_add_rule $PORT_AD  "$(gw_ad_json on)"                                       8084 8085 || return 1
  gw_add_rule $PORT_TT  "$(gw_tt_json)"                                          8084 8085 || return 1
  gw_add_rule $PORT_WU  "$(gw_wu_json)"                                          8082 8083 || return 1
  gw_add_rule $PORT_TS  "$(gw_ts_json)"                                          8080 8081 || return 1
  gw_add_rule $PORT_TQ  "$(gw_tq_json)"                                          8080 8081 || return 1
  gw_add_rule $PORT_XH  "$(gw_xh_json on)"                                       8080 8081 || return 1
  gw_add_rule $PORT_XH2 ", \"backend_protocol\": \"http2\"$(gw_xh_json on)"      8090 8091 || return 1
  gw_add_rule $PORT_DEAD ""                                                      $DEAD_TARGET || return 1
  sleep 2
}

# gw_restart <mode>: the gate reads its mode from the process environment
# when a pool is created, so a mode change is a new gateway process. The
# container, its links and its certificate mount stay; the datapath process
# is replaced the way cicd/cfg-persist-negative replaces it, and the rules
# are created again.
gw_restart() {
  local mode=$1 i
  echo "  restarting the gateway in $mode mode"
  docker exec llb1 pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
  for i in $(seq 1 20); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
  done
  docker exec -d llb1 bash -c "$(gw_env "$mode") /root/loxilb-io/loxilb/loxilb -p $GW_ARGS $(gw_db_args) --loglevel debug > /tmp/loxilb.out 2> /tmp/loxilb.err"
  sleep 3
  gw_wait_api && gw_wait_boot && gw_wait_audit && gw_add_rules
}
