#!/bin/bash
# CICD scenario: ai-ha-failover-bfd
#
# Two gateways peered by loxilb's own BFD (--cluster --self --ka), ONE shared
# VIP that the client alone knows, one shared PostgreSQL API-key store, one
# Keycloak both nodes fetch their JWKS from, identical configuration on both
# nodes. validation.sh then fails the pair over and reports what a client
# that only knows the VIP sees.
#
# Topology
#
#   hfc1 10.10.10.1 ──┐                       ┌── hfe1 31.31.31.1 (echo :8080, witness :8081)
#                     │ hfsw1 br0   hfsw2 br0 ├── hfe2 31.31.31.2
#   llb1 10.10.10.11 ─┤ (client     (backend  ├── hfe3 31.31.31.3
#   llb2 10.10.10.12 ─┘  segment)    segment) └── hfe4 31.31.31.4
#        VIP 10.10.10.254 (on whichever node is MASTER)
#        llb1 31.31.31.11 / llb2 31.31.31.12 on the backend segment
#
#   pg-ha-fo, kc-ha-fo: docker bridge, reached by both nodes over eth0.
#   BFD (UDP 3784) and the sync channel (TCP 22222/22223) also run over eth0;
#   that is where spawn_docker_host --with-ka puts them.
#
# The client segment is one L2 broadcast domain and the VIP is an address in
# its subnet that sits on no interface. The product moves it: the MASTER adds
# it to lo and sends a gratuitous ARP. The harness never tells the client
# which node is master and never touches the client's route, ARP entry or NAT.
#
# The harness never sleeps a fixed time before configuring a node: it polls
# the REST API, then the roles (see lib.sh wait_api / wait_roles).
#
# Mutations (each must make FAILOVER-0 fail; used by the mutation table):
#   HAFO_MUTATE=ka-peer     llb2's --ka names a peer address nobody holds
#   HAFO_MUTATE=drop-rule   llb2 is missing the affinity rule
#   HAFO_MUTATE=fo8-ep-order   llb2 gets the affinity rule with its endpoints reversed
#   HAFO_MUTATE=fo3-wrong-aud  the JWT profile expects an audience no token carries
#   HAFO_MUTATE=drop-limit  llb2 is not sent one tenant limit. Kept as a
#                           probe, not as a mutation: tenant limits live in
#                           the shared store, so llb2 reads the limit back
#                           anyway and FAILOVER-0 is right to stay green.

source ../common.sh
echo SCENARIO-ai-ha-failover-bfd
source ./lib.sh

CFGDIR="$HAFO_DIR"
ECHO_PY="${CFGDIR}/../ai-jwtauth/hdr_echo.py"
WITNESS_PY="${CFGDIR}/hafo_backend.py"
JWT_DIR="${CFGDIR}/../ai-jwtauth"
[ -f "$ECHO_PY" ] || { echo "FATAL: echo backend missing: $ECHO_PY"; exit 1; }
fatal() { echo "FATAL: $*"; exit 1; }

# Refuse to take over names this scenario did not create. spawn_docker_host
# force-removes a namesake container, which on a shared bed could be someone
# else's gateway.
if [ ! -f "${CFGDIR}/.owned" ]; then
  for c in llb1 llb2 $CLIENT $BACKENDS $PG_NAME $KC_NAME; do
    docker container inspect "$c" >/dev/null 2>&1 && \
      fatal "a container named $c exists and was not created by this scenario; not touching it"
  done
  for n in $NODES; do
    shared="/etc/shared/$n"
    if [ -d "$shared" ] && [ -n "$(sudo find "$shared" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      fatal "$shared already holds data and is not owned by this run"
    fi
  done
  for ns in $SW_C $SW_B $MON; do
    [ -e "/var/run/netns/$ns" ] && fatal "a network namespace named $ns exists and is not ours"
  done
else
  "${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true
fi
date -u +%FT%TZ > "${CFGDIR}/.owned"
# What this run adds to the host's image list, for rmconfig's report.
docker images --format '{{.Repository}}:{{.Tag}}' | LC_ALL=C sort > "${CFGDIR}/.images-before"

PG_OWNER=oamuser; PG_OWNER_PW=oampass; PG_DB=loxilb; DP_PW=dp-secret-1
KC_REALM=aigw

echo "#########################################"
echo "Spawning the shared API-key store"
echo "#########################################"
# No --rm: FAILOVER-9 stops and starts this container and the store must survive.
docker run -d --name "$PG_NAME" \
  -e POSTGRES_USER="$PG_OWNER" -e POSTGRES_PASSWORD="$PG_OWNER_PW" \
  -e POSTGRES_DB="$PG_DB" postgres:18.6 >/dev/null || fatal "could not start PostgreSQL"
for i in $(seq 1 120); do
  docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1 && \
    { echo "  PostgreSQL ready (${i})"; break; }
  sleep 0.5
  [ "$i" = 120 ] && fatal "PostgreSQL did not come up"
done
docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$DP_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || \
  fatal "aigw db bootstrap failed"
PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME")
echo "$PG_IP" > "${CFGDIR}/.pg-ip"
echo "  shared key store at $PG_IP:5432"

echo "#########################################"
echo "Spawning Keycloak (the image cicd/ai-jwtauth builds)"
echo "#########################################"
KC_IMAGE=${AIGW_KEYCLOAK_IMAGE:-loxilb-aigw-keycloak:26.0-aigw}
KC_REALM_JSON="$JWT_DIR/keycloak/aigw-realm.json"
python3 "$JWT_DIR/mkrealm.py" "$KC_REALM_JSON" >/dev/null || fatal "could not generate the realm"
KC_REALM_HASH=$(sha256sum "$KC_REALM_JSON" | cut -c1-16)
KC_IMAGE_HASH=$(docker image inspect -f '{{index .Config.Labels "aigw.realm.hash"}}' "$KC_IMAGE" 2>/dev/null || true)
if [ "$KC_IMAGE_HASH" != "$KC_REALM_HASH" ]; then
  echo "  $KC_IMAGE absent or baked from another realm — building it"
  AIGW_KEYCLOAK_IMAGE="$KC_IMAGE" "$JWT_DIR/keycloak/build.sh" "$KC_IMAGE" || fatal "could not build $KC_IMAGE"
fi
docker run -d --name "$KC_NAME" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=adminpw \
  "$KC_IMAGE" start-dev >/dev/null || fatal "could not start Keycloak"
KC_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KC_NAME")
KC_ISSUER="http://$KC_IP:8080/realms/$KC_REALM"
KC_JWKS="$KC_ISSUER/protocol/openid-connect/certs"
for i in $(seq 1 180); do
  curl -sf --max-time 3 "$KC_JWKS" | grep -q '"keys"' && { echo "  Keycloak realm ready (${i})"; break; }
  sleep 1
  [ "$i" = 180 ] && { docker logs --tail 40 "$KC_NAME"; fatal "Keycloak never served a JWKS"; }
done

echo "#########################################"
echo "Spawning the two-node BFD pair"
echo "#########################################"
pick_config=yes
for n in $NODES; do
  mkdir -p "${n}_config"
  echo "$DP_PW" > "${n}_config/aikey_password"
done
AIKEY_ARGS="--loglevel info --aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser \
    --aikey-db-name $PG_DB --aikey-db-password-file /etc/loxilb/aikey_password"
SPAWN_T0=$(now_ms)
spawn_docker_host --dock-type loxilb --dock-name llb1 --with-ka in --extra-args "$AIKEY_ARGS"
LLB1_T0=$SPAWN_T0
LLB2_T0=$(now_ms)
spawn_docker_host --dock-type loxilb --dock-name llb2 --with-ka in --extra-args "$AIKEY_ARGS"
pick_config=""

get_llb_peerIP llb1
actual=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb2)
[ "$actual" = "$llb2IP" ] || fatal "llb2 bridge IP $actual != predicted $llb2IP (cluster peering would be dark)"
echo "$llb1IP" > "${CFGDIR}/.llb1-bridge-ip"
echo "$llb2IP" > "${CFGDIR}/.llb2-bridge-ip"
echo "  cluster peers over the docker bridge: llb1=$llb1IP llb2=$llb2IP"

# The exact command line each gateway runs with, as the process reports it.
# node_return starts the gateway again with this and nothing else.
for n in $NODES; do
  p=$(loxilb_pid "$n")
  [ -n "$p" ] || fatal "$n has no loxilb process"
  tr '\0' ' ' < "/proc/$p/cmdline" | sed 's/ *$//' > "${CFGDIR}/.${n}-cmdline"
  echo "  $n: $(cat "${CFGDIR}/.${n}-cmdline")"
done

if [ "${HAFO_MUTATE:-}" = "ka-peer" ]; then
  echo "  MUTATION ka-peer: restarting llb2 with a --ka peer nobody holds"
  sudo kill -9 "$(loxilb_pid llb2)"
  sed -i "s/--ka=[0-9.]*:/--ka=172.17.0.250:/" "${CFGDIR}/.llb2-cmdline"
  docker exec -d llb2 bash -c "$(cat "${CFGDIR}/.llb2-cmdline") >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  LLB2_T0=$(now_ms)
fi

echo "#########################################"
echo "Building the two L2 segments"
echo "#########################################"
for ns in $SW_C $SW_B; do
  sudo ip netns add "$ns"
  sudo ip -n "$ns" link set lo up
  sudo ip -n "$ns" link add br0 type bridge stp_state 0 forward_delay 0
  sudo ip -n "$ns" link set br0 mtu 9000 up
done
spawn_docker_host --dock-type host --dock-name $CLIENT
for b in $BACKENDS; do spawn_docker_host --dock-type host --dock-name "$b"; done

connect_docker_hosts $CLIENT $SW_C
sudo ip -n $SW_C link set "e${SW_C}${CLIENT}" master br0
sudo ip -n $CLIENT addr add "$CLIENT_IP/24" dev "e${CLIENT}${SW_C}"
for b in $BACKENDS; do
  connect_docker_hosts "$b" $SW_B
  sudo ip -n $SW_B link set "e${SW_B}${b}" master br0
  sudo ip -n "$b" addr add "$(be_ip "$b")/24" dev "e${b}${SW_B}"
done
for n in $NODES; do node_wire "$n"; done
# An observer on the client segment. It only asks who has the VIP and records
# who answers; the client's own neighbour table is never touched.
sudo ip netns add $MON
sudo ip -n $MON link set lo up
connect_docker_hosts $MON $SW_C
sudo ip -n $SW_C link set "e${SW_C}${MON}" master br0
sudo ip -n $MON addr add "$MON_IP/24" dev "e${MON}${SW_C}"

echo "#########################################"
echo "Starting the echo backends"
echo "#########################################"
for b in $BACKENDS; do
  $hexec "$b" sh -c "nohup python3 $ECHO_PY ha-fo-$b 8080 >/tmp/ha-fo-$b.log 2>&1 &"
done
for b in $BACKENDS; do
  for i in $(seq 1 50); do
    $hexec "$b" curl -sf --max-time 1 http://127.0.0.1:8080/ | grep -q "ha-fo-$b|.*\"total_tokens\":12" && break
    sleep 0.2
    [ "$i" = 50 ] && fatal "echo backend on $b not ready or not charging 12 tokens"
  done
done
echo "  four echo backends ready, 12 tokens per answer"
# The witness backend (paced streams, held requests, its own in-flight count)
# runs beside the echo on the first backend host.
$hexec $WITNESS_HOST sh -c "nohup python3 $WITNESS_PY ha-fo-witness $WITNESS_PORT >/tmp/ha-fo-witness.log 2>&1 &"
for i in $(seq 1 50); do
  $hexec $WITNESS_HOST curl -sf --max-time 1 "http://127.0.0.1:$WITNESS_PORT/" | grep -q "ha-fo-witness|ready" && break
  sleep 0.2
  [ "$i" = 50 ] && fatal "witness backend on $WITNESS_HOST:$WITNESS_PORT not ready"
done
echo "  witness backend ready on $WITNESS_HOST:$WITNESS_PORT"

echo "#########################################"
echo "Waiting for both REST APIs, then for the roles"
echo "#########################################"
: > "${CFGDIR}/.startup-times"
for n in $NODES; do
  ms=$(wait_api "$n" 120) || fatal "$n REST API not ready after ${ms} ms"
  t0v="LLB1_T0"; [ "$n" = llb2 ] && t0v="LLB2_T0"
  echo "$n api_ready_ms_since_spawn=$(( $(now_ms) - ${!t0v} ))" | tee -a "${CFGDIR}/.startup-times"
done
# A lone node waits out the hello window (90 s by default) plus the cool-off
# before it takes a role, so the bound here is well above that.
if wait_roles 240 6; then
  echo "roles_converged_ms_since_llb2_spawn=$(( $(now_ms) - LLB2_T0 )) master=$MASTER_NODE backup=$BACKUP_NODE" | tee -a "${CFGDIR}/.startup-times"
else
  echo "roles_not_converged last=[$ROLE_LAST] waited_ms=$ROLE_WAIT_MS" | tee -a "${CFGDIR}/.startup-times"
  # Not a warning and not a downgrade: the bed is unusable. validation.sh
  # reads this marker and reports every case NOT_RUN.
  echo "roles did not converge within 240 s: $ROLE_LAST" > "${CFGDIR}/.unhealthy"
  echo "UNHEALTHY: roles did not converge; nothing is configured. validation.sh will report NOT_RUN."
  exit 3
fi

echo "#########################################"
echo "Reaching the IdP and the store from both nodes"
echo "#########################################"
for n in $NODES; do
  $dexec "$n" curl -sf --max-time 5 "$KC_JWKS" | grep -q '"keys"' || fatal "$n cannot reach the JWKS at $KC_JWKS"
done
echo "  both nodes reach $KC_JWKS"

echo "#########################################"
echo "Writing the configuration list and applying it to both nodes"
echo "#########################################"
CFG="${CFGDIR}/.cfg-list"
: > "$CFG"
cfg() { printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr -d '\n' | tr -s ' ')" >> "$CFG"; }
EPS1='[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]'
EPSW='[{"endpointIP":"'"$(be_ip $WITNESS_HOST)"'","targetPort":'"$WITNESS_PORT"',"weight":1}]'
EPS4='[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1},{"endpointIP":"31.31.31.2","targetPort":8080,"weight":1},{"endpointIP":"31.31.31.3","targetPort":8080,"weight":1},{"endpointIP":"31.31.31.4","targetPort":8080,"weight":1}]'
rule() { # <port> <model> <endpoints-json> <extra serviceArguments json, leading comma>
  cfg POST /config/loadbalancer '{"serviceArguments":{"externalIP":"'"$VIP"'","port":'"$1"',"protocol":"tcp","sel":0,"mode":4,"host":"'"$VIP"'","path_prefix":"/","path_match_mode":"prefix","model_name":"'"$2"'","sse_mode":true,"inactiveTimeOut":60'"$4"'},"endpoints":'"$3"'}'
}
KC_AUD=aigw-api
[ "${HAFO_MUTATE:-}" = "fo3-wrong-aud" ] && { KC_AUD=never-issued; echo "  MUTATION fo3-wrong-aud: the profile expects audience $KC_AUD"; }
cfg POST /config/ai/jwtauthprofile '{"name":"kc","issuer":"'"$KC_ISSUER"'","jwks_url":"'"$KC_JWKS"'","audiences":["'"$KC_AUD"'"],"leeway_sec":2,"refresh_sec":300}'
rule $PORT_KEY $MODEL_KEY "$EPS1" ',"api_key_auth":"required"'
rule $PORT_JWT $MODEL_JWT "$EPS1" ',"api_key_auth":"jwt","jwt_auth_profile":"kc"'
rule $PORT_FC  $MODEL_FC  "$EPSW" ',"fc_mode":"enforce","fc_max_outstanding":2,"fc_max_queue_depth":4,"fc_max_queue_wait_ms":20000'
rule $PORT_WIT $MODEL_WIT "$EPSW" ',"api_key_auth":"required"'
rule $PORT_AFF $MODEL_AFF "$EPS4" ',"session_header_name":"X-Conversation-Id"'
# Tenants. The debt tenants have a bound of 10 tokens/min; a case puts one in
# debt with a single answer that reports 60 tokens (the witness backend), so
# the debt outlasts a failover. How long a refusal must last is never assumed:
# the cases read it from the Retry-After the gateway itself sends.
tenant() { cfg POST /config/ai/tenant/ratelimit '{"tenant_id":"'"$1"'","rps":0,"tokens_per_min":'"$2"'}'; }
tenant fo-seed   100000   # sync-liveness seed: charges, can never be refused
tenant fo-probe  100000   # FAILOVER-1 open-loop probe
tenant fo6-stream 100000  # FAILOVER-6: charged, never refused
tenant fo5-debt  10
tenant fo5-ctl   10
tenant fo11-debt 10
tenant fo11-ctl  10
tenant fo11r-debt 10
tenant fo11r-ctl  10
tenant fo10-debt 10
tenant fo10-ctl  10
cfg POST /config/ai/tenant/ratelimit '{"tenant_id":"fo5-rps","rps":1,"tokens_per_min":0}'
if [ "${HAFO_MUTATE:-}" = "drop-limit" ]; then
  echo "  PROBE drop-limit: llb2 will not be sent the fo5-ctl tenant limit"
  grep -v '"tenant_id":"fo5-ctl"' "$CFG" > "${CFGDIR}/.cfg-list.llb2"
fi
if [ "${HAFO_MUTATE:-}" = "fo8-ep-order" ]; then
  echo "  MUTATION fo8-ep-order: llb2 gets the :$PORT_AFF rule with its endpoints in the opposite order"
  python3 - "$CFG" "$PORT_AFF" > "${CFGDIR}/.cfg-list.llb2" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    m, p, b = ln.rstrip("\n").split("\t")
    d = json.loads(b)
    if p == "/config/loadbalancer" and d["serviceArguments"]["port"] == int(sys.argv[2]):
        d["endpoints"].reverse()
        b = json.dumps(d, separators=(",", ":"))
    print("\t".join((m, p, b)))
PY
fi
if [ "${HAFO_MUTATE:-}" = "drop-rule" ]; then
  echo "  MUTATION drop-rule: llb2 will not receive the :$PORT_AFF rule"
  grep -v "\"port\":$PORT_AFF," "$CFG" > "${CFGDIR}/.cfg-list.llb2"
fi
for n in $NODES; do
  list="$CFG"
  [ "$n" = llb2 ] && [ -f "${CFGDIR}/.cfg-list.llb2" ] && list="${CFGDIR}/.cfg-list.llb2"
  apply_cfg "$n" "$list" || fatal "configuration rejected on $n"
  echo "  $n: $(wc -l < "$CFG") writes applied"
done

echo "#########################################"
echo "Minting API keys in the shared store"
echo "#########################################"
: > "${CFGDIR}/.keys"
mint_key() { # <name> <tenant> <tokens_per_min> [rps]
  local name=$1 tenant=$2 tpm=$3 rps=${4:-0} resp raw kid n rb
  resp=$(api_get_post llb1 "$name" "$tenant" "$tpm" "$rps")
  raw=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
  kid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('key_id',''))" 2>/dev/null)
  [ -n "$raw" ] && [ -n "$kid" ] || fatal "could not mint key $name: $resp"
  rb=$($hexec llb2 curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:11111/netlox/v1/config/ai/apikey/$kid")
  [ "$rb" = 200 ] || fatal "key $name ($kid) minted on llb1 is not visible on llb2 (HTTP $rb): the store is not shared"
  echo "${name}:${kid}:${raw}" >> "${CFGDIR}/.keys"
}
api_get_post() {
  local rpsf=""
  [ "$5" != 0 ] && rpsf=',"rps":'"$5"
  $hexec "$1" curl -s -m 5 -X POST http://127.0.0.1:11111/netlox/v1/config/ai/apikey \
    -H 'Content-Type: application/json' \
    -d '{"tenant_id":"'"$3"'","name":"'"$2"'","tokens_per_min":'"$4$rpsf"'}'
}
mint_key fo-seed-key   fo-seed   0
mint_key fo-probe-key  fo-probe  0
mint_key fo2-key       fo2-tenant 0
mint_key fo4-del-key   fo4-tenant 0
mint_key fo4-ctl-key   fo4-tenant 0
mint_key fo5-debt-key  fo5-debt  0
mint_key fo5-ctl-key   fo5-ctl   0
mint_key fo11-debt-key fo11-debt 0
mint_key fo11-ctl-key  fo11-ctl  0
mint_key fo11r-debt-key fo11r-debt 0
mint_key fo11r-ctl-key  fo11r-ctl  0
mint_key fo5-rps-key   fo5-rps   0
mint_key fo10-debt-key fo10-debt 0
mint_key fo10-ctl-key  fo10-ctl  0
mint_key fo6-key       fo6-stream 0
mint_key fo13-key      fo13-tenant 0
# FAILOVER-2's reconnect burst: 200 distinct keys under one unbounded tenant.
: > "${CFGDIR}/.burst-headers"
for i in $(seq 1 200); do
  resp=$(api_get_post llb1 "fo2-burst-$i" fo2-burst 0 0)
  raw=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
  [ -n "$raw" ] || fatal "could not mint burst key $i: $resp"
  echo "X-Api-Key: $raw" >> "${CFGDIR}/.burst-headers"
done
chmod 0600 "${CFGDIR}/.keys" "${CFGDIR}/.burst-headers"
echo "  $(wc -l < "${CFGDIR}/.keys") keys minted on llb1 and read back on llb2"

cat > "${CFGDIR}/.env" <<EOF
KC_ISSUER='$KC_ISSUER'
KC_JWKS='$KC_JWKS'
KC_IP='$KC_IP'
PG_IP='$PG_IP'
PG_OWNER='$PG_OWNER'
PG_DB='$PG_DB'
LXIMAGE='$lxdocker'
EOF
: > "${CFGDIR}/.fresh"

echo "#########################################"
echo "ai-ha-failover-bfd testbed ready"
echo "#########################################"
cat "${CFGDIR}/.startup-times"
echo "  VIP $VIP ports: $PORT_KEY key / $PORT_JWT jwt / $PORT_FC flow control / $PORT_WIT witness / $PORT_AFF affinity"
