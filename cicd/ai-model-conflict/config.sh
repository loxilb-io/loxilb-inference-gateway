#!/bin/bash
# CICD scenario: ai-model-conflict
#
# Proves the effective-model contract on enforcing VIPs: authorization and
# routing must act on ONE model resolution (body-first), and a request that
# carries BOTH a JSON body "model" and an X-Model header that disagree is
# answered 400 model_conflict instead of being silently steered by
# whichever value each subsystem happened to prefer.
#
# The defect this suite was born red against: the auth gate binds
# allowed_models to the body model (body-first), while endpoint selection
# derived its own effective model header-first — so a key authorized only
# for model A could reach model B's pool by naming A in the body and B in
# X-Model. The red run against the pre-fix binary is the evidence that the
# green run means something.
#
# Non-enforcing VIPs keep their legacy behavior on purpose (no silent
# change for unauthenticated consumers); T6 pins that.
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, llama-70b)
#                                                  ── l3ep2 (32.32.32.1, mistral-7b)
#   pg-conflict (docker bridge, aikey store only — no --userservice: the
#   data-plane verdict must not depend on the management plane, and this
#   scenario needs only the key store)
#
#   port 2030: enforcing (api_key_auth=required), llama + mistral pools
#   port 2031: non-enforcing, same two pools (legacy-behavior control)

source ../common.sh

PG_NAME=pg-conflict
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1
MGMT_PW=mgmt-secret-1

echo "#########################################"
echo "Spawning PostgreSQL for the key store"
echo "#########################################"

docker rm -f "$PG_NAME" >/dev/null 2>&1
docker run --rm -d --name "$PG_NAME" \
  -e POSTGRES_USER="$PG_OWNER" \
  -e POSTGRES_PASSWORD="$PG_OWNER_PW" \
  -e POSTGRES_DB="$PG_DB" \
  postgres:18.6 >/dev/null

echo "Waiting for PostgreSQL to be ready..."
for i in $(seq 1 60); do
  if docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1; then
    echo "PostgreSQL ready (${i}s)"
    break
  fi
  sleep 1
done
docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null || {
  echo "PostgreSQL did not come up"; exit 1; }

docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
  echo "bootstrap script failed"; exit 1; }

PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME")
echo "PostgreSQL IP: $PG_IP"

echo "#########################################"
echo "Preparing loxilb config directory"
echo "#########################################"

pick_config=yes
mkdir -p llb1_config
echo "$DP_PW" > llb1_config/aikey_password

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser \
    --aikey-db-name $PG_DB --aikey-db-password-file /etc/loxilb/aikey_password"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

# Reset pick_config so config_docker_host does NOT skip llb1 IP assignment.
pick_config=""

config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24  --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24  --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1  --ptype phy --addr 32.32.32.1/24  --gw 32.32.32.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3h1  32.32.32.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254
add_route l3ep2 10.10.10.0/24 32.32.32.254

# Start the mock listeners before the full-proxy rules exist (a rule against
# a closed backend takes the 10-second reconnect path; see ai-model-routing).
start_mock_backend() { # <namespace> <response label>
  local ns=$1 label=$2
  $hexec "$ns" sh -c "nohup node ../common/tcp_server.js '$label' >/tmp/ai-model-conflict-$label.log 2>&1 &"
  for i in $(seq 1 20); do
    if $hexec "$ns" curl -sf --max-time 1 http://127.0.0.1:8080/ | grep -q "$label"; then
      echo "  $label backend ready (${i})"
      return 0
    fi
    sleep 1
  done
  echo "  FATAL: $label backend did not become ready"
  return 1
}

start_mock_backend l3ep1 server-llama   || exit 1
start_mock_backend l3ep2 server-mistral || exit 1

echo "#########################################"
echo "Waiting for loxilb REST API to be ready"
echo "#########################################"

for i in $(seq 1 30); do
  if $hexec l3h1 curl -sf http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i}s)"
    break
  fi
  sleep 2
done

# Wait out the boot-config freeze window (see ai-model-routing for why an
# empty-body probe is the right instrument: it can never apply).
for i in $(seq 1 40); do
  if ! $hexec l3h1 curl -s -m 3 -X POST http://10.10.10.254:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}' | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled"
    exit 1
  fi
  sleep 2
done

# add_lb_rule <port> <model> <ep_ip> <auth: required|""> — one model pool.
add_lb_rule() {
  local port=$1 model=$2 ep=$3 auth=$4
  local auth_field=""
  if [ -n "$auth" ]; then
    auth_field='"api_key_auth": "required",'
  fi
  local resp
  resp=$($hexec l3h1 curl -s -X POST \
    http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
    -H "Content-Type: application/json" \
    -d '{
      "serviceArguments": {
        "externalIP":     "10.10.10.254",
        "port":            '"$port"',
        "protocol":       "tcp",
        "sel":             0,
        "mode":            4,
        "host":           "10.10.10.254",
        "path_prefix":    "/",
        "path_match_mode": "prefix",
        "model_name":     "'"$model"'",
        '"$auth_field"'
        "inactiveTimeOut": 30
      },
      "endpoints": [
        {"endpointIP": "'"$ep"'", "targetPort": 8080, "weight": 1}
      ]
    }')
  echo "  rule $port/$model -> $ep: $resp"
  case "$resp" in
    *Success*) ;;
    *) echo "FATAL: LB rule $port/$model rejected"; exit 1 ;;
  esac
}

echo "## Enforcing VIP: port 2030, llama + mistral pools, api_key_auth=required"
add_lb_rule 2030 "llama-70b"  "31.31.31.1" required
add_lb_rule 2030 "mistral-7b" "32.32.32.1" required

echo "## Non-enforcing VIP: port 2031, same pools (legacy-behavior control)"
add_lb_rule 2031 "llama-70b"  "31.31.31.1" ""
add_lb_rule 2031 "mistral-7b" "32.32.32.1" ""

echo "#########################################"
echo "Creating the llama-only API key"
echo "#########################################"

# The key is the point: allowed_models is llama-70b ONLY. Any request that
# reaches the mistral pool with this key is an authorization bypass.
KEY_RESP=$($hexec llb1 curl -s -X POST \
  http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "conflict-tenant",
    "name": "llama-only",
    "allowed_models": ["llama-70b"]
  }')
RAW_KEY=$(echo "$KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
if [ -z "$RAW_KEY" ]; then
  echo "FATAL: API key creation failed: $KEY_RESP"
  exit 1
fi
echo "RAW_KEY=$RAW_KEY" > .state
echo "key created (llama-70b only)"

sleep 2
echo "config.sh done"
