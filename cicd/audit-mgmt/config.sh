#!/bin/bash
# CICD scenario: audit-mgmt
#
# The management-plane audit trail, end to end, on a self-contained bed:
# a gateway with the user service on a PostgreSQL store, the OAuth routes
# registered against a placeholder provider, the API-key store for the raw
# PATCH route, and the trail written under --audit-dir with --audit-required.
# validation.sh drives the fail-closed gate, actor attribution, canary
# hygiene, the orphaned-intent recovery, the write-failure fallback and the
# delegated originator; it restarts the gateway process itself, so the
# flag sets are recorded in .state for it.
#
# Topology (the ai-apikey shape):
#   l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)
#   pg-audit (docker bridge, reachable from llb1)

source ../common.sh

PG_NAME=pg-audit
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1
MGMT_PW=mgmt-secret-1
AUDIT_DIR=/var/log/loxilb/audit
ADMIN_USER=admin
# The administrator password is itself a canary: validation.sh proves it
# appears in no segment, no error body and no operational log line.
ADMIN_PW='Adm1n-cnry-pw!9x'

echo "#########################################"
echo "Spawning PostgreSQL for the two stores"
echo "#########################################"

docker rm -f "$PG_NAME" >/dev/null 2>&1
# The container runs with --rm, so a previous run's removal may still be in
# flight when the name is reused. Wait, bounded, until it is actually free.
for i in $(seq 1 30); do
  docker inspect "$PG_NAME" >/dev/null 2>&1 || break
  sleep 1
done
if docker inspect "$PG_NAME" >/dev/null 2>&1; then
  echo "a previous $PG_NAME container is still being removed; giving up"; exit 1
fi
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

# The product's own bootstrap script provisions both roles and schemas, so
# the fixture and the deployment path are the same thing.
docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
  echo "bootstrap script failed"; exit 1; }

PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME")
echo "PostgreSQL IP: $PG_IP"

echo "#########################################"
echo "Preparing loxilb config directory"
echo "#########################################"

# pick_config=yes mounts $(pwd)/llb1_config as /etc/loxilb/ inside the container
pick_config=yes
rm -rf llb1_config
mkdir -p llb1_config
# Both store secrets arrive as mounted files, which is the deployment shape;
# neither ever becomes a command-line argument.
echo "$MGMT_PW" > llb1_config/mgmt_db_password
echo "$DP_PW"   > llb1_config/aikey_password

MGMT_ARGS="--userservice --mgmt-db-host $PG_IP --mgmt-db-port 5432 --mgmt-db-user aigw_mgmt_user --mgmt-db-name $PG_DB --mgmt-db-password-file /etc/loxilb/mgmt_db_password"
AIKEY_ARGS="--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser --aikey-db-name $PG_DB --aikey-db-password-file /etc/loxilb/aikey_password"
# The OAuth routes exist only when the service is enabled. The provider
# credentials are placeholders: the start route mints a state token and
# answers a redirect without contacting anyone, which is all the healthy
# start arm needs; the callback that would complete a login needs a real
# identity provider and is out of this bed's reach (README).
OAUTH_ARGS="--oauth2 --oauth2provider google --oauth2google-clientid audit-cicd-placeholder --oauth2google-clientsecret audit-cicd-placeholder --oauth2google-redirecturl http://127.0.0.1:11111/netlox/v1/oauth/google/callback"
AUDIT_ARGS="--audit-dir $AUDIT_DIR --audit-required"

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "$MGMT_ARGS $AIKEY_ARGS $OAUTH_ARGS $AUDIT_ARGS"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1

sleep 5

# Reset pick_config so config_docker_host does NOT skip llb1 IP assignment.
pick_config=""

config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24   --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24   --gw 31.31.31.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

add_route l3h1  31.31.31.0/24 10.10.10.254
add_route l3ep1 10.10.10.0/24 31.31.31.254

echo "#########################################"
echo "Waiting for loxilb REST API to be ready"
echo "#########################################"

for i in $(seq 1 30); do
  if docker exec llb1 curl -sf -m 3 http://127.0.0.1:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i}s)"
    break
  fi
  sleep 2
done

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation. Probe the freeze with a
# write that can never apply (an empty body fails validation).
for i in $(seq 1 40); do
  if ! docker exec llb1 curl -s -m 3 -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}' | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled; last probe answer:"
    docker exec llb1 curl -s -m 3 -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer -H 'Content-Type: application/json' -d '{}'
    exit 1
  fi
  sleep 2
done

# validation.sh extracts every field with jq on THIS host (the requests go
# through docker exec, the extraction does not). A missing extractor reads
# as the gateway omitting a field, so it is refused before anything scores.
if ! command -v jq >/dev/null 2>&1; then
  echo "Installing jq on the host (validation.sh extracts JSON fields with it)"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq
fi
require_host_tools jq || exit 1

echo "#########################################"
echo "Creating the administrator (loopback bootstrap) and logging in"
echo "#########################################"

docker exec llb1 curl -s -X POST http://127.0.0.1:11111/netlox/v1/auth/users \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\",\"role\":\"admin\"}"
echo ""

TOKEN=""
for i in $(seq 1 10); do
  LOGIN_RESP=$(docker exec llb1 curl -s -X POST http://127.0.0.1:11111/netlox/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}")
  TOKEN=$(printf '%s' "$LOGIN_RESP" | jq -r '.token // empty' 2>/dev/null)
  [ -n "$TOKEN" ] && break
  sleep 2
done
if [ -z "$TOKEN" ]; then
  echo "  FATAL: no session token; last login answer: $LOGIN_RESP"
  exit 1
fi
echo "Auth token obtained: ${TOKEN:0:20}..."

echo "#########################################"
echo "Audit trail is up (--audit-required)"
echo "#########################################"
STATUS=$(docker exec llb1 curl -s -m 5 -H "Authorization: Bearer $TOKEN" http://127.0.0.1:11111/netlox/v1/audit/status)
echo "  $STATUS" | cut -c1-200
if ! printf '%s' "$STATUS" | jq -e '.available == true and .running == true' >/dev/null 2>&1; then
  echo "  FATAL: the audit writer is not running; nothing below can be measured"
  exit 1
fi

# Auto-persist is a debounced write fired by a successful mutation, and the
# user create above is one; /status/ready is the positive signal that the
# configuration is not frozen behind it.
echo "Waiting for /status/ready"
for i in $(seq 1 40); do
  rs=$(docker exec llb1 curl -s -m 5 -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:11111/netlox/v1/status/ready 2>/dev/null)
  if printf '%s' "$rs" | jq -e '.ready == true' >/dev/null 2>&1; then
    echo "  configuration ready (${i})"
    break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: /status/ready never reported ready; last answer:"
    printf '%s\n' "$rs"
    exit 1
  fi
  sleep 2
done

# validation.sh restarts the gateway process with other flag sets; it needs
# the pieces, not the composed line.
cat > .state <<EOF
PG_NAME='$PG_NAME'
PG_IP='$PG_IP'
AUDIT_DIR='$AUDIT_DIR'
ADMIN_USER='$ADMIN_USER'
ADMIN_PW='$ADMIN_PW'
MGMT_ARGS='$MGMT_ARGS'
AIKEY_ARGS='$AIKEY_ARGS'
OAUTH_ARGS='$OAUTH_ARGS'
EOF

echo "#########################################"
echo "audit-mgmt testbed ready"
echo "#########################################"
echo "  Control plane API: http://llb1:11111/netlox/v1"
echo "  Audit directory:   llb1:$AUDIT_DIR"
echo "  PostgreSQL:        $PG_IP:5432"
