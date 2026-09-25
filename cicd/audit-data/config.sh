#!/bin/bash
# CICD scenario: audit-data
#
# The inference-path audit trail on a self-contained bed: a gateway with the
# API-key store on PostgreSQL, an enforcing AI service, and the trail written
# under --audit-dir with --audit-required. validation.sh drives admitted,
# refused and charged requests and reads the records back.
#
# No --userservice here. The data path authenticates with an API key, and
# the management plane's own trail is the other scenario's subject; leaving
# the user service out keeps this bed to the thing under test.
#
# Topology (the ai-model-conflict shape):
#   l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)
#   pg-audit-data (docker bridge, reachable from llb1)
#
# Services on the VIP:
#   :2020  enforcing, non-streaming        model audit-model
#   :2021  enforcing, SSE                  model audit-model
#
# Keys:
#   K_ALL    tenant audit-tenant, every model      the admitted arms
#   K_MODEL  tenant audit-tenant, audit-model only the 403 refusal arm,
#            which is the one that must still name its tenant
#   K_QUOTA  tenant quota-tenant, every model      the charged/refused arm

source ../common.sh

PG_NAME=pg-audit-data
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1
AUDIT_DIR=/var/log/loxilb/audit
VIP=10.10.10.254
TENANT=audit-tenant
QUOTA_TENANT=quota-tenant
MODEL=audit-model

echo SCENARIO-audit-data-config

echo "#########################################"
echo "Spawning PostgreSQL for the API-key store"
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

# The product's own bootstrap script provisions the role and schema, so the
# fixture and the deployment path are the same thing.
docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$DP_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
  echo "bootstrap script failed"; exit 1; }

PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME")
echo "PostgreSQL IP: $PG_IP"

echo "#########################################"
echo "Preparing the loxilb config directory"
echo "#########################################"

# pick_config=yes mounts $(pwd)/llb1_config as /etc/loxilb/ inside the container.
pick_config=yes
rm -rf llb1_config
mkdir -p llb1_config
printf '%s' "$DP_PW" > llb1_config/aikey_password

# --audit-required: the gateway refuses to run without a usable trail. This
# scenario measures the trail, so a boot that quietly came up without one
# would score every assertion against an absence.
GW_ARGS="--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser"
GW_ARGS="$GW_ARGS --aikey-db-name $PG_DB --aikey-db-password-file /etc/loxilb/aikey_password"
GW_ARGS="$GW_ARGS --audit-dir $AUDIT_DIR --audit-required"

echo "#########################################"
echo "Spawning the topology"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 --extra-args "$GW_ARGS"
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type host   --dock-name l3ep1

connect_docker_hosts l3h1  llb1
connect_docker_hosts l3ep1 llb1

sleep 5

# pick_config did its job at spawn (it mounted the config directory). Left
# set, config_docker_host skips the loxilb host entirely and llb1's own
# interfaces never get an address.
pick_config=""

config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24  --gw $VIP
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24  --gw 31.31.31.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr $VIP/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24

add_route l3h1  31.31.31.0/24 $VIP
add_route l3ep1 10.10.10.0/24 31.31.31.254

echo "#########################################"
echo "Starting the inference backend"
echo "#########################################"

$hexec l3ep1 python3 "$(pwd)/mock_inference.py" 8080 &
track_helper
sleep 2

# The token counts this scenario asserts on come from the backend, so a
# fixture that is not answering with them would turn every accounting
# assertion into a test of the fixture.
if ! $hexec l3ep1 curl -sf --max-time 5 "http://127.0.0.1:8080/v1/chat/completions?pt=5&ct=7" \
     -H 'Content-Type: application/json' -d '{"model":"probe"}' | grep -q '"total_tokens": 12'; then
  echo "FATAL: the backend does not report the usage counts it was asked for"
  exit 1
fi
echo "  backend reports the usage counts it is asked for"

echo "#########################################"
echo "Waiting for the loxilb REST API"
echo "#########################################"

for i in $(seq 1 30); do
  if $hexec l3h1 curl -sf --max-time 3 http://$VIP:11111/netlox/v1/version >/dev/null 2>&1; then
    echo "loxilb REST API ready (${i})"
    break
  fi
  sleep 2
done

# The REST listener answers before the boot config replay settles, and until
# it does the freeze middleware 503s every mutation — a fast runner's first
# write below lands inside that window and reads as a phantom product
# failure. Probe the freeze itself with a write that can never apply.
for i in $(seq 1 40); do
  if ! $hexec l3h1 curl -s -m 3 -X POST http://$VIP:11111/netlox/v1/config/loadbalancer \
       -H 'Content-Type: application/json' -d '{}' \
       | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
    echo "  boot config settled (${i})"; break
  fi
  if [ "$i" -eq 40 ]; then
    echo "  FATAL: boot config replay never settled"; exit 1
  fi
  sleep 2
done

# validation.sh extracts every field with jq on THIS host (the requests go
# through a namespace, the extraction does not). A missing extractor reads
# as the gateway omitting a field, so it is refused before anything scores.
if ! command -v jq >/dev/null 2>&1; then
  echo "Installing jq on the host (validation.sh extracts JSON fields with it)"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq
fi
require_host_tools jq || exit 1

echo "#########################################"
echo "The audit trail is up"
echo "#########################################"

STATUS=$($hexec l3h1 curl -s -m 5 http://$VIP:11111/netlox/v1/audit/status)
echo "  $STATUS" | cut -c1-200
if ! printf '%s' "$STATUS" | jq -e '.available == true and .running == true' >/dev/null 2>&1; then
  echo "  FATAL: the audit writer is not running; nothing below can be measured"
  exit 1
fi

echo "#########################################"
echo "Creating the API keys"
echo "#########################################"

mkkey() { # mkkey <tenant> <name> <models-json> → raw key on stdout
  $hexec l3h1 curl -s -m 10 -X POST http://$VIP:11111/netlox/v1/config/ai/apikey \
    -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$1\",\"name\":\"$2\",\"allowed_models\":$3,\"rate_limit_rps\":500,\"burst_size\":1000,\"enabled\":true}"
}

K_ALL_RESP=$(mkkey "$TENANT" audit-all '[]')
K_ALL=$(printf '%s' "$K_ALL_RESP" | jq -r '.raw_key // empty')
K_ALL_ID=$(printf '%s' "$K_ALL_RESP" | jq -r '.key_id // empty')

K_MODEL_RESP=$(mkkey "$TENANT" audit-model-only "[\"$MODEL\"]")
K_MODEL=$(printf '%s' "$K_MODEL_RESP" | jq -r '.raw_key // empty')
K_MODEL_ID=$(printf '%s' "$K_MODEL_RESP" | jq -r '.key_id // empty')

K_QUOTA_RESP=$(mkkey "$QUOTA_TENANT" audit-quota '[]')
K_QUOTA=$(printf '%s' "$K_QUOTA_RESP" | jq -r '.raw_key // empty')
K_QUOTA_ID=$(printf '%s' "$K_QUOTA_RESP" | jq -r '.key_id // empty')

for pair in "K_ALL:$K_ALL" "K_MODEL:$K_MODEL" "K_QUOTA:$K_QUOTA"; do
  if [ -z "${pair#*:}" ]; then
    echo "  FATAL: ${pair%%:*} was not created"
    echo "    all:   $K_ALL_RESP"
    echo "    model: $K_MODEL_RESP"
    echo "    quota: $K_QUOTA_RESP"
    exit 1
  fi
done
echo "  three keys created (raw values withheld)"

# The enforced token quota is the tenant's, not the key's: tokens_per_min on
# an API key is stored metadata and charges nothing. The backend answers 12
# tokens, so one admitted request puts this tenant's bucket in debt and the
# next request is refused at admission — an oracle with no timing in it.
$hexec l3h1 curl -s -m 10 -X POST http://$VIP:11111/netlox/v1/config/ai/tenant/ratelimit \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$QUOTA_TENANT\",\"rps\":0,\"tokens_per_min\":10}" >/dev/null
echo "  quota-tenant limited to 10 tokens per minute"

echo "#########################################"
echo "Creating the AI services"
echo "#########################################"

# mode 4 (full proxy) turns on the userspace HTTP path; api_key_auth decides
# whether the admission gate enforces. Both are needed: a rule with the
# streaming flag alone accounts but never refuses.
mkrule() { # mkrule <port> <sse>
  $hexec l3h1 curl -s -m 10 -X POST http://$VIP:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d "{
      \"serviceArguments\": {
        \"externalIP\":      \"$VIP\",
        \"port\":             $1,
        \"protocol\":        \"tcp\",
        \"sel\":              0,
        \"mode\":             4,
        \"host\":            \"$VIP\",
        \"path_prefix\":     \"/\",
        \"path_match_mode\": \"prefix\",
        \"model_name\":      \"$MODEL\",
        \"api_key_auth\":    \"required\",
        \"sse_mode\":         $2,
        \"inactiveTimeOut\":  60
      },
      \"endpoints\": [
        {\"endpointIP\": \"31.31.31.1\", \"targetPort\": 8080, \"weight\": 1}
      ]
    }"
}

for spec in "2020 false" "2021 true"; do
  set -- $spec
  resp=$(mkrule "$1" "$2")
  case "$resp" in
    *Success*) echo "  service :$1 created (sse=$2)" ;;
    *) echo "  FATAL: service :$1 rejected: $resp"; exit 1 ;;
  esac
done

sleep 2

cat > .state <<EOF
VIP='$VIP'
PG_NAME='$PG_NAME'
AUDIT_DIR='$AUDIT_DIR'
TENANT='$TENANT'
QUOTA_TENANT='$QUOTA_TENANT'
MODEL='$MODEL'
K_ALL='$K_ALL'
K_ALL_ID='$K_ALL_ID'
K_MODEL='$K_MODEL'
K_MODEL_ID='$K_MODEL_ID'
K_QUOTA='$K_QUOTA'
K_QUOTA_ID='$K_QUOTA_ID'
GW_ARGS='$GW_ARGS'
EOF

echo "#########################################"
echo "audit-data testbed ready"
echo "#########################################"
echo "  Control plane API: http://$VIP:11111/netlox/v1"
echo "  Audit directory:   llb1:$AUDIT_DIR"
echo "  Services:          $VIP:2020 (non-streaming), $VIP:2021 (SSE)"
