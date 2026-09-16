#!/bin/bash
# CICD scenario: ai-qos-ha-sync
#
# The AI-QoS rate-limiter HA sync path, on a two-node container cluster.
# GPU-free: the backend is the usage-bearing echo this programme already
# uses, so every answered request charges exactly 12 tokens and the quota
# arithmetic in validation.sh is exact rather than approximate.
#
# Topology
#
#   l3h1 10.10.10.1 ── llb1 10.10.10.254:2020 ─┐
#        20.20.20.1 ── llb2 20.20.20.254:2020 ─┴─ l3ep1 (echo, :8080)
#                                                 31.31.31.1 via llb1
#                                                 61.61.61.1 via llb2
#
# llb1 and llb2 are peered with --cluster/--ka (spawn_docker_host --with-ka),
# which is what brings up the XSync channel the rate-limiter push rides.
#
# Both nodes share ONE PostgreSQL API-key store, which is the deployment
# shape and also a correctness requirement for this suite: the per-key TPM
# bucket is keyed "kq:<key_id>", so two nodes minting their own key ids
# would give the same human key two different buckets and QOS-HA-004 could
# never be true for a reason that has nothing to do with sync.
#
# Why BOTH nodes carry the whole configuration
# --------------------------------------------
# The sync wire carries quota STATE, never quota CONFIG — RateLimiterEntry
# has no rate and no burst field at all. Limits reach a peer through the
# control plane, so a scenario that configured only llb1 would be measuring
# a node with no limits and would read every admission on llb2 as a sync
# failure. Both nodes are configured identically, from one list, and the
# read-back is asserted per node.
#
# Why the standby is driven directly instead of via a VIP failover
# ----------------------------------------------------------------
# What QOS-HA-002..006 actually claim is that a caller cannot buy fresh
# quota by arriving at the other node. Moving a keepalived VIP proves that
# only if the move happens, which makes the case a timing test wearing a
# quota test's name. Driving the SAME identity at llb2's own VIP asserts
# the same property with no election in the loop. QOS-HA-012 covers
# promotion separately, where the election IS the subject.

source ../common.sh
echo SCENARIO-ai-qos-ha-sync

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
# The usage-bearing echo backend is shared with ai-jwtauth rather than
# copied: a second copy is a second thing to keep honest, and the charge
# arithmetic here depends on its fixed 5+7 usage object.
ECHO_PY="${CFGDIR}/../ai-jwtauth/hdr_echo.py"
[ -f "$ECHO_PY" ] || { echo "FATAL: echo backend missing: $ECHO_PY"; exit 1; }

# Idempotency: always self-clean a prior aborted run first.
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

PG_NAME=pg-qos-ha
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1

echo "#########################################"
echo "Spawning the shared API-key store"
echo "#########################################"
docker rm -f "$PG_NAME" >/dev/null 2>&1
docker run --rm -d --name "$PG_NAME" \
  -e POSTGRES_USER="$PG_OWNER" -e POSTGRES_PASSWORD="$PG_OWNER_PW" \
  -e POSTGRES_DB="$PG_DB" postgres:18.6 >/dev/null
for i in $(seq 1 60); do
  # Over TCP, not the unix socket: pg_isready answers on the socket before
  # the server is listening on a port the gateway can reach.
  docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" >/dev/null 2>&1 && \
    { echo "  PostgreSQL ready (${i}s)"; break; }
  sleep 1
  [ "$i" = 60 ] && { echo "FATAL: PostgreSQL did not come up"; exit 1; }
done
docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$DP_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
  echo "FATAL: aigw db bootstrap failed"; exit 1; }
PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG_NAME")
echo "  shared key store at $PG_IP:5432"

echo "#########################################"
echo "Spawning the two-node cluster"
echo "#########################################"
pick_config=yes
for n in llb1 llb2; do
  mkdir -p "${n}_config"
  # The secret arrives as a mounted file, which is the deployment shape; it
  # never becomes a command-line argument.
  echo "$DP_PW" > "${n}_config/aikey_password"
done
AIKEY_ARGS="--aikey-db-host $PG_IP --aikey-db-port 5432 --aikey-db-user aigwuser \
    --aikey-db-name $PG_DB --aikey-db-password-file /etc/loxilb/aikey_password"
spawn_docker_host --dock-type loxilb --dock-name llb1 --with-ka in --extra-args "$AIKEY_ARGS"
spawn_docker_host --dock-type loxilb --dock-name llb2 --with-ka in --extra-args "$AIKEY_ARGS"
# Reset pick_config so config_docker_host does NOT skip llb IP assignment
# (the /etc/loxilb mount already happened during spawn_docker_host).
pick_config=""
spawn_docker_host --dock-type host   --dock-name l3h1
spawn_docker_host --dock-type host   --dock-name l3ep1

# llb1's --cluster peer address was predicted as its own bridge IP + 1 at
# spawn time. If the prediction missed, cluster peering is dark and every
# sync assertion below would fail for a reason that has nothing to do with
# the product.
get_llb_peerIP llb1
actual=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' llb2)
if [ "$actual" != "$llb2IP" ]; then
  echo "FATAL: llb2 bridge IP $actual != predicted $llb2IP (cluster peering would be dark)"
  exit 1
fi
echo "$llb1IP" > "${CFGDIR}/.llb1-bridge-ip"
echo "$llb2IP" > "${CFGDIR}/.llb2-bridge-ip"
echo "  cluster peers: llb1=$llb1IP llb2=$llb2IP"

echo "#########################################"
echo "Connecting and configuring links"
echo "#########################################"
connect_docker_hosts l3h1  llb1
connect_docker_hosts l3h1  llb2
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep1 llb2

sleep 5

config_docker_host --host1 l3h1  --host2 llb1  --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3h1  --host2 llb2  --ptype phy --addr 20.20.20.1/24
config_docker_host --host1 l3ep1 --host2 llb1  --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep1 --host2 llb2  --ptype phy --addr 61.61.61.1/24
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb2  --host2 l3h1  --ptype phy --addr 20.20.20.254/24
config_docker_host --host1 llb2  --host2 l3ep1 --ptype phy --addr 61.61.61.254/24
# Replies from the llb2-side endpoint address back to the llb2-side client net.
$hexec l3ep1 ip route add 20.20.20.0/24 via 61.61.61.254

echo "#########################################"
echo "Starting the usage-bearing echo backend"
echo "#########################################"
$hexec l3ep1 sh -c "nohup python3 $ECHO_PY qos-ha-echo 8080 >/tmp/ai-qos-ha-echo.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep1 curl -sf --max-time 1 http://127.0.0.1:8080/ | grep -q "qos-ha-echo"; then
    echo "  echo backend ready (${i})"; break
  fi
  sleep 1
  [ "$i" = 20 ] && { echo "FATAL: echo backend did not become ready"; cat /tmp/ai-qos-ha-echo.log; exit 1; }
done
# The quota arithmetic below depends on this backend charging a FIXED 12
# tokens per answered request. Assert it rather than trust the filename:
# a usage-free variant would leave every bucket clean and turn the
# exhaustion legs green for the wrong reason.
if ! $hexec l3ep1 curl -sf --max-time 2 http://127.0.0.1:8080/ | grep -q '"total_tokens":12'; then
  echo "FATAL: the echo backend is not emitting the expected 12-token usage object"
  $hexec l3ep1 curl -s --max-time 2 http://127.0.0.1:8080/
  exit 1
fi
echo "  backend charge shape confirmed (12 tokens/answer)"

echo "#########################################"
echo "Waiting for both REST APIs"
echo "#########################################"
for n in llb1 llb2; do
  ok=0
  for _ in $(seq 1 60); do
    rc=$($hexec "$n" curl -s -m 3 -o /dev/null -w "%{http_code}" \
      "http://localhost:11111/netlox/v1/config/loadbalancer/all" 2>/dev/null)
    [ "$rc" = "200" ] && { ok=1; break; }
    sleep 1
  done
  [ "$ok" = 1 ] || { echo "FATAL: $n REST API not ready"; exit 1; }
  # The REST listener answers before the boot config replay settles, and
  # until it does the freeze middleware 503s every mutation. Probe the
  # freeze with a write that can never apply (an empty body fails
  # validation, so nothing is created).
  for i in $(seq 1 40); do
    if ! $hexec "$n" curl -s -m 3 -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
         -H 'Content-Type: application/json' -d '{}' \
         | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      echo "  $n boot config settled (${i})"; break
    fi
    [ "$i" = 40 ] && { echo "FATAL: $n boot config replay never settled"; exit 1; }
    sleep 2
  done
done

echo "#########################################"
echo "Configuring both nodes identically"
echo "#########################################"

# cfg_both <method> <path> <json> — applies one configuration write to BOTH
# nodes and fails the run unless both answer 2xx. A node that silently
# missed a write would make the other node's verdict unreadable.
cfg_both() {
  local method=$1 path=$2 body=$3 n resp code
  for n in llb1 llb2; do
    if [ -n "$body" ]; then
      resp=$($hexec "$n" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X "$method" \
        "http://localhost:11111/netlox/v1$path" -H 'Content-Type: application/json' -d "$body")
    else
      resp=$($hexec "$n" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X "$method" \
        "http://localhost:11111/netlox/v1$path")
    fi
    code=$(echo "$resp" | sed -n 's/^http_code=//p')
    case "$code" in
      2*) ;;
      *) echo "FATAL: $n $method $path -> ${code:-<no code>}: $resp"; exit 1 ;;
    esac
  done
  echo "  both nodes: $method $path -> 2xx"
}

# node_vip <node> — the VIP each node serves on its own client-side link.
node_vip() { [ "$1" = "llb1" ] && echo "10.10.10.254" || echo "20.20.20.254"; }
node_ep()  { [ "$1" = "llb1" ] && echo "31.31.31.1"   || echo "61.61.61.1"; }

# The AI rule. api_key_auth=required: key enforcement is a per-service
# policy, and this suite exists to test enforcement, so it declares it.
for n in llb1 llb2; do
  vip=$(node_vip "$n"); ep=$(node_ep "$n")
  resp=$($hexec "$n" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X POST \
    http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{
      "serviceArguments": {
        "externalIP":      "'"$vip"'",
        "port":            2020,
        "protocol":        "tcp",
        "sel":             0,
        "mode":            4,
        "host":            "'"$vip"'",
        "path_prefix":     "/",
        "path_match_mode": "prefix",
        "model_name":      "qos-ha-model",
        "api_key_auth":    "required",
        "sse_mode":        true,
        "inactiveTimeOut": 60
      },
      "endpoints": [ {"endpointIP": "'"$ep"'", "targetPort": 8080, "weight": 1} ]
    }')
  case "$resp" in
    *http_code=2*) echo "  $n AI rule $vip:2020 -> $ep:8080 created" ;;
    *) echo "FATAL: $n AI rule rejected: $resp"; exit 1 ;;
  esac
done

# A keyless service for the per-VIP shared bucket (QOS-HA-006). Keyless
# traffic carries no tenant, so the VIP bucket is the ONLY thing bounding
# it — which is the whole claim of that case.
for n in llb1 llb2; do
  vip=$(node_vip "$n"); ep=$(node_ep "$n")
  resp=$($hexec "$n" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X POST \
    http://localhost:11111/netlox/v1/config/loadbalancer \
    -H 'Content-Type: application/json' \
    -d '{
      "serviceArguments": {
        "externalIP":      "'"$vip"'",
        "port":            2021,
        "protocol":        "tcp",
        "sel":             0,
        "mode":            4,
        "host":            "'"$vip"'",
        "path_prefix":     "/",
        "path_match_mode": "prefix",
        "model_name":      "qos-ha-keyless",
        "sse_mode":        true,
        "inactiveTimeOut": 60
      },
      "endpoints": [ {"endpointIP": "'"$ep"'", "targetPort": 8080, "weight": 1} ]
    }')
  case "$resp" in
    *http_code=2*) echo "  $n keyless rule $vip:2021 created" ;;
    *) echo "FATAL: $n keyless rule rejected: $resp"; exit 1 ;;
  esac
done

# The shared keyless bucket is OPT-IN, per rule ident, and the rule ident is
# node-local because the VIP is. vip_shared_tpm=10 against a fixed 12-token
# answer means request 1 is admitted and its settle puts the bucket in debt.
for n in llb1 llb2; do
  vip=$(node_vip "$n")
  resp=$($hexec "$n" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X POST \
    http://localhost:11111/netlox/v1/config/ai/ratelimit/defaults \
    -H 'Content-Type: application/json' \
    -d '{"scope":"rule","rule_ident":"'"$vip"':2021","vip_shared_rps":100,"vip_shared_tpm":10}')
  case "$resp" in
    *http_code=2*) echo "  $n vip bucket $vip:2021 (rps=100 tpm=10)" ;;
    *) echo "FATAL: $n vip bucket rejected: $resp"; exit 1 ;;
  esac
done

# Tenant-scope quotas. tokens_per_min=10 with a 12-token answer means the
# first answered request puts the bucket in debt and the next request is
# refused — two requests decide a leg, with no timing in the oracle.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-tenant","rps":0,"tokens_per_min":10}'
# QOS-HA-005's pair. Both tenants carry BOTH an aggregate bound and a
# per-model bound, and the two differ only in WHICH of the two is small
# enough to refuse. QOS-HA-002 and -003 each configure one scope alone, so
# neither can tell whether the scopes still cross when a tenant holds both —
# the shape a real tenant with a model carve-out actually has. Here the
# generous bound is 100000, far beyond anything the case spends, so the rung
# that refuses at the far node is the only rung that COULD have.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-agg-only","rps":0,"tokens_per_min":10,"model_limits":[{"model":"qos-ha-model","tokens_per_min":100000}]}'
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-model-only","rps":0,"tokens_per_min":100000,"model_limits":[{"model":"qos-ha-model","tokens_per_min":10}]}'
for t in ha-ctl-005a ha-ctl-005b; do
  cfg_both POST /config/ai/tenant/ratelimit \
    '{"tenant_id":"'"$t"'","rps":0,"tokens_per_min":10,"model_limits":[{"model":"qos-ha-model","tokens_per_min":10}]}'
done
# QOS-HA-007's subject: an identity with a bound it cannot exhaust, used to
# ask whether peer snapshots arriving at a node reduce what a caller that
# has spent NOTHING there may have. Phantom headroom is the failure the
# declared case names, and the only way to see it is to spend nothing.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-phantom-tenant","rps":0,"tokens_per_min":100000}'
# QOS-HA-012's subject: spent at the node that is about to be killed, asked
# again at the survivor after it promotes.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-kill-tenant","rps":0,"tokens_per_min":10}'
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-ctl-012","rps":0,"tokens_per_min":10}'
# QOS-HA-009's subject: a tenant whose quota has to survive a snapshot that
# does not fit in one RPC. Bounded exactly like the others so the only thing
# distinguishing its result is the size of the snapshot carrying it.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-chunk-tenant","rps":0,"tokens_per_min":10}'
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-tenant-model","rps":0,"model_limits":[{"model":"qos-ha-model","tokens_per_min":10}]}'
# The per-user rungs live under a tenant with NO aggregate bound of its own,
# so a refusal there can only be the user rung.
cfg_both POST /config/ai/user/ratelimit \
  '{"tenant_id":"ha-user-tenant","user_id":"ha-user","tokens_per_min":10}'
cfg_both POST /config/ai/user/ratelimit \
  '{"tenant_id":"ha-um-tenant","user_id":"ha-um-user","model_limits":[{"model":"qos-ha-model","tokens_per_min":10}]}'
# A control tenant that is bounded but will never be driven: it proves a
# post-sync refusal is about the identity that spent, not about the node.
# One control tenant PER CASE. A single shared control would be spent by
# the first case that used it and would then be refused for its own reasons
# in every later case — a control that is itself exhausted has stopped
# controlling for anything.
# The warm-up probe's tenant. It carries a bound (so the warming gate
# applies to it at all) that is far too large for the probe itself ever to
# spend — a probe that exhausted its own bucket would report the warm-up as
# never ending.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-warm-tenant","rps":0,"tokens_per_min":100000}'
# The sync-liveness seed's tenant. It needs a bound for the seed request to
# CHARGE anything — AllowTokens returns before creating an entry when the
# tenant has no quota — and the bound has to be far beyond what one request
# spends, because a seed that could be refused would leave SYNC-1 asserting
# a push that never had state to carry.
cfg_both POST /config/ai/tenant/ratelimit \
  '{"tenant_id":"ha-seed-tenant","rps":0,"tokens_per_min":100000}'
for t in ha-ctl-002 ha-ctl-003 ha-ctl-004 ha-ctl-009; do
  cfg_both POST /config/ai/tenant/ratelimit \
    '{"tenant_id":"'"$t"'","rps":0,"tokens_per_min":10}'
done

echo "#########################################"
echo "Minting API keys in the shared store"
echo "#########################################"
# One mint, both nodes. The key id is what the per-key TPM bucket is keyed
# on, so it has to be the same id on both sides or QOS-HA-004 is testing
# two unrelated buckets. Each mint is read back on the OTHER node before it
# is used, so a store that is not in fact shared fails here, loudly, rather
# than surfacing later as a quota that did not sync.
: > "${CFGDIR}/.keys"
mint_key() { # <name> <tenant> <tokens_per_min>
  local name=$1 tenant=$2 tpm=$3 resp raw kid rb
  resp=$($hexec llb1 curl -s -m 5 -X POST \
    http://localhost:11111/netlox/v1/config/ai/apikey \
    -H 'Content-Type: application/json' \
    -d '{"tenant_id":"'"$tenant"'","name":"'"$name"'","tokens_per_min":'"$tpm"'}')
  raw=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
  kid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('key_id',''))" 2>/dev/null)
  if [ -z "$raw" ] || [ -z "$kid" ]; then
    echo "FATAL: could not mint key $name: $resp"; exit 1
  fi
  rb=$($hexec llb2 curl -s -m 5 -o /dev/null -w '%{http_code}' \
    "http://localhost:11111/netlox/v1/config/ai/apikey/$kid")
  if [ "$rb" != "200" ]; then
    echo "FATAL: key $name ($kid) minted on llb1 is not visible on llb2 (HTTP $rb) —"
    echo "       the API-key store is not shared, so no per-key case below can mean anything"
    exit 1
  fi
  echo "${name}:${kid}:${raw}" >> "${CFGDIR}/.keys"
  echo "  key '$name' minted and confirmed on both nodes (tenant=$tenant tpm=$tpm id=$kid)"
}
# tpm=0 on the tenant-scope keys: their tenant's own bound is the subject,
# and a key bound would be a second possible reason for the same refusal.
mint_key ha-tenant-key       ha-tenant         0
mint_key ha-tenant-model-key ha-tenant-model   0
mint_key ha-user-key         ha-user-tenant    0
mint_key ha-um-key           ha-um-tenant      0
mint_key ha-ctl-002-key      ha-ctl-002        0
mint_key ha-ctl-003-key      ha-ctl-003        0
mint_key ha-ctl-004-key      ha-ctl-004        0
mint_key ha-chunk-key        ha-chunk-tenant   0
mint_key ha-ctl-009-key      ha-ctl-009        0
mint_key ha-agg-only-key     ha-agg-only       0
mint_key ha-model-only-key   ha-model-only     0
mint_key ha-ctl-005a-key     ha-ctl-005a       0
mint_key ha-ctl-005b-key     ha-ctl-005b       0
mint_key ha-phantom-key      ha-phantom-tenant 0
mint_key ha-kill-key         ha-kill-tenant    0
mint_key ha-ctl-012-key      ha-ctl-012        0
# The key-TPM rung (QOS-HA-004): the key itself carries the bound, and its
# tenant deliberately has no row, so a refusal can only be the key rung.
mint_key ha-key-tpm          ha-keytpm-tenant  10
# The rate rung's own key. Its tenant carries no row and its own tpm is 0,
# so the only thing that can ever refuse it is the per-key RPS bucket —
# which is exactly what the snapshot case is about.
mint_key ha-rps-key          ha-rps-tenant     0
# The sync-liveness seed. It must be drivable without ever being refused —
# a seed that spends a bounded identity would leave that identity exhausted
# for whatever case uses it next, and a control that is itself exhausted
# has stopped controlling for anything.
mint_key ha-seed-key         ha-seed-tenant    0
mint_key ha-warm-key         ha-warm-tenant    0
chmod 0600 "${CFGDIR}/.keys"
# One-shot marker. Every quota case here spends an identity down to its
# bound, and a 12-token charge against a 10/min limit takes 72 seconds to
# drain — longer than the whole suite runs. A second validation.sh against
# the same bed therefore starts with exhausted buckets and reports a pile
# of failures that describe the previous run, not the product. The marker
# makes that say so instead.
: > "${CFGDIR}/.fresh"

echo "#########################################"
echo "ai-qos-ha-sync testbed ready"
echo "#########################################"
echo "  llb1 VIP: 10.10.10.254:2020 (keyed) / :2021 (keyless)"
echo "  llb2 VIP: 20.20.20.254:2020 (keyed) / :2021 (keyless)"
echo "  backend:  l3ep1:8080, fixed 12 tokens per answered request"
