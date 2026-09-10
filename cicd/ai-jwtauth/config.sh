#!/bin/bash
# CICD scenario: ai-jwtauth
#
# The bearer (JWT) admission arm end to end, against a real identity
# provider. A hand-minted token proves only that the verifier accepts what
# the test author signed; a Keycloak realm proves the defaults this feature
# ships with (realm_access.roles, sub, a user-attribute tenant claim) match
# what an actual IdP emits.
#
# What the matrix pins:
#   - valid token admits; expired / bad-signature / wrong-issuer /
#     wrong-audience / unattributable are refused 401;
#   - a token whose roles do not cover the requested model is 403, not 401
#     and never a silent admit;
#   - apikey-or-jwt precedence: a present API key decides alone, and its
#     refusal is FINAL — no JWT fallback behind a single 401;
#   - upstream hygiene: the backend never sees the client's Authorization
#     unless the profile opts into passthrough, never sees a client-sent
#     X-Auth-* spoof, and sees gateway-verified identity only when the
#     profile forwards it;
#   - a large token sent in small TCP writes still admits (the header value
#     reaches the parser in fragments; a capture that kept only one of them
#     failed as an indistinguishable bad-signature 401);
#   - HTTP/2 on a JWT-enforcing service is refused, not admitted unchecked;
#   - a profile whose JWKS endpoint never answers refuses 503 — never 200.
#
# Topology:
#   l3h1 (10.10.10.1) ── llb1 (VIP 10.10.10.254) ── l3ep1 (31.31.31.1, llama-70b)
#                                                 ── l3ep2 (32.32.32.1, mistral-7b)
#   kc-aigw    (docker bridge) — Keycloak, realm "aigw"
#   pg-jwtauth (docker bridge) — API-key store, needed only by the
#                                apikey-or-jwt precedence legs
#
#   VIP ports, one profile each so a profile switch is the only variable:
#     2040 jwt            profile kc           main arm + hygiene defaults
#     2041 apikey-or-jwt  profile kc           precedence
#     2042 jwt            profile kc-wrongaud  audience mismatch
#     2043 jwt            profile kc-wrongiss  issuer mismatch
#     2044 jwt            profile kc-blackhole JWKS never answers
#     2045 jwt            profile kc-fwd       forward_identity=true
#     2046 jwt            profile kc-pass      authorization_passthrough=true

source ../common.sh

PG_NAME=pg-jwtauth
PG_OWNER=oamuser
PG_OWNER_PW=oampass
PG_DB=loxilb
DP_PW=dp-secret-1
MGMT_PW=mgmt-secret-1

KC_NAME=kc-aigw
KC_ADMIN=admin
KC_ADMIN_PW=adminpw
KC_REALM=aigw

SDIR=$(cd "$(dirname "$0")" && pwd)

echo "#########################################"
echo "Spawning Keycloak with the aigw realm"
echo "#########################################"

# A pinned, realm-baked image rather than an upstream pull plus a
# bind-mounted import: a re-run has to meet the same identity provider it
# met the first time, and a CI job should not need an external registry to
# be reachable. Built on demand the first time, reused afterwards —
# keycloak/build.sh regenerates the realm from mkrealm.py, so the image can
# never drift from the users and roles the assertions assume.
KC_IMAGE=${AIGW_KEYCLOAK_IMAGE:-loxilb-aigw-keycloak:26.0-aigw}
if ! docker image inspect "$KC_IMAGE" >/dev/null 2>&1; then
  echo "  $KC_IMAGE not present — building it (first run only)"
  AIGW_KEYCLOAK_IMAGE="$KC_IMAGE" "$SDIR/keycloak/build.sh" "$KC_IMAGE" || {
    echo "FATAL: could not build $KC_IMAGE"; exit 1; }
fi
echo "  using $KC_IMAGE"

docker rm -f "$KC_NAME" >/dev/null 2>&1
docker run --rm -d --name "$KC_NAME" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME="$KC_ADMIN" \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
  "$KC_IMAGE" start-dev >/dev/null || {
  echo "FATAL: could not start Keycloak"; exit 1; }

KC_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KC_NAME")
echo "Keycloak IP: $KC_IP"
KC_BASE="http://$KC_IP:8080"
KC_ISSUER="$KC_BASE/realms/$KC_REALM"
KC_JWKS="$KC_ISSUER/protocol/openid-connect/certs"

echo "Waiting for the realm to serve keys..."
for i in $(seq 1 90); do
  if curl -sf --max-time 3 "$KC_JWKS" | grep -q '"keys"'; then
    echo "Keycloak realm ready (${i}s)"
    break
  fi
  sleep 2
done
curl -sf --max-time 3 "$KC_JWKS" | grep -q '"keys"' || {
  echo "FATAL: Keycloak realm never served a JWKS"
  docker logs --tail 40 "$KC_NAME"
  exit 1; }

# mint <client> <user> <password> -> access token on stdout
mint() {
  curl -s --max-time 10 -X POST \
    -d "client_id=$1" -d "username=$2" -d "password=$3" \
    -d "grant_type=password" \
    "$KC_ISSUER/protocol/openid-connect/token" |
    python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

echo "#########################################"
echo "Spawning PostgreSQL for the API-key store"
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
  echo "FATAL: PostgreSQL did not come up"; exit 1; }

docker cp ../../scripts/aigw-db-bootstrap.sql "$PG_NAME:/tmp/aigw-db-bootstrap.sql"
docker exec -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
  "$PG_NAME" psql -h 127.0.0.1 -U "$PG_OWNER" -d "$PG_DB" -q -f /tmp/aigw-db-bootstrap.sql || {
  echo "FATAL: bootstrap script failed"; exit 1; }

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

# Backends report what reached them; the upstream-hygiene assertions read
# the response body rather than a shared /tmp log, so a previous run (or a
# root-owned leftover) can never poison them.
start_hdr_backend() { # <namespace> <response label>
  local ns=$1 label=$2
  $hexec "$ns" sh -c "nohup python3 $SDIR/hdr_echo.py '$label' 8080 >/tmp/ai-jwtauth-$label.log 2>&1 &"
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

start_hdr_backend l3ep1 server-llama   || exit 1
start_hdr_backend l3ep2 server-mistral || exit 1

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

# Wait out the boot-config freeze window with a probe that can never apply.
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

echo "#########################################"
echo "Reaching Keycloak from the gateway"
echo "#########################################"

# The gateway fetches JWKS itself; if it cannot reach Keycloak every JWT leg
# would fail 503 and the matrix would report a network fault as a verifier
# verdict. Prove reachability from inside llb1 before configuring anything.
$dexec llb1 curl -sf --max-time 5 "$KC_JWKS" | grep -q '"keys"' || {
  echo "FATAL: llb1 cannot reach the Keycloak JWKS at $KC_JWKS"
  exit 1; }
echo "llb1 reaches $KC_JWKS"

echo "#########################################"
echo "Creating JWT auth profiles"
echo "#########################################"

# add_profile <name> <issuer> <jwks_url> <audiences-json> <extra-json-fields>
add_profile() {
  local name=$1 issuer=$2 jwks=$3 auds=$4 extra=$5
  local resp
  resp=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' -X POST \
    http://10.10.10.254:11111/netlox/v1/config/ai/jwtauthprofile \
    -H "Content-Type: application/json" \
    -d '{
      "name":       "'"$name"'",
      "issuer":     "'"$issuer"'",
      "jwks_url":   "'"$jwks"'",
      "audiences":  '"$auds"',
      "leeway_sec": 2,
      "refresh_sec": 300
      '"$extra"'
    }')
  echo "  profile $name: HTTP $resp"
  case "$resp" in
    2*) ;;
    *) echo "FATAL: profile $name rejected (HTTP $resp)"; exit 1 ;;
  esac
}

# leeway 2s throughout: the expiry leg uses a 1-second-lifespan client, and
# the shipped 30s default would make that leg sleep for most of a minute.
add_profile kc           "$KC_ISSUER" "$KC_JWKS" '["aigw-api"]'      ''
add_profile kc-wrongaud  "$KC_ISSUER" "$KC_JWKS" '["never-issued"]'  ''
# Same keys, issuer the tokens will not carry: isolates the iss check from
# the signature check.
add_profile kc-wrongiss  "$KC_BASE/realms/not-this-realm" "$KC_JWKS" '["aigw-api"]' ''
# Nothing listens on port 9 inside the gateway: the keyset is never fetched.
add_profile kc-blackhole "http://127.0.0.1:9/realms/void" "http://127.0.0.1:9/certs" '[]' ''
add_profile kc-fwd       "$KC_ISSUER" "$KC_JWKS" '["aigw-api"]' ', "forward_identity": true'
add_profile kc-pass      "$KC_ISSUER" "$KC_JWKS" '["aigw-api"]' ', "authorization_passthrough": true'

echo "#########################################"
echo "Creating LB rules"
echo "#########################################"

# add_lb_rule <port> <model> <ep_ip> <auth-mode> <profile>
add_lb_rule() {
  local port=$1 model=$2 ep=$3 auth=$4 profile=$5
  local resp
  resp=$($hexec l3h1 curl -s -X POST \
    http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
    -H "Content-Type: application/json" \
    -d '{
      "serviceArguments": {
        "externalIP":       "10.10.10.254",
        "port":              '"$port"',
        "protocol":         "tcp",
        "sel":               0,
        "mode":              4,
        "host":             "10.10.10.254",
        "path_prefix":      "/",
        "path_match_mode":  "prefix",
        "model_name":       "'"$model"'",
        "api_key_auth":     "'"$auth"'",
        "jwt_auth_profile": "'"$profile"'",
        "inactiveTimeOut":   30
      },
      "endpoints": [
        {"endpointIP": "'"$ep"'", "targetPort": 8080, "weight": 1}
      ]
    }')
  echo "  rule $port/$model ($auth/$profile) -> $ep: $resp"
  case "$resp" in
    *Success*) ;;
    *) echo "FATAL: LB rule $port/$model rejected"; exit 1 ;;
  esac
}

# Both pools on the two enforcing VIPs: a model-denied request must be
# refused by authorization, not by the absence of somewhere to send it.
add_lb_rule 2040 "llama-70b"  "31.31.31.1" jwt           kc
add_lb_rule 2040 "mistral-7b" "32.32.32.1" jwt           kc
add_lb_rule 2041 "llama-70b"  "31.31.31.1" apikey-or-jwt kc
add_lb_rule 2041 "mistral-7b" "32.32.32.1" apikey-or-jwt kc
add_lb_rule 2042 "llama-70b"  "31.31.31.1" jwt           kc-wrongaud
add_lb_rule 2043 "llama-70b"  "31.31.31.1" jwt           kc-wrongiss
add_lb_rule 2044 "llama-70b"  "31.31.31.1" jwt           kc-blackhole
add_lb_rule 2045 "llama-70b"  "31.31.31.1" jwt           kc-fwd
add_lb_rule 2046 "llama-70b"  "31.31.31.1" jwt           kc-pass

echo "#########################################"
echo "Creating the llama-only API key"
echo "#########################################"

# allowed_models is llama-70b ONLY, and the JWT identity used beside it
# (bob) is authorized for mistral-7b ONLY. That asymmetry is what makes the
# precedence leg decisive: whichever credential decided is visible in the
# verdict.
KEY_RESP=$($hexec llb1 curl -s -X POST \
  http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "key-tenant",
    "name": "llama-only",
    "allowed_models": ["llama-70b"]
  }')
RAW_KEY=$(echo "$KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
if [ -z "$RAW_KEY" ]; then
  echo "FATAL: API key creation failed: $KEY_RESP"
  exit 1
fi
echo "key created (llama-70b only)"

echo "#########################################"
echo "Minting tokens"
echo "#########################################"

TOK_ALICE=$(mint aigw-client alice alicepw)
TOK_BOB=$(mint aigw-client bob   bobpw)
TOK_CAROL=$(mint aigw-client carol carolpw)
TOK_DAVE=$(mint aigw-client dave  davepw)

for pair in "alice:$TOK_ALICE" "bob:$TOK_BOB" "carol:$TOK_CAROL" "dave:$TOK_DAVE"; do
  if [ -z "${pair#*:}" ]; then
    echo "FATAL: could not mint a token for ${pair%%:*}"
    exit 1
  fi
done

# The segmented-send leg needs a token that genuinely spans several parser
# fragments; padding roles make dave's token large. Assert the size rather
# than assume it: under ~2 KB the leg would stop testing what it claims,
# and over the 4 KB capture cap it would be refused as oversize instead.
DAVE_LEN=${#TOK_DAVE}
echo "dave token length: $DAVE_LEN chars"
if [ "$DAVE_LEN" -lt 2048 ] || [ "$DAVE_LEN" -gt 3800 ]; then
  echo "FATAL: dave token is $DAVE_LEN chars — outside the 2048..3800 band the"
  echo "       segmented-send leg needs (>2 KB to span reads, <4 KB capture cap)."
  exit 1
fi
printf '%s' "$TOK_DAVE" > .tok_dave

# A valid token with its signature corrupted: same header and payload, so a
# refusal can only come from signature verification.
TOK_BADSIG=$(printf '%s' "$TOK_ALICE" | python3 -c "
import sys
t = sys.stdin.read().strip()
h, p, s = t.split('.')
# Flip characters inside the signature only, keeping base64url alphabet.
flip = {'A': 'B', 'B': 'A'}
s = ''.join(flip.get(c, 'A' if c != 'A' else 'B') for c in s[:8]) + s[8:]
print('.'.join([h, p, s]))
")
[ -n "$TOK_BADSIG" ] || { echo "FATAL: could not build the bad-signature token"; exit 1; }

cat > .state <<EOF
RAW_KEY=$RAW_KEY
TOK_ALICE=$TOK_ALICE
TOK_BOB=$TOK_BOB
TOK_CAROL=$TOK_CAROL
TOK_BADSIG=$TOK_BADSIG
KC_NAME=$KC_NAME
KC_ISSUER=$KC_ISSUER
KC_CLIENT_SHORT=aigw-short
SDIR=$SDIR
EOF

echo "tokens minted (alice/bob/carol/dave/bad-signature)"
sleep 2
echo "config.sh done"
