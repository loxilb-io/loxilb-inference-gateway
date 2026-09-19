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
#   - the raw Authorization capture boundary is exact: 4095 raw bytes is
#     the largest value that reaches verification, 4096 is refused at
#     capture — on HTTP/1.1 and HTTP/2 alike;
#   - HTTP/2 runs the SAME admission gate as HTTP/1.1: a valid JWT admits
#     end to end, a valid API key on a jwt-only service is refused, and
#     nothing refused is forwarded (the raw recorder is the witness);
#   - two streams of different models and identities multiplexed on ONE
#     HTTP/2 connection are routed, denied, and settled independently;
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
#     2047 jwt            profile kc-outage    IdP outage after a fetch (10s refresh)
#     2048 jwt            profile kc           HTTP/2 legs (h2c echo backend)
#     2049 jwt            profile kc           H2 forwarding oracle (raw recorder)
#     2050 jwt            profile kc           H2 multiplex, two model pools
#     2051 none+sse       (keyless)            per-VIP token bound, H/1.1
#     2052 none+sse       (keyless)            per-VIP token bound, H/2
#     2054 jwt            profile kc           TLS + ALPN-negotiated h2 (the
#                                              only leg where the gateway
#                                              terminates TLS; every other H2
#                                              port above is h2c)
#     2055 jwt            profile kc           backend answers 200 with NO
#                                              usage object (missing-usage
#                                              accounting)
#     2056 jwt            profile kc           the same, over HTTP/2 (h2c echo
#                                              with usage suppressed) — the H2
#                                              settle path is a different
#                                              recorder from the H/1.1 one, so
#                                              2055 proves nothing about it
#     2057 jwt            profile kc           backend answers 500 with no
#                                              usage (H/1.1) — an error is not
#                                              an accounting hole
#     2058 jwt            profile kc           the same 500, over HTTP/2
#     2059 jwt            profile kc           QoS ladder: the rule-scope
#                                              defaults row SETS the user rps,
#                                              so the rule value must win over
#                                              global
#     2060 jwt            profile kc           QoS ladder: the rule-scope row
#                                              exists but leaves the user rps
#                                              zero, so global must reach
#                                              through it (field-wise, not
#                                              all-or-nothing)
#     2061 jwt            profile kc           QoS ladder: a CREDENTIALED
#                                              service whose rule-scope row
#                                              arms the per-VIP shared bucket,
#                                              so an attributed answer's spend
#                                              can be seen landing there
#     2062 none+sse       (keyless)            QoS ladder: per-VIP RATE bound
#                                              (rps=1, no token bound), so a
#                                              refusal there names the rate
#                                              rung and could not have come
#                                              from the token side
#
#     2063 jwt            profile kc           QoS fault injection: the store
#                                              outage arms. Driven ONCE while
#                                              the store is healthy, so its
#                                              rule-scope defaults row and its
#                                              tenant row are store-confirmed
#                                              before the outage begins
#     2064 none+sse       (keyless)            QoS fault injection: the
#                                              keyless opt-in bucket whose
#                                              defaults row the store has
#                                              NEVER answered for. Nothing
#                                              may drive it before the
#                                              outage -- the first read has
#                                              to happen while the store is
#                                              down, or the fail-open arm
#                                              measures a cache hit
#     2065 jwt            profile kc           QoS fault injection: the
#                                              reservation arms (slow backend,
#                                              aborted and re-configured
#                                              in-flight requests)
#     2066 jwt            profile kc           QoS fault injection: :2064's
#                                              control. Same never-read
#                                              defaults row, same outage, but
#                                              CREDENTIALED -- so the pair
#                                              differs only in whether an
#                                              identity was presented
#     2067 jwt            profile kc           HTTP/2 lifecycle: the h2c pool
#                                              again, but its OWN service so
#                                              the reservation arms hold a
#                                              bucket nothing else spends.
#                                              Every teardown shape (client
#                                              RST_STREAM, GOAWAY, an abrupt
#                                              socket death) is driven here
#     2068 jwt            profile kc           HTTP/2 lifecycle: the endpoint
#                                              is a port NOTHING listens on,
#                                              so every dispatch fails to
#                                              create its backend connection.
#                                              A live-but-wrong backend would
#                                              answer something; a refused
#                                              connect is the only shape that
#                                              exercises the failure path
#
#   :2053 and :2069 are NOT in this map on purpose — the P2 case creates a
#   rule at :2053 at RUNTIME to prove a 63-byte profile name is usable, and
#   the HTTP/2 rule-deletion case creates and then DELETES one at :2069. A
#   port added here would silently collide with either.

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

# Rebuild on realm CHANGE, not merely on absence. Presence alone was the old
# trigger, and it cannot notice that the baked realm has drifted from
# mkrealm.py: an image built before a user was added is still present, so it
# is still reused, and the drift surfaces much later as a token that cannot
# be minted — which reads like an identity-provider fault and is not one.
#
# The realm is generated here and fingerprinted; the image carries the
# fingerprint it was baked from as a label. Different, or absent on an image
# built before the label existed, means rebuild.
KC_REALM_JSON="$SDIR/keycloak/aigw-realm.json"
python3 "$SDIR/mkrealm.py" "$KC_REALM_JSON" >/dev/null || {
  echo "FATAL: could not generate the aigw realm"; exit 1; }
KC_REALM_HASH=$(sha256sum "$KC_REALM_JSON" | cut -c1-16)
KC_IMAGE_HASH=$(docker image inspect \
  -f '{{index .Config.Labels "aigw.realm.hash"}}' "$KC_IMAGE" 2>/dev/null || true)
if [ "$KC_IMAGE_HASH" != "$KC_REALM_HASH" ]; then
  if [ -z "$KC_IMAGE_HASH" ]; then
    echo "  $KC_IMAGE is absent or carries no realm fingerprint — building it"
  else
    echo "  $KC_IMAGE was baked from realm $KC_IMAGE_HASH, the suite needs $KC_REALM_HASH — rebuilding"
  fi
  AIGW_KEYCLOAK_IMAGE="$KC_IMAGE" "$SDIR/keycloak/build.sh" "$KC_IMAGE" || {
    echo "FATAL: could not build $KC_IMAGE"; exit 1; }
  KC_IMAGE_HASH=$(docker image inspect \
    -f '{{index .Config.Labels "aigw.realm.hash"}}' "$KC_IMAGE" 2>/dev/null || true)
  # A build that "succeeded" without producing the realm the suite asked for
  # would put every identity assertion back on an unknown realm.
  if [ "$KC_IMAGE_HASH" != "$KC_REALM_HASH" ]; then
    echo "FATAL: $KC_IMAGE still carries realm '${KC_IMAGE_HASH:-none}', want $KC_REALM_HASH"
    exit 1
  fi
fi
echo "  using $KC_IMAGE (realm $KC_REALM_HASH)"

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

# A backend that answers 200 with NO usage object. Every other backend here
# emits one, which is why nothing ever exercised the accounting path for a
# response that carries none — and that path reported nothing at all, so the
# gap was invisible rather than merely uncharged. Same echo, usage suppressed,
# on its own port so the with-usage control keeps running beside it.
$hexec l3ep1 sh -c "nohup python3 $SDIR/hdr_echo.py server-nousage 8092 no-usage >/tmp/ai-jwtauth-nousage.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep1 curl -sf --max-time 1 http://127.0.0.1:8092/ | grep -q "server-nousage"; then
    echo "  server-nousage backend ready (${i})"
    break
  fi
  [ "$i" = 20 ] && { echo "FATAL: no-usage backend did not become ready"; exit 1; }
  sleep 1
done
# It must not accidentally still be emitting usage — that would make the
# leg below assert against the wrong response shape and pass for the wrong
# reason.
if $hexec l3ep1 curl -sf --max-time 2 http://127.0.0.1:8092/ | grep -q '"usage"'; then
  echo "FATAL: the no-usage backend emitted a usage object"; exit 1
fi

# The H2 legs need two backends of their own. The h2c echo completes an
# HTTP/2 exchange, so "admitted" and "refused" finally produce different
# client-visible outcomes over H2 (the H/1.1 pools cannot parse the h2
# frames the gateway forwards, and their silence looks like a refusal).
# The raw recorder is the forwarding oracle: it answers nothing and keeps
# every byte, so "nothing was forwarded" is read from the recorded bytes,
# never inferred from a client-side reset.
# The h2 mocks below are launched with `hexec`, which is "sudo ip netns exec":
# they run as ROOT and import from root's sys.path. This scenario exports no
# PYTHONPATH into those commands, so root's interpreter is the only one that
# counts, and it is the one probed here.
#
# Probing as the calling user instead would be worse than not probing: a
# `pip3 install --user h2` satisfies the caller and leaves root untouched, so
# the gate would pass and the backends would fail afterwards, obscurely.
require_host_python h2 || exit 1
$hexec l3ep1 sh -c "rm -f /tmp/ai-jwtauth-rawsink.out; nohup python3 $SDIR/rawsink.py 8091 /tmp/ai-jwtauth-rawsink.out >/tmp/ai-jwtauth-rawsink.log 2>&1 &"
$hexec l3ep1 sh -c "nohup python3 $SDIR/h2c_echo.py server-h2-llama 8090 >/tmp/ai-jwtauth-h2echo.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep1 curl -sf --max-time 1 --http2-prior-knowledge \
       http://127.0.0.1:8090/__receipts/probe | grep -q "0"; then
    echo "  server-h2-llama backend ready (${i})"
    break
  fi
  [ "$i" = 20 ] && { echo "FATAL: h2c echo backend did not become ready"; exit 1; }
  sleep 1
done
# The H2 twin of the 8092 no-usage backend. An H/2 response settles through
# proxy_h2_settle_stream, which reads usage out of the STREAM's own tail
# window — a different recorder from the H/1.1 relay — so the 8092 pool proves
# nothing about it. Same h2c echo, usage suppressed, own port so the
# with-usage H2 control on 8090 keeps running beside it.
$hexec l3ep1 sh -c "nohup python3 $SDIR/h2c_echo.py server-h2-nousage 8093 no-usage >/tmp/ai-jwtauth-h2nousage.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep1 curl -sf --max-time 1 --http2-prior-knowledge \
       http://127.0.0.1:8093/__receipts/probe | grep -q "0"; then
    echo "  server-h2-nousage backend ready (${i})"
    break
  fi
  [ "$i" = 20 ] && { echo "FATAL: h2 no-usage backend did not become ready"; exit 1; }
  sleep 1
done
# Same guard as the H/1.1 no-usage pool: if it is still emitting usage the
# leg below would assert against the wrong response shape and pass for the
# wrong reason.
if $hexec l3ep1 curl -sf --max-time 2 --http2-prior-knowledge \
     -X POST http://127.0.0.1:8093/ -d '{}' | grep -q '"usage"'; then
  echo "FATAL: the H2 no-usage backend emitted a usage object"; exit 1
fi

# The error pools. An error body carries no usage object either, so to the
# accounting it looks exactly like the no-usage case — the only thing telling
# them apart is the response status. Without a backend that actually answers
# 4xx/5xx there is nothing to prove the status test with, and a filter nothing
# exercises is indistinguishable from no filter at all.
$hexec l3ep1 sh -c "nohup python3 $SDIR/hdr_echo.py server-err 8094 error-500 >/tmp/ai-jwtauth-err.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep1 curl -s --max-time 1 -o /dev/null -w '%{http_code}' \
       http://127.0.0.1:8094/ | grep -q "500"; then
    echo "  server-err backend ready (${i})"
    break
  fi
  [ "$i" = 20 ] && { echo "FATAL: error backend did not become ready"; exit 1; }
  sleep 1
done
$hexec l3ep1 sh -c "nohup python3 $SDIR/h2c_echo.py server-h2-err 8095 error-500 >/tmp/ai-jwtauth-h2err.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep1 curl -s --max-time 1 --http2-prior-knowledge \
       -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8095/ -d '{}' \
       | grep -q "500"; then
    echo "  server-h2-err backend ready (${i})"
    break
  fi
  [ "$i" = 20 ] && { echo "FATAL: H2 error backend did not become ready"; exit 1; }
  sleep 1
done

# Second h2 pool, DIFFERENT namespace: the multiplexing legs need two
# model pools whose endpoint lists both start at index 0, so that a
# backend cache keyed by index alone has an alias to hit. Each pool's
# receipt counter is queried inside its own namespace — per-backend
# delivery evidence no client-side response can fake.
$hexec l3ep2 sh -c "nohup python3 $SDIR/h2c_echo.py server-h2-mistral 8090 >/tmp/ai-jwtauth-h2echo.log 2>&1 &"
for i in $(seq 1 20); do
  if $hexec l3ep2 curl -sf --max-time 1 --http2-prior-knowledge \
       http://127.0.0.1:8090/__receipts/probe | grep -q "0"; then
    echo "  server-h2-mistral backend ready (${i})"
    break
  fi
  [ "$i" = 20 ] && { echo "FATAL: second h2c echo backend did not become ready"; exit 1; }
  sleep 1
done

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
echo "Confirming the image serves the JWT profile API"
echo "#########################################"

# The JWT bearer arm is not in a released image, so the auto-detected
# default (a published :latest-u24) answers 404 to every profile create.
# Without this check that surfaces as a bare "HTTP 404" from the first
# add_profile, after Keycloak, PostgreSQL and four containers are already
# up -- a missing image pin reading like a rejected profile. Ask the route
# whether it exists at all, and name the image in the refusal.
prof_rc=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' -m 5 \
  http://10.10.10.254:11111/netlox/v1/config/ai/jwtauthprofile)
if [[ "$prof_rc" == "404" ]]; then
  echo "FATAL: $lxdocker does not serve /config/ai/jwtauthprofile (HTTP 404)."
  echo "       This suite needs a build carrying the JWT bearer data plane;"
  echo "       pin one explicitly, e.g."
  echo "         LOXILB_DOCKER_IMAGE=<jwt-capable-tag> ./config.sh"
  exit 1
fi
echo "  $lxdocker serves the profile API (HTTP $prof_rc)"

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
# Short refresh so an IdP outage of a few tens of seconds spans a refresh
# that must fail. kc keeps the 300s default, so the outage group cannot
# perturb the profile every other leg runs against.
add_profile kc-outage    "$KC_ISSUER" "$KC_JWKS" '["aigw-api"]' ', "refresh_sec": 10'

echo "#########################################"
echo "Creating LB rules"
echo "#########################################"

# add_lb_rule <port> <model> <ep_ip> <auth-mode> <profile>
add_lb_rule() {
  local port=$1 model=$2 ep=$3 auth=$4 profile=$5 tport=${6:-8080}
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
        {"endpointIP": "'"$ep"'", "targetPort": '"$tport"', "weight": 1}
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
add_lb_rule 2047 "llama-70b"  "31.31.31.1" jwt           kc-outage
# H2 legs: a jwt-only service whose backend actually speaks HTTP/2.
add_lb_rule 2048 "llama-70b"  "31.31.31.1" jwt           kc 8090
# The no-usage service, for the missing-usage accounting leg.
add_lb_rule 2055 "llama-70b"  "31.31.31.1" jwt           kc 8092
# Its HTTP/2 twin, on the h2c no-usage pool.
add_lb_rule 2056 "llama-70b"  "31.31.31.1" jwt           kc 8093
# The error pools, one per protocol, for the status test.
add_lb_rule 2057 "llama-70b"  "31.31.31.1" jwt           kc 8094
add_lb_rule 2058 "llama-70b"  "31.31.31.1" jwt           kc 8095

# The QoS ladder's two defaults-scoped services. Level-3 defaults resolve as
# global, then the rule-scope row for THIS service overriding it field by
# field, so a claim about the rule/global relationship needs a service whose
# rule row the claim controls. 2040 cannot be that service: it carries the
# bearer arm every other block drives, and a defaults row there would bound
# alice and bob for the rest of the suite.
#
# Two are needed rather than one because the two halves of the relationship
# disagree about the same field: :2059's rule row SETS default_user_rps (so
# the rule value must win), while :2060's leaves it zero (so the global value
# must reach through a row that exists). One row cannot do both.
#
# Both point at the usage-bearing echo, the same backend :2040 uses — the
# ladder's subject is the limit that admitted or refused the request, so the
# pool must not be a second variable.
add_lb_rule 2059 "llama-70b"  "31.31.31.1" jwt           kc 8080
add_lb_rule 2060 "llama-70b"  "31.31.31.1" jwt           kc 8080

# The credentialed service whose rule-scope row arms the per-VIP shared
# bucket. Same profile and same backend as :2040, so the only difference
# between a request here and one there is the shared bucket itself.
add_lb_rule 2061 "llama-70b"  "31.31.31.1" jwt           kc 8080

# The fault-injection services. Same profile and same backend as :2040, so
# nothing about the arms below turns on the service being different -- only
# on what the store can and cannot answer at the moment they run.
#
# :2066 exists to be the CONTROL for :2064: one unreadable defaults row, two
# requests, and the only difference between them is a credential. Without it
# "keyless fails open" is a claim about one observation with nothing to
# compare it to.
add_lb_rule 2063 "llama-70b"  "31.31.31.1" jwt           kc 8080
add_lb_rule 2065 "llama-70b"  "31.31.31.1" jwt           kc 8080
add_lb_rule 2066 "llama-70b"  "31.31.31.1" jwt           kc 8080

# The HTTP/2 lifecycle services.
#
# :2067 is :2048's backend (the h2c echo, usage-bearing) behind its own VIP
# port. It is separate because the lifecycle arms read a token bucket before
# and after a teardown, and :2048 is driven by the H2 gate legs -- a bucket
# another block spends cannot say whether a claim came back.
add_lb_rule 2067 "llama-70b"  "31.31.31.1" jwt           kc 8090

# :2068's endpoint is a port in l3ep1 that nothing binds. The gateway's
# connect() is refused immediately, which is the backend-connection-creation
# failure the lifecycle case needs; an endpoint that is merely wrong would
# complete a connection and answer something, and the failure path would
# never run. 8099 is not served by any backend config.sh starts -- keep it
# that way.
add_lb_rule 2068 "llama-70b"  "31.31.31.1" jwt           kc 8099

# TLS + ALPN. Every H2 port above is h2c, so nothing here has ever run the
# bearer gate on a connection whose HTTP/2 was negotiated through the TLS
# handshake instead of a cleartext preface. That is a different entry path in
# the datapath — proxy_check_and_setup_h2() reads SSL_get0_alpn_selected() at
# accept time — so it needs its own legs rather than an assumption of parity.
#
# The server cert is issued here and installed before the rule exists: the
# listener reads it when the rule is created, so a later copy would leave the
# service unable to complete a handshake at all.
TLS_DIR=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" \
  -subj "/CN=10.10.10.254" \
  -addext "subjectAltName=IP:10.10.10.254" >/dev/null 2>&1 || {
    echo "FATAL: could not issue the TLS test certificate"; exit 1; }
docker exec llb1 mkdir -p /opt/loxilb/cert
docker cp "$TLS_DIR/server.crt" llb1:/opt/loxilb/cert/server.crt
docker cp "$TLS_DIR/server.key" llb1:/opt/loxilb/cert/server.key
rm -rf "$TLS_DIR"

# security:1 = the gateway terminates TLS. backend_protocol http2 keeps the
# backend leg on the h2c echo, so the only thing this rule changes relative to
# 2048 is how the client's HTTP/2 was arrived at.
resp=$($hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":       "10.10.10.254",
      "port":              2054,
      "protocol":         "tcp",
      "sel":               0,
      "security":          1,
      "mode":              4,
      "host":             "10.10.10.254",
      "path_prefix":      "/",
      "path_match_mode":  "prefix",
      "model_name":       "llama-70b",
      "api_key_auth":     "jwt",
      "jwt_auth_profile": "kc",
      "backend_protocol": "http2",
      "inactiveTimeOut":   30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8090, "weight": 1}
    ]
  }')
echo "  rule 2054/llama-70b (jwt/kc, TLS+ALPN) -> 31.31.31.1:8090: $resp"
case "$resp" in
  *Success*) ;;
  *) echo "FATAL: TLS LB rule 2054 rejected"; exit 1 ;;
esac

# The forwarding-oracle rule: jwt-only, pointed at the raw recorder, and
# deliberately WITHOUT a model key — on a build whose H2 forwarder still
# looks endpoints up with the wildcard model, only a model-less rule can
# resolve, and the red twin needs the forward to actually happen so the
# recorder can catch it.
resp=$($hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":       "10.10.10.254",
      "port":              2049,
      "protocol":         "tcp",
      "sel":               0,
      "mode":              4,
      "host":             "10.10.10.254",
      "path_prefix":      "/",
      "path_match_mode":  "prefix",
      "api_key_auth":     "jwt",
      "jwt_auth_profile": "kc",
      "inactiveTimeOut":   30
    },
    "endpoints": [
      {"endpointIP": "31.31.31.1", "targetPort": 8091, "weight": 1}
    ]
  }')
echo "  rule 2049/(no model) (jwt/kc) -> rawsink: $resp"
case "$resp" in
  *Success*) ;;
  *) echo "FATAL: LB rule 2049 rejected"; exit 1 ;;
esac

# Multiplexing legs: ONE VIP:port, TWO model pools, each pool's endpoint
# list starting at index 0 and each pool backed by a DIFFERENT h2 echo.
# The models' authorized identities are disjoint (alice→llama, bob→mistral)
# so every stream also proves per-stream identity on the shared connection.
add_lb_rule 2050 "llama-70b"  "31.31.31.1" jwt kc 8090
add_lb_rule 2050 "mistral-7b" "32.32.32.1" jwt kc 8090

# Keyless per-VIP token-bound legs. api_key_auth 'none' with sse_mode on:
# ai_gw_mode is sse||pd||required-auth, and only ai_gw_mode services run
# the admission ladder and the response settle — a keyless service that
# never opted into AI-gateway treatment pays no per-request probe.
add_keyless_rule() { # <port> <ep_ip> <tport>
  local port=$1 ep=$2 tport=$3 resp
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
        "model_name":       "llama-70b",
        "api_key_auth":     "disabled",
        "sse_mode":          true,
        "inactiveTimeOut":   30
      },
      "endpoints": [
        {"endpointIP": "'"$ep"'", "targetPort": '"$tport"', "weight": 1}
      ]
    }')
  echo "  rule $port/llama-70b (none+sse, keyless) -> $ep:$tport: $resp"
  case "$resp" in
    *Success*) ;;
    *) echo "FATAL: keyless LB rule $port rejected"; exit 1 ;;
  esac
}
add_keyless_rule 2051 "31.31.31.1" 8080   # H/1.1 echo (usage-bearing)
add_keyless_rule 2052 "31.31.31.1" 8090   # h2 echo (usage-bearing)
add_keyless_rule 2062 "31.31.31.1" 8080   # H/1.1 echo — the VIP rate rung
# The fail-open arm's service. It deliberately gets NO defaults row, here or
# anywhere: the row's absence is what leaves the read unknowable during the
# outage, and a row created here would be remembered at config time and
# answer from cache when the arm needs it to fail.
add_keyless_rule 2064 "31.31.31.1" 8080   # H/1.1 echo — never driven before the outage

# The shared bucket is OPT-IN: a rule-scope defaults row arms it for the
# services that ask for one. vip_shared_tpm=10 with the echoes' fixed
# usage of 12 tokens/answer means: request 1 admitted (bucket clean),
# its settle puts the bucket in debt, request 2 refused — two requests
# decide the leg. vip_shared_rps stays high where only the token side is
# under test, and the rate side is armed on its own port instead, so that
# neither half can ever be the reason the other one refused.
add_vip_bucket() { # <port> [rps] [tpm]
  local port=$1 rps=${2:-100} tpm=${3:-10} resp
  resp=$($hexec llb1 curl -s -w '\nhttp_code=%{http_code}' -X POST \
    http://localhost:11111/netlox/v1/config/ai/ratelimit/defaults \
    -H "Content-Type: application/json" \
    -d '{
      "scope": "rule",
      "rule_ident": "10.10.10.254:'"$port"'",
      "vip_shared_rps": '"$rps"',
      "vip_shared_tpm": '"$tpm"'
    }')
  echo "  vip bucket 10.10.10.254:$port (rps=$rps tpm=$tpm): $(echo "$resp" | tail -1)"
  case "$resp" in
    *http_code=2*) ;;
    *) echo "FATAL: defaults row for :$port rejected: $resp"; exit 1 ;;
  esac
}
add_vip_bucket 2051
add_vip_bucket 2052
# The rate half of the same shared bucket, on its own keyless service:
# rps=1 and NO token bound, so a refusal here can only be the rate rung.
add_vip_bucket 2062 1 0
# The shared bucket armed on a CREDENTIALED service. Nothing else on :2061
# bounds anything, and the two identities driven there sit in different
# tenants with no rows of their own, so the VIP is the only thing they
# share — which is the whole claim.
add_vip_bucket 2061 100 10

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

echo "#########################################"
echo "Minting the QoS ladder's identities"
echo "#########################################"

# The per-user rungs are keyed by (tenant_id, user_id), and user_id is
# whatever the profile's user_claim resolves to. The kc profile names no
# user_claim, so the shipped default applies and the identity is the token's
# "sub" — a Keycloak UUID, not the username. Writing a row for "q1" would
# configure a user the gateway never sees, and every throttling assertion
# would then pass on a build that enforces nothing.
#
# So the identity is read out of the minted token rather than assumed. That
# also keeps the block honest about which claim the product actually uses: if
# the default ever moves off "sub", these rows stop matching and the cases go
# red instead of quietly becoming unlimited.
sub_of() { # sub_of <jwt> -> the token's sub claim
  printf '%s' "$1" | python3 -c "
import base64, json, sys
t = sys.stdin.read().strip()
p = t.split('.')[1]
p += '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p)).get('sub', ''))
" 2>/dev/null
}

QOS_STATE=""
# f1..f4 (tenant-qf), r1/r2 (tenant-qr), x1/x2 (unsafe tenant claims),
# z/zz (tenant-qi) and hl1/hl2 (tenant-hl, the HTTP/2 lifecycle arms) belong
# to the fault-injection and lifecycle blocks; they are minted here with the
# rest so a token expiry cannot separate them from the identities the earlier
# blocks use.
for qu in q1 q2 q3 q4 q5 q6 q7 q8 q9 q10 t1 t2 m1 m2 n1 \
          f1 f2 f3 f4 r1 r2 x1 x2 z zz hl1 hl2; do
  tok=$(mint aigw-client "$qu" "${qu}pw")
  if [ -z "$tok" ]; then
    echo "FATAL: could not mint a token for the QoS identity $qu"
    exit 1
  fi
  sub=$(sub_of "$tok")
  # An empty sub is not a small problem: the ladder's user stage is skipped
  # outright when user_id is empty, so every per-user case would report the
  # product as unlimited when the harness is what failed.
  if [ -z "$sub" ]; then
    echo "FATAL: token for $qu carries no sub claim — the per-user rungs would"
    echo "       configure nothing and pass against any build"
    exit 1
  fi
  QOS_STATE="$QOS_STATE
TOK_${qu}='$tok'
SUB_${qu}='$sub'"
done
echo "QoS identities minted (q1..q10 tenant-q, t1/t2 tenant-qt, m1/m2 tenant-qm, n1 tenant-qn,"
echo "                       f1..f4 tenant-qf, r1/r2 tenant-qr, x1/x2 unsafe, z/zz tenant-qi,"
echo "                       hl1/hl2 tenant-hl)"

# The key arm's own credential. The llama-only key above is spent by the
# precedence legs, and the key rung PATCHes its holder's rps — doing that to
# a key another block is using would bound that block too.
QOS_KEY_RESP=$($hexec llb1 curl -s -X POST \
  http://localhost:11111/netlox/v1/config/ai/apikey \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "qos-key-tenant",
    "name": "qos-ladder",
    "allowed_models": ["llama-70b"]
  }')
QOS_RAW_KEY=$(echo "$QOS_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('raw_key',''))" 2>/dev/null)
QOS_KEY_ID=$(echo "$QOS_KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key_id',''))" 2>/dev/null)
if [ -z "$QOS_RAW_KEY" ] || [ -z "$QOS_KEY_ID" ]; then
  echo "FATAL: QoS ladder API key creation failed: $QOS_KEY_RESP"
  exit 1
fi
echo "QoS ladder key created (key_id $QOS_KEY_ID)"

# Quoted: validation.sh sources this file, so an unquoted credential would be
# word-split and glob-expanded by the shell before it ever reached a request.
cat > .state <<EOF
RAW_KEY='$RAW_KEY'
QOS_RAW_KEY='$QOS_RAW_KEY'
QOS_KEY_ID='$QOS_KEY_ID'$QOS_STATE
TOK_ALICE='$TOK_ALICE'
TOK_BOB='$TOK_BOB'
TOK_CAROL='$TOK_CAROL'
TOK_BADSIG='$TOK_BADSIG'
PG_NAME='$PG_NAME'
PG_DP_USER='aigwuser'
PG_DP_PW='$DP_PW'
PG_SCHEMA='aigw'
PG_OWNER='$PG_OWNER'
PG_DB='$PG_DB'
KC_ISSUER='$KC_ISSUER'
KC_CLIENT_SHORT='aigw-short'
KC_NAME='$KC_NAME'
EOF

echo "tokens minted (alice/bob/carol/dave/bad-signature)"
sleep 2
echo "config.sh done"
