#!/usr/bin/env bash
# Live HTTP/2 security-order proof.
#
# Prerequisite: cicd/e2ehttpsproxy-prefix/config.sh has created llb1, l3h1,
# l3ep1 and the shared certificates.  The test creates only VIP :2039 and a
# uniquely named backend process, and removes both on exit.
set -u

cd "$(dirname "$0")" || exit 2
# common.sh reads its first positional argument to support an optional "init"
# mode. Supply an explicit no-op value so this strict-mode harness does not
# depend on the caller's argument vector.
LOXILB_DOCKER_IMAGE=${LOXILB_DOCKER_IMAGE:-}
source ../common.sh noop

VIP=10.10.10.254
PORT=2039
TARGET_PORT=18090
API=http://localhost:11111/netlox/v1/config/loadbalancer
BACKEND_LOG=/tmp/ai-security-h2-backend.log
BUILD_DIR=$(mktemp -d /tmp/s03h2-build.XXXXXX) || exit 2
SERVER_BIN=$BUILD_DIR/s03h2server
CLIENT_BIN=$BUILD_DIR/s03h2probe
SERVER_COMM=s03h2server
SERVER_PID=
PASS=0
FAIL=0

ok() { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
expect_contains() {
  local label=$1 expected=$2 actual=$3
  if [[ "$actual" == *"$expected"* ]]; then ok "$label"; else bad "$label: expected '$expected', got '$actual'"; fi
}
backend_count() {
  $hexec l3ep1 sh -c "test -f '$BACKEND_LOG' && wc -l < '$BACKEND_LOG' || echo 0" 2>/dev/null | tr -d '[:space:]'
}
gateway_log_count() {
  local needle=$1
  $dexec llb1 sh -c "test -f /var/log/loxilbdp.log && grep -F -c '$needle' /var/log/loxilbdp.log || echo 0" 2>/dev/null | tail -1 | tr -d '[:space:]'
}
cleanup() {
  if [[ -n $SERVER_PID ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  $hexec l3ep1 pkill -x "$SERVER_COMM" >/dev/null 2>&1 || true
  $dexec llb1 curl -sS -X DELETE \
    "$API/hosturl/$VIP/externalipaddress/$VIP/port/$PORT/protocol/tcp" >/dev/null 2>&1 || true
  $dexec llb1 curl -sS -X DELETE \
    "$API/externalipaddress/$VIP/port/$PORT/protocol/tcp" >/dev/null 2>&1 || true
  rm -f "$SERVER_BIN" "$CLIENT_BIN"
  rmdir "$BUILD_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

build_tool() {
  local source=$1 output=$2
  if command -v go >/dev/null 2>&1; then
    go build -o "$output" "$source"
    return
  fi
  if [[ -z ${S03_UNIT_IMAGE:-} ]]; then
    echo "FATAL: Go is absent; set S03_UNIT_IMAGE to the verified test-build image" >&2
    exit 2
  fi
  docker run --rm --network none \
    --mount "type=bind,src=$PWD,dst=/src,readonly" \
    --mount "type=bind,src=$BUILD_DIR,dst=/out" \
    --entrypoint /bin/bash "$S03_UNIT_IMAGE" \
    -ec "cd /src && go build -o /out/$(basename "$output") $source"
}

for required in llb1 l3h1 l3ep1; do
  docker inspect "$required" >/dev/null 2>&1 || {
    echo "FATAL: prerequisite container $required is absent" >&2
    exit 2
  }
done

build_tool h2_count_server.go "$SERVER_BIN" || exit 2
build_tool h2_probe.go "$CLIENT_BIN" || exit 2
$hexec l3ep1 pkill -x "$SERVER_COMM" >/dev/null 2>&1 || true
$hexec l3ep1 rm -f "$BACKEND_LOG"
$hexec l3ep1 "$SERVER_BIN" -addr ":$TARGET_PORT" \
  -cert "$PWD/../e2ehttpsproxy-prefix/31.31.31.1/cert.pem" \
  -key "$PWD/../e2ehttpsproxy-prefix/31.31.31.1/key.pem" \
  -log "$BACKEND_LOG" >/tmp/ai-security-h2-server.out 2>&1 &
SERVER_PID=$!
sleep 2
kill -0 "$SERVER_PID" >/dev/null 2>&1 || {
  echo "FATAL: HTTP/2 backend did not start" >&2
  exit 2
}

probe() {
  local key=${1-}
  local args=("$CLIENT_BIN" -url "https://$VIP:$PORT/v1/security" \
    -ca "$PWD/../e2ehttpsproxy-prefix/minica.pem" \
    -cert "$PWD/../e2ehttpsproxy-prefix/10.10.10.1/cert.pem" \
    -key "$PWD/../e2ehttpsproxy-prefix/10.10.10.1/key.pem")
  [[ -n "$key" ]] && args+=(-api-key "$key")
  $hexec l3h1 "${args[@]}" 2>&1
}

rule_body() {
  local policy=$1
  cat <<JSON
{"serviceArguments":{"externalIP":"$VIP","port":$PORT,"protocol":"tcp","security":2,"mode":4,"host":"$VIP","backend_protocol":"http2","api_key_auth":"$policy"},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":$TARGET_PORT,"weight":1}]}
JSON
}

# Explicitly disabled is the positive control.  It must reach the backend over
# H2, but the gateway credential must already have been stripped.
$dexec llb1 curl -sS -X POST "$API" -H 'Content-Type: application/json' \
  -d "$(rule_body disabled)" >/tmp/ai-security-h2-rule-disabled.json
sleep 2
before=$(backend_count)
control=$(probe control-secret)
printf 'CONTROL: %s\n' "$control"
after=$(backend_count)
expect_contains "disabled control uses HTTP/2" "PROTO=HTTP/2.0" "$control"
expect_contains "disabled control reaches backend" "STATUS=200" "$control"
[[ "$after" -eq $((before + 1)) ]] && ok "disabled control increments backend oracle" || bad "disabled control backend delta: before=$before after=$after"
last=$($hexec l3ep1 tail -1 "$BACKEND_LOG" 2>/dev/null)
expect_contains "declared credential is stripped before backend" "api_key=false" "$last"

# Replace the same service with mandatory auth.  This gateway intentionally has
# no key store: both keyless and presented credentials must be 503 because the
# gateway cannot issue a credential verdict without its mandatory policy
# dependency. Neither request may consume a routing tier or reach the backend.
$dexec llb1 curl -sS -X POST "$API" -H 'Content-Type: application/json' \
  -d "$(rule_body required)" >/tmp/ai-security-h2-rule-required.json
sleep 2
before=$(backend_count)
keyless=$(probe)
printf 'REQUIRED_KEYLESS: %s\n' "$keyless"
mid=$(backend_count)
unknown=$(probe lxb_s03_unknown_key_0000000000000000)
printf 'REQUIRED_PRESENTED: %s\n' "$unknown"
after=$(backend_count)
expect_contains "required keyless uses HTTP/2" "PROTO=HTTP/2.0" "$keyless"
expect_contains "required keyless reports unavailable policy store" "STATUS=503" "$keyless"
expect_contains "required unknown key uses HTTP/2" "PROTO=HTTP/2.0" "$unknown"
expect_contains "unavailable policy store fails closed" "STATUS=503" "$unknown"
[[ "$before" == "$mid" && "$mid" == "$after" ]] && ok "all HTTP/2 denials have backend delta zero" || bad "denial leaked upstream: before=$before mid=$mid after=$after"

# A denial log may record whether a credential was present, but never bytes
# from the credential itself.  The known test values make this a non-vacuous
# runtime assertion against the data-plane log sink.
control_secret_logs=$(gateway_log_count control-secret)
presented_secret_logs=$(gateway_log_count lxb_s03_unknown_key_0000000000000000)
presence_logs=$(gateway_log_count credential_present=)
[[ "$control_secret_logs" -eq 0 && "$presented_secret_logs" -eq 0 ]] && \
  ok "credential bytes are absent from gateway logs" || \
  bad "credential bytes leaked to logs: control=$control_secret_logs presented=$presented_secret_logs"
[[ "$presence_logs" -ge 2 ]] && ok "presence-only denial records are non-vacuous" || \
  bad "expected at least two presence-only denial records, got $presence_logs"

printf 'SUMMARY: pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
