#!/bin/bash
# Notification-path canary: prove alert evaluation -> Alertmanager delivery ->
# resolved delivery, end to end, without touching production rules.
#
# Method: start the local webhook sink, inject a synthetic always-firing rule
# (a canary group in a drop-in file), reload Prometheus, wait for the firing
# notification at the sink, remove the rule, wait for the resolved
# notification. The drop-in is removed and Prometheus reloaded on every exit;
# a checksum over the shipped rule files proves nothing else changed.
set -u
PROM=${PROM:-http://127.0.0.1:9090}
RULES_DIR=${RULES_DIR:-../../deploy/monitoring/prometheus/rules}
SINK_OUT=$(mktemp /tmp/notify-sink.XXXXXX.jsonl)
CANARY_FILE="${RULES_DIR}/zz-canary.yml"
FAILS=0
ok()   { echo "  [OK]   $1"; }
fail() { echo "  [FAIL] $1"; FAILS=$((FAILS+1)); }

before_sum=$(find "$RULES_DIR" -maxdepth 1 -name '*.yml' ! -name 'zz-canary.yml' -exec sha256sum {} + | sort | sha256sum)

python3 notify-sink.py --out "$SINK_OUT" &
SINK_PID=$!
cleanup() {
    rm -f "$CANARY_FILE"
    docker kill -s HUP loxilb-prometheus >/dev/null 2>&1 || \
        docker kill -s HUP loxilb-ci-prometheus >/dev/null 2>&1
    kill "$SINK_PID" 2>/dev/null
}
trap cleanup EXIT

cat > "$CANARY_FILE" <<'YAML'
groups:
  - name: canary
    rules:
      - alert: LoxilbNotificationCanary
        expr: vector(1)
        labels: { severity: info }
        annotations:
          summary: "Notification-path canary (synthetic, always firing)"
YAML
docker kill -s HUP loxilb-prometheus >/dev/null 2>&1 || \
    docker kill -s HUP loxilb-ci-prometheus >/dev/null 2>&1

wait_sink() { # $1 status, $2 timeout-s
    local t=0
    while [ $t -lt "$2" ]; do
        grep -q "\"status\": \"$1\".*LoxilbNotificationCanary\|LoxilbNotificationCanary.*\"status\": \"$1\"" "$SINK_OUT" 2>/dev/null && return 0
        sleep 5; t=$((t+5))
    done
    return 1
}

echo "canary: waiting for FIRING delivery at the sink"
if wait_sink firing 180; then ok "firing notification delivered"; else fail "no firing delivery in 180s"; fi

rm -f "$CANARY_FILE"
docker kill -s HUP loxilb-prometheus >/dev/null 2>&1 || \
    docker kill -s HUP loxilb-ci-prometheus >/dev/null 2>&1
echo "canary: waiting for RESOLVED delivery"
if wait_sink resolved 420; then ok "resolved notification delivered"; else fail "no resolved delivery in 420s"; fi

# secret-redaction check: the sink log must carry no credential-shaped strings
if grep -qiE "authorization|bearer |password|secret|api[_-]?key" "$SINK_OUT"; then
    fail "sink log contains credential-shaped content (redaction check)"
else
    ok "sink log clean of credential-shaped content"
fi

after_sum=$(find "$RULES_DIR" -maxdepth 1 -name '*.yml' ! -name 'zz-canary.yml' -exec sha256sum {} + | sort | sha256sum)
if [ "$before_sum" = "$after_sum" ]; then ok "shipped rule files unchanged (checksum)"; else fail "rule checksum changed"; fi

echo ""
[ "$FAILS" -eq 0 ] && { echo "notify-canary: PASS (receipts: $SINK_OUT)"; exit 0; }
echo "notify-canary: ${FAILS} FAILURE(s) (log: $SINK_OUT)"; exit 1
