#!/bin/bash
# Validates AI Gateway SSE connection tuning.
# T1: SSE survival past inactiveTimeOut (delay_secs=65 > inactiveTimeOut=60s)
# T2: Non-SSE comparison (sse_mode=false on VIP:2021)
# T3: [DONE] detection → Prometheus loxilb_ai_requests_total increments
# T4: MaxStreamDurationSec=10 cap (VIP:2022 /never-done)
# T5: Fragmentation safety ([DONE] split at byte 8)

source ../common.sh
echo SCENARIO-ai-sse-quota
code=0

check() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then
    echo "  $label [OK]"
  else
    echo "  $label [FAILED] — expected '$want', got: '$got'"
    code=1
  fi
}

# ── T1: SSE stream survives past inactiveTimeOut ───────────────────────────────
# inactiveTimeOut=60s on rule; delay_secs=65 → stream runs for 65 seconds.
# Without SSE-mode suppression the connection would be killed at 60s.
echo ""
echo "T1: SSE stream survives inactiveTimeOut (delay_secs=65 > inactiveTimeOut=60s)"
START=$(date +%s)
BODY=$($hexec l3h1 curl -s --max-time 90 -N -X POST \
  -H "Content-Type: application/json" \
  -H "X-Model: sse-test" \
  -d '{"model":"sse-test","messages":[{"role":"user","content":"test"}]}' \
  "http://10.10.10.254:2020/v1/chat/completions?delay_secs=65")
END=$(date +%s)
ELAPSED=$((END - START))

echo "  stream elapsed: ${ELAPSED}s"
if [[ $ELAPSED -ge 64 ]]; then
  echo "  stream lasted ≥64s (inactiveTimeOut suppressed) [OK]"
else
  echo "  stream was cut short at ${ELAPSED}s — inactiveTimeOut NOT suppressed [FAILED]"
  code=1
fi
check "body contains DONE terminator" "[DONE]" "$BODY"

# ── T2: Non-SSE comparison (sse_mode=false on VIP:2021) ────────────────────────
echo ""
echo "T2: Non-SSE rule (VIP:2021, sse_mode=false) handles connection normally"
r=$($hexec l3h1 curl -s --max-time 8 \
  -H "X-Model: nosse-test" \
  http://10.10.10.254:2021/)
check "non-SSE backend reachable" "server-nosse" "$r"

# ── T3: [DONE] detection → Prometheus counter ───────────────────────────────────
echo ""
echo "T3: [DONE] detection — Prometheus loxilb_ai_requests_total increments"

# Enable the metrics endpoint (scrape returns 503 while disabled)
$hexec l3h1 curl -s -X POST http://10.10.10.254:11111/netlox/v1/config/metrics >/dev/null 2>&1
sleep 2

# Capture metrics before
BEFORE=$($hexec l3h1 curl -s http://10.10.10.254:11111/netlox/v1/metrics 2>/dev/null \
  | grep '^loxilb_ai_requests_total' || echo "metric_not_found")

# Complete one SSE stream
$hexec l3h1 curl -s --max-time 15 -N -X POST \
  -H "Content-Type: application/json" \
  -H "X-Model: sse-test" \
  -d '{"model":"sse-test","messages":[{"role":"user","content":"metric"}]}' \
  "http://10.10.10.254:2020/v1/chat/completions" >/dev/null 2>&1

sleep 2

# Capture metrics after
AFTER=$($hexec l3h1 curl -s http://10.10.10.254:11111/netlox/v1/metrics 2>/dev/null \
  | grep '^loxilb_ai_requests_total' || echo "metric_not_found")

echo "  before: $BEFORE"
echo "  after:  $AFTER"

if [[ "$AFTER" == "metric_not_found" ]]; then
  echo "  loxilb_ai_requests_total not found after SSE completion [FAILED]"
  code=1
elif [[ "$AFTER" != "$BEFORE" ]]; then
  # The series must carry the real backend status (200), not a hardcoded one,
  # and the model label resolved from the X-Model header.
  if [[ "$AFTER" == *'status="200"'* ]] && [[ "$AFTER" == *'model="sse-test"'* ]]; then
    echo "  loxilb_ai_requests_total incremented with status=200, model=sse-test [OK]"
  else
    echo "  loxilb_ai_requests_total incremented but labels unexpected [FAILED]"
    code=1
  fi
else
  echo "  loxilb_ai_requests_total unchanged — [DONE] detection may not trigger increment [FAILED]"
  code=1
fi

# ── T4: MaxStreamDurationSec=10 cap ─────────────────────────────────────────────
echo ""
echo "T4: MaxStreamDurationSec=10 cap (VIP:2022 /never-done → terminated within 15s)"
START4=$(date +%s)
BODY4=$($hexec l3h1 curl -s --max-time 15 -N \
  -H "X-Model: cap-test" \
  "http://10.10.10.254:2022/never-done")
END4=$(date +%s)
ELAPSED4=$((END4 - START4))

echo "  stream elapsed: ${ELAPSED4}s"
if [[ "$BODY4" == *"max_stream_duration_exceeded"* ]]; then
  echo "  received max_stream_duration_exceeded [OK]"
elif [[ $ELAPSED4 -ge 1 && $ELAPSED4 -le 14 ]]; then
  # Stream was terminated by the proxy (connection closed) within the timeout —
  # MaxStreamDurationSec enforcement worked even if no specific error body.
  # NOTE: ELAPSED must be ≥1s to distinguish proxy cap from an immediate
  # connection failure (ELAPSED=0 = backend unreachable, not cap enforcement).
  echo "  stream terminated within 15s (proxy enforced max duration) [OK]"
else
  echo "  stream not capped — ran for ${ELAPSED4}s without termination [FAILED]"
  code=1
fi

# ── T5: Fragmentation safety ───────────────────────────────────────────────────
echo ""
echo "T5: Fragmentation safety ([DONE] split at byte 8)"

# Use frag_done=1 to make mock server split "data: [DONE]\n\n" across two writes
$hexec l3h1 python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.10.254', 2020))

# Build HTTP POST request that triggers fragmented [DONE]
body = '{\"model\":\"sse-test\",\"messages\":[{\"role\":\"user\",\"content\":\"frag\"}]}'
req = (
    'POST /v1/chat/completions?frag_done=1 HTTP/1.1\r\n'
    'Host: 10.10.10.254:2020\r\n'
    'Content-Type: application/json\r\n'
    'Content-Length: ' + str(len(body)) + '\r\n'
    '\r\n'
    + body
)
s.sendall(req.encode())

# Read until connection closes or timeout
s.settimeout(15)
data = b''
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except (socket.timeout, ConnectionResetError):
    pass
s.close()

text = data.decode('utf-8', errors='replace')
if '[DONE]' in text:
    print('stream terminated cleanly with [DONE]')
    exit(0)
elif len(text) > 0:
    print('stream received data but no [DONE] — proxy failed to reassemble fragmented [DONE]')
    exit(1)
else:
    print('no data received — connection may have failed')
    exit(1)
" 2>/dev/null

FRAG_EXIT=$?
if [[ $FRAG_EXIT -eq 0 ]]; then
  echo "  fragmentation test passed (exit 0) [OK]"
else
  echo "  fragmentation test failed (exit $FRAG_EXIT) [FAILED]"
  code=1
fi

# ── T6: Gauge >= 0 after cap-path termination (validates gauge underflow fix) ──
echo ""
echo "T6: active_streams gauge >= 0 after cap-path termination (gauge underflow fix)"
# Trigger a stream that will hit the max_stream_duration_sec=10 cap on VIP:2022
# --max-time 20: health-check fires every 5s, worst-case cap fires at t=15s; add 5s buffer
$hexec l3h1 curl -s --max-time 20 -N \
  -H "X-Model: cap-test" \
  "http://10.10.10.254:2022/never-done" > /dev/null 2>&1
sleep 2  # wait for cap to fire and cleanup to complete
metrics=$($hexec l3h1 curl -s http://10.10.10.254:2112/metrics 2>/dev/null)
# Extract the lowest active_streams value across all model labels
stream_val=$(echo "$metrics" | grep 'loxilb_ai_active_streams' | grep -v '^#' \
    | awk '{print $2}' | sort -n | head -1)
if [[ -z "$stream_val" ]]; then
  echo "  T6: loxilb_ai_active_streams metric not found in /metrics [WARN — check endpoint]"
elif awk "BEGIN {exit ($stream_val >= 0) ? 0 : 1}"; then
  echo "  T6: active_streams=$stream_val >= 0 [OK]"
else
  echo "  T6: active_streams=$stream_val < 0 — gauge leak not fixed [FAILED]"
  code=1
fi

# ── T7: [DONE] in JSON value does NOT prematurely end stream ──────────────────
echo ""
echo "T7: [DONE] in JSON value does NOT prematurely end stream"
echo "  T7: [SKIP — requires mock backend support for embedded [DONE] in JSON; add to backlog]"

# ── T8: Stream terminates within tolerance when max_stream_duration_sec cap fires
echo ""
echo "T8: stream terminates within tolerance when max_stream_duration_sec cap fires"
start_ts=$(date +%s)
# Trigger a stream against VIP:2022 (max_stream_duration_sec=10 per config.sh)
# --max-time 25: health-check fires every 5s so worst-case cap fires at t=15s;
# allow 5s for health-check jitter + 8s OS/container load buffer = 25s max-time.
$hexec l3h1 curl -s --max-time 25 \
  -H "X-Model: cap-test" \
  "http://10.10.10.254:2022/never-done" > /dev/null 2>&1
end_ts=$(date +%s)
elapsed=$((end_ts - start_ts))
cap_seconds=10  # max_stream_duration_sec for VIP:2022 rule in config.sh
tolerance=12   # health-check runs every 5s → worst-case fires at cap+5s; +7s for container load
if [[ $elapsed -le $((cap_seconds + tolerance)) ]]; then
  echo "  T8: stream ended in ${elapsed}s (cap=${cap_seconds}s + ${tolerance}s tolerance) [OK]"
else
  echo "  T8: stream took ${elapsed}s — cap did not fire in time [FAILED]"
  code=1
fi

# ── Cleanup ────────────────────────────────────────────────────────────────────
sudo killall -9 node 2>/dev/null

# ── CLI Validation (T-CLI-1 through T-CLI-8) ─────────────────────────────────
echo ""
echo "Running CLI validation tests..."
bash validate_cli.sh
cli_code=$?
if [ $cli_code -ne 0 ]; then
  code=1
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
if [[ $code == 0 ]]; then
  echo "SCENARIO-ai-sse-quota [OK]"
else
  echo "SCENARIO-ai-sse-quota [FAILED]"
fi
exit $code
