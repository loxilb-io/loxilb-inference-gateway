#!/bin/bash
# Validates the three monitoring correctness surfaces against driver-controlled
# ground truth (Tier 1 of the internal monitoring CI plan, incl. its assertion
# catalog).
#
# T0:  Prometheus scrapes loxilb (up==1) within scrape-duration budget
# T1:  metrics disable → up==0; re-enable → up==1 (scrape access matrix)
# T2:  N SSE completions → Δ loxilb_ai_requests_total{model="sse-test",status="200"} == N
# T3:  M plain-JSON 500s via the AI rule → Δ ai_requests_total{status="500"} == M
#      (regression guard: non-SSE responses on AI rules must be recorded);
#      T3b: a mode-4 rule without sse_mode/pd/apikey stays out of AI accounting
# T4:  L7 traffic → loxilb_proxy_http_ttfb_seconds_count > 0 (TTFB recording guard)
# T5:  C held L4 conns → Δ loxilb_active_conntrack_entries within [C, 3C]
# T6:  30 mgmt-plane REST calls → Δ loxilb_l4_error_events_total{proto="tcp"} ≈ 0
#      (regression guard: management-plane conns must not tick the L4 error signal)
# T7:  R server-RST closes → Δ loxilb_l4_error_events_total{proto="tcp"} ≥ R
#      (established-connection errors are still counted after the T6 fix)
# T8:  every shipped rule + dashboard PromQL expr executes cleanly
# T9:  Grafana provisioning + datasource + every panel target through the proxy
# T10: idle-alert guard — zero alerts firing after the run (0/0 false-positive property)

source ../common.sh
echo SCENARIO-monitoring
code=0

PROM=http://127.0.0.1:9090
SWEEP=../../deploy/monitoring/ci/sweep-monitoring.py

# Instant-query helper: prints the (summed) value or "0" when the series is absent.
pq() {
  local q="$1"
  curl -s --get "$PROM/api/v1/query" --data-urlencode "query=sum($q)" \
    | python3 -c 'import sys,json
r=json.load(sys.stdin).get("data",{}).get("result",[])
print(r[0]["value"][1] if r else 0)' 2>/dev/null || echo 0
}

# Numeric comparison helper: intcmp <a> <op> <b> (awk, handles floats)
intcmp() { awk "BEGIN {exit !($1 $2 $3)}"; }

# Poll a counter/gauge query until (value - base) >= want, or the window
# elapses; echoes the final delta. Replaces a single fixed sleep + one sample:
# the loxilb 10s stats sweep and the 10s scrape interval land at unpredictable
# offsets, so a lone sample often reads 0 while the sweep has not yet observed
# the driver traffic. Polling stops the instant the expected delta is reached,
# so it absorbs that timing jitter without hiding a genuine no-record regression
# (which never reaches `want` and still fails downstream). tries*3s ≈ max wait.
wait_delta() {
  local q="$1" base="$2" want="$3" tries="${4:-14}" now d=0
  for _ in $(seq 1 "$tries"); do
    now=$(pq "$q")
    d=$(awk "BEGIN {print $now - $base}")
    intcmp "$d" ">=" "$want" && break
    sleep 3
  done
  echo "$d"
}

fail() { echo "  $1 [FAILED]"; code=1; }
ok()   { echo "  $1 [OK]"; }

# ── T0: scrape health ─────────────────────────────────────────────────────────
echo ""
echo "T0: Prometheus scrapes loxilb"
up=$(pq 'up{job="loxilb"}')
if intcmp "$up" == 1; then ok "up{job=\"loxilb\"} == 1"; else fail "up{job=\"loxilb\"} = $up"; fi
sd=$(pq 'scrape_duration_seconds{job="loxilb"}')
if intcmp "$sd" "<" 5; then ok "scrape_duration ${sd}s within budget"; else fail "scrape_duration ${sd}s ≥ 5s"; fi

# ── T1: metrics disable / re-enable matrix ────────────────────────────────────
echo ""
echo "T1: metrics endpoint disable → up==0 → re-enable → up==1"
$hexec l3h1 curl -s -X DELETE http://10.10.10.254:11111/netlox/v1/config/metrics >/dev/null
disabled=0
for i in $(seq 1 12); do          # ≤36s — keep the window under ScrapeDown's for:1m
  sleep 3
  if intcmp "$(pq 'up{job="loxilb"}')" == 0; then disabled=1; break; fi
done
if [ "$disabled" = "1" ]; then ok "up==0 after disable"; else fail "up stayed 1 after metrics disable"; fi
$hexec l3h1 curl -s -X POST http://10.10.10.254:11111/netlox/v1/config/metrics >/dev/null
enabled=0
for i in $(seq 1 15); do
  sleep 3
  if intcmp "$(pq 'up{job="loxilb"}')" == 1; then enabled=1; break; fi
done
if [ "$enabled" = "1" ]; then ok "up==1 after re-enable"; else fail "up never recovered after re-enable"; fi

# ── T2: SSE ground truth ──────────────────────────────────────────────────────
echo ""
echo "T2: 3 SSE completions → Δ ai_requests_total{model=sse-test,status=200} == 3"
base_sse=$(pq 'loxilb_ai_requests_total{model="sse-test",status="200"}')
for i in 1 2 3; do
  $hexec l3h1 curl -s --max-time 15 -N -X POST \
    -H "Content-Type: application/json" -H "X-Model: sse-test" \
    -d '{"model":"sse-test","messages":[{"role":"user","content":"m"}]}' \
    "http://10.10.10.254:2020/v1/chat/completions" >/dev/null 2>&1
done
# Poll until the sweep+scrape observe all 3 (see wait_delta); avoids a lone
# too-early sample reading 0 while the 10s stats sweep has not yet run.
d=$(wait_delta 'loxilb_ai_requests_total{model="sse-test",status="200"}' "$base_sse" 3)
if intcmp "$d" == 3; then ok "Δ == 3"; else fail "Δ == $d (want 3; base $base_sse)"; fi

# ── T3: non-SSE recording guard ──────────────────────────────────────
# Plain-JSON responses on an AI rule (the OpenAI error shape) must be recorded;
# ai_gw_mode is derived from sse_mode/pd_disagg/apikey, so the SSE rule is the
# AI rule and the sse_mode=false rule below is deliberately outside AI accounting.
echo ""
echo "T3: 4 plain-JSON 500s via the AI rule → Δ ai_requests_total{model=sse-test,status=500} == 4"
base_json=$(pq 'loxilb_ai_requests_total{model="sse-test",status="500"}')
for i in 1 2 3 4; do
  $hexec l3h1 curl -s --max-time 8 -X POST \
    -H "Content-Type: application/json" -H "X-Model: sse-test" \
    -d '{"model":"sse-test","messages":[{"role":"user","content":"e"}]}' \
    "http://10.10.10.254:2020/v1/error" >/dev/null 2>&1
done
d=$(wait_delta 'loxilb_ai_requests_total{model="sse-test",status="500"}' "$base_json" 4)
if intcmp "$d" == 4; then ok "Δ == 4 (plain-JSON responses recorded)"; else fail "Δ == $d (want 4; base $base_json)"; fi

echo "T3b: requests on a non-AI mode-4 rule stay out of AI accounting"
base_nosse=$(pq 'loxilb_ai_requests_total{model="nosse-test"}')
for i in 1 2 3 4; do
  $hexec l3h1 curl -s --max-time 8 -H "X-Model: nosse-test" \
    http://10.10.10.254:2021/ >/dev/null 2>&1
done
sleep 25
now_nosse=$(pq 'loxilb_ai_requests_total{model="nosse-test"}')
d=$(awk "BEGIN {print $now_nosse - $base_nosse}")
if intcmp "$d" == 0; then ok "Δ == 0 (sse_mode=false rule not AI-accounted, by design)"; else fail "Δ == $d (want 0; non-AI rule entered AI accounting)"; fi

# ── T4: TTFB recording guard ─────────────────────────────────────────────
echo ""
echo "T4: L7 traffic recorded TTFB samples"
ttfb=$(pq 'loxilb_proxy_http_ttfb_seconds_count')
if intcmp "$ttfb" ">" 0; then ok "ttfb_seconds_count == $ttfb > 0"; else fail "ttfb_seconds_count == $ttfb (no TTFB samples after L7 traffic)"; fi

# ── T5: conntrack ground truth (hold-driver) ──────────────────────────────────
echo ""
echo "T5: 10 held L4 conns reflected in loxilb_active_conntrack_entries"
base_ct=$(pq 'loxilb_active_conntrack_entries')
rm -f /tmp/monitoring-hold.log
# Hold long enough (60s) to cover the polled settle window below.
$hexec l3h1 python3 $(pwd)/hold_conns.py 10.10.10.254 2023 10 60 > /tmp/monitoring-hold.log &
HOLD_PID=$!
ready=0
for i in $(seq 1 20); do
  grep -q READY /tmp/monitoring-hold.log 2>/dev/null && { ready=1; break; }
  sleep 1
done
if [ "$ready" != "1" ]; then
  fail "hold-driver never established its connections"
else
  # Poll (≤36s, within the 60s hold) until the sweep+scrape observe the held
  # conns, rather than a single fixed sample that can land before the 10s
  # stats sweep populates the gauge (the intermittent 0→0 conntrack failure).
  d=$(wait_delta 'loxilb_active_conntrack_entries' "$base_ct" 10 12)
  # Each held conn contributes 1–2 entries (both NAT legs) → accept [10, 30]
  if intcmp "$d" ">=" 10 && intcmp "$d" "<=" 30; then
    ok "Δ conntrack == $d for 10 held conns (legs included)"
  else
    fail "Δ conntrack == $d for 10 held conns (want 10–30; base $base_ct)"
  fi
fi
wait $HOLD_PID 2>/dev/null

# ── T6: management-plane guard ───────────────────────────────────────────
echo ""
echo "T6: 30 REST calls do not tick the L4 error signal"
base_err=$(pq 'loxilb_l4_error_events_total{proto="tcp"}')
for i in $(seq 1 30); do
  $hexec l3h1 curl -s http://10.10.10.254:11111/netlox/v1/version >/dev/null 2>&1
done
sleep 25
now_err=$(pq 'loxilb_l4_error_events_total{proto="tcp"}')
d=$(awk "BEGIN {print $now_err - $base_err}")
if intcmp "$d" "<=" 2; then ok "Δ l4_error == $d after 30 REST calls (≈0)"; else fail "Δ l4_error == $d after 30 REST calls — mgmt-plane conns still counted"; fi

# ── T7: server-RST errors still counted ────────────────────────
echo ""
echo "T7: 5 server-RST closes increment the L4 error signal"
base_rst=$(pq 'loxilb_l4_error_events_total{proto="tcp"}')
for i in 1 2 3 4 5; do
  $hexec l3h1 curl -s --max-time 5 http://10.10.10.254:2024/ >/dev/null 2>&1
done
d=$(wait_delta 'loxilb_l4_error_events_total{proto="tcp"}' "$base_rst" 5)
if intcmp "$d" ">=" 5; then ok "Δ l4_error == $d after 5 server RSTs (≥5)"; else fail "Δ l4_error == $d after 5 server RSTs — established-conn errors lost"; fi

# ── T8: PromQL expression sweep ───────────────────────────────────────────────
echo ""
echo "T8: every shipped rule + dashboard expression executes"
if python3 "$SWEEP" promql --prom "$PROM"; then ok "promql sweep"; else fail "promql sweep"; fi

# ── T9: Grafana end-to-end ────────────────────────────────────────────────────
# The required panels are the P0 surfaces this scenario's drives feed: if any
# comes back empty after the T1-T7 traffic, the panel (not the drive) broke.
echo ""
echo "T9: Grafana provisioning + datasource + panel proxy sweep"
if python3 "$SWEEP" grafana --min-nonempty 10 \
    --require-panel "loxilb-overview.json:Gateway up" \
    --require-panel "loxilb-overview.json:Healthy endpoints" \
    --require-panel "loxilb-ai.json:AI requests/s by status" \
    --require-panel "loxilb-l4.json:Requests/s per service"; then
  ok "grafana sweep"; else fail "grafana sweep"; fi

# ── T10: idle-alert guard ─────────────────────────────────────────────────────
echo ""
echo "T10: zero alerts firing (0/0 false-positive guard)"
if python3 "$SWEEP" alerts-idle --prom "$PROM"; then ok "no alerts firing"; else fail "alerts firing on a healthy system"; fi

# ── T11: package boundary holds live ──────────────────────────────────────────
echo ""
echo "T11: no package-excluded family has live series"
if python3 "$SWEEP" excluded-absent --prom "$PROM"; then ok "excluded families absent"; else fail "excluded families present in live TSDB"; fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $code == 0 ]]; then
  echo "SCENARIO-monitoring [OK]"
else
  echo "SCENARIO-monitoring [FAILED]"
fi
exit $code
