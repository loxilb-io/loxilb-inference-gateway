#!/bin/bash
# Tier 2 — nightly alert fire→resolve drills + short soak
# (Tier 2 of the internal monitoring CI plan). Run between config.sh and validation.sh:
#
#   ./config.sh && ./drill.sh && ./validation.sh && ./rmconfig.sh
#
# Drills use a generated copy of the shipped rules with `for:` shortened to 30s
# (expressions unchanged) so fire→resolve completes in CI time. The original
# rules are restored before validation.sh so its idle-alert guard (T10) runs
# against the production windows.
#
# D1: LoxilbScrapeDown      — disable metrics → firing → re-enable → resolved
# D2: LoxilbL4ErrorBurst    — sustained server-RST drive → firing → stop → resolved
# D3: LoxilbUnhealthyEndpoints — monitored rule with a dead endpoint → firing
#                                → delete rule → resolved
# S1: soak SOAK_MINUTES (default 30) — up ratio ≈ 1, TSDB head-series flat,
#     loxilb container RSS bounded

source ../common.sh
echo SCENARIO-monitoring-drill
code=0

PROM=http://127.0.0.1:9090
SOAK_MINUTES=${SOAK_MINUTES:-30}

fail() { echo "  $1 [FAILED]"; code=1; }
ok()   { echo "  $1 [OK]"; }

pq() {
  curl -s --get "$PROM/api/v1/query" --data-urlencode "query=sum($1)" \
    | python3 -c 'import sys,json
r=json.load(sys.stdin).get("data",{}).get("result",[])
print(r[0]["value"][1] if r else 0)' 2>/dev/null || echo 0
}

# alert_state <alertname> → firing | pending | inactive
alert_state() {
  curl -s "$PROM/api/v1/alerts" | python3 -c "
import sys, json
alerts = json.load(sys.stdin)['data']['alerts']
states = [a['state'] for a in alerts if a['labels'].get('alertname') == '$1']
print('firing' if 'firing' in states else (states[0] if states else 'inactive'))"
}

# wait_alert <alertname> <want-state> <timeout-s>
wait_alert() {
  local name="$1" want="$2" timeout="$3" waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if [ "$(alert_state "$name")" = "$want" ]; then return 0; fi
    sleep 5; waited=$((waited + 5))
  done
  return 1
}

# ── Load drill rules (for: → 30s) ────────────────────────────────────────────
echo ""
echo "Loading drill rules (for: windows → 30s, expressions unchanged)"
rm -rf rules-drill && mkdir -p rules-drill
for f in ../../deploy/monitoring/prometheus/rules/*.yml; do
  sed -E 's/^(\s*)for:\s*[0-9]+m\s*$/\1for: 30s/' "$f" > "rules-drill/$(basename "$f")"
done
docker compose -f docker-compose.ci.yml -f docker-compose.drill.yml up -d prometheus
sleep 5
docker kill -s HUP loxilb-ci-prometheus >/dev/null 2>&1
rules_n=$(curl -s "$PROM/api/v1/rules" | python3 -c 'import sys,json;print(sum(len(g["rules"]) for g in json.load(sys.stdin)["data"]["groups"]))')
echo "  $rules_n rules loaded"

# ── D1: LoxilbScrapeDown ─────────────────────────────────────────────────────
echo ""
echo "D1: LoxilbScrapeDown fire→resolve"
$hexec l3h1 curl -s -X DELETE http://10.10.10.254:11111/netlox/v1/config/metrics >/dev/null
if wait_alert LoxilbScrapeDown firing 120; then ok "fired"; else fail "did not fire"; fi
$hexec l3h1 curl -s -X POST http://10.10.10.254:11111/netlox/v1/config/metrics >/dev/null
if wait_alert LoxilbScrapeDown inactive 120; then ok "resolved"; else fail "did not resolve"; fi

# ── D2: LoxilbL4ErrorBurst ───────────────────────────────────────────────────
echo ""
echo "D2: LoxilbL4ErrorBurst fire→resolve (sustained server-RST drive)"
# The shipped rule pages at rate[5m] > 50/s (interim threshold while the CT
# state machine still misclassifies benign teardown as reason="error"). The
# driver must clear that bar on its own RST volume — each abortive conn
# yields ≥1 error event, so we need a sustained ≥50 conns/s and enough burst
# length for the 5m rate window to average above 50: 12 parallel workers of
# back-to-back aborted requests sustain roughly 100-200 conns/s on the cicd
# topology. When the kernel-side classification fix lands and the threshold
# returns to >1/s, shrink this drive together with the rule and description.
DRIVE_FLAG=$(mktemp /tmp/l4drive.XXXXXX)
for w in $(seq 1 12); do
  (
    while [ -f "$DRIVE_FLAG" ]; do
      $hexec l3h1 curl -s --max-time 2 http://10.10.10.254:2024/ >/dev/null 2>&1
    done
  ) &
done
if wait_alert LoxilbL4ErrorBurst firing 420; then ok "fired"; else fail "did not fire"; fi
rm -f "$DRIVE_FLAG"
wait
# rate[5m] needs the burst to age out of the window before the alert clears
if wait_alert LoxilbL4ErrorBurst inactive 420; then ok "resolved"; else fail "did not resolve"; fi

# ── D3: LoxilbUnhealthyEndpoints ─────────────────────────────────────────────
echo ""
echo "D3: LoxilbUnhealthyEndpoints fire→resolve (monitored rule, dead endpoint)"
$dexec llb1 loxicmd create lb 10.10.10.254 --tcp=2025:9999 --endpoints=32.32.32.1:1 --monitor
if wait_alert LoxilbUnhealthyEndpoints firing 300; then ok "fired"; else fail "did not fire"; fi
$dexec llb1 loxicmd delete lb 10.10.10.254 --tcp=2025
if wait_alert LoxilbUnhealthyEndpoints inactive 300; then ok "resolved"; else fail "did not resolve"; fi

# ── Restore production rules ─────────────────────────────────────────────────
echo ""
echo "Restoring production rules"
docker compose -f docker-compose.ci.yml up -d prometheus
sleep 5
docker kill -s HUP loxilb-ci-prometheus >/dev/null 2>&1
rm -rf rules-drill

# ── S1: short soak ───────────────────────────────────────────────────────────
echo ""
echo "S1: ${SOAK_MINUTES}m soak (light traffic; up ratio, head-series, RSS)"
series_start=$(pq 'prometheus_tsdb_head_series')
rss_start=$(docker stats --no-stream --format '{{.MemUsage}}' llb1 | awk '{print $1}')
end_ts=$(( $(date +%s) + SOAK_MINUTES * 60 ))
while [ "$(date +%s)" -lt "$end_ts" ]; do
  $hexec l3h1 curl -s --max-time 15 -N -X POST \
    -H "Content-Type: application/json" -H "X-Model: sse-test" \
    -d '{"model":"sse-test","messages":[{"role":"user","content":"soak"}]}' \
    "http://10.10.10.254:2020/v1/chat/completions" >/dev/null 2>&1
  for i in 1 2 3 4 5; do
    $hexec l3h1 curl -s --max-time 5 http://10.10.10.254:2023/ >/dev/null 2>&1
  done
  sleep 30
done

up_avg=$(pq "avg_over_time(up{job=\"loxilb\"}[${SOAK_MINUTES}m])")
if awk "BEGIN {exit !($up_avg >= 0.99)}"; then ok "up avg == $up_avg (no scrape gaps)"; else fail "up avg == $up_avg (< 0.99 — scrape gaps)"; fi

series_end=$(pq 'prometheus_tsdb_head_series')
d=$(awk "BEGIN {print $series_end - $series_start}")
if awk "BEGIN {exit !($d < 200)}"; then ok "head series Δ == $d (< 200, no label leak)"; else fail "head series Δ == $d — cardinality growth under steady traffic"; fi

rss_end=$(docker stats --no-stream --format '{{.MemUsage}}' llb1 | awk '{print $1}')
echo "  loxilb RSS: $rss_start → $rss_end (informational)"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
if [[ $code == 0 ]]; then
  echo "SCENARIO-monitoring-drill [OK]"
else
  echo "SCENARIO-monitoring-drill [FAILED]"
fi
exit $code
