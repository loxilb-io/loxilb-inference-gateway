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
# D4: LoxilbRestoreProblem  — unparseable restore document → rejected run
#                             → firing → resolved once the 15m window ages out
# D5: LoxilbUnmeteredTraffic — sustained keyless AI traffic (api_key_auth
#                              disabled ⇒ every request is unmetered) → firing
#                              → stop → resolved
# D6: LoxilbPolicyStoreUnavailable — api_key_auth=required rule with NO key
#                                    store configured; keyed requests answer
#                                    503 → firing → stop+delete rule → resolved
# S1: soak SOAK_MINUTES (default 30) — up ratio ≈ 1, TSDB head-series flat,
#     loxilb container RSS bounded
#
# Alerts NOT drilled here (topology cannot drive them honestly — no KV event
# publisher, no engines, no HA peer in this scenario): the loxilb-kv-events
# and loxilb-pd groups, KvExact* attestation, LoxilbRestoreRollbackFailed
# (would need fault injection mid-apply), LoxilbHaSyncFailing (needs an xsync
# peer applying asymmetric state). They are covered by promtool unit tests
# (rules/tests/) and by the engine-matrix/HA-pair qualification runs.

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

# ── D4: LoxilbRestoreProblem ─────────────────────────────────────────────────
echo ""
echo "D4: LoxilbRestoreProblem fire→resolve (unparseable restore document)"
# A document that fails parse/validate never reaches APPLY — nothing mutates,
# but loxilb_restore_total{result="rejected"|"error"} increments (children are
# pre-created, so increase() is reliable from the first event).
$hexec l3h1 curl -s -X POST -H "Content-Type: application/json" \
  -d '{"not":"a snapshot document"}' \
  "http://10.10.10.254:11111/netlox/v1/config/restore?mode=commit" >/dev/null
if wait_alert LoxilbRestoreProblem firing 120; then ok "fired"; else fail "did not fire"; fi
# The rule is increase[15m] with no `for:` — it stays up until the single
# rejected run ages out of the window.
if wait_alert LoxilbRestoreProblem inactive 1020; then ok "resolved"; else fail "did not resolve"; fi

# ── D5: LoxilbUnmeteredTraffic ───────────────────────────────────────────────
echo ""
echo "D5: LoxilbUnmeteredTraffic fire→resolve (sustained keyless AI traffic)"
# The alert is guarded on loxilb_ai_keyed_services > 0: a fully keyless
# deployment is a posture, not an incident (the guard exists because this
# drill's own soak proved the unguarded alert fires forever on this
# topology). Arm the guard with a transient api_key_auth=required rule, then
# drive the :2020 SSE rule — the AI-accounted one (:2021 is sse_mode=false
# and deliberately outside AI accounting, the T3b guard), whose keyless
# traffic is exactly the "forgot to put it behind enforcement" anomaly.
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":      "10.10.10.254",
      "port":             2027,
      "protocol":        "tcp",
      "sel":              0,
      "mode":             4,
      "name":            "guardarm",
      "host":            "10.10.10.254",
      "path_prefix":     "/",
      "path_match_mode": "prefix",
      "model_name":      "guardarm-test",
      "api_key_auth":    "required",
      "inactiveTimeOut":  60
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }' >/dev/null
DRIVE_FLAG=$(mktemp /tmp/unmetered.XXXXXX)
(
  while [ -f "$DRIVE_FLAG" ]; do
    $hexec l3h1 curl -s --max-time 10 -N -X POST \
      -H "Content-Type: application/json" -H "X-Model: sse-test" \
      -d '{"model":"sse-test","messages":[{"role":"user","content":"drill"}]}' \
      "http://10.10.10.254:2020/v1/chat/completions" >/dev/null 2>&1
    sleep 2
  done
) &
if wait_alert LoxilbUnmeteredTraffic firing 300; then ok "fired"; else fail "did not fire"; fi
rm -f "$DRIVE_FLAG"
wait
$dexec llb1 loxicmd delete lb --name=guardarm
# rate[5m] ages out after the drive stops (and the guard disarms with the
# rule gone — either alone resolves the alert; both must, together)
if wait_alert LoxilbUnmeteredTraffic inactive 420; then ok "resolved"; else fail "did not resolve"; fi

# ── D6: LoxilbPolicyStoreUnavailable ─────────────────────────────────────────
echo ""
echo "D6: LoxilbPolicyStoreUnavailable fire→resolve (keyed traffic, no key store)"
# The scenario runs loxilb WITHOUT --aikey-db-host. A service with
# api_key_auth=required must refuse keyed requests with 503 (fail closed, the
# outage's own error code) and increment the policy-store counter — never
# answer 401 for a credential it could not check.
$hexec l3h1 curl -s -X POST \
  http://10.10.10.254:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
    "serviceArguments": {
      "externalIP":      "10.10.10.254",
      "port":             2026,
      "protocol":        "tcp",
      "sel":              0,
      "mode":             4,
      "name":            "authdrill",
      "host":            "10.10.10.254",
      "path_prefix":     "/",
      "path_match_mode": "prefix",
      "model_name":      "authdrill-test",
      "api_key_auth":    "required",
      "inactiveTimeOut":  60
    },
    "endpoints": [
      {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
    ]
  }' >/dev/null
DRIVE_FLAG=$(mktemp /tmp/policystore.XXXXXX)
(
  while [ -f "$DRIVE_FLAG" ]; do
    $hexec l3h1 curl -s --max-time 5 -X POST \
      -H "Content-Type: application/json" -H "X-Api-Key: drill-key" \
      -H "X-Model: authdrill-test" \
      -d '{"model":"authdrill-test","messages":[{"role":"user","content":"drill"}]}' \
      "http://10.10.10.254:2026/v1/chat/completions" >/dev/null 2>&1
    sleep 2
  done
) &
if wait_alert LoxilbPolicyStoreUnavailable firing 300; then ok "fired"; else fail "did not fire"; fi
rm -f "$DRIVE_FLAG"
wait
# L7/AI rules are keyed by host+path+model — delete by the rule's name (a
# bare --tcp=2026 delete answers 404 and leaks the rule into the soak).
$dexec llb1 loxicmd delete lb --name=authdrill
if wait_alert LoxilbPolicyStoreUnavailable inactive 420; then ok "resolved"; else fail "did not resolve"; fi

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
