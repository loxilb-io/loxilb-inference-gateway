#!/bin/bash
# Re-arm the monitoring/observability test state on top of a freshly deployed
# vllm-kvcache-routing-cpu topology. Run on the testbed host AFTER ./config.sh.
#
#   ./monitoring-redeploy.sh up       # (default) rules + metrics + traffic + prometheus retarget + verify
#   ./monitoring-redeploy.sh stop     # stop the continuous traffic units
#   ./monitoring-redeploy.sh status   # show units, rules, metrics reachability
#
# What "up" does, in order:
#   1. enable loxilb Prometheus collection if it is off (config.sh does not pass -p)
#   2. ensure the extra LB rules exist: SSE :2020 (fullproxy) + NAMED l4-echo :2222
#      (config.sh only creates the KV :8080 rule; per-service Grafana panels need
#      a named rule, and the L4 keepalive generator needs :2222)
#   3. (re)start the six continuous traffic units (systemd-run transient):
#      gen-traffic-loop, gen-traffic-l4, sse-mock, kvpub-epA/B/C
#      - per-EP publisher corpora are generated from prompts/corpus.json if absent
#   4. re-point deploy/monitoring prometheus.yml at llb1's current bridge IP
#      (it changes across container re-creation) and reload prometheus
#   5. verify: /metrics up, rules present, VIPs reachable
#
# Needs: docker, jq, python3, sudo (systemd-run / ip netns exec).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
MON="$REPO/deploy/monitoring"
VIP=10.10.10.254
API="http://127.0.0.1:11111/netlox/v1"
UNITS=(gen-traffic-loop gen-traffic-l4 sse-mock kvpub-epA kvpub-epB kvpub-epC)

llb() { docker exec llb1 "$@"; }
rest_post() { # path json -> http code
    echo "$2" | docker exec -i llb1 sh -c \
        "curl -s -o /dev/null -w '%{http_code}' -X POST $API$1 -H 'Content-Type: application/json' -d @-"
}
metrics_ok() { llb curl -s --max-time 5 "$API/metrics" 2>/dev/null | grep -q '^loxilb_'; }
lb_ports() { llb loxicmd get lb -o json 2>/dev/null | jq -c '[.lbAttr[].serviceArguments.port]'; }

status() {
    echo "== traffic units =="
    for u in "${UNITS[@]}"; do printf '  %-18s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done
    echo "== lb rules ==";  llb loxicmd get lb -o wide 2>/dev/null | head -15
    echo "== metrics ==";   metrics_ok && echo "  /metrics OK" || echo "  /metrics NOT serving (503? run: $0 up)"
    command -v curl >/dev/null && curl -sG --max-time 3 "http://localhost:9090/api/v1/query" \
        --data-urlencode 'query=up{job="loxilb"}' 2>/dev/null \
        | jq -r '"  prometheus up{job=loxilb}: " + (.data.result[0].value[1] // "no data")' 2>/dev/null
}

stop_units() {
    for u in "${UNITS[@]}"; do sudo systemctl stop "$u" 2>/dev/null; done
    echo "traffic units stopped"
}

ensure_metrics() {
    if metrics_ok; then echo "[1/5] metrics already enabled"; return; fi
    # POST toggles collection on; only issue it when metrics are actually off
    llb curl -s -o /dev/null -X POST "$API/config/metrics"
    sleep 2
    metrics_ok && echo "[1/5] metrics enabled" || { echo "[1/5] FAILED to enable metrics"; exit 1; }
}

ensure_rule() { # port json
    local port=$1 json=$2 tries code
    for tries in 1 2 3; do
        lb_ports | grep -q "\b$port\b" && { echo "  :$port present"; return; }
        code=$(rest_post /config/loadbalancer "$json")
        # A fullproxy rule POSTed right after loxilb start can return 200 yet
        # not register (sockproxy init race) - settle, verify, retry.
        sleep 3
        lb_ports | grep -q "\b$port\b" && { echo "  :$port created (POST $code)"; return; }
    done
    echo "  FAILED to create :$port rule"; exit 1
}

ensure_rules() {
    echo "[2/5] ensuring extra LB rules (:2020 SSE, :2222 l4-echo)"
    ensure_rule 2020 '{"serviceArguments":{"externalIP":"'$VIP'","port":2020,"protocol":"tcp","block":0,"sel":0,"mode":4,"host":"'$VIP'","monitor":false,"inactiveTimeout":240},"endpoints":[{"endpointIP":"32.32.32.1","targetPort":8080,"weight":1,"state":"active"}]}'
    ensure_rule 2222 '{"serviceArguments":{"externalIP":"'$VIP'","port":2222,"protocol":"tcp","block":0,"sel":0,"mode":0,"name":"l4-echo","monitor":false,"inactiveTimeout":240},"endpoints":[{"endpointIP":"32.32.32.1","targetPort":80,"weight":1,"state":"active"},{"endpointIP":"34.34.34.1","targetPort":80,"weight":1,"state":"active"},{"endpointIP":"36.36.36.1","targetPort":80,"weight":1,"state":"active"}]}'
}

gen_corpus() { # id outfile
    python3 - "$1" "$2" "$DIR/prompts/corpus.json" <<'EOF'
import json, sys
pid, out, corpus = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(corpus))
sel = [x for x in d["prompts"] if x["id"] == pid]
json.dump(sel, open(out, "w"))
print(f"  wrote {out} ({len(sel)} prompt)")
EOF
}

start_units() {
    echo "[3/5] (re)starting continuous traffic units"
    stop_units >/dev/null
    local TOK="$DIR/../common/kv_hash/fixtures/tokenizers/Qwen__Qwen3-0.6B/tokenizer.json"
    local VEC="$DIR/../common/kv_hash/fixtures/kv_hash_vectors.json"
    # per-EP publisher corpora: base->EP-A(l3ep1), noncontig->EP-B(l3ep3), divergent->EP-C(l3ep5)
    [ -f "$HOME/.kvpub-epA-corpus.json" ] || gen_corpus shared-prefix-base           "$HOME/.kvpub-epA-corpus.json"
    [ -f "$HOME/.kvpub-epB-corpus.json" ] || gen_corpus noncontiguous-bitmask-target "$HOME/.kvpub-epB-corpus.json"
    [ -f "$HOME/.kvpub-epC-corpus.json" ] || gen_corpus shared-prefix-divergent      "$HOME/.kvpub-epC-corpus.json"

    # Resolve the INVOKING user's site-packages here, before the sudo boundary:
    # the units run as root, whose own user-site lacks the publisher's deps.
    local USERSITE
    USERSITE=$(python3 -m site --user-site 2>/dev/null)
    sudo systemd-run --collect --unit=sse-mock ip netns exec l3ep2 \
        python3 "$REPO/cicd/ai-sse-quota/mock_sse_server.py" 8080
    local ns bind tag
    for tag in "A l3ep1 31.31.31.1" "B l3ep3 33.33.33.1" "C l3ep5 35.35.35.1"; do
        set -- $tag; ns=$2; bind=$3
        sudo systemd-run --collect --unit="kvpub-ep$1" ip netns exec "$ns" bash -c \
            "export PYTHONPATH='$USERSITE' PYTHONHASHSEED=0; exec python3 '$DIR/kv_event_publisher.py' --corpus '$HOME/.kvpub-ep$1-corpus.json' --tokenizer '$TOK' --vectors '$VEC' --service-id 1 --bind $bind --port 5557 --algo sha256_cbor --block-size 16 --repeat 999999 --repeat-interval 30 --no-vocabulary"
    done
    sudo systemd-run --collect --unit=gen-traffic-loop "$DIR/gen-traffic.sh" loop 5
    # slow keepalive conns: the ONLY traffic the conntrack-derived L4 panels can
    # see (flows shorter than one 10s sweep are invisible to sip/dip breakdowns)
    sudo systemd-run --collect --unit=gen-traffic-l4 /usr/bin/docker exec l3h1 sh -c \
        'while true; do (for i in $(seq 1 30); do printf "GET / HTTP/1.1\r\nHost: '"$VIP"'\r\n\r\n"; sleep 2; done; printf "GET / HTTP/1.1\r\nHost: '"$VIP"'\r\nConnection: close\r\n\r\n") | nc '"$VIP"' 2222 >/dev/null 2>&1; sleep 1; done'
    for u in "${UNITS[@]}"; do printf '  %-18s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done
}

retarget_prometheus() {
    echo "[4/5] re-pointing prometheus at llb1"
    if ! docker ps --format '{{.Names}}' | grep -q '^loxilb-prometheus$'; then
        echo "  monitoring stack not running - start it: cd $MON && docker compose up -d"; return
    fi
    local ip
    ip=$(docker inspect llb1 --format '{{(index .NetworkSettings.Networks "bridge").IPAddress}}')
    [ -n "$ip" ] || { echo "  cannot determine llb1 bridge IP"; exit 1; }
    sed -i -E "s/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:11111/$ip:11111/" "$MON/prometheus/prometheus.yml"
    docker exec loxilb-prometheus kill -HUP 1
    echo "  target set to $ip:11111, prometheus reloaded"
}

verify() {
    echo "[5/5] verify"
    metrics_ok && echo "  /metrics OK" || echo "  /metrics FAILED"
    echo "  rules: $(lb_ports)"
    docker exec l3h1 curl -s --max-time 5 -o /dev/null -w "  kv :8080 -> %{http_code}\n"   "http://$VIP:8080/" 2>/dev/null
    docker exec l3h1 curl -s --max-time 5 -o /dev/null -w "  echo :2222 -> %{http_code}\n" "http://$VIP:2222/" 2>/dev/null
    echo "  counters advance on 10s sweeps - give Grafana ~30s, then check the"
    echo "  Overview dashboard (gateway up, error rate ~0) and L4 'Service throughput' (l4-echo)."
}

case "${1:-up}" in
    up)     docker ps --format '{{.Names}}' | grep -q '^llb1$' || { echo "llb1 not running - run ./config.sh first"; exit 1; }
            ensure_metrics; ensure_rules; start_units; retarget_prometheus; verify ;;
    stop)   stop_units ;;
    status) status ;;
    *)      echo "usage: $0 {up|stop|status}"; exit 1 ;;
esac
