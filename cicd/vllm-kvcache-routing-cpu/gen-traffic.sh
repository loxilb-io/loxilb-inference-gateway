#!/bin/bash
# LoxiLB AI Gateway live-traffic generator (run on the testbed host, after
# config.sh has built the topology).
# Usage:
#   ./gen-traffic.sh kv   [N]   # KV-cache routing -> PD + KV routing panels
#   ./gen-traffic.sh sse  [N]   # SSE streams      -> general AI family panels
#   ./gen-traffic.sh all  [N]   # both
#   ./gen-traffic.sh loop [N]   # repeat "all" forever (Ctrl-C to stop)
set -u
CFG="$(cd "$(dirname "$0")" && pwd)"
VIP=10.10.10.254
N=${2:-10}

body() {
    python3 -c "import json,sys;d=json.load(open(\"$CFG/prompts/corpus.json\"));p=[x[\"prompt\"] for x in d[\"prompts\"] if x[\"id\"]==sys.argv[1]][0];print(json.dumps({\"model\":\"Qwen/Qwen3-0.6B\",\"prompt\":p,\"max_tokens\":8}))" "$1"
}

kv() {
    echo "[kv] $N req/prompt to $VIP:8080 (base->EP-A, noncontig->EP-B, divergent->EP-C)"
    for pid in shared-prefix-base noncontiguous-bitmask-target shared-prefix-divergent; do
        B=$(body "$pid")
        for i in $(seq 1 "$N"); do
            docker exec l3h1 curl -s --max-time 8 -X POST "http://$VIP:8080/v1/completions" \
                -H "Content-Type: application/json" --data-binary "$B" >/dev/null 2>&1
        done
    done
}

sse() {
    echo "[sse] $N SSE streams to $VIP:2020 (model=sse-test) + one 15s held stream"
    # One long-held stream per burst (mock delay_secs keepalive): the
    # loxilb_ai_active_streams gauge is instantaneous and the mock finishes
    # normal streams in milliseconds, so without this no 10s scrape ever
    # overlaps a live stream and the "Active SSE streams" panel reads 0
    # forever. Real LLM streams last seconds-to-minutes.
    docker exec -d l3h1 curl -s -N --max-time 20 -X POST "http://$VIP:2020/v1/chat/completions?delay_secs=15" \
        -H "Content-Type: application/json" \
        -d '{"model":"sse-test","messages":[{"role":"user","content":"held stream"}],"stream":true}'
    for i in $(seq 1 "$N"); do
        docker exec l3h1 curl -s -N --max-time 6 -X POST "http://$VIP:2020/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"sse-test\",\"messages\":[{\"role\":\"user\",\"content\":\"hi $i\"}],\"stream\":true}" >/dev/null 2>&1
    done
}

case "${1:-all}" in
    kv)   kv ;;
    sse)  sse ;;
    all)  kv; sse ;;
    loop) while true; do kv; sse; sleep 2; done ;;
    *)    echo "usage: $0 {kv|sse|all|loop} [N]"; exit 1 ;;
esac
