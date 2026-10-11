#!/bin/bash
# lib.sh — helpers shared by validation.sh (coexistence matrix) and
# validation-ddos.sh (DDoS option matrix). Sourced after ../common.sh.
CFGDIR="$(cd "$(dirname "$0")" && pwd)"
KVCPU="${CFGDIR}/../vllm-kvcache-routing-cpu"
# The arm options config.sh ran with (XDP_NATIVE, TOTAL_INFLIGHT) when the caller did not
# pass them to this script as well.
if [[ -f "${CFGDIR}/.arm-env" ]]; then
    while IFS='=' read -r _k _v; do
        [[ "$_k" == XDP_NATIVE && -z "${XDP_NATIVE:-}" ]] && XDP_NATIVE="$_v"
        [[ "$_k" == TOTAL_INFLIGHT && -z "${TOTAL_INFLIGHT:-}" ]] && TOTAL_INFLIGHT="$_v"
    done <"${CFGDIR}/.arm-env"
fi
VIP="10.10.10.254"; VPORT="8080"
API="http://localhost:11111/netlox/v1"
LBBASE="${API}/config/loadbalancer"
METRICS="${API}/metrics"
KVINV="${API}/config/ai/kv/inventory"
KV_ZMQ_PORT=5557; KV_HASH_ALGO="sha256_cbor"; KV_BLOCK_SIZE=16; KV_WARMUP_SEC=20
KV_MODEL="${KV_MODEL:-Qwen/Qwen3-0.6B}"
KV_MODEL_SLUG="${KV_MODEL//\//__}"
TOKENIZER_SRC="${CFGDIR}/../common/kv_hash/fixtures/tokenizers/${KV_MODEL_SLUG}/tokenizer.json"
VECTORS_SRC="${CFGDIR}/../common/kv_hash/fixtures/kv_hash_vectors.json"
PUBLISHER="${KVCPU}/kv_event_publisher.py"
CORPUS="${KVCPU}/prompts/corpus.json"
PUB_TAG="${PUB_TAG:-kvpubsec}"
PY_USER_SITE="$(python3 -m site --user-site 2>/dev/null || echo '')"
EP_A_IP="31.31.31.1"; EP_A_IDX=0   # serverP0
EP_B_IP="33.33.33.1"; EP_B_IDX=2   # serverP1
CLIENT_A_IP="10.10.10.1"           # l3h1, allowed
CLIENT_B_IP="11.11.11.2"           # l3h2, the other one

code=0
hard_fail=0
assert() {   # assert <label> <0|1>
    if [[ "$2" == 1 ]]; then echo "  [OK] $1"; else echo "  [FAILED] $1"; code=1; hard_fail=1; fi
}
soft() {     # soft <label> <0|1>  — recorded, never fails the gate
    if [[ "$2" == 1 ]]; then echo "  [OK] $1"; else echo "  [SOFT-FAIL] $1"; fi
}

llb_curl() { $hexec llb1 curl -s --max-time 10 "$@"; }
rest_code() {  # rest_code <method> <path> [json]
    if [[ -n "$3" ]]; then
        llb_curl -o /dev/null -w "%{http_code}" -X"$1" "${API}$2" -H "Content-Type: application/json" -d "$3"
    else
        llb_curl -o /dev/null -w "%{http_code}" -X"$1" "${API}$2"
    fi
}
metric_val() {   # summed over every series matching the regex
    local v; v=$(llb_curl "${METRICS}" 2>/dev/null | grep -E "$1" | awk '{s+=$NF} END{printf "%d", s}'); echo "${v:-0}"
}
tier15_hits() {
    llb_curl "${METRICS}" 2>/dev/null | grep -E "loxilb_pd_kv_tier15_hits_total\{[^}]*ep_idx=\"$1\"" \
        | awk '{print $NF}' | tail -1 | grep -Eo '^[0-9]+' || echo 0
}
inv_total() {
    llb_curl "${KVINV}?service_id=${SERVICE_ID}&ep_idx=$1" 2>/dev/null \
        | python3 -c "import sys,json
try: d=json.load(sys.stdin); print(int(d.get('total_blocks', d.get('Size', d.get('size',0)))))
except Exception: print(0)" 2>/dev/null || echo 0
}
dp_log_count() {   # lines of the datapath (sockproxy) log matching the regex
    local n; n=$(docker exec llb1 sh -c 'cat /var/log/loxilbdp.log 2>/dev/null' 2>/dev/null | grep -cE "$1"); echo "${n:-0}"
}
loxilb_log_count() {
    local n; n=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' 2>/dev/null | grep -cE "$1"); echo "${n:-0}"
}
lb_stats_active() {   # activeConnections of the VIP rule (Octavia stats quad)
    local response
    if ! response=$(llb_curl -f "${LBBASE}/externalipaddress/${VIP}/port/${VPORT}/protocol/tcp/stats" 2>/dev/null); then
        echo -1; return
    fi
    printf '%s\n' "$response" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    lower={'activeConnections','bytesIn','bytesOut','totalConnections'}
    upper={'ActiveConnections','BytesIn','BytesOut','TotalConnections'}
    if not isinstance(d,dict) or not d: raise ValueError('empty stats')
    if not (set(d)<=lower or set(d)<=upper): raise ValueError('not stats quad')
    if any(type(v) is not int or not 0<=v<2**64 for v in d.values()): raise ValueError('invalid stats')
    # The generated optional uint64 quad omits zero fields. Infer zero only
    # from a nonempty, wholly valid quad; HTTP/error/empty objects stay unknown.
    print(d.get('activeConnections',d.get('ActiveConnections',0)))
except Exception: print(-1)" 2>/dev/null
}
prompt_text() {
    python3 -c "import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        sys.stdout.write(p['prompt']); break" "$1"
}
body_for() {   # body_for <prompt-id> [user]
    python3 -c "import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        b={'model':'${KV_MODEL}','prompt':p['prompt'],'max_tokens':8}
        if len(sys.argv)>2 and sys.argv[2]: b['user']=sys.argv[2]
        print(json.dumps(b)); break" "$1" "${2:-}"
}
# request from a client netns; echoes the backend banner (serverP*/serverD*) or ""
req_banner() {   # req_banner <netns> <prompt-id> [curl extra args...]
    local ns="$1" pid="$2"; shift 2
    $hexec "$ns" curl -s --max-time 10 -o - -w '' -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' --data-binary "$(body_for "$pid")" "$@" 2>/dev/null \
        | grep -Eo 'server[PD][0-9]' | head -1
}
# connect-level outcome from a client: prints "served", "timeout" (no SYN-ACK — dropped
# in XDP/TC), "reset" (connection refused/reset after the handshake) or "error:<rc>"
req_outcome() {  # req_outcome <netns> <prompt-id>
    local ns="$1" pid="$2" rc out
    out=$($hexec "$ns" curl -s --max-time 4 --connect-timeout 3 -o /dev/null -w '%{http_code}' \
        -X POST "http://${VIP}:${VPORT}/v1/completions" -H 'Content-Type: application/json' \
        --data-binary "$(body_for "$pid")" 2>/dev/null); rc=$?
    case "$rc" in
        0) [[ "$out" == 200 ]] && echo served || echo "http:$out" ;;
        28) echo timeout ;;
        # a reset at accept surfaces as 7 (connect refused), 56 (recv failure), 52 (empty reply)
        # or 55 (send failure: the RST landed while curl was still writing the body — seen on
        # the two-hop l3h2 path), depending on where in the exchange the RST arrives
        7|56|52|55) echo reset ;;
        *) echo "error:$rc" ;;
    esac
}
netns_for_ep_ip() { case "$1" in "${EP_A_IP}") echo l3ep1;; "${EP_B_IP}") echo l3ep3;; *) echo "";; esac; }
publish_prompt_to_ep() {   # publish_prompt_to_ep <prompt-id> <ep-ip>
    local pid="$1" ep_ip="$2" one="${CFGDIR}/.kvpub-${1}-${2}.json" ns
    python3 -c "import json,sys
d=json.load(open('${CORPUS}'))
for p in d['prompts']:
    if p['id']==sys.argv[1]:
        json.dump([{'prompt':p['prompt']}], open(sys.argv[2],'w')); break" "$pid" "$one"
    ns="$(netns_for_ep_ip "$ep_ip")"
    for _pp in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do kill "${_pp}" >/dev/null 2>&1 || true; done
    sleep 1
    setsid $hexec "${ns}" bash -c "export PYTHONPATH='${PY_USER_SITE}' PYTHONHASHSEED=0; exec -a ${PUB_TAG} python3 '${PUBLISHER}' \
        --corpus '${one}' --tokenizer '${TOKENIZER_SRC}' --vectors '${VECTORS_SRC}' \
        --bind '${ep_ip}' --port ${KV_ZMQ_PORT} --algo ${KV_HASH_ALGO} \
        --block-size ${KV_BLOCK_SIZE} --repeat 3 --repeat-interval 6 --no-vocabulary" >"${CFGDIR}/.kvpub-${pid}-${ep_ip}.log" 2>&1 &
    sleep 10
}
rule_replace() {   # rule_replace <extra service-args JSON fragment> [extra top-level fragment] -> http code
    # allowedSources is a top-level member of the LB document (next to endpoints), not a
    # service argument; connectionLimit / fc_* / api_key_auth / timeouts are service arguments.
    local extra="$1" top="${2:-}"; [[ -n "$extra" ]] && extra="${extra},"
    [[ -n "$top" ]] && top="${top},"
    rest_code POST /config/loadbalancer "$(cat <<JSON
{"serviceArguments":{"externalIP":"${VIP}","port":${VPORT},"protocol":"tcp","sel":0,"mode":4,
 "host":"${VIP}","model_name":"${KV_MODEL}",${extra}
 "pd_disagg_mode":true,"probeRetries":1,"kvExactMode":1,"kvZmqPort":${KV_ZMQ_PORT},
 "kvHashAlgo":"${KV_HASH_ALGO}","kvWarmupSec":${KV_WARMUP_SEC},"kvBlockSize":${KV_BLOCK_SIZE}},
 ${top}
 "endpoints":[{"endpointIP":"31.31.31.1","targetPort":80,"weight":1,"ep_role":1},
  {"endpointIP":"32.32.32.1","targetPort":80,"weight":1,"ep_role":2},
  {"endpointIP":"33.33.33.1","targetPort":80,"weight":1,"ep_role":1},
  {"endpointIP":"34.34.34.1","targetPort":80,"weight":1,"ep_role":2},
  {"endpointIP":"35.35.35.1","targetPort":80,"weight":1,"ep_role":1},
  {"endpointIP":"36.36.36.1","targetPort":80,"weight":1,"ep_role":2}]}
JSON
)"
}
# the Octavia quad is refreshed by the rules ticker, so wait on the value, not a clock
wait_active() {   # wait_active <expected> [max-seconds] -> prints the last value read
    local want="$1" max="${2:-20}" v=-1
    for _ in $(seq 1 "$max"); do v=$(lb_stats_active); [[ "$v" == "$want" ]] && break; sleep 1; done
    echo "$v"
}
# a counter crosses two pipelines (proxy stats snapshot, then the Prometheus collector), each
# with its own period: wait on the value, never on a clock
wait_metric_ge() {   # wait_metric_ge <metric regex> <min value> [max-seconds] -> prints the last value read
    local re="$1" want="$2" max="${3:-30}" v=0
    for _ in $(seq 1 "$max"); do v=$(metric_val "$re"); [[ "$v" -ge "$want" ]] && break; sleep 1; done
    echo "$v"
}
# A listener gauge may change before the sampled idle connection is reaped.
# Poll the owning datapath event before ending a holder; zero gauge alone is
# not evidence that inactiveTimeOut fired.
wait_dp_log_count_ge() { # <regex> <min count> [max-seconds]
    local re="$1" want="$2" max="${3:-40}" v=0
    for _ in $(seq 1 "$max"); do
        v=$(dp_log_count "$re")
        [[ "$v" -ge "$want" ]] && break
        sleep 1
    done
    echo "$v"
}
# securityrate off switch: a POST with every protection off is refused (400) by design
sec_reset_off() { rest_code DELETE /config/securityrate >/dev/null 2>&1; }
# KV-exact status of the rule (GET .../kvexactstatus?model_name=): "<desiredState> <enforcedState>"
KVSTATUS="${LBBASE}/externalipaddress/${VIP}/port/${VPORT}/protocol/tcp/kvexactstatus"
kv_status_states() {
    llb_curl -G --data-urlencode "model_name=${KV_MODEL}" "${KVSTATUS}" 2>/dev/null | python3 -c "import sys,json
try:
    d=json.load(sys.stdin); d=d.get('kvExactStatusAttr', d) if isinstance(d,dict) else d
    e=d[0] if isinstance(d,list) else d
    print(e.get('desiredState',''), e.get('enforcedState',''))
except Exception: print('unreadable unreadable')" 2>/dev/null || echo "unreadable unreadable"
}
# A profile-less KV-exact rule that arrives through POST /config/restore is REQUIRES_MIGRATION
# by contract (swagger kvModelProfile: "Snapshot restore has a separate recovery contract ...
# fencing Exact routing"): requests are served through the normal tiers and the exact tier
# is Go-fenced until a profile is attached. A FRESH create (DELETE + POST, never a replace:
# a replace keeps the restored identity) is the operator's way back to the exact tier for a
# legacy rule. The rule key carries host + model_name, so the delete is the hosturl form
# with model_name (the short path matches a different key and answers 404).
rule_recreate_fresh() {   # -> "<delete code> <create code>"
    local c_d c_a
    c_d=$(llb_curl -o /dev/null -w '%{http_code}' -X DELETE -G --data-urlencode "model_name=${KV_MODEL}" \
        "${LBBASE}/hosturl/${VIP}/externalipaddress/${VIP}/port/${VPORT}/protocol/tcp")
    sleep 2
    c_a=$(rule_replace "")
    echo "${c_d} ${c_a}"
}
# A keep-alive holder: one COMPLETE routed request (so the connection is an idle keep-alive
# one afterwards, not a partial-header one the header-completion deadline drops at
# timeoutTcpInspect, 10 s by default), then silence for <hold-seconds>. Echoes the holder's pid.
hold_request_conn() {   # hold_request_conn <netns> [hold-seconds]
    local ns="$1" secs="${2:-25}" req="${CFGDIR}/.hold-req-${1}.bin"
    python3 -c "import sys
body=open(sys.argv[2]).read()
sys.stdout.write('POST /v1/completions HTTP/1.1\\r\\nHost: ${VIP}:${VPORT}\\r\\nContent-Type: application/json\\r\\nContent-Length: %d\\r\\n\\r\\n%s' % (len(body), body))" \
        "$ns" <(body_for "${KV_PID}") >"${req}"
    $hexec "$ns" bash -c "exec 3<>/dev/tcp/${VIP}/${VPORT}; cat '${req}' >&3; sleep ${secs}" >/dev/null 2>&1 &
    echo $!
}
# end every connection holder of a client namespace. The holder's bash execs its trailing
# sleep in place, so a pkill on the "exec 3<>" pattern reaches only the sudo wrapper, and
# sudo 1.9.9 (ubuntu-22.04) does not pass that signal on to its command: the sleep keeps the
# socket open until it expires and the listener still counts it. The namespace's pid list
# reaches the command itself whatever wraps it; a client namespace runs nothing else at
# these points (the publisher lives in the endpoint namespace).
end_holders() {   # end_holders <netns> [wrapper pids...]
    local ns="$1" p; shift
    for p in $(sudo ip netns pids "$ns" 2>/dev/null); do sudo kill "$p" >/dev/null 2>&1; done
    [[ $# -gt 0 ]] && kill "$@" >/dev/null 2>&1
    pkill -f "exec 3<>/dev/tcp/${VIP}/${VPORT}" >/dev/null 2>&1
    return 0
}
fence_rules() {   # the fw rules of the VIP fence as GET /config/firewall/all shows them: "<pref> <src>" per line
    llb_curl "${API}/config/firewall/all" 2>/dev/null | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    for r in d.get('fwAttr', d.get('fwRules', [])):
        a=r.get('ruleArguments',{})
        if a.get('destinationIP','').startswith('${VIP}/'):
            print(a.get('preference',0), a.get('sourceIP',''))
except Exception: pass" 2>/dev/null
}
# a routed probe from l3h1 that must land on EP-A with a Tier-1.5 hit. The client-visible
# banner is the DECODE echo (serverD*): in P/D mode the prefill choice is not client-observable
# by design (see vllm-kvcache-routing-cpu/validation.sh), so the dual proof is banner==serverD*
# (the request went through the full P/D flow) AND the Tier-1.5 hit counter of EP-A moved
# (the selection proof).
kv_probe_a() {   # kv_probe_a <label>
    local before after banner
    before=$(tier15_hits "${EP_A_IDX}")
    banner=$(req_banner l3h1 "${KV_PID}")
    after=$(tier15_hits "${EP_A_IDX}")
    assert "$1: allowed client routed Tier-1.5 to EP-A (banner=${banner:-none}, hits ${before}->${after})" \
        "$([[ "$banner" == serverD* && "$after" -gt "$before" ]] && echo 1 || echo 0)"
}

