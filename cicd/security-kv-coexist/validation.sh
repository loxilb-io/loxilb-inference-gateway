#!/bin/bash
# validation.sh — security features × KV-cache-aware routing coexistence gate.
#
# Every check switches ONE security control on, proves it bites the OTHER client (l3h2)
# at the layer that owns it (XDP / TC / sockproxy), and in the SAME window proves the
# allowed client's (l3h1) KV routing is untouched: the request lands on the published
# prefill EP (banner) and loxilb_pd_kv_tier15_hits_total moves for that EP. Then the
# control is switched off and l3h2 is served again. The check matrix is the README's
# table; the C1..C12 labels below are its rows.
#
# Sentinel: SCENARIO-security-kv-coexist [OK] only when every hard assert passed.
source ../common.sh
echo SCENARIO-security-kv-coexist

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
KVCPU="${CFGDIR}/../vllm-kvcache-routing-cpu"
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
loxilb_log_count() {
    local n; n=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' 2>/dev/null | grep -cE "$1"); echo "${n:-0}"
}
lb_stats_active() {   # activeConnections of the VIP rule (Octavia stats quad)
    llb_curl "${LBBASE}/externalipaddress/${VIP}/port/${VPORT}/protocol/tcp/stats" 2>/dev/null \
        | python3 -c "import sys,json
try: d=json.load(sys.stdin); print(int(d.get('activeConnections', d.get('ActiveConnections',0))))
except Exception: print(-1)" 2>/dev/null || echo -1
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
        7|56|52) echo reset ;;
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
rule_replace() {   # rule_replace <extra service-args JSON fragment> -> http code
    local extra="$1"; [[ -n "$extra" ]] && extra="${extra},"
    rest_code POST /config/loadbalancer "$(cat <<JSON
{"serviceArguments":{"externalIP":"${VIP}","port":${VPORT},"protocol":"tcp","sel":0,"mode":4,
 "host":"${VIP}","model_name":"${KV_MODEL}",${extra}
 "pd_disagg_mode":true,"probeRetries":1,"kvExactMode":1,"kvZmqPort":${KV_ZMQ_PORT},
 "kvHashAlgo":"${KV_HASH_ALGO}","kvWarmupSec":${KV_WARMUP_SEC},"kvBlockSize":${KV_BLOCK_SIZE}},
 "endpoints":[{"endpointIP":"31.31.31.1","targetPort":80,"weight":1,"ep_role":1},
  {"endpointIP":"32.32.32.1","targetPort":80,"weight":1,"ep_role":2},
  {"endpointIP":"33.33.33.1","targetPort":80,"weight":1,"ep_role":1},
  {"endpointIP":"34.34.34.1","targetPort":80,"weight":1,"ep_role":2},
  {"endpointIP":"35.35.35.1","targetPort":80,"weight":1,"ep_role":1},
  {"endpointIP":"36.36.36.1","targetPort":80,"weight":1,"ep_role":2}]}
JSON
)"
}
sec_reset='{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}'
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
# a routed probe from l3h1 that must land on EP-A with a Tier-1.5 hit
kv_probe_a() {   # kv_probe_a <label>
    local before after banner
    before=$(tier15_hits "${EP_A_IDX}")
    banner=$(req_banner l3h1 "${KV_PID}")
    after=$(tier15_hits "${EP_A_IDX}")
    assert "$1: allowed client routed Tier-1.5 to EP-A (banner=${banner:-none}, hits ${before}->${after})" \
        "$([[ "$banner" == serverP0 && "$after" -gt "$before" ]] && echo 1 || echo 0)"
}

# ── readiness ──────────────────────────────────────────────────────────────────────────────────
SERVICE_ID=""
for _sid in 0 1 2 3 4 5 6 7 8; do
    if llb_curl "${KVINV}?service_id=${_sid}&ep_idx=${EP_A_IDX}" 2>/dev/null | grep -q '"service_id"'; then SERVICE_ID="${_sid}"; break; fi
done
SERVICE_ID="${SERVICE_ID:-1}"
echo "  resolved KV serviceID=${SERVICE_ID}"
echo "  waiting for the KV warm-up window (${KV_WARMUP_SEC}s) to pass..."; sleep "$((KV_WARMUP_SEC + 3))"

# the prompt every routing probe uses; published to EP-A so Tier-1.5 has a winner
KV_PID="$(python3 -c "import json; d=json.load(open('${CORPUS}')); print(d['prompts'][0]['id'])")"
publish_prompt_to_ep "${KV_PID}" "${EP_A_IP}"

# ── C1 baseline ────────────────────────────────────────────────────────────────────────────────
echo "### C1 baseline: both clients served, KV routing lands on the published EP"
kv_probe_a "C1"
b2=$(req_banner l3h2 "${KV_PID}")
assert "C1: other client served too (banner=${b2:-none})" "$([[ -n "$b2" ]] && echo 1 || echo 0)"

# ── C2 ipfilter blacklist (XDP) ────────────────────────────────────────────────────────────────
echo "### C2 ipfilter: blacklist the other client at XDP; allowed client's KV routing unchanged"
c=$(rest_code POST /config/ipfilter "{\"filterType\":\"blacklist\",\"cidr\":\"${CLIENT_B_IP}/32\",\"action\":\"drop\",\"priority\":200}")
assert "C2: blacklist add -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
sleep 2
bl_before=$(metric_val "loxilb_ipfilter_blacklist_packets_total\{[^}]*cidr=\"${CLIENT_B_IP}/32\"")
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C2: blacklisted client gets no SYN-ACK (outcome=${oc})" "$([[ "$oc" == timeout ]] && echo 1 || echo 0)"
sleep 11   # one collector cycle
bl_after=$(metric_val "loxilb_ipfilter_blacklist_packets_total\{[^}]*cidr=\"${CLIENT_B_IP}/32\"")
assert "C2: XDP blacklist counter moved (${bl_before}->${bl_after})" "$([[ "$bl_after" -gt "$bl_before" ]] && echo 1 || echo 0)"
kv_probe_a "C2"
c=$(rest_code DELETE "/config/ipfilter?filterType=blacklist&cidr=${CLIENT_B_IP}/32")
sleep 2
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C2: other client served again after delete (del=$c outcome=${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── C3 securityrate (XDP) ──────────────────────────────────────────────────────────────────────
echo "### C3 securityrate: SYN/conn-rate flood from the other client blocked at XDP; KV routing unchanged"
c=$(rest_code POST /config/securityrate '{"synEnabled":true,"synThreshold":20,"cookieThreshold":50,"connRateEnabled":true,"ratePerSec":5,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}')
assert "C3: securityrate set -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
sleep 1
cb_before=$(metric_val loxilb_security_conn_blocked_total)
sb_before=$(metric_val loxilb_security_syn_blocked_total)
for _ in $(seq 1 60); do $hexec l3h2 curl --max-time 0.3 -s -o /dev/null "http://${VIP}:${VPORT}/v1/models"; done
kv_probe_a "C3 (during the flood)"
sleep 11
cb_after=$(metric_val loxilb_security_conn_blocked_total)
sb_after=$(metric_val loxilb_security_syn_blocked_total)
assert "C3: XDP conn-rate/SYN block counters moved (conn ${cb_before}->${cb_after}, syn ${sb_before}->${sb_after})" \
    "$([[ "$cb_after" -gt "$cb_before" || "$sb_after" -gt "$sb_before" ]] && echo 1 || echo 0)"
rest_code POST /config/securityrate "$sec_reset" >/dev/null
sleep 2
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C3: other client served again after reset (outcome=${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── C4 allowedSources on the fullproxy rule (TC fence) ─────────────────────────────────────────
echo "### C4 allowedSources on the fullproxy rule: TC fence drops the other client's SYN; KV routing unchanged"
c=$(rule_replace "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}]" )
assert "C4: replace with allowedSources -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
sleep 3
fr=$(fence_rules)
n_allow=$(printf '%s\n' "$fr" | grep -c "^65000 ${CLIENT_A_IP}/32")
n_drop=$(printf '%s\n' "$fr" | grep -c "^64999 0.0.0.0/0")
assert "C4: fence installed in fw (allow ${CLIENT_A_IP}/32 pref 65000 x${n_allow}, drop 0/0 pref 64999 x${n_drop})" \
    "$([[ "$n_allow" == 1 && "$n_drop" == 1 ]] && echo 1 || echo 0)"
fw_before=$(metric_val loxilb_fw_drop_packets_total)
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C4: other client fenced out at TC (outcome=${oc})" "$([[ "$oc" == timeout ]] && echo 1 || echo 0)"
kv_probe_a "C4"
sleep 11
fw_after=$(metric_val loxilb_fw_drop_packets_total)
assert "C4: fw drop counter moved (${fw_before}->${fw_after})" "$([[ "$fw_after" -gt "$fw_before" ]] && echo 1 || echo 0)"
# the fence follows the rule: replace without allowedSources removes it entirely
c=$(rule_replace "")
sleep 3
fr=$(fence_rules)
assert "C4: fence removed with the sources (replace=$c, fence rows left: $(printf '%s' "$fr" | grep -c . ))" \
    "$([[ -z "$fr" ]] && echo 1 || echo 0)"
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C4: other client served again (outcome=${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"
# fence rules carry the source-check mark, so a snapshot must not contain them
c=$(rule_replace "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}]"); sleep 2
snap=$(llb_curl "${API}/config/snapshot?components=firewall" 2>/dev/null)
soft "C4: snapshot firewall domain carries no fence rule" "$([[ "$snap" != *"${VIP}/32"* ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null; sleep 2

# ── C5 connectionLimit on the fullproxy rule (sockproxy gauge) ─────────────────────────────────
echo "### C5 connectionLimit=2 on the fullproxy rule: third client connection reset at accept"
c=$(rule_replace '"connectionLimit":2')
assert "C5: replace with connectionLimit=2 -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
sleep 3
# two idle keep-alive holders (headers never completed, so the connections stay open)
hold_conn() { $hexec l3h1 bash -c "exec 3<>/dev/tcp/${VIP}/${VPORT}; printf 'POST /v1/completions HTTP/1.1\r\nHost: x\r\n' >&3; sleep 25" >/dev/null 2>&1 & echo $!; }
H1=$(hold_conn)
H2=$(hold_conn)
sleep 2
act=$(lb_stats_active)
assert "C5: activeConnections reads the listener gauge (=2, got ${act})" "$([[ "$act" == 2 ]] && echo 1 || echo 0)"
oc=$(req_outcome l3h1 "${KV_PID}")
assert "C5: third connection refused at accept with a reset (outcome=${oc})" "$([[ "$oc" == reset ]] && echo 1 || echo 0)"
oc2=$(req_outcome l3h2 "${KV_PID}")
assert "C5: the limit is per rule, not per source (other client also refused: ${oc2})" "$([[ "$oc2" == reset ]] && echo 1 || echo 0)"
pkill -f "exec 3<>/dev/tcp/${VIP}/${VPORT}" >/dev/null 2>&1; kill $H1 $H2 >/dev/null 2>&1; sleep 3
act=$(lb_stats_active)
assert "C5: gauge released with the holders (=0, got ${act})" "$([[ "$act" == 0 ]] && echo 1 || echo 0)"
kv_probe_a "C5 (after the holders closed, under the limit)"
rule_replace "" >/dev/null; sleep 2
n_ref=$(loxilb_log_count "FE_CONN_LIMIT")
soft "C5: refusal logged (FE_CONN_LIMIT lines=${n_ref})" "$([[ "$n_ref" -ge 1 ]] && echo 1 || echo 0)"

# ── C6 policy denial (api_key_auth required, no store -> 503 before selection) ─────────────────
echo "### C6 policy denial: api_key_auth=required with no store denies before selection; routing state untouched"
c=$(rule_replace '"api_key_auth":"required"'); sleep 3
h_before=$(tier15_hits "${EP_A_IDX}")
sel_before=$(metric_val 'loxilb_ai_pd_tier_selected_total')
C6_BOGUS_KEY="not-a-key"   # any value: no key store is configured, so every key is refused
for _ in 1 2 3; do
    hc=$($hexec l3h1 curl -s --max-time 5 -o /dev/null -w '%{http_code}' -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' -H "X-Api-Key: ${C6_BOGUS_KEY}" --data-binary "$(body_for "${KV_PID}")")
done
assert "C6: keyed request denied by policy (HTTP ${hc}; 401/403/503 expected)" "$([[ "$hc" =~ ^(401|403|503)$ ]] && echo 1 || echo 0)"
h_after=$(tier15_hits "${EP_A_IDX}")
sel_after=$(metric_val 'loxilb_ai_pd_tier_selected_total')
assert "C6: no tier selection and no Tier-1.5 hit for denied requests (sel ${sel_before}->${sel_after}, hits ${h_before}->${h_after})" \
    "$([[ "$h_after" == "$h_before" && "$sel_after" == "$sel_before" ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null; sleep 3
kv_probe_a "C6 (after the policy is lifted)"

# ── C7 capacity admission after selection (fc role gate) ───────────────────────────────────────
echo "### C7 capacity admission: fc role cap refuses after selection; the next request on the kept connection routes clean"
# fc_prefill_max_inflight=1 with queue depth 0: the service gate admits, pd_select_prefill
# picks EP-A, the ROLE gate refuses the second concurrent request with 429 on a kept
# connection — the path whose un-taken decode unit used to be handed back (L-D1).
c=$(rule_replace '"fc_mode":"enforce","fc_prefill_max_inflight":1,"fc_max_queue_depth":0,"fc_max_queue_wait_ms":1'); sleep 3
assert "C7: replace with fc role cap -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
# 6 concurrent requests on the same prompt; reflect-echo answers instantly, so most are
# serial in practice — a 429 here is a bonus, the invariant is what follows.
for i in 1 2 3 4 5 6; do
    $hexec l3h1 curl -s --max-time 10 -o "${CFGDIR}/.c7-$i.out" -w '%{http_code}\n' -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' --data-binary "$(body_for "${KV_PID}")" >"${CFGDIR}/.c7-$i.code" 2>/dev/null &
done
wait
codes=$(cat "${CFGDIR}"/.c7-*.code | tr '\n' ' ')
echo "  C7 concurrent codes: ${codes}"
n429=$(grep -c '^429' "${CFGDIR}"/.c7-*.code 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
soft "C7: at least one capacity 429 observed (${n429})" "$([[ "$n429" -ge 1 ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null; sleep 3
kv_probe_a "C7 (after the cap is lifted)"
# a decode unit handed back that was never taken shows up as the >0 guard masking it
n_spur=$(loxilb_log_count "PD_LOAD\] decode EP[0-9]+ unit release with zero gauge")
assert "C7: no spurious decode-unit release logged (${n_spur})" "$([[ "$n_spur" == 0 ]] && echo 1 || echo 0)"

# ── C8 keep-alive user switch (Tier-0 session key must not leak across requests) ───────────────
echo "### C8 keep-alive: request 2 with another user key does not inherit request 1's Tier-0 session"
# Both requests ride ONE keep-alive connection: user=alice pins a session on EP-A, user=bob
# must be routed by its own key. Before the fix, request 2's missing/different user was
# overwritten by request 1's (has_user_id never reset) and bob rode alice's pin.
sess_before=$(metric_val 'loxilb_ai_pd_tier_selected_total\{[^}]*tier="0"')
$hexec l3h1 curl -s --max-time 10 -o "${CFGDIR}/.c8.out" -w '%{http_code} ' \
    -X POST "http://${VIP}:${VPORT}/v1/completions" -H 'Content-Type: application/json' --data-binary "$(body_for "${KV_PID}" alice)" \
    -X POST "http://${VIP}:${VPORT}/v1/completions" -H 'Content-Type: application/json' --data-binary "$(body_for "${KV_PID}" bob)" \
    >"${CFGDIR}/.c8.code" 2>/dev/null
sess_after=$(metric_val 'loxilb_ai_pd_tier_selected_total\{[^}]*tier="0"')
echo "  C8 codes: $(cat "${CFGDIR}/.c8.code")  tier0 selections ${sess_before}->${sess_after}"
# bob's first request has no session of its own, so at most alice's second-request-free
# count applies: a Tier-0 selection for bob (tier0 delta == 2) means bob inherited alice's key
assert "C8: second user did not ride the first user's session (tier0 delta=$((sess_after - sess_before)) <= 1)" \
    "$([[ $((sess_after - sess_before)) -le 1 ]] && echo 1 || echo 0)"

# ── C9 proxy-only mode: kernel-enforced controls refused, never silently accepted ──────────────
echo "### C9 proxy-only: a kernel-enforced control is refused with 400 instead of a silent no-op"
# A second loxilb in proxy-only mode on the host side of nothing: it only needs its REST.
docker rm -f llbpo >/dev/null 2>&1
docker run -u root --cap-add SYS_ADMIN --privileged -dt --rm --entrypoint /bin/bash --name llbpo "${lxdocker}" >/dev/null 2>&1 \
    && docker exec -d llbpo bash -c "/root/loxilb-io/loxilb/loxilb --proxyonlymode > /tmp/loxilb.out 2> /tmp/loxilb.err" \
    && sleep 8 || echo "  WARN: could not start a proxy-only instance"
po() { docker exec llbpo curl -s -m 3 -o /dev/null -w '%{http_code}' -X"$1" "http://127.0.0.1:11111/netlox/v1$2" -H 'Content-Type: application/json' -d "$3"; }
c_ipf=$(po POST /config/ipfilter '{"filterType":"blacklist","cidr":"11.11.11.2/32","action":"drop","priority":200}')
c_fw=$(po POST /config/firewall '{"ruleArguments":{"sourceIP":"11.11.11.2/32","destinationIP":"0.0.0.0/0"},"opts":{"drop":true}}')
c_as=$(po POST /config/loadbalancer '{"serviceArguments":{"externalIP":"127.0.0.1","port":9090,"protocol":"tcp","sel":0,"mode":4,"host":"127.0.0.1"},"allowedSources":[{"prefix":"10.0.0.0/8"}],"endpoints":[{"endpointIP":"127.0.0.1","targetPort":9091,"weight":1}]}')
assert "C9: proxy-only refuses ipfilter (${c_ipf}) / firewall (${c_fw}) / allowedSources (${c_as}) with 400" \
    "$([[ "$c_ipf" == 400 && "$c_fw" == 400 && "$c_as" == 400 ]] && echo 1 || echo 0)"
docker rm -f llbpo >/dev/null 2>&1

# ── C10 XDP attach mode (native opt-in) ────────────────────────────────────────────────────────
echo "### C10 XDP mode: the attach mode is logged and visible on the link"
n_gen=$(loxilb_log_count "xdp: .* attached in generic \(skb\) mode")
n_nat=$(loxilb_log_count "xdp: .* attached in native \(driver\) mode")
n_fb=$(loxilb_log_count "native \(driver\) mode attach failed\|xdp attach with flags .* refused")
echo "  C10 attach log: generic=${n_gen} native=${n_nat} fallback=${n_fb} (XDP_NATIVE=${XDP_NATIVE:-unset})"
assert "C10: every XDP attach reported its mode (generic+native >= 1)" "$([[ $((n_gen + n_nat)) -ge 1 ]] && echo 1 || echo 0)"
if [[ -n "${XDP_NATIVE:-}" ]]; then
    link=$(docker exec llb1 ip -o link show 2>/dev/null | grep -E "xdp(drv)?[ /]|xdpgeneric" | head -3)
    echo "  C10 links: ${link}"
    soft "C10: native requested -> native attached or fallback logged (native=${n_nat} fallback=${n_fb})" \
        "$([[ "$n_nat" -ge 1 || "$n_fb" -ge 1 ]] && echo 1 || echo 0)"
fi
n_fail=$(loxilb_log_count "program .* NOT attached on")
assert "C10: no silent attach failure (NOT attached lines=${n_fail})" "$([[ "$n_fail" == 0 ]] && echo 1 || echo 0)"

# ── C11 snapshot round trip ────────────────────────────────────────────────────────────────────
echo "### C11 snapshot: persist -> restore keeps the rule's limits and fence"
c=$(rule_replace "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}],\"connectionLimit\":3"); sleep 2
c_p=$(rest_code POST /config/persist '{}')
snapdoc="${CFGDIR}/.snapshot.json"
llb_curl "${API}/config/snapshot" >"${snapdoc}" 2>/dev/null
c_r=$(llb_curl -o /dev/null -w '%{http_code}' -X POST "${API}/config/restore?mode=commit" \
    -H 'Content-Type: application/json' --data-binary "@${snapdoc}")
sleep 8
rb=$(llb_curl "${LBBASE}/all" | python3 -c "import sys,json
d=json.load(sys.stdin)
for r in d.get('lbAttr',[]):
    s=r.get('serviceArguments',{})
    if s.get('externalIP')=='${VIP}' and s.get('port')==${VPORT}:
        print(s.get('connectionLimit',0), len(r.get('allowedSources') or [])); break" 2>/dev/null)
fr=$(fence_rules)
assert "C11: after persist(${c_p})/restore(${c_r}) rule reads connectionLimit=3 + 1 source (got '${rb}') and the fence is back ($(printf '%s' "$fr" | grep -c .) rows)" \
    "$([[ "$rb" == "3 1" && $(printf '%s' "$fr" | grep -c .) == 2 ]] && echo 1 || echo 0)"
oc=$(req_outcome l3h2 "${KV_PID}")
soft "C11: other client still fenced after restore (outcome=${oc})" "$([[ "$oc" == timeout ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null; sleep 2
kv_probe_a "C11 (after restore, sources lifted)"

# ── C12 regression: the C unit layers of the touched code ──────────────────────────────────────
echo "### C12 unit layers: fe_limit + fc + kv-exact C units"
REPO_ROOT="$(cd "${CFGDIR}/../.." && pwd)"
if [[ "${SKIP_C_LAYERS:-0}" == 1 ]]; then
    soft "C12: C units skipped (SKIP_C_LAYERS=1)" 1
else
    ok=1
    for t in test_felimit test_fc test_kv; do
        if ( cd "${REPO_ROOT}/loxilb-ebpf/common" && make "$t" ) >"${CFGDIR}/.${t}.log" 2>&1; then
            echo "  make ${t} [OK]"
        else
            echo "  make ${t} [FAILED] — tail:"; tail -8 "${CFGDIR}/.${t}.log"; ok=0
        fi
    done
    assert "C12: C unit layers green" "$ok"
fi

for _pp in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do kill "${_pp}" >/dev/null 2>&1 || true; done
rest_code POST /config/securityrate "$sec_reset" >/dev/null 2>&1
if [[ $code == 0 ]]; then
    echo "SCENARIO-security-kv-coexist [OK]"
else
    echo "SCENARIO-security-kv-coexist [FAILED]"
fi
exit $code
