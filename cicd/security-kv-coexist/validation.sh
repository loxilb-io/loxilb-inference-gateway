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

# Shared helpers and topology constants (validation-ddos.sh sources the same file).
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

# The fence rules carry the source-check mark, and GET /config/firewall/all hides every
# marked (auto-generated) rule — exactly as it hides the allowedSources rules of NAT rules —
# so the read-back of the fence is the gateway's own install/delete log lines, and the
# operator-facing list must NOT show them.
FENCE_ALLOW_LOG="fw-rule added - [0-9]+:dst-${VIP}/32,src-${CLIENT_A_IP}/32,proto-6,dport-${VPORT},-allow"
FENCE_DROP_LOG="fw-rule added - [0-9]+:dst-${VIP}/32,src-0.0.0.0/0,proto-6,dport-${VPORT},-drop"
FENCE_DEL_LOG="fw-rule deleted dst-${VIP}/32,src-(${CLIENT_A_IP}/32|0.0.0.0/0),proto-6,dport-${VPORT},-(allow|drop)"

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
# cookieThreshold must be below synThreshold (handler: 400 otherwise)
c=$(rest_code POST /config/securityrate '{"synEnabled":true,"synThreshold":20,"cookieThreshold":10,"connRateEnabled":true,"ratePerSec":5,"udpEnabled":false,"udpPktThreshold":1000,"udpBandwidthMB":100}')
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
# a POST with every protection off is refused (400) by design; DELETE is the off switch
rest_code DELETE /config/securityrate >/dev/null
sleep 2
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C3: other client served again after reset (outcome=${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── C4 allowedSources on the fullproxy rule (TC fence) ─────────────────────────────────────────
echo "### C4 allowedSources on the fullproxy rule: TC fence drops the other client's SYN; KV routing unchanged"
fa_b=$(loxilb_log_count "$FENCE_ALLOW_LOG"); fd_b=$(loxilb_log_count "$FENCE_DROP_LOG"); fx_b=$(loxilb_log_count "$FENCE_DEL_LOG")
c=$(rule_replace "" "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}]")
assert "C4: replace with allowedSources -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
sleep 3
fa_a=$(loxilb_log_count "$FENCE_ALLOW_LOG"); fd_a=$(loxilb_log_count "$FENCE_DROP_LOG")
assert "C4: fence installed (allow ${CLIENT_A_IP}/32->${VIP}:${VPORT} +$((fa_a - fa_b)), drop 0/0->${VIP}:${VPORT} +$((fd_a - fd_b)))" \
    "$([[ $((fa_a - fa_b)) == 1 && $((fd_a - fd_b)) == 1 ]] && echo 1 || echo 0)"
fr=$(fence_rules)
assert "C4: fence hidden from GET /config/firewall/all like every source-check rule ($(printf '%s' "$fr" | grep -c .) rows)" \
    "$([[ -z "$fr" ]] && echo 1 || echo 0)"
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
fx_a=$(loxilb_log_count "$FENCE_DEL_LOG")
assert "C4: fence removed with the sources (replace=$c, fence deletes +$((fx_a - fx_b)))" \
    "$([[ $((fx_a - fx_b)) == 2 ]] && echo 1 || echo 0)"
# the delete must reach the kernel: a stale drop row in fw_v4_map kept the other client out
# for the rest of the run before the pdi port-match fix (campaign finding K-P0b)
oc=$(req_outcome l3h2 "${KV_PID}")
assert "C4: other client served again (outcome=${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"
# fence rules carry the source-check mark, so a snapshot must not contain them
c=$(rule_replace "" "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}]"); sleep 2
snap=$(llb_curl "${API}/config/snapshot?components=firewall" 2>/dev/null)
soft "C4: snapshot firewall domain carries no fence rule" "$([[ "$snap" != *"${VIP}/32"* ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null; sleep 2

# ── C5 connectionLimit on the fullproxy rule (sockproxy gauge) ─────────────────────────────────
echo "### C5 connectionLimit=2 on the fullproxy rule: third client connection reset at accept"
c=$(rule_replace '"connectionLimit":2')
assert "C5: replace with connectionLimit=2 -> 200 (got $c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"
sleep 3
# two idle keep-alive holders: each sends one complete routed request and then stays
# silent (a partial-header holder is dropped by the header-completion deadline instead)
H1=$(hold_request_conn l3h1)
H2=$(hold_request_conn l3h1)
act=$(wait_active 2)
assert "C5: activeConnections reads the listener gauge (=2, got ${act})" "$([[ "$act" == 2 ]] && echo 1 || echo 0)"
oc=$(req_outcome l3h1 "${KV_PID}")
assert "C5: third connection refused at accept with a reset (outcome=${oc})" "$([[ "$oc" == reset ]] && echo 1 || echo 0)"
oc2=$(req_outcome l3h2 "${KV_PID}")
assert "C5: the limit is per rule, not per source (other client also refused: ${oc2})" "$([[ "$oc2" == reset ]] && echo 1 || echo 0)"
pkill -f "exec 3<>/dev/tcp/${VIP}/${VPORT}" >/dev/null 2>&1; kill $H1 $H2 >/dev/null 2>&1; sleep 1
act=$(wait_active 0)
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
# api_key_auth is kept by a replace that omits it (apiKeyAuthOnReplace): lift it explicitly
rule_replace '"api_key_auth":"disabled"' >/dev/null; sleep 3
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
# fc_* fields are kept by a replace that omits them: lift explicitly (0 = process default)
rule_replace '"fc_mode":"off","fc_prefill_max_inflight":0,"fc_max_queue_depth":0,"fc_max_queue_wait_ms":0' >/dev/null; sleep 3
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
# --next separates the two transfers: without it curl joins both -d bodies into one
# (invalid JSON -> 503 no_route) and the test never exercises the keep-alive switch
$hexec l3h1 curl -s --max-time 10 -o "${CFGDIR}/.c8.out" -w '%{http_code} ' \
    -X POST "http://${VIP}:${VPORT}/v1/completions" -H 'Content-Type: application/json' --data-binary "$(body_for "${KV_PID}" alice)" \
    --next -s --max-time 10 -o "${CFGDIR}/.c8b.out" -w '%{http_code} ' \
    -X POST "http://${VIP}:${VPORT}/v1/completions" -H 'Content-Type: application/json' --data-binary "$(body_for "${KV_PID}" bob)" \
    >"${CFGDIR}/.c8.code" 2>/dev/null
sess_after=$(metric_val 'loxilb_ai_pd_tier_selected_total\{[^}]*tier="0"')
echo "  C8 codes: $(cat "${CFGDIR}/.c8.code")  tier0 selections ${sess_before}->${sess_after}"
# bob's first request has no session of its own, so at most alice's second-request-free
# count applies: a Tier-0 selection for bob (tier0 delta == 2) means bob inherited alice's key
c8codes="$(cat "${CFGDIR}/.c8.code")"
assert "C8: both keep-alive requests served (codes: ${c8codes})" "$([[ "$c8codes" == "200 200 " ]] && echo 1 || echo 0)"
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
n_fb=$(loxilb_log_count "(native \(driver\) mode attach failed|xdp attach with flags .* refused)")
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
c=$(rule_replace '"connectionLimit":3' "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}]"); sleep 2
fa_b=$(loxilb_log_count "$FENCE_ALLOW_LOG"); fd_b=$(loxilb_log_count "$FENCE_DROP_LOG")
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
fa_a=$(loxilb_log_count "$FENCE_ALLOW_LOG"); fd_a=$(loxilb_log_count "$FENCE_DROP_LOG")
assert "C11: after persist(${c_p})/restore(${c_r}) rule reads connectionLimit=3 + 1 source (got '${rb}') and the fence was re-installed (allow +$((fa_a - fa_b)), drop +$((fd_a - fd_b)))" \
    "$([[ "$rb" == "3 1" && $((fa_a - fa_b)) -ge 1 && $((fd_a - fd_b)) -ge 1 ]] && echo 1 || echo 0)"
oc=$(req_outcome l3h2 "${KV_PID}")
soft "C11: other client still fenced after restore (outcome=${oc})" "$([[ "$oc" == timeout ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null; sleep 2
# The restore contract for a profile-less KV-exact rule (see rule_recreate_fresh in lib.sh):
# the rule comes back REQUIRES_MIGRATION — served through the normal tiers, exact tier fenced
# (tokenize bridge answers NOT_READY, Tier-1.5 hits stay flat) — and a replace does not lift it.
st=$(kv_status_states)
assert "C11: restored profile-less rule reports REQUIRES_MIGRATION on kvexactstatus (got '${st}')" \
    "$([[ "$st" == "REQUIRES_MIGRATION REQUIRES_MIGRATION" ]] && echo 1 || echo 0)"
hb=$(tier15_hits "${EP_A_IDX}"); banner=$(req_banner l3h1 "${KV_PID}"); ha=$(tier15_hits "${EP_A_IDX}")
assert "C11: restored rule still serves the allowed client through the normal tiers with the exact tier fenced (banner=${banner:-none}, hits ${hb}->${ha})" \
    "$([[ "$banner" == serverD* && "$ha" -eq "$hb" ]] && echo 1 || echo 0)"
rc=$(rule_recreate_fresh); sleep "${KV_WARMUP_SEC}"
publish_prompt_to_ep "${KV_PID}" "${EP_A_IP}"
st=$(kv_status_states)
assert "C11: a fresh create (delete/create=${rc}) lifts the fence (status '${st}')" \
    "$([[ "$st" != *REQUIRES_MIGRATION* && "$st" != unreadable* ]] && echo 1 || echo 0)"
kv_probe_a "C11 (fresh rule after the restore)"

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
rest_code DELETE /config/securityrate >/dev/null 2>&1
if [[ $code == 0 ]]; then
    echo "SCENARIO-security-kv-coexist [OK]"
else
    echo "SCENARIO-security-kv-coexist [FAILED]"
fi
exit $code
