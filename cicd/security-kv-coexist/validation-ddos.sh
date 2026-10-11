#!/bin/bash
# validation-ddos.sh — every DDoS-protection option, one at a time, in front of the
# KV-exact fullproxy service of this topology (run config.sh first; validation.sh is
# the coexistence matrix, this is the option matrix).
#
# For each option the pattern is the same as validation.sh: switch it on, prove it bites
# the other client (l3h2) at the layer that owns it, prove the counters that belong to
# it move and the counters that belong to OTHER options do not, prove the allowed
# client's (l3h1) Tier-1.5 routing is untouched in the same window, switch it off,
# prove l3h2 is served again.
#
#   D1  securityrate SYN threshold alone (XDP)            syn_blocked moves, conn_blocked does not;
#                                                         cookie counter moves above cookieThreshold
#   D2  securityrate connection rate alone (XDP)          conn_blocked moves, syn_blocked does not
#   D3  threshold boundary (XDP)                          a burst under the threshold is not touched
#   D4  securityrate whitelist bypass (XDP)               a whitelisted flooder is never limited
#   D5  UDP flood protection (XDP)                        UDP from l3h2 limited; TCP KV traffic untouched
#   D6  stacked: ipfilter blacklist + securityrate        ipfilter drops first (XDP order), secrate silent
#   D7  securityrate durability                           GET reflects, persist -> restore keeps it
#   D8  header-completion deadline (proxy, slowloris)     partial-header holders dropped at timeoutTcpInspect
#   D9  process accept valve LLB_PD_MAX_TOTAL_INFLIGHT    (only when config.sh ran with TOTAL_INFLIGHT=<n>,
#                                                         which passes -e LLB_PD_MAX_TOTAL_INFLIGHT=<n> to llb1)
#   D10 inactiveTimeOut (proxy)                           idle connection reaped
#   D11 oversize request body (proxy)                     served via stream fallback or 413 — never a hang
#   D12 operator firewall rule to the VIP (TC)            explicit drop rule bites; fence band documented
#   D13 XDP mode under a SYN flood                        loxilb CPU sampled for the record (generic/native)
#
# Sentinel: SCENARIO-security-kv-coexist-ddos [OK]
source ../common.sh
echo SCENARIO-security-kv-coexist-ddos
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

sec() {   # sec <syn on> <syn thr> <cookie thr> <conn on> <rate> <udp on> <udp pkt> <udp mb> [whitelist json array]
    local wl="${9:-[]}"
    rest_code POST /config/securityrate "{\"synEnabled\":$1,\"synThreshold\":$2,\"cookieThreshold\":$3,\"connRateEnabled\":$4,\"ratePerSec\":$5,\"udpEnabled\":$6,\"udpPktThreshold\":$7,\"udpBandwidthMB\":$8,\"whitelistIps\":${wl}}"
}
# POST with every protection off is refused (400); DELETE is the off switch
sec_off() { rest_code DELETE /config/securityrate >/dev/null; sleep 1; }
# <n> short connection attempts from l3h2 as fast as curl allows (one SYN each)
syn_burst() { for _ in $(seq 1 "$1"); do $hexec l3h2 curl --max-time 0.3 -s -o /dev/null "http://${VIP}:${VPORT}/v1/models"; done; }
snap() {   # snap <var-prefix>: capture the five secrate counters
    eval "$1_sb=$(metric_val loxilb_security_syn_blocked_total)"
    eval "$1_sp=$(metric_val loxilb_security_syn_passed_total)"
    eval "$1_sc=$(metric_val loxilb_security_syn_cookies_total)"
    eval "$1_cb=$(metric_val loxilb_security_conn_blocked_total)"
    eval "$1_ub=$(metric_val loxilb_security_udp_blocked_total)"
}
delta() { echo $(( $2 - $1 )); }

# ── readiness ──────────────────────────────────────────────────────────────────────────────────
SERVICE_ID=""
for _sid in 0 1 2 3 4 5 6 7 8; do
    if llb_curl "${KVINV}?service_id=${_sid}&ep_idx=${EP_A_IDX}" 2>/dev/null | grep -q '"service_id"'; then SERVICE_ID="${_sid}"; break; fi
done
SERVICE_ID="${SERVICE_ID:-1}"
sleep 3
KV_PID="$(python3 -c "import json; d=json.load(open('${CORPUS}')); print(d['prompts'][0]['id'])")"
publish_prompt_to_ep "${KV_PID}" "${EP_A_IP}"
sec_off
kv_probe_a "D0 baseline"
oc=$(req_outcome l3h2 "${KV_PID}"); assert "D0: other client served (${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── D1 SYN threshold alone ─────────────────────────────────────────────────────────────────────
echo "### D1 securityrate: SYN threshold alone (synThreshold=10, cookieThreshold=5, conn-rate off)"
c=$(sec true 10 5 false 50 false 1000 100); assert "D1: set -> 200 ($c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"; sleep 1
snap b; syn_burst 40; kv_probe_a "D1 (during the SYN burst)"; sleep 11; snap a
assert "D1: syn_blocked moved ($(delta $b_sb $a_sb))" "$([[ $a_sb -gt $b_sb ]] && echo 1 || echo 0)"
assert "D1: conn_blocked did NOT move with conn-rate off ($(delta $b_cb $a_cb))" "$([[ $a_cb -eq $b_cb ]] && echo 1 || echo 0)"
assert "D1: syn_cookies counter moved above cookieThreshold ($(delta $b_sc $a_sc)) — a counter, the real cookies are the kernel's (§6)" "$([[ $a_sc -gt $b_sc ]] && echo 1 || echo 0)"
sec_off; oc=$(req_outcome l3h2 "${KV_PID}"); assert "D1: served after reset (${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── D2 connection rate alone ───────────────────────────────────────────────────────────────────
echo "### D2 securityrate: connection rate alone (ratePerSec=5, SYN off)"
c=$(sec false 100 50 true 5 false 1000 100); assert "D2: set -> 200 ($c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"; sleep 1
snap b; syn_burst 40; kv_probe_a "D2 (during the burst)"; sleep 11; snap a
assert "D2: conn_blocked moved ($(delta $b_cb $a_cb))" "$([[ $a_cb -gt $b_cb ]] && echo 1 || echo 0)"
assert "D2: syn_blocked did NOT move with SYN off ($(delta $b_sb $a_sb))" "$([[ $a_sb -eq $b_sb ]] && echo 1 || echo 0)"
sec_off; oc=$(req_outcome l3h2 "${KV_PID}"); assert "D2: served after reset (${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── D3 threshold boundary ──────────────────────────────────────────────────────────────────────
echo "### D3 securityrate: a burst under the threshold is not touched (synThreshold=200, 30 SYN burst)"
c=$(sec true 200 150 true 200 false 1000 100); sleep 1
snap b; syn_burst 30; sleep 11; snap a
assert "D3: no SYN blocked under the threshold (blocked delta $(delta $b_sb $a_sb), conn $(delta $b_cb $a_cb))" "$([[ $a_sb -eq $b_sb && $a_cb -eq $b_cb ]] && echo 1 || echo 0)"
assert "D3: SYNs counted as passed (>=30: $(delta $b_sp $a_sp))" "$([[ $(delta $b_sp $a_sp) -ge 30 ]] && echo 1 || echo 0)"
sec_off

# ── D4 whitelist bypass ────────────────────────────────────────────────────────────────────────
echo "### D4 securityrate: whitelisted source bypasses every limit (synThreshold=5 + whitelist l3h2)"
c=$(sec true 5 3 true 5 false 1000 100 "[\"${CLIENT_B_IP}/32\"]"); assert "D4: set with whitelist -> 200 ($c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"; sleep 1
wl=$(llb_curl "${API}/config/ipfilter/all" 2>/dev/null | grep -c "${CLIENT_B_IP}")
soft "D4: whitelist entry visible in the shared ipfilter map (${wl}) — ownership is shared (campaign K-P1e)" "$([[ $wl -ge 1 ]] && echo 1 || echo 0)"
snap b; syn_burst 40; sleep 11; snap a
assert "D4: whitelisted flooder never limited (syn $(delta $b_sb $a_sb), conn $(delta $b_cb $a_cb))" "$([[ $a_sb -eq $b_sb && $a_cb -eq $b_cb ]] && echo 1 || echo 0)"
kv_probe_a "D4 (whitelist on, l3h1 not whitelisted)"
# the allowed client is NOT whitelisted: a burst from it IS limited (the whitelist is per source)
snap b; for _ in $(seq 1 40); do $hexec l3h1 curl --max-time 0.3 -s -o /dev/null "http://${VIP}:${VPORT}/v1/models"; done; sleep 11; snap a
assert "D4: a non-whitelisted source is still limited (syn $(delta $b_sb $a_sb), conn $(delta $b_cb $a_cb))" "$([[ $a_sb -gt $b_sb || $a_cb -gt $b_cb ]] && echo 1 || echo 0)"
sec_off; sleep 2
wl=$(llb_curl "${API}/config/ipfilter/all" 2>/dev/null | grep -c "${CLIENT_B_IP}")
soft "D4: whitelist entry removed with the config (${wl} left)" "$([[ $wl -eq 0 ]] && echo 1 || echo 0)"

# ── D5 UDP flood protection coexistence ────────────────────────────────────────────────────────
echo "### D5 securityrate: UDP flood from l3h2 limited at XDP while TCP KV traffic is untouched"
c=$(sec false 100 50 false 50 true 100 100); assert "D5: udp set -> 200 ($c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"; sleep 1
snap b
$hexec l3h2 bash -c "for i in \$(seq 1 300); do echo -n x > /dev/udp/${VIP}/5300; done" 2>/dev/null
kv_probe_a "D5 (during the UDP flood)"
sleep 11; snap a
assert "D5: udp_blocked moved ($(delta $b_ub $a_ub))" "$([[ $a_ub -gt $b_ub ]] && echo 1 || echo 0)"
assert "D5: TCP SYN counters untouched by UDP limiting (syn $(delta $b_sb $a_sb), conn $(delta $b_cb $a_cb))" "$([[ $a_sb -eq $b_sb && $a_cb -eq $b_cb ]] && echo 1 || echo 0)"
sec_off

# ── D6 stacked ipfilter + securityrate ─────────────────────────────────────────────────────────
echo "### D6 stacked: ipfilter blacklist + securityrate — the blacklist drops first, secrate never sees the flooder"
rest_code POST /config/ipfilter "{\"filterType\":\"blacklist\",\"cidr\":\"${CLIENT_B_IP}/32\",\"action\":\"drop\",\"priority\":200}" >/dev/null
sec true 10 5 true 5 false 1000 100 >/dev/null; sleep 2
bl_b=$(metric_val "loxilb_ipfilter_blacklist_packets_total\{[^}]*cidr=\"${CLIENT_B_IP}/32\"")
snap b; syn_burst 40; kv_probe_a "D6 (both on)"; sleep 11; snap a
bl_a=$(metric_val "loxilb_ipfilter_blacklist_packets_total\{[^}]*cidr=\"${CLIENT_B_IP}/32\"")
assert "D6: ipfilter counted the flood ($(delta $bl_b $bl_a))" "$([[ $bl_a -gt $bl_b ]] && echo 1 || echo 0)"
assert "D6: securityrate saw none of it (syn $(delta $b_sb $a_sb), conn $(delta $b_cb $a_cb)) — XDP order ipfilter -> secrate" "$([[ $a_sb -eq $b_sb && $a_cb -eq $b_cb ]] && echo 1 || echo 0)"
rest_code DELETE "/config/ipfilter?filterType=blacklist&cidr=${CLIENT_B_IP}/32" >/dev/null; sec_off; sleep 2
oc=$(req_outcome l3h2 "${KV_PID}"); assert "D6: served after both removed (${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── D7 securityrate durability ─────────────────────────────────────────────────────────────────
echo "### D7 securityrate: GET reflects the config; persist -> restore keeps it and re-applies it to XDP"
# synThreshold=123 is the distinctive read-back value; ratePerSec=5 is the rate the sequential
# curl burst is proven to exceed (D2) — a sequential docker-exec burst runs at ~10/s, so a
# ratePerSec of 67 can never be exceeded by it and would make the enforcement check vacuous.
DP_APPLY_RE='Security rate config updated: version=[0-9]+ syn=true\(123/45\) conn=true\(5\)'
ap_b=$(loxilb_log_count "$DP_APPLY_RE")
sec true 123 45 true 5 false 1000 100 >/dev/null; sleep 1
g=$(llb_curl "${API}/config/securityrate/all" 2>/dev/null)
assert "D7: GET reflects synThreshold=123 ratePerSec=5" "$([[ "$g" == *'"synThreshold":123'* && "$g" == *'"ratePerSec":5'* ]] && echo 1 || echo 0)"
rest_code POST /config/persist '{}' >/dev/null
llb_curl "${API}/config/snapshot" >"${CFGDIR}/.snapshot-ddos.json" 2>/dev/null
c_r=$(llb_curl -o /dev/null -w '%{http_code}' -X POST "${API}/config/restore?mode=commit" -H 'Content-Type: application/json' --data-binary "@${CFGDIR}/.snapshot-ddos.json")
sleep 8
g=$(llb_curl "${API}/config/securityrate/all" 2>/dev/null)
assert "D7: after restore (${c_r}) securityrate still synThreshold=123 ratePerSec=5" "$([[ "$g" == *'"synThreshold":123'* && "$g" == *'"ratePerSec":5'* ]] && echo 1 || echo 0)"
ap_a=$(loxilb_log_count "$DP_APPLY_RE")
assert "D7: the restore re-applied the thresholds to the XDP datapath (DPEBPF apply lines ${ap_b}->${ap_a}, expected +2: set + restore)" \
    "$([[ $((ap_a - ap_b)) -ge 2 ]] && echo 1 || echo 0)"
snap b; t0=$(date +%s%N); syn_burst 100; t1=$(date +%s%N); sleep 11; snap a
burst_rate=$(( 100 * 1000000000 / (t1 - t0 + 1) ))
assert "D7: restored config enforces (burst of 100 at ~${burst_rate}/s vs ratePerSec=5: conn blocked $(delta $b_cb $a_cb))" "$([[ $a_cb -gt $b_cb ]] && echo 1 || echo 0)"
sec_off
# The restore brought the LB rule back REQUIRES_MIGRATION (restore contract for a profile-less
# KV-exact rule, see rule_recreate_fresh in lib.sh): assert the documented state, then a fresh
# create lifts the fence for the rows that follow.
st=$(kv_status_states)
assert "D7: restored profile-less rule reports REQUIRES_MIGRATION on kvexactstatus (got '${st}')" \
    "$([[ "$st" == "REQUIRES_MIGRATION REQUIRES_MIGRATION" ]] && echo 1 || echo 0)"
rc=$(rule_recreate_fresh); sleep "${KV_WARMUP_SEC}"
publish_prompt_to_ep "${KV_PID}" "${EP_A_IP}"
st=$(kv_status_states)
assert "D7: a fresh create (delete/create=${rc}) lifts the fence (status '${st}')" \
    "$([[ "$st" != *REQUIRES_MIGRATION* && "$st" != unreadable* ]] && echo 1 || echo 0)"
kv_probe_a "D7 (fresh rule after the restore)"

# ── D8 header-completion deadline (slowloris) ──────────────────────────────────────────────────
echo "### D8 proxy: header-completion deadline drops partial-header holders (timeoutTcpInspect=22000)"
# The deadline is sized so the holders outlive two stats ticks (LoxinetTiVal=10s): the Octavia
# quad the gauge assert reads is refreshed by the rules ticker, and a 2 s deadline dropped the
# holders before the first refresh could count them.
c=$(rule_replace '"timeoutTcpInspect":22000'); assert "D8: replace -> 200 ($c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"; sleep 3
hd_b=$(metric_val loxilb_proxy_header_deadline_drops_total)
# With the process valve armed (TOTAL_INFLIGHT=N) the listener's own shell holds one of the N
# units and the routing probe below needs one more accept (the valve counts every pooled shell,
# campaign L-I1), so this row opens N-2 holders there; the valve itself is D9's row.
n_hold=5
if [[ -n "${TOTAL_INFLIGHT:-}" && $((TOTAL_INFLIGHT - 2)) -lt 5 ]]; then n_hold=$((TOTAL_INFLIGHT - 2)); fi
for _ in $(seq 1 "${n_hold}"); do
    $hexec l3h2 bash -c "exec 3<>/dev/tcp/${VIP}/${VPORT}; printf 'POST /v1/completions HTTP/1.1\r\nHost: x\r\nX-Slow: ' >&3; sleep 60" >/dev/null 2>&1 &   # outlives the deadline: only the gateway may end these
done
act=$(wait_active "${n_hold}" 21)
assert "D8: the listener gauge counts the holders while they are open (activeConnections=${act}, expected ${n_hold}: no connectionLimit set$([[ -n "${TOTAL_INFLIGHT:-}" ]] && echo ", valve bound ${TOTAL_INFLIGHT} minus the listener's unit and the probe's"))" \
    "$([[ "$act" == "$n_hold" ]] && echo 1 || echo 0)"
kv_probe_a "D8 (${n_hold} slowloris holders open)"
# the drops land at deadline + one health pass; the counter then crosses the proxy stats
# snapshot and the collector, each on its own period — wait on the counter, not a clock
hd_a=$(wait_metric_ge loxilb_proxy_header_deadline_drops_total $((hd_b + n_hold)) 60)
assert "D8: header deadline drops moved by >=${n_hold} ($(delta $hd_b $hd_a))" "$([[ $(delta $hd_b $hd_a) -ge "$n_hold" ]] && echo 1 || echo 0)"
act=$(wait_active 0)
assert "D8: holders gone from the listener gauge (activeConnections=${act})" "$([[ "$act" == 0 ]] && echo 1 || echo 0)"
end_holders l3h2
rule_replace "" >/dev/null; sleep 2

# ── D9 process accept valve (only when armed) ──────────────────────────────────────────────────
echo "### D9 proxy: process accept valve LLB_PD_MAX_TOTAL_INFLIGHT (armed: ${TOTAL_INFLIGHT:-no})"
if [[ -n "${TOTAL_INFLIGHT:-}" ]]; then
    ab_b=$(metric_val loxilb_proxy_accept_blocked_total)
    for _ in $(seq 1 "${TOTAL_INFLIGHT}"); do
        $hexec l3h2 bash -c "exec 3<>/dev/tcp/${VIP}/${VPORT}; printf 'GET /v1/models HTTP/1.1\r\nHost: x\r\n' >&3; sleep 20" >/dev/null 2>&1 &
    done
    sleep 2
    oc=$(req_outcome l3h1 "${KV_PID}")
    assert "D9: at the valve the next connection is held in the backlog, not served (${oc})" "$([[ "$oc" != served ]] && echo 1 || echo 0)"
    sleep 11
    ab_a=$(metric_val loxilb_proxy_accept_blocked_total)
    assert "D9: accept_blocked moved ($(delta $ab_b $ab_a))" "$([[ $ab_a -gt $ab_b ]] && echo 1 || echo 0)"
    end_holders l3h2; sleep 3
    kv_probe_a "D9 (valve released)"
else
    soft "D9: skipped — run config.sh with TOTAL_INFLIGHT=4 for this arm" 1
fi

# ── D10 inactiveTimeOut ────────────────────────────────────────────────────────────────────────
echo "### D10 proxy: idle connection reaped at inactiveTimeOut=22"
# Like D8, the timeout is sized so the idle connection outlives two stats ticks (LoxinetTiVal=10s):
# activeConnections of a fullproxy rule is refreshed by the rules ticker (DpCtStatsRollup), and
# a 3 s timeout reaped the connection (dp log [IDLE_TIMEOUT] idle=4s) before a tick could count it.
c=$(rule_replace '"inactiveTimeOut":22'); sleep 3
assert "D10: idle policy update accepted ($c)" "$([[ "$c" == 200 ]] && echo 1 || echo 0)"
# one complete ROUTED request first (the idle clock starts at the last activity; an unrouted
# path such as GET /v1/models is answered 503 and closed, so it never idles), then silence
# the holder outlives the whole wait window (120 s > 25 + 40 + 20): only the gateway's reap can end
# it, and the reap is asserted on the gateway's own [IDLE_TIMEOUT] line, not on the gauge alone
it_b=$(dp_log_count "IDLE_TIMEOUT")
H10=$(hold_request_conn l3h2 120)
act1=$(wait_active 1 25)
# Do not stop a live client when an asynchronous gauge first reports zero:
# that used to kill the holder before 22s and manufacture a peer reset.
it_a=$(wait_dp_log_count_ge "IDLE_TIMEOUT" $((it_b + 1)) 40)
act2=$(wait_active 0 20)
assert "D10: keep-alive connection counted then reaped after 22s idle (${act1} -> ${act2}; gateway IDLE_TIMEOUT lines +$((it_a - it_b)))" \
    "$([[ "$act1" -ge 1 && "$act2" == 0 && $((it_a - it_b)) -ge 1 ]] && echo 1 || echo 0)"
end_holders l3h2 "$H10"
rule_replace "" >/dev/null; sleep 2

# ── D11 oversize body ──────────────────────────────────────────────────────────────────────────
echo "### D11 proxy: a 2 MB request body is answered (stream fallback or 413), never held or reset"
python3 -c "import json; print(json.dumps({'model':'${KV_MODEL}','prompt':'x'*2000000,'max_tokens':8}))" >"${CFGDIR}/.big.json"
hc=$($hexec l3h2 curl -s --max-time 20 -o /dev/null -w '%{http_code}' -X POST "http://${VIP}:${VPORT}/v1/completions" -H 'Content-Type: application/json' --data-binary "@${CFGDIR}/.big.json" 2>/dev/null); rc=$?
assert "D11: oversize body answered (rc=${rc} http=${hc}; 200 or 413)" "$([[ $rc == 0 && "$hc" =~ ^(200|413)$ ]] && echo 1 || echo 0)"
kv_probe_a "D11 (after the oversize request)"

# ── D12 operator firewall rule to the VIP ──────────────────────────────────────────────────────
echo "### D12 TC firewall: an operator drop rule for 11.11.11.0/24 -> VIP:8080 bites; the fence band is above it"
fwrule="{\"ruleArguments\":{\"sourceIP\":\"11.11.11.0/24\",\"destinationIP\":\"${VIP}/32\",\"minDestinationPort\":${VPORT},\"maxDestinationPort\":${VPORT},\"protocol\":6,\"preference\":100},\"opts\":{\"drop\":true}}"
c=$(rest_code POST /config/firewall "$fwrule"); assert "D12: fw rule add -> 200 ($c)" "$([[ $c == 200 ]] && echo 1 || echo 0)"; sleep 2
fwr_b=$(metric_val loxilb_fw_rule_drop_packets_total)
oc=$(req_outcome l3h2 "${KV_PID}"); assert "D12: other client dropped at TC (${oc})" "$([[ "$oc" == timeout ]] && echo 1 || echo 0)"
kv_probe_a "D12 (operator rule on)"
sleep 11; fwr_a=$(metric_val loxilb_fw_rule_drop_packets_total)
assert "D12: fw_rule_drop moved ($(delta $fwr_b $fwr_a))" "$([[ $fwr_a -gt $fwr_b ]] && echo 1 || echo 0)"
# with the fence on too, the fence's allow (pref 65000) for l3h1 and the operator drop
# (pref 100) for l3h2 compose: l3h1 in, l3h2 out, whichever rule is hit first
rule_replace "" "\"allowedSources\":[{\"prefix\":\"${CLIENT_A_IP}/32\"}]" >/dev/null; sleep 3
kv_probe_a "D12 (operator rule + fence)"
oc=$(req_outcome l3h2 "${KV_PID}"); assert "D12: other client still out with both (${oc})" "$([[ "$oc" == timeout ]] && echo 1 || echo 0)"
rule_replace "" >/dev/null
# DELETE /config/firewall keys the rule by query parameters, not by a body
c=$(llb_curl -o /dev/null -w '%{http_code}' -X DELETE "${API}/config/firewall?sourceIP=11.11.11.0/24&destinationIP=${VIP}/32&minDestinationPort=${VPORT}&maxDestinationPort=${VPORT}&protocol=6&preference=100"); sleep 2
oc=$(req_outcome l3h2 "${KV_PID}"); assert "D12: served after the rule is deleted (del=${c}, ${oc})" "$([[ "$oc" == served ]] && echo 1 || echo 0)"

# ── D13 XDP mode under a SYN flood: CPU for the record ─────────────────────────────────────────
echo "### D13 XDP mode under a SYN flood: loxilb CPU sampled (generic vs native arms, XDP_NATIVE=${XDP_NATIVE:-unset})"
sec true 10 5 true 5 false 1000 100 >/dev/null; sleep 1
mode=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep -Eo "attached in (native|generic)[^,]*mode on [a-z0-9]+" | sort | uniq -c | tr '\n' ';')
( syn_burst 400 ) & FL=$!
sleep 2
cpu=$(docker stats --no-stream --format '{{.CPUPerc}}' llb1 2>/dev/null)
wait $FL
echo "  D13 record: xdp modes [${mode}] loxilb CPU during a 400-SYN burst from one source: ${cpu}"
soft "D13: CPU sample recorded (${cpu})" "$([[ -n "$cpu" ]] && echo 1 || echo 0)"
sec_off
kv_probe_a "D13 (after the flood)"

for _pp in $(pgrep -f "${PUB_TAG}" 2>/dev/null); do kill "${_pp}" >/dev/null 2>&1 || true; done
end_holders l3h1; end_holders l3h2
sec_off
if [[ $code == 0 ]]; then echo "SCENARIO-security-kv-coexist-ddos [OK]"; else echo "SCENARIO-security-kv-coexist-ddos [FAILED]"; fi
exit $code
