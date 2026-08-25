#!/bin/bash
# qos-fullproxy — Tier-1 (L7) byte-shaper validation on fullproxy LB rules.
#
# The shaper paces PLAINTEXT payload bytes inside the sockproxy relay
# (client->backend direction). It is driven by the same policer-attachment
# API as the Tier-0 rule policer; on a fullproxy rule the policer configures
# the L7 shaper instead of the (non-existent) nat_map policer. Rates below
# are policer-API Mbps; the shaper meters bytes (CIR Mbps / 8 = MB/s).
#
# Legs:
#   F1 baseline      : un-shaped upload through the fullproxy VIP is fast
#   F2 attach+cap    : 16 Mbps policer on the rule -> upload collapses to
#                      ~2 MB/s for the WHOLE transfer (the token check must
#                      sit inside the relay burst loop; a check outside it
#                      passes small probes and lets big bursts through)
#   F3 engage-proof  : llb1 logs carry the shaper-on line for this VIP
#   F4 download-free : response direction is NOT shaped (scope pin — flips
#                      when the response-direction phase lands)
#   F5 isolation     : second VIP with a 64 Mbps policer caps at ~8 MB/s
#                      while VIP1 still caps at ~2 MB/s — no cross-talk
#   F6 detach heal   : deleting the policy restores full-rate upload
#   F7 policy-first  : policer associated to a VIP whose rule does not exist
#                      yet; rule created after -> shaping converges without
#                      any further control-plane action
#   F8 re-create heal: delete + re-create the LB rule with the association
#                      surviving -> the fresh rule re-acquires the shaper
#                      (config is dropped with the proxy entry on delete;
#                      the policer ticker must re-drive it)
#   F9 park-vs-bp    : concurrent shaped upload and unshaped bulk download
#                      on the same VIP -> both complete, neither wedges
#                      (shaper park and cache backpressure must not clear
#                      each other's read-pause)
source ../common.sh
echo SCENARIO-qos-fullproxy

FPVIP1=20.20.20.3
FPVIP2=20.20.20.4
FPVIP3=20.20.20.5
API="http://127.0.0.1:11111/netlox/v1"

# 16 Mbps CIR = 2 MB/s payload; CBS 250000 B (~125ms of CIR) keeps the
# initial burst small against a multi-second transfer
POL1_JSON='{"policyIdent":"qsh1","policyInfo":{"type":0,"committedInfoRate":16,"peakInfoRate":16,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.3:2020:tcp"}}'
# 64 Mbps CIR = 8 MB/s payload for the isolation VIP
POL2_JSON='{"policyIdent":"qsh2","policyInfo":{"type":0,"committedInfoRate":64,"peakInfoRate":64,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.4:2020:tcp"}}'
# policy-before-rule VIP
POL3_JSON='{"policyIdent":"qsh3","policyInfo":{"type":0,"committedInfoRate":16,"peakInfoRate":16,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.5:2020:tcp"}}'

code=0

api_post_policy() {
    $dexec llb1 curl -s -X POST -H 'Content-Type: application/json' -d "$1" $API/config/policy
}

api_del_policy() {
    $dexec llb1 curl -s -X DELETE $API/config/policy/ident/$1
}

# HTTP backend: python3 sink accepting arbitrary-size POST bodies and serving
# a bulk GET (the download-direction probe). Runs inside l3ep1.
sudo docker exec -d l3ep1 sh -c 'cd /tmp && dd if=/dev/zero of=big.bin bs=1M count=64 2>/dev/null && cat > qsink.py << "PYEOF"
import http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        left = n
        while left > 0:
            chunk = self.rfile.read(min(left, 1 << 20))
            if not chunk:
                break
            left -= len(chunk)
        body = b"sunk %d\n" % (n - left)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        with open("/tmp/big.bin", "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *a):
        pass

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

S(("0.0.0.0", 8080), H).serve_forever()
PYEOF
python3 qsink.py'

# upload blob on the client
$dexec l3h1 sh -c 'dd if=/dev/urandom of=/tmp/blob16.bin bs=1M count=16 2>/dev/null'
sleep 3

# wait for the sink through the VIP
waitCount=0
while : ; do
    res=$($dexec l3h1 curl --max-time 5 -s -X POST --data-binary 'ping' http://$FPVIP1:2020/)
    if [[ "$res" == sunk* ]]; then break; fi
    waitCount=$(( waitCount + 1 ))
    if [[ $waitCount -ge 15 ]]; then
        echo "backend sink never became reachable through $FPVIP1"
        echo SCENARIO-qos-fullproxy [FAILED]
        exit 1
    fi
    sleep 1
done

# Measured upload speed (bytes/sec) of a 16MB POST through a VIP
up_speed() {
    local vip=$1
    $dexec l3h1 curl --max-time 90 -s -o /dev/null -w '%{speed_upload}' \
        -X POST -H 'Content-Type: application/octet-stream' \
        --data-binary @/tmp/blob16.bin http://$vip:2020/ | cut -d. -f1
}

# Measured download speed (bytes/sec) of the 64MB GET through a VIP
down_speed() {
    local vip=$1
    $dexec l3h1 curl --max-time 90 -s -o /dev/null -w '%{speed_download}' \
        http://$vip:2020/big.bin | cut -d. -f1
}

MB=1048576

# --- F1: baseline upload must be fast (>12 MB/s) ---
s0=$(up_speed $FPVIP1)
echo "F1 baseline upload: $s0 B/s"
if [[ -z "$s0" || "$s0" -lt $((12 * MB)) ]]; then
    echo "F1 baseline upload too slow ($s0 B/s) - topology unusable" ; code=1
fi

# --- F2: attach 16 Mbps shaper -> upload caps at ~2 MB/s ---
res=$(api_post_policy "$POL1_JSON")
echo "F2 attach: $res"
if [[ "$res" != *"Success"* ]]; then
    echo "F2 policer attach on fullproxy rule FAILED: $res" ; code=1
fi
sleep 2
s1=$(up_speed $FPVIP1)
echo "F2 shaped upload: $s1 B/s (CIR 2 MB/s)"
if [[ -z "$s1" || "$s1" -gt $((7 * MB / 2)) || "$s1" -lt $((MB / 2)) ]]; then
    echo "F2 shaper NOT pacing (got $s1 B/s, want ~2 MB/s band [0.5,3.5])" ; code=1
fi

# --- F3: the shaper-on log line must exist for this VIP ---
lg=$(sudo docker exec llb1 sh -c 'cat /var/log/loxilbdp*.log 2>/dev/null' | grep -c "qos: shaper on 20.20.20.3")
echo "F3 shaper-on log lines: $lg"
if [[ "$lg" -lt 1 ]]; then
    echo "F3 no shaper-on log for $FPVIP1 (config never reached sockproxy)" ; code=1
fi

# --- F4: download direction is NOT shaped (scope pin until response phase) ---
s2=$(down_speed $FPVIP1)
echo "F4 download with upload-shaper attached: $s2 B/s"
if [[ -z "$s2" || "$s2" -lt $((12 * MB)) ]]; then
    echo "F4 download unexpectedly slow ($s2 B/s) - response direction must be un-shaped in this phase" ; code=1
fi

# --- F5: per-rule isolation - VIP2 at 64 Mbps, VIP1 still at 16 ---
res=$(api_post_policy "$POL2_JSON")
if [[ "$res" != *"Success"* ]]; then
    echo "F5 second policer attach failed: $res" ; code=1
fi
sleep 2
s3=$(up_speed $FPVIP2)
s4=$(up_speed $FPVIP1)
echo "F5 shaped uploads: vip2=$s3 B/s (CIR 8 MB/s) vip1=$s4 B/s (CIR 2 MB/s)"
if [[ -z "$s3" || "$s3" -gt $((12 * MB)) || "$s3" -lt $((4 * MB)) ]]; then
    echo "F5 vip2 outside its own band (got $s3 B/s, want ~8 MB/s)" ; code=1
fi
if [[ -z "$s4" || "$s4" -gt $((7 * MB / 2)) ]]; then
    echo "F5 vip1 leaked past its cap under vip2 load (got $s4 B/s)" ; code=1
fi

# --- F6: detach restores full rate ---
res=$(api_del_policy qsh1)
echo "F6 detach: $res"
sleep 2
s5=$(up_speed $FPVIP1)
echo "F6 post-detach upload: $s5 B/s"
if [[ -z "$s5" || "$s5" -lt $((12 * MB)) ]]; then
    echo "F6 upload NOT restored after policy delete ($s5 B/s)" ; code=1
fi

# --- F7: policy associated before its rule exists -> converges on rule add ---
res=$(api_post_policy "$POL3_JSON")
echo "F7 policy-first attach: $res"
if [[ "$res" != *"Success"* ]]; then
    echo "F7 policy add for not-yet-created rule refused: $res" ; code=1
fi
$dexec llb1 loxicmd create lb $FPVIP3 --tcp=2020:8080 --endpoints=31.31.31.1:1 --mode=fullproxy --host=$FPVIP3
# Convergence backstop is the policer ticker: 10s period, and the not-in-sync
# detection + re-drive can span TWO ticks — poll up to ~35s.
s6=""
for i in $(seq 1 7); do
    sleep 5
    s6=$(up_speed $FPVIP3)
    [[ -n "$s6" && "$s6" -le $((7 * MB / 2)) && "$s6" -ge $((MB / 2)) ]] && break
done
echo "F7 policy-first shaped upload: $s6 B/s (CIR 2 MB/s, polled ≤35s)"
if [[ -z "$s6" || "$s6" -gt $((7 * MB / 2)) || "$s6" -lt $((MB / 2)) ]]; then
    echo "F7 policy-before-rule did NOT converge (got $s6 B/s, want ~2 MB/s)" ; code=1
fi

# --- F8: rule delete + re-create with surviving association re-acquires ---
# A rule created with --host is keyed BY the host: the host-less delete route
# builds a different rule key and 404s while the rule stays alive. Delete via
# loxicmd with the host so the keys match.
del8=$($dexec llb1 loxicmd delete lb $FPVIP3 --tcp=2020 --host=$FPVIP3 2>&1)
echo "F8 rule delete: $del8"
# confirm the rule is gone before re-creating (a 409 on create means the
# delete never landed and the leg would silently re-measure F7's shaper)
gone=0
for i in $(seq 1 10); do
    sleep 1
    if ! $dexec llb1 loxicmd get lb -o wide 2>/dev/null | grep -q "$FPVIP3"; then gone=1; break; fi
done
if [[ "$gone" != 1 ]]; then
    echo "F8 rule delete never landed (rule still listed)" ; code=1
fi
# Rule delete rips the VIP off lo (DeleteRuleVIP -> DelAddrNoHook) even though
# rule create never added it in this standalone topology — without re-adding,
# SYNs to the VIP are dropped below TCP and the leg wedges on a dead address.
$dexec llb1 ip addr add $FPVIP3/32 dev lo 2>/dev/null
res8=$($dexec llb1 loxicmd create lb $FPVIP3 --tcp=2020:8080 --endpoints=31.31.31.1:1 --mode=fullproxy --host=$FPVIP3)
echo "F8 rule re-create: $res8"
s7=""
for i in $(seq 1 7); do
    sleep 5
    s7=$(up_speed $FPVIP3)
    [[ -n "$s7" && "$s7" -le $((7 * MB / 2)) && "$s7" -ge $((MB / 2)) ]] && break
done
echo "F8 re-created-rule shaped upload: $s7 B/s (CIR 2 MB/s, polled ≤35s)"
if [[ -z "$s7" || "$s7" -gt $((7 * MB / 2)) || "$s7" -lt $((MB / 2)) ]]; then
    echo "F8 re-created rule lost its shaper (got $s7 B/s)" ; code=1
fi

# --- F9: shaped upload + bulk download concurrently on one VIP - no wedge ---
# (vip2 still carries its 64 Mbps shaper; download must stay un-shaped and
# both transfers must complete: a shaper park mistaken for backpressure, or
# vice versa, wedges one of the two)
$dexec l3h1 sh -c "curl --max-time 90 -s -o /dev/null -w '%{speed_upload}' \
    -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary @/tmp/blob16.bin http://$FPVIP2:2020/ | cut -d. -f1 > /tmp/f9up.txt" &
F9PID=$!
s8=$(down_speed $FPVIP2)
wait $F9PID
s9=$($dexec l3h1 cat /tmp/f9up.txt)
echo "F9 concurrent: download=$s8 B/s upload=$s9 B/s"
if [[ -z "$s8" || "$s8" -lt $((12 * MB)) ]]; then
    echo "F9 download wedged/slow during shaped upload ($s8 B/s)" ; code=1
fi
if [[ -z "$s9" || "$s9" -lt $((4 * MB)) || "$s9" -gt $((12 * MB)) ]]; then
    echo "F9 shaped upload wedged or unshaped during download ($s9 B/s)" ; code=1
fi

$dexec l3ep1 pkill -9 python3 2>/dev/null
if [[ $code == 0 ]]; then
    echo SCENARIO-qos-fullproxy [OK]
else
    echo SCENARIO-qos-fullproxy [FAILED]
fi
exit $code
