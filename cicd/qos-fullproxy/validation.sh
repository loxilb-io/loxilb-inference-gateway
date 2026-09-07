#!/bin/bash
# qos-fullproxy — Tier-1 (L7) byte-shaper validation on fullproxy LB rules.
#
# The shaper paces PLAINTEXT payload bytes inside the sockproxy relay, in
# BOTH directions: client->backend (upload) and backend->client (download),
# each against its own bucket at the full CIR. It is driven by the same
# policer-attachment API as the Tier-0 rule policer; on a fullproxy rule the
# policer configures the L7 shaper instead of the (non-existent) nat_map
# policer. Rates below are policer-API Mbps; the shaper meters bytes
# (CIR Mbps / 8 = MB/s).
#
# Legs:
#   F1 baseline      : un-shaped upload AND download through the fullproxy
#                      VIP are fast
#   F2 attach+cap    : 16 Mbps policer on the rule -> upload collapses to
#                      ~2 MB/s for the WHOLE transfer (the token check must
#                      sit inside the relay burst loop; a check outside it
#                      passes small probes and lets big bursts through)
#   F3 engage-proof  : llb1 logs carry the shaper-on line for this VIP
#   F4 download-cap  : response direction is shaped to the same ~2 MB/s
#                      (the odir==1 gate against the qos_down bucket)
#   F5 isolation     : second VIP with a 64 Mbps policer caps at ~8 MB/s
#                      while VIP1 still caps at ~2 MB/s — no cross-talk
#   F6 detach heal   : deleting the policy restores full rate BOTH ways
#   F7 policy-first  : policer associated to a VIP whose rule does not exist
#                      yet; rule created after -> shaping converges without
#                      any further control-plane action
#   F8 re-create heal: delete + re-create the LB rule with the association
#                      surviving -> the pre-configured VIP survives the
#                      delete and the fresh rule re-acquires the shaper
#                      (config is dropped with the proxy entry on delete;
#                      the policer ticker must re-drive it)
#   F9 dir-independent: full-length concurrent shaped upload + shaped
#                      download on one VIP -> EACH holds its own ~CIR band
#                      and the sum clears what a single shared bucket could
#                      pass — proves per-direction buckets, and that shaper
#                      parks and cache backpressure never clear each other's
#                      read-pause (neither transfer wedges)
#   F10 park-safe cap : SSE rule with max-stream-duration=10s.
#                      (a) a 40MB SSE stream shaped to 2 MB/s (~20s wall
#                      clock, parked most of that) survives to the last
#                      byte — shaper-paused time is excluded from the cap;
#                      (b) with the shaper detached, a server-paced slow
#                      SSE stream (~25s, never parked) is still cut at the
#                      cap — the reaper stays armed for genuine slowness.
#                      (The per-rule inactive/idle reapers key on activity
#                      anchors a parked conn also freezes; they are guarded
#                      by the same health-pass refresh this leg pins.)
#   F11 observability : the per-service shaper series on /metrics. Re-attach
#                      the 2 MB/s policer, push a shaped upload, and pin the
#                      exported numbers against the transfer that produced
#                      them: CIR in BYTES (not the policer's bits), passed
#                      bytes matching the body, non-zero parks AND park
#                      seconds (the counter that did not exist before), and
#                      delayed <= passed. Then detach: the series must
#                      DISAPPEAR — a collector that keeps emitting an
#                      un-shaped service is reporting a shaper that is not
#                      running.
source ../common.sh
echo SCENARIO-qos-fullproxy

FPVIP1=20.20.20.3
FPVIP2=20.20.20.4
FPVIP3=20.20.20.5
FPVIP4=20.20.20.6
API="http://127.0.0.1:11111/netlox/v1"

# 16 Mbps CIR = 2 MB/s payload; CBS 250000 B (~125ms of CIR) keeps the
# initial burst small against a multi-second transfer
POL1_JSON='{"policyIdent":"qsh1","policyInfo":{"type":0,"committedInfoRate":16,"peakInfoRate":16,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.3:2020:tcp"}}'
# 64 Mbps CIR = 8 MB/s payload for the isolation VIP
POL2_JSON='{"policyIdent":"qsh2","policyInfo":{"type":0,"committedInfoRate":64,"peakInfoRate":64,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.4:2020:tcp"}}'
# policy-before-rule VIP
POL3_JSON='{"policyIdent":"qsh3","policyInfo":{"type":0,"committedInfoRate":16,"peakInfoRate":16,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.5:2020:tcp"}}'
# SSE-cap VIP (F10): same 2 MB/s shaping profile
POL4_JSON='{"policyIdent":"qsh4","policyInfo":{"type":0,"committedInfoRate":16,"peakInfoRate":16,"committedBlkSize":250000},"targetObject":{"attachment":0,"polObjName":"20.20.20.6:2020:tcp"}}'

code=0

api_post_policy() {
    $dexec llb1 curl -s -X POST -H 'Content-Type: application/json' -d "$1" $API/config/policy
}

api_del_policy() {
    $dexec llb1 curl -s -X DELETE $API/config/policy/ident/$1
}

# HTTP backend: perl sink accepting arbitrary-size POST bodies and serving
# a bulk GET (the download-direction probe). Runs inside l3ep1. Perl, not
# python: the canonical nettest host image ships perl but NO python, and the
# hosts have no internet once config.sh points their default route at llb1 —
# a runtime install is impossible, so the sink must run on what the image
# carries (first hit on a freshly spawned testbed; earlier green runs leaned
# on a long-lived l3ep1 container that had python provisioned by hand).
if ! $dexec l3ep1 sh -c 'command -v perl' > /dev/null 2>&1; then
    echo "l3ep1 host image lacks perl - qsink cannot run"
    echo SCENARIO-qos-fullproxy [FAILED]
    exit 1
fi
sudo docker exec -d l3ep1 sh -c 'cd /tmp && dd if=/dev/zero of=big.bin bs=1M count=64 2>/dev/null && cat > qsink.pl << "PLEOF"
use strict; use warnings;
use IO::Socket::INET;
$SIG{CHLD} = "IGNORE";
$SIG{PIPE} = "IGNORE";

# 40MB of 1024-byte SSE frames for the shaped stream-duration leg: at the
# 2 MB/s shaper CIR this is ~20s of wall clock against a 10s rule cap.
my $frame = "data: " . ("x" x 1016) . "\n\n";
my $sse   = $frame x 40960;

my $srv = IO::Socket::INET->new(LocalHost => "0.0.0.0", LocalPort => 8080,
                                Listen => 64, ReuseAddr => 1) or die $!;
while (my $c = $srv->accept) {
    if (fork) { close $c; next; }   # parent keeps accepting
    close $srv;
    $c->autoflush(1);
    # HTTP/1.1 keep-alive per request, like the python handler this replaces:
    # the connection stays open after a Content-Length response until the
    # CLIENT closes. Closing server-side right after the /sse write would put
    # a backend FIN behind ~a shaper-CIR-second of parked bytes and change
    # what F10a measures (observed: the tail went missing, no cap marker).
    while (1) {
        my $head = "";
        while ($head !~ /\r?\n\r?\n/) {
            my $n = sysread($c, my $buf, 65536);
            last unless $n;
            $head .= $buf;
        }
        last unless $head =~ /^(\S+)\s+(\S+)/;
        my ($meth, $path) = ($1, $2);
        # curl sends Expect: 100-continue on big POST bodies and stalls ~1s
        # without the interim response - that stall would poison speed_upload
        print $c "HTTP/1.1 100 Continue\r\n\r\n" if $head =~ /Expect:\s*100-continue/i;
        if ($meth eq "POST") {
            my ($cl) = $head =~ /Content-Length:\s*(\d+)/i; $cl ||= 0;
            my $got = 0;
            $got = length($1) if $head =~ /\r?\n\r?\n(.*)$/s;
            while ($got < $cl) {
                my $n = sysread($c, my $buf, 1 << 20);
                last unless $n;
                $got += $n;
            }
            my $body = "sunk $got\n";
            last unless print $c "HTTP/1.1 200 OK\r\nContent-Length: " .
                length($body) . "\r\n\r\n" . $body;
        } elsif ($path eq "/sse") {
            # source-fast SSE stream; the shaper is what paces it
            last unless print $c "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" .
                "Content-Length: " . length($sse) . "\r\n\r\n";
            last unless print $c $sse;
        } elsif ($path eq "/sse-slow") {
            # source-paced trickle: one frame per second, no shaper parks -
            # the stream-duration cap must cut this one
            print $c "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" .
                     "Connection: close\r\n\r\n";
            for (1 .. 25) {
                last unless print $c $frame;
                sleep 1;
            }
            last;
        } else {
            my $data = "";
            if (open my $f, "<", "/tmp/big.bin") { local $/; $data = <$f>; close $f; }
            last unless print $c "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n" .
                "Content-Length: " . length($data) . "\r\n\r\n";
            last unless print $c $data;
        }
    }
    close $c;
    exit 0;
}
PLEOF
perl qsink.pl'

# upload blobs on the client (64M for the full-length concurrent F9 leg: at
# 8 MB/s both transfers run ~8s, so the up/down overlap spans the whole
# measurement and the per-direction assert is meaningful)
$dexec l3h1 sh -c 'dd if=/dev/urandom of=/tmp/blob16.bin bs=1M count=16 2>/dev/null &&
                   dd if=/dev/urandom of=/tmp/blob64.bin bs=1M count=64 2>/dev/null'
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

# --- F1: baseline upload AND download must be fast (>12 MB/s) ---
s0=$(up_speed $FPVIP1)
d0=$(down_speed $FPVIP1)
echo "F1 baseline: upload=$s0 B/s download=$d0 B/s"
if [[ -z "$s0" || "$s0" -lt $((12 * MB)) ]]; then
    echo "F1 baseline upload too slow ($s0 B/s) - topology unusable" ; code=1
fi
if [[ -z "$d0" || "$d0" -lt $((12 * MB)) ]]; then
    echo "F1 baseline download too slow ($d0 B/s) - topology unusable" ; code=1
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

# --- F4: download direction is shaped to the same CIR (qos_down bucket) ---
# 64MB at ~2 MB/s is ~32s of the 90s curl budget; the WHOLE transfer must
# hold the band, same rationale as F2.
s2=$(down_speed $FPVIP1)
echo "F4 shaped download: $s2 B/s (CIR 2 MB/s)"
if [[ -z "$s2" || "$s2" -gt $((7 * MB / 2)) || "$s2" -lt $((MB / 2)) ]]; then
    echo "F4 response direction NOT pacing (got $s2 B/s, want ~2 MB/s band [0.5,3.5])" ; code=1
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

# --- F6: detach restores full rate in BOTH directions ---
res=$(api_del_policy qsh1)
echo "F6 detach: $res"
sleep 2
s5=$(up_speed $FPVIP1)
d5=$(down_speed $FPVIP1)
echo "F6 post-detach: upload=$s5 B/s download=$d5 B/s"
if [[ -z "$s5" || "$s5" -lt $((12 * MB)) ]]; then
    echo "F6 upload NOT restored after policy delete ($s5 B/s)" ; code=1
fi
if [[ -z "$d5" || "$d5" -lt $((12 * MB)) ]]; then
    # Detached means the shaper is out of the data path entirely (the burst
    # loop resolves a NULL bucket), so a slow read here is the plain relay or
    # the backend. Measure the endpoint directly to say which — one observed
    # red (2026-08-26) sat exactly on the 90s curl budget while every shaped
    # leg in the same run was exact, and was not reproducible.
    dep5=$($dexec l3h1 curl --max-time 120 -s -o /dev/null -w '%{speed_download}' \
        http://31.31.31.1:8080/big.bin | cut -d. -f1)
    echo "F6 download NOT restored after policy delete ($d5 B/s; direct-to-endpoint $dep5 B/s)" ; code=1
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
# The VIP must still be on lo. config.sh pre-configures it (fullproxy VIPs
# have to be locally bindable) and rule create never added it in this
# standalone topology, so rule delete has no business taking it down — a
# ripped address leaves the re-created rule deaf below TCP, SYNs dropped
# while the listener looks healthy on a vanished address.
if ! $dexec llb1 ip addr show dev lo 2>/dev/null | grep -q "$FPVIP3/32"; then
    echo "F8 rule delete took the pre-configured VIP $FPVIP3 off lo" ; code=1
    # re-add so the shaper half of the leg still reports its own verdict
    $dexec llb1 ip addr add $FPVIP3/32 dev lo 2>/dev/null
else
    echo "F8 pre-configured VIP $FPVIP3 survived the rule delete"
fi
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

# --- F9: full-length concurrent shaped upload + shaped download on one VIP ---
# vip2 still carries its 64 Mbps (8 MB/s) shaper. Both 64MB transfers run
# ~8s, overlapping for essentially the whole measurement, so:
#   - EACH direction must hold its own ~8 MB/s band (a park/backpressure
#     cross-clear wedges one of them),
#   - the SUM must clear 11 MB/s — a single shared bucket would cap the
#     combined rate near one CIR (~8 MB/s), so the sum is the discriminator
#     that the directions meter independently.
$dexec l3h1 sh -c "curl --max-time 90 -s -o /dev/null -w '%{speed_upload}' \
    -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary @/tmp/blob64.bin http://$FPVIP2:2020/ | cut -d. -f1 > /tmp/f9up.txt" &
F9PID=$!
s8=$(down_speed $FPVIP2)
wait $F9PID
s9=$($dexec l3h1 cat /tmp/f9up.txt)
echo "F9 concurrent shaped: download=$s8 B/s upload=$s9 B/s (CIR 8 MB/s each)"
if [[ -z "$s8" || "$s8" -lt $((4 * MB)) || "$s8" -gt $((12 * MB)) ]]; then
    echo "F9 shaped download wedged or unshaped during upload ($s8 B/s)" ; code=1
fi
if [[ -z "$s9" || "$s9" -lt $((4 * MB)) || "$s9" -gt $((12 * MB)) ]]; then
    echo "F9 shaped upload wedged or unshaped during download ($s9 B/s)" ; code=1
fi
if [[ -n "$s8" && -n "$s9" && $((s8 + s9)) -lt $((11 * MB)) ]]; then
    echo "F9 directions NOT independent (sum $((s8 + s9)) B/s ≈ one shared CIR)" ; code=1
fi

# --- F10: stream-duration cap must not count shaper-paused time ---
# F10a: 2 MB/s shaper on the SSE VIP (rule cap max-stream-duration=10s).
# The 40MB SSE stream needs ~20s of wall clock, parked for most of every
# second of it — it must arrive COMPLETE, because the health pass excludes
# paused time from the cap. The speed staying in the shaped band is the
# proof the parks actually happened (i.e. the leg discriminates).
res=$(api_post_policy "$POL4_JSON")
echo "F10a attach: $res"
if [[ "$res" != *"Success"* ]]; then
    echo "F10a policer attach on SSE rule FAILED: $res" ; code=1
fi
sleep 2
out10=$($dexec l3h1 curl --max-time 90 -s -o /tmp/f10a.out \
    -w '%{size_download} %{time_total} %{speed_download}' http://$FPVIP4:2020/sse)
sz10=$(echo $out10 | awk '{print int($1)}')
tt10=$(echo $out10 | awk '{print int($2)}')
sp10=$(echo $out10 | awk '{print int($3)}')
mk10=$($dexec l3h1 sh -c 'grep -c max_stream_duration_exceeded /tmp/f10a.out 2>/dev/null; true')
echo "F10a shaped SSE: size=$sz10 time=${tt10}s speed=$sp10 B/s marker=$mk10 (want 41943040 bytes over >=15s, no marker)"
if [[ "$sz10" -ne 41943040 || "$mk10" != "0" ]]; then
    echo "F10a shaped SSE stream was CUT by the duration cap while parked (size=$sz10 marker=$mk10)" ; code=1
fi
if [[ "$tt10" -lt 15 ]]; then
    echo "F10a transfer too fast (${tt10}s) — cap was never at stake, leg does not discriminate" ; code=1
fi
if [[ -z "$sp10" || "$sp10" -gt $((7 * MB / 2)) || "$sp10" -lt $((MB / 2)) ]]; then
    echo "F10a SSE stream not in the shaped band ($sp10 B/s) — no parks, leg does not discriminate" ; code=1
fi

# F10b: shaper detached — a server-paced slow SSE stream (~25s trickle,
# never parked) must STILL be cut at the 10s cap: the guard only spares
# parked conns, the reaper stays armed for genuinely slow streams.
res=$(api_del_policy qsh4)
echo "F10b detach: $res"
sleep 2
out10b=$($dexec l3h1 curl --max-time 40 -s -o /tmp/f10b.out \
    -w '%{time_total}' http://$FPVIP4:2020/sse-slow)
tt10b=$(echo $out10b | awk '{print int($1)}')
mk10b=$($dexec l3h1 sh -c 'grep -c max_stream_duration_exceeded /tmp/f10b.out 2>/dev/null; true')
echo "F10b un-shaped slow SSE: time=${tt10b}s marker=$mk10b (want cut at ~10s with the cap marker)"
if [[ "$mk10b" == "0" || "$tt10b" -gt 18 ]]; then
    echo "F10b duration cap went BLIND for un-shaped streams (time=${tt10b}s marker=$mk10b)" ; code=1
fi
capln=$(sudo docker exec llb1 sh -c 'cat /var/log/loxilbdp*.log 2>/dev/null' | grep -c "SSE_CAP")
if [[ "$capln" -lt 1 ]]; then
    echo "F10b no SSE_CAP log line — the cut did not come from the duration cap" ; code=1
fi

# --- F11: shaper observability series on /metrics ---
# /metrics is unauthenticated (security:[] in the swagger), so the scrape is a
# plain GET from inside llb1. The exporter republishes the store once per 10s
# collection cycle, hence the polls.
qos_scrape() {
    $dexec llb1 curl -s -m10 "$API/metrics" 2>/dev/null | grep '^loxilb_proxy_qos_'
}

# qos_val <scrape> <metric> <vip> <direction> [scale]
# prints the series value scaled by <scale> (default 1) as an integer, or
# MISSING when the series is absent. Values arrive in Go float form
# (1.6777216e+07), so awk does the parsing, not bash arithmetic.
qos_val() {
    echo "$1" | awk -v m="$2" -v v="$3" -v d="$4" -v sc="${5:-1}" '
        index($0, m "{") == 1 && index($0, "vip=\"" v "\"") > 0 &&
        index($0, "direction=\"" d "\"") > 0 { val = $2; found = 1 }
        END { if (found) printf "%.0f", val * sc; else printf "MISSING" }'
}

# qos_settled <vip> <direction>
# Leaves a SETTLED scrape in $SC — one taken after the exporter's 10s cycle
# has published a post-traffic snapshot. Two reads 12s apart must agree:
# a delta computed against a mid-transfer snapshot silently under-counts
# (the first cut of this leg lost 4MB of a 16MB body that way), and two
# equal reads also prove the counters stop moving when the traffic does.
SC=""
qos_settled() {
    local vip=$1 dir=$2 a b i
    for i in 1 2 3; do
        sleep 15
        SC=$(qos_scrape)
        a=$(qos_val "$SC" loxilb_proxy_qos_bytes_passed_total $vip $dir)
        sleep 12
        SC=$(qos_scrape)
        b=$(qos_val "$SC" loxilb_proxy_qos_bytes_passed_total $vip $dir)
        [[ "$a" != MISSING && "$a" == "$b" ]] && return 0
    done
    return 1
}

res=$(api_post_policy "$POL1_JSON")
echo "F11 re-attach: $res"
if [[ "$res" != *"Success"* ]]; then
    echo "F11 policer re-attach on $FPVIP1 FAILED: $res" ; code=1
fi

# wait for the exporter to publish the freshly shaped service, settled
if ! qos_settled $FPVIP1 upload; then
    echo "F11 no settled shaper series for $FPVIP1 after attach — counters still invisible" ; code=1
fi
sc0=$SC
mb0=$(qos_val "$sc0" loxilb_proxy_qos_bytes_passed_total $FPVIP1 upload)
mp0=$(qos_val "$sc0" loxilb_proxy_qos_parks_total $FPVIP1 upload)
mk0=$(qos_val "$sc0" loxilb_proxy_qos_park_seconds_total $FPVIP1 upload 1000)
md0=$(qos_val "$sc0" loxilb_proxy_qos_bytes_delayed_total $FPVIP1 upload)
mcir=$(qos_val "$sc0" loxilb_proxy_qos_cir_bytes_per_second $FPVIP1 upload)
mcbs=$(qos_val "$sc0" loxilb_proxy_qos_cbs_bytes $FPVIP1 upload)
echo "F11 pre-transfer: passed=$mb0 parks=$mp0 park_ms=$mk0 delayed=$md0 cir=$mcir cbs=$mcbs"

# the configured rate must be exported in BYTES/s (16 Mbps policer / 8), not
# the policer's bits — a unit slip here is invisible in a dashboard
if [[ "$mcir" != "2000000" ]]; then
    echo "F11 exported CIR is $mcir B/s, want 2000000 (16 Mbps policer / 8)" ; code=1
fi
if [[ "$mcbs" != "250000" ]]; then
    echo "F11 exported CBS is $mcbs B, want the configured 250000" ; code=1
fi

# a 16MB shaped upload: ~8s of transfer, parked for most of it
s11=$(up_speed $FPVIP1)
echo "F11 shaped upload: $s11 B/s"
if [[ -z "$s11" || "$s11" -gt $((7 * MB / 2)) || "$s11" -lt $((MB / 2)) ]]; then
    echo "F11 upload not in the shaped band ($s11 B/s) — no parks, leg does not discriminate" ; code=1
fi

if ! qos_settled $FPVIP1 upload; then
    echo "F11 counters never settled after the transfer — exported values keep moving" ; code=1
fi
sc1=$SC
mb1=$(qos_val "$sc1" loxilb_proxy_qos_bytes_passed_total $FPVIP1 upload)
mp1=$(qos_val "$sc1" loxilb_proxy_qos_parks_total $FPVIP1 upload)
mk1=$(qos_val "$sc1" loxilb_proxy_qos_park_seconds_total $FPVIP1 upload 1000)
md1=$(qos_val "$sc1" loxilb_proxy_qos_bytes_delayed_total $FPVIP1 upload)
echo "F11 post-transfer: passed=$mb1 parks=$mp1 park_ms=$mk1 delayed=$md1"

if [[ "$mb1" == MISSING || "$mb0" == MISSING ]]; then
    echo "F11 bytes_passed series vanished across the transfer" ; code=1
else
    dpass=$(( mb1 - mb0 ))
    dparks=$(( mp1 - mp0 ))
    dpark=$(( mk1 - mk0 ))
    ddelay=$(( md1 - md0 ))
    echo "F11 deltas: passed=$dpass parks=$dparks park_ms=$dpark delayed=$ddelay"
    # the 16MB body must show up in the upload direction's counter
    if [[ "$dpass" -lt 16000000 || "$dpass" -gt 25000000 ]]; then
        echo "F11 bytes_passed delta $dpass does not match the 16MB upload" ; code=1
    fi
    if [[ "$dparks" -le 0 ]]; then
        echo "F11 parks_total did not move on a transfer the shaper demonstrably paced" ; code=1
    fi
    # park seconds: at 2 MB/s a 16MB body is ~8s of mostly-parked transfer.
    # The upper bound is the unit trap — ns exported as seconds would land
    # around 8e9 ms here.
    if [[ "$dpark" -lt 1000 ]]; then
        echo "F11 park_seconds_total moved $dpark ms — park duration is not being accumulated" ; code=1
    fi
    if [[ "$dpark" -gt 60000 ]]; then
        echo "F11 park_seconds_total moved $dpark ms on a ~8s transfer — wrong unit or double counting" ; code=1
    fi
    if [[ "$ddelay" -le 0 || "$ddelay" -gt "$dpass" ]]; then
        echo "F11 bytes_delayed delta $ddelay is not a subset of passed $dpass" ; code=1
    fi
fi

# the download direction of the same service must carry its own series
mdn=$(qos_val "$sc1" loxilb_proxy_qos_bytes_passed_total $FPVIP1 download)
echo "F11 download-direction series: passed=$mdn"
if [[ "$mdn" == MISSING ]]; then
    echo "F11 no download-direction series — the per-direction label is not exported" ; code=1
fi

# detach: an un-shaped service must stop being exported entirely, otherwise
# the dashboard shows a shaper that is no longer running
res=$(api_del_policy qsh1)
echo "F11 detach: $res"
gone11=0
for i in $(seq 1 8); do
    sleep 4
    sc2=$(qos_scrape)
    if [[ "$(qos_val "$sc2" loxilb_proxy_qos_bytes_passed_total $FPVIP1 upload)" == MISSING ]]; then
        gone11=1 ; break
    fi
done
if [[ "$gone11" != 1 ]]; then
    echo "F11 series for $FPVIP1 still exported after detach — store is stale" ; code=1
fi
# the SSE VIP was detached back at F10b and must be absent for the same reason
if [[ "$(qos_val "$sc2" loxilb_proxy_qos_bytes_passed_total $FPVIP4 download)" != MISSING ]]; then
    echo "F11 detached SSE VIP $FPVIP4 still exported" ; code=1
fi

$dexec l3ep1 pkill -9 perl 2>/dev/null
if [[ $code == 0 ]]; then
    echo SCENARIO-qos-fullproxy [OK]
else
    echo SCENARIO-qos-fullproxy [FAILED]
fi
exit $code
