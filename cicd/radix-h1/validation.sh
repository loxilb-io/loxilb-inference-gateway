#!/bin/bash
# validation.sh - the legs of radix-h1 (HTTP/1.1 non-P/D prefix routing).
#
# Two gateway arms on the same client and mocks: OFF (switch unset) then ON
# (LLB_RADIX_POOLS=1). Each arm: gateway container, gateway, rules, the
# mandatory host check, then traffic. One line per leg in evidence/legs.txt:
#   LEG <id> PASS|FAIL|INFO <detail>
# Legs that need radix decisions read the [RADIX_STATS] line (names and
# counts only); before the request path calls radix they fail by design.
source "$(dirname "$0")/lib.sh"
LEGS=$EVID/legs.txt
: > "$LEGS"
leg() { echo "LEG $1 $2 $3" | tee -a "$LEGS"; }

# snap: wait one [RADIX_STATS] period (5 s, printed only on change) and keep
# the lines as of now; stat reads the latest snapshot.
snap() { sleep 6; stats_lines > "$EVID/stats.snap"; }
# stat <name>: the last [RADIX_STATS] value of <name> summed over pools, or -1 when no line
stat() {
  python3 -c '
import sys, re
name = sys.argv[1]; last = {}
for line in sys.stdin:
    m = re.search(r"pool=(\S+)", line)
    key = m.group(1) if m else "?"
    last[key] = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
print(sum(int(v.get(name, 0)) for v in last.values()) if last else -1)' "$1" < "$EVID/stats.snap"
}
results() { python3 -c 'import json,sys; [print(json.dumps(json.loads(l))) for l in sys.stdin if l.startswith("{")]'; }
jget() { python3 -c 'import json,sys; rs=[json.loads(l) for l in sys.stdin]; print(eval(sys.argv[1]))' "$1"; }

host_check() { # host_check <tag>: mandatory before traffic; a STOP ends the run
  "$SCN_DIR/hostcheck.sh" "$1" "$EVID/host" $NAMES | tee "$EVID/hostcheck-$1.txt"
  [ "${PIPESTATUS[0]}" = 0 ] || { say "host check $1 failed: stopping"; exit 3; }
}

E1_PLAN='['
for t in 1 2 3; do for c in 1 2 3 4 5 6; do
  E1_PLAN="$E1_PLAN{\"rid\":\"e1-c$c-t$t\",\"conn\":\"k$((c % 2))\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":$t}},"
done; done
E1_PLAN="$E1_PLAN{\"rid\":\"e1-short\",\"body\":{\"kind\":\"short\"}},{\"rid\":\"e1-sse\",\"body\":{\"kind\":\"conv\",\"conv\":7,\"turns\":1,\"stream\":true}}]"

arm() { # arm <off|on>
  local a=$1 sw=0
  [ "$a" = on ] && sw=1
  say "=== arm $a"
  start_gw_container || { say "FATAL: gateway container"; exit 2; }
  start_gateway "$a" "$sw" || exit 2
  add_rules || { say "FATAL: rules"; exit 2; }
  sleep 2
  host_check "poststart-$a"
  client $PORT_RR run "$(plan e1 "$E1_PLAN")" | results > "$EVID/e1-$a.jsonl"
  client $PORT_RR latency 200 "m1-$a" | results > "$EVID/m1-$a.jsonl"
  docker exec "${P}llb1" sh -c 'cp /var/log/loxilbdp.log /opt/radix-s4/loxilbdp-'"$a"'.log 2>/dev/null; true'
}

# ------------------------------------------------------------------ OFF arm
arm off
docker rm -f -v "${P}llb1" >/dev/null

# ------------------------------------------------------------------ ON arm
arm on

# E1: off is unchanged (no call site in this build: on == off), and the switch works
python3 - "$EVID/e1-off.jsonl" "$EVID/e1-on.jsonl" > "$EVID/e1-compare.txt" <<'EOF'
import json, sys
a = [json.loads(l) for l in open(sys.argv[1])]
b = [json.loads(l) for l in open(sys.argv[2])]
diff = [(x["rid"], x.get("status"), x.get("ep"), y.get("status"), y.get("ep"))
        for x, y in zip(a, b) if (x.get("status"), x.get("ep"), x.get("sse")) != (y.get("status"), y.get("ep"), y.get("sse"))]
ok200 = all(x.get("status") == 200 for x in a + b)
print("requests %d/%d, differing %d, all 200: %s" % (len(a), len(b), len(diff), ok200))
for d in diff[:10]:
    print("  diff", d)
sys.exit(0 if len(a) == len(b) and not diff and ok200 else 1)
EOF
if [ $? = 0 ]; then leg E1a PASS "on equals off per request (status, endpoint, SSE): $(head -1 "$EVID/e1-compare.txt")"
else leg E1a FAIL "$(head -3 "$EVID/e1-compare.txt" | tr '\n' ' ')"; fi
n_on=$(grep -c '\[RADIX\] pool .*: on' "$RUN/llb1/loxilb-on.out" 2>/dev/null)
n_off=$(grep -c '\[RADIX\]' "$RUN/llb1/loxilb-off.out" 2>/dev/null)
npools=$(echo $POOL_PORTS | wc -w)
[ "${n_on:-0}" = "$npools" ] && [ "${n_off:-0}" = 0 ] && leg E1b PASS "switch: $npools pools with radix state in the ON arm (one per rule), 0 [RADIX] lines in the OFF arm" \
  || leg E1b FAIL "switch: ON pools=$n_on OFF lines=$n_off (expected $npools and 0)"
leg E1c INFO "existing H1 scenario cicd/llamacpp-lb not run here (needs its own engine image); listed as a gap"

# M1: client-side latency, off vs on (report only)
python3 - "$EVID/m1-off.jsonl" "$EVID/m1-on.jsonl" > "$EVID/m1.txt" <<'EOF'
import json, sys
def pc(f):
    v = sorted(json.loads(l)["ms"] for l in open(f) if json.loads(l).get("status") == 200)
    return len(v), v[len(v) // 2], v[len(v) * 99 // 100]
for name, f in (("off", sys.argv[1]), ("on", sys.argv[2])):
    n, p50, p99 = pc(f)
    print("%s: n=%d p50=%.3f ms p99=%.3f ms" % (name, n, p50, p99))
EOF
leg M1 INFO "latency (200 sequential requests, :$PORT_RR): $(tr '\n' ';' < "$EVID/m1.txt")"

# KA: on HTTP/1.1 a kept-alive connection keeps its backend leg (no selection
# for the next request): recorded from E1, which uses two kept-alive connections.
ka=$(python3 -c '
import json, sys
for f in sys.argv[1:]:
    rs = [json.loads(l) for l in open(f)]
    per = {}
    for r in rs:
        if r["conn"].startswith("k"):
            per.setdefault(r["conn"], set()).add(r["ep"])
    print("%s: %s" % (f.rsplit("/", 1)[1], {k: sorted(v) for k, v in per.items()}), end="; ")' "$EVID/e1-off.jsonl" "$EVID/e1-on.jsonl")
leg KA INFO "endpoints per kept-alive connection (round robin, 9 requests each): $ka"

# E2: hit routing. Turn 1 of six conversations, then turn 2 of each, each on
# a fresh connection; round robin sends turn 2 to the next endpoint, radix to
# turn 1's.
P2='['
for c in 101 102 103 104 105 106; do
  P2="$P2{\"rid\":\"e2-c$c-t1\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":1}},{\"rid\":\"e2-c$c-t2\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":2}},"
done
P2="${P2%,}]"
snap; hits0=$(stat hit)
client $PORT_RR run "$(plan e2 "$P2")" | results > "$EVID/e2.jsonl"
same=$(jget 'sum(1 for i in range(0, len(rs), 2) if rs[i]["ep"] == rs[i+1]["ep"] and rs[i+1]["status"] == 200)' < "$EVID/e2.jsonl")
snap; hits1=$(stat hit)
if [ "$same" = 6 ] && [ "$hits1" -ge $((hits0 + 6)) ] 2>/dev/null; then leg E2 PASS "6/6 turn-2 requests on turn 1's endpoint; hits $hits0 -> $hits1"
else leg E2 FAIL "turn 2 on turn 1's endpoint: $same/6 (round robin alone gives 0); [RADIX_STATS] hit: $hits0 -> $hits1"; fi

# E2-KA: the keep-alive rule. Conversations A and B are learned on two
# endpoints (fresh connections, consecutive round robin picks); their next
# turns then alternate on ONE kept-alive connection. Today the connection keeps
# its first backend; with the rule, a full HIT on another endpoint releases it.
snap; mv0=$(stat ka_moved)
PK='[{"rid":"ka-A-t1","body":{"kind":"conv","conv":151,"turns":1}},
     {"rid":"ka-B-t1","body":{"kind":"conv","conv":152,"turns":1}},
     {"rid":"ka-A-t2","conn":"K","body":{"kind":"conv","conv":151,"turns":2}},
     {"rid":"ka-B-t2","conn":"K","body":{"kind":"conv","conv":152,"turns":2}},
     {"rid":"ka-A-t3","conn":"K","body":{"kind":"conv","conv":151,"turns":3}},
     {"rid":"ka-B-t3","conn":"K","body":{"kind":"conv","conv":152,"turns":3}}]'
client $PORT_RR run "$(plan e2ka "$PK")" | results > "$EVID/e2ka.jsonl"
snap; mv1=$(stat ka_moved)
okka=$(jget 'rs[0]["ep"] != rs[1]["ep"] and [r["ep"] for r in rs[2:]] == [rs[0]["ep"], rs[1]["ep"]] * 2 and all(r["status"] == 200 for r in rs)' < "$EVID/e2ka.jsonl")
eps=$(jget '" ".join(str(r["ep"]) for r in rs)' < "$EVID/e2ka.jsonl")
if [ "$okka" = True ] && [ "$mv1" -ge $((mv0 + 3)) ] 2>/dev/null; then leg E2-KA PASS "learned A,B then on one kept-alive connection: $eps; ka_moved $mv0 -> $mv1"
else leg E2-KA FAIL "endpoints (A t1, B t1, then kept-alive A t2, B t2, A t3, B t3): $eps; [RADIX_STATS] ka_moved $mv0 -> $mv1"; fi

# GUARD legs: the balance guard on the round-robin pool. A HIT falls back to
# the selector's pick when the radix pick's in-flight minus the lowest
# in-flight over the eligible endpoints exceeds balance_abs (3). The mock
# holds requests at an endpoint (delay); they are sent one per second in the
# background, so each decision sees the earlier ones in flight.
bgreq() {  # bgreq <name> <port> <plan-json>: the plan in the background on the client
  plan "$1" "$3" >/dev/null
  docker exec -d "${P}h1" sh -c "python3 /opt/rx4/client.py $VIP $2 run /opt/out/$1.json > /opt/out/$1.jsonl"
}
hold4() {  # hold4 <tag> <ep> <conv>: four requests of the conversation's turn 2, held 8 s at <ep>
  local i
  mock_admin "$2" /admin/delay/8000/4
  for i in 1 2 3 4; do
    bgreq "$1-h$i" $PORT_RR "[{\"rid\":\"$1-h$i\",\"body\":{\"kind\":\"conv\",\"conv\":$3,\"turns\":2}}]"
    sleep 1
  done
}
held() { cat "$RUN"/h1/$1-h1.jsonl "$RUN"/h1/$1-h2.jsonl "$RUN"/h1/$1-h3.jsonl "$RUN"/h1/$1-h4.jsonl 2>/dev/null | results; }
gu0=$(gw_log | grep -c 'underflow protection')

# GUARD-FALLBACK: a prefix learned on X; four requests of it held at X (in
# flight 0, 1, 2, 3 at their decisions: each a HIT on X); the fifth sees
# 4 - 0 > 3: counted spread, routed by the selector.
client $PORT_RR run "$(plan gf1 '[{"rid":"gf-t1","body":{"kind":"conv","conv":821,"turns":1}}]')" | results > "$EVID/gf-1.jsonl"
X=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else ""' < "$EVID/gf-1.jsonl")
snap; gh0=$(stat hit); gs0=$(stat balance)
if [ -n "$X" ]; then
  hold4 gf "$X" 821
  client $PORT_RR run "$(plan gf5 '[{"rid":"gf-5th","body":{"kind":"conv","conv":821,"turns":2}}]')" | results > "$EVID/gf-5.jsonl"
  sleep 9
  mock_admin "$X" /admin/reset
fi
snap; gh1=$(stat hit); gs1=$(stat balance)
held gf > "$EVID/gf-held.jsonl"
okh=$(jget "len(rs) == 4 and all(r['ep'] == '$X' and r['status'] == 200 for r in rs)" < "$EVID/gf-held.jsonl" 2>/dev/null)
ep5=$(jget 'rs[0]["ep"] if rs and rs[0]["status"] == 200 else "none"' < "$EVID/gf-5.jsonl" 2>/dev/null)
detail="learned on ${X:-?}; held 4 on it: $okh; fifth answered by $ep5; hit $gh0 -> $gh1, spread $gs0 -> $gs1"
if [ -n "$X" ] && [ "$okh" = True ] && [ "$ep5" != none ] && [ "$gh1" = $((gh0 + 4)) ] && [ "$gs1" = $((gs0 + 1)) ] 2>/dev/null; then
  leg GUARD-FALLBACK PASS "$detail"
else
  leg GUARD-FALLBACK FAIL "$detail (want hit +4, spread +1)"
fi

# GUARD-RULES-APART: prefixes learned on Y and on X (two consecutive round
# robin picks); four requests held at Y; then X's prefix, X idle: a HIT on X
# (X - min = 0). The previous rule (max - min = 4 > 3) fell back here.
client $PORT_RR run "$(plan ga1 '[{"rid":"ga-Y-t1","body":{"kind":"conv","conv":831,"turns":1}},{"rid":"ga-X-t1","body":{"kind":"conv","conv":832,"turns":1}}]')" | results > "$EVID/ga-1.jsonl"
Y=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else ""' < "$EVID/ga-1.jsonl")
X=$(jget 'rs[1]["ep"] if rs[1]["status"] == 200 and rs[1]["ep"] != rs[0]["ep"] else ""' < "$EVID/ga-1.jsonl")
snap; ah0=$(stat hit); as0=$(stat balance)
if [ -n "$Y" ] && [ -n "$X" ]; then
  hold4 ga "$Y" 831
  client $PORT_RR run "$(plan ga5 '[{"rid":"ga-X-t2","body":{"kind":"conv","conv":832,"turns":2}}]')" | results > "$EVID/ga-5.jsonl"
  sleep 9
  mock_admin "$Y" /admin/reset
fi
snap; ah1=$(stat hit); as1=$(stat balance)
held ga > "$EVID/ga-held.jsonl"
okh=$(jget "len(rs) == 4 and all(r['ep'] == '$Y' and r['status'] == 200 for r in rs)" < "$EVID/ga-held.jsonl" 2>/dev/null)
epx=$(jget 'rs[0]["ep"] if rs and rs[0]["status"] == 200 else "none"' < "$EVID/ga-5.jsonl" 2>/dev/null)
detail="Y=${Y:-?} X=${X:-?}; held 4 on Y: $okh; X's prefix answered by $epx; hit $ah0 -> $ah1, spread $as0 -> $as1"
if [ -n "$X" ] && [ "$okh" = True ] && [ "$epx" = "$X" ] && [ "$ah1" = $((ah0 + 5)) ] && [ "$as1" = "$as0" ] 2>/dev/null; then
  leg GUARD-RULES-APART PASS "$detail"
else
  leg GUARD-RULES-APART FAIL "$detail (want X, hit +5, spread +0)"
fi

# After both: the pool's admission in-flight is back to 0, no underflow line.
sleep 2
gu1=$(gw_log | grep -c 'underflow protection')
ginf=$(inflight $PORT_RR)
if [ "$gu1" = "$gu0" ] && { [ "$ginf" = 0 ] || [ "$ginf" = n/a ]; }; then
  leg GUARD-QUIESCE PASS "admission in-flight on :$PORT_RR after both: $ginf; underflow lines $gu0 -> $gu1"
else
  leg GUARD-QUIESCE FAIL "admission in-flight on :$PORT_RR after both: $ginf; underflow lines $gu0 -> $gu1"
fi

# KA-session: a session-header pool on one kept-alive connection behaves as
# today (the keep-alive rule cannot evaluate the session overlay: leg kept).
snap; ms0=$(stat ka_moved)
PS='[{"rid":"kas-1","conn":"S","headers":{"x-session-id":"s5"},"body":{"kind":"conv","conv":161,"turns":1}},
     {"rid":"kas-2","conn":"S","headers":{"x-session-id":"s5"},"body":{"kind":"conv","conv":162,"turns":1}},
     {"rid":"kas-3","conn":"S","headers":{"x-session-id":"s5"},"body":{"kind":"conv","conv":161,"turns":2}},
     {"rid":"kas-4","conn":"S","headers":{"x-session-id":"s5"},"body":{"kind":"conv","conv":162,"turns":2}}]'
client $PORT_SESS run "$(plan kas "$PS")" | results > "$EVID/kas.jsonl"
snap; ms1=$(stat ka_moved)
oks=$(jget 'len(set(r["ep"] for r in rs)) == 1 and all(r["status"] == 200 for r in rs)' < "$EVID/kas.jsonl")
[ "$ms0" -lt 0 ] && ms0=0; [ "$ms1" -lt 0 ] && ms1=0
if [ "$oks" = True ] && [ "$ms1" = "$ms0" ]; then leg KA-session PASS "4 requests, one session, one kept-alive connection: one endpoint; ka_moved unchanged ($ms0)"
else leg KA-session FAIL "one endpoint for the session: $oks; ka_moved $ms0 -> $ms1"; fi

# E3 (session priority): the session header wins over radix and is counted as a pin
P3='[{"rid":"e3-s-1","headers":{"x-session-id":"s1"},"body":{"kind":"conv","conv":201,"turns":1}},
     {"rid":"e3-s-2","headers":{"x-session-id":"s1"},"body":{"kind":"conv","conv":201,"turns":2}},
     {"rid":"e3-s-3","headers":{"x-session-id":"s1"},"body":{"kind":"conv","conv":202,"turns":1}}]'
snap; pin0=$(stat pinned)
client $PORT_SESS run "$(plan e3s "$P3")" | results > "$EVID/e3s.jsonl"
sticky=$(jget 'len(set(r["ep"] for r in rs)) == 1 and all(r["status"] == 200 for r in rs)' < "$EVID/e3s.jsonl")
snap; pin1=$(stat pinned)
if [ "$sticky" = True ] && [ "$pin1" -ge $((pin0 + 3)) ] 2>/dev/null; then leg E3-session PASS "3 requests on one endpoint; pinned $pin0 -> $pin1"
else leg E3-session FAIL "session stickiness held: $sticky; [RADIX_STATS] pinned: $pin0 -> $pin1"; fi

# E4: guards counted under their own names (short body, miss)
snap; s0=$(stat scan.short); m0=$(stat miss)
client $PORT_RR run "$(plan e4 '[{"rid":"e4-short","body":{"kind":"short"}},{"rid":"e4-miss","body":{"kind":"conv","conv":301,"turns":1}}]')" | results > "$EVID/e4.jsonl"
snap; s1=$(stat scan.short); m1=$(stat miss)
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/e4.jsonl")
if [ "$ok" = True ] && [ "$s1" -ge $((s0 + 1)) ] && [ "$m1" -ge $((m0 + 1)) ] 2>/dev/null; then leg E4 PASS "scan.short $s0->$s1, miss $m0->$m1"
else leg E4 FAIL "replies 200: $ok; [RADIX_STATS] scan.short $s0->$s1, miss $m0->$m1"; fi

# E5: learning on the first final 2xx only: 500 not learned, 100 then 200 learned, SSE learned
for n in $EPS; do mock_admin "$n" /admin/status/500/1; done
snap; r0=$(stat learn.refused); k0=$(stat learn.ok)
client $PORT_RR run "$(plan e5a '[{"rid":"e5-500","body":{"kind":"conv","conv":401,"turns":1}}]')" | results > "$EVID/e5.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; mock_admin "$n" /admin/interim/1; done
client $PORT_RR run "$(plan e5b '[{"rid":"e5-100-200","body":{"kind":"conv","conv":402,"turns":1}}]')" | results >> "$EVID/e5.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; done
client $PORT_RR run "$(plan e5c '[{"rid":"e5-sse","body":{"kind":"conv","conv":403,"turns":1,"stream":true}}]')" | results >> "$EVID/e5.jsonl"
snap; r1=$(stat learn.refused); k1=$(stat learn.ok)
replies=$(jget '[r["status"] for r in rs] == [500, 200, 200] and rs[2]["sse"]' < "$EVID/e5.jsonl")
if [ "$replies" = True ] && [ "$r1" -ge $((r0 + 1)) ] && [ "$k1" -ge $((k0 + 2)) ] 2>/dev/null; then leg E5 PASS "500 relayed and not learned, 100+200 and SSE learned: refused $r0->$r1, ok $k0->$k1"
else leg E5 FAIL "replies 500/200/SSE as sent: $replies; [RADIX_STATS] learn.refused $r0->$r1, learn.ok $k0->$k1"; fi

# E6: CHWBL pool, keep-alive requests, client close, then backend-first close
P6='['
for k in 1 2 3 4; do for t in 1 2 3 4 5; do
  P6="$P6{\"rid\":\"e6-k$k-$t\",\"conn\":\"c$k\",\"body\":{\"kind\":\"conv\",\"conv\":$((500 + k)),\"turns\":$t}},"
done; P6="$P6{\"rid\":\"e6-k$k-last\",\"conn\":\"c$k\",\"close\":true,\"body\":{\"kind\":\"short\"}},"; done
P6="${P6%,}]"
under0=$(gw_log | grep -c 'underflow protection')
client $PORT_CHWBL run "$(plan e6a "$P6")" | results > "$EVID/e6.jsonl"
for n in $EPS; do mock_admin "$n" /admin/close/2; done
client $PORT_CHWBL run "$(plan e6b '[{"rid":"e6-bc-1","conn":"b1","body":{"kind":"conv","conv":511,"turns":1}},{"rid":"e6-bc-2","conn":"b1","body":{"kind":"conv","conv":511,"turns":2}},{"rid":"e6-bc-3","conn":"b2","body":{"kind":"conv","conv":512,"turns":1}}]')" | results >> "$EVID/e6.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; done
sleep 3
under1=$(gw_log | grep -c 'underflow protection')
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/e6.jsonl")
if [ "$ok" = True ] && [ "$under1" = "$under0" ]; then leg E6 PASS "27 CHWBL requests 200, keep-alive then client and backend close, underflow lines $under0 -> $under1 (here the CHWBL pick and radix agree; the unit move is leg E6-move)"
else leg E6 FAIL "replies 200: $ok; underflow lines $under0 -> $under1"; fi

# E6-move: on a CHWBL pool, a radix HIT on another endpoint than the CHWBL
# pick moves the bounded-load unit (dec on the pick, inc on the radix pick).
# Pool :3006 admits one request per endpoint (enforce). Y = CHWBL's pick for
# one system prompt (probe D). While a slow request holds Y, C1 and C2 (same
# system prompt) are moved off Y by admission and learned on X. Once Y is
# free, their next turns are CHWBL -> Y but radix -> X: fresh connection,
# kept-alive closed by the client, kept-alive closed by the backend. Then an
# admission move after a HIT: X held by a slow request, a HIT on X is moved.
mvplan() { plan "$1" "$2" >/dev/null; client $PORT_MOVE run "/opt/out/$1.json" | results; }
mvbg() {  # mvbg <name> <plan-json>: the plan in the background on the client
  plan "$1" "$2" >/dev/null
  docker exec -d "${P}h1" sh -c "python3 /opt/rx4/client.py $VIP $PORT_MOVE run /opt/out/$1.json > /opt/out/$1.jsonl"
}
u0=$(gw_log | grep -c 'underflow protection')
mvplan m0 '[{"rid":"m-D-t1","body":{"kind":"conv","conv":951,"variant":1,"turns":1}}]' > "$EVID/e6m-0.jsonl"
Y=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else ""' < "$EVID/e6m-0.jsonl")
if [ -n "$Y" ]; then
  mock_admin "$Y" /admin/delay/6000/1
  mvbg m1bg '[{"rid":"m-D-t2-held","body":{"kind":"conv","conv":951,"variant":1,"turns":2}}]'
  sleep 1
  mvplan m2 '[{"rid":"m-C1-t1","body":{"kind":"conv","conv":951,"turns":1}},{"rid":"m-C2-t1","body":{"kind":"conv","conv":951,"variant":3,"turns":1}}]' > "$EVID/e6m-2.jsonl"
  sleep 6; cp "$RUN/h1/m1bg.jsonl" "$EVID/e6m-1bg.jsonl" 2>/dev/null
  mock_admin "$Y" /admin/reset
  X1=$(jget 'rs[0]["ep"]' < "$EVID/e6m-2.jsonl")
  snap; mo0=$(stat moved)
  # fresh connection; kept-alive closed by the client
  mvplan m4 '[{"rid":"m-C1-t2","body":{"kind":"conv","conv":951,"turns":2}},
              {"rid":"m-C2-t2","conn":"K","body":{"kind":"conv","conv":951,"variant":3,"turns":2}},
              {"rid":"m-C2-t3","conn":"K","close":true,"body":{"kind":"conv","conv":951,"variant":3,"turns":3}}]' > "$EVID/e6m-4.jsonl"
  # kept-alive closed by the backend
  mock_admin "$X1" /admin/close/1
  mvplan m5 '[{"rid":"m-C1-t3","conn":"B","body":{"kind":"conv","conv":951,"turns":3}}]' > "$EVID/e6m-5.jsonl"
  mock_admin "$X1" /admin/reset
  # admission move after a HIT: X1 held at its ceiling by a slow request
  mock_admin "$X1" /admin/delay/4000/1
  mvbg m6bg '[{"rid":"m-C1-t4-held","body":{"kind":"conv","conv":951,"turns":4}}]'
  sleep 1
  mvplan m6 '[{"rid":"m-C1-t5-moved","body":{"kind":"conv","conv":951,"turns":5}}]' > "$EVID/e6m-6.jsonl"
  sleep 5; cp "$RUN/h1/m6bg.jsonl" "$EVID/e6m-6bg.jsonl" 2>/dev/null
  mock_admin "$X1" /admin/reset
  sleep 3                                  # quiesce
  snap; mo1=$(stat moved)
  infl=$(inflight $PORT_MOVE)
fi
u1=$(gw_log | grep -c 'underflow protection')
gw_log | grep 'underflow protection' > "$EVID/e6m-underflow.txt"
docker exec "${P}llb1" curl -s -m 5 "$API/metrics" 2>/dev/null | grep '^loxilb_ai_admission_inflight{' > "$EVID/e6m-inflight.txt"
res=$(python3 - "$EVID" "${Y:-}" <<'PYEOF'
import json, sys
d, Y = sys.argv[1], sys.argv[2]
def rs(n):
    try:
        return [json.loads(l) for l in open("%s/e6m-%s.jsonl" % (d, n))]
    except OSError:
        return []
out = []
ok = bool(Y)
r1, r2, r4, r5, r6, bg = rs("1bg"), rs(2), rs(4), rs(5), rs(6), rs("6bg")
X1 = r2[0]["ep"] if r2 else None
X2 = r2[1]["ep"] if len(r2) > 1 else None
def need(cond, what):
    global ok
    out.append(("ok " if cond else "NO ") + what)
    ok = ok and bool(cond)
need(bool(Y), "probe: CHWBL pick Y=%s" % Y)
need(len(r1) == 1 and r1[0]["ep"] == Y and r1[0]["status"] == 200, "slow request held Y: %s" % (r1[0]["ep"] if r1 else None))
need(X1 not in (None, Y) and X2 not in (None, Y) and all(r["status"] == 200 for r in r2), "C1, C2 moved off Y by admission and learned on %s, %s" % (X1, X2))
need(len(r4) == 3 and [r["ep"] for r in r4] == [X1, X2, X2] and all(r["status"] == 200 for r in r4),
     "radix moves off the CHWBL pick: fresh -> %s, kept-alive -> %s, %s (client close)" % tuple((r4 + [{"ep": None}] * 3)[k]["ep"] for k in range(3)))
need(len(r5) == 1 and r5[0]["ep"] == X1 and r5[0]["status"] == 200, "kept-alive, backend close: %s" % (r5[0]["ep"] if r5 else None))
need(len(bg) == 1 and bg[0]["ep"] == X1 and bg[0]["status"] == 200, "slow request held X1: %s" % (bg[0]["ep"] if bg else None))
need(len(r6) == 1 and r6[0]["ep"] not in (None, X1) and r6[0]["status"] == 200, "admission moved the HIT off X1: %s" % (r6[0]["ep"] if r6 else None))
print(("PASS" if ok else "FAIL") + "|" + "; ".join(out))
PYEOF
)
verdict=${res%%|*}; detail=${res#*|}
if [ "$verdict" = PASS ] && [ "$u1" = "$u0" ] && [ "${mo1:-0}" -ge $(( ${mo0:-0} + 1 )) ] 2>/dev/null && { [ "$infl" = 0 ] || [ "$infl" = n/a ]; }; then
  leg E6-move PASS "$detail; underflow lines $u0 -> $u1; moved ${mo0:-?} -> ${mo1:-?}; admission in-flight after quiesce: $infl"
else
  leg E6-move FAIL "$detail; underflow lines $u0 -> $u1; moved ${mo0:-?} -> ${mo1:-?}; admission in-flight after quiesce: ${infl:-?}"
fi

# E3-cb/E7: purge. Conversations learned on ep3 in the CB pool; ep3 goes
# down and its breaker opens (the trip purges ep3); after ep3 is back and its
# breaker closes, those conversations' next turns find no entry on ep3 (miss,
# no hit), and a new conversation learns on ep3 again.
P7a='['
for c in $(seq 701 709); do P7a="$P7a{\"rid\":\"e7a-$c\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":1}},"; done
client $PORT_CB run "$(plan e7a "${P7a%,}]")" | results > "$EVID/e7a.jsonl"
ep3c=$(jget '" ".join(r["rid"].split("-")[1] for r in rs if r["ep"] == "ep3" and r["status"] == 200)' < "$EVID/e7a.jsonl")
n3=$(echo $ep3c | wc -w)
snap; pg0=$(stat purges)
nsx ep3 ip link set rx0 down
# Exactly the breaker's 5 failures: each request is a radix HIT on ep3 (its
# only candidate), fails, and is not learned; a 6th would be served elsewhere
# and learned, and the check after the return would see that new entry.
P7b='['
set -- $ep3c; k=0
while [ $k -lt 5 ] && [ $# -gt 0 ]; do
  c=$(echo $ep3c | cut -d' ' -f$((k % $# + 1)))
  P7b="$P7b{\"rid\":\"e7b-$k-$c\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":2}},"; k=$((k + 1))
done
client $PORT_CB run "$(plan e7b "${P7b%,}]")" | results > "$EVID/e7b.jsonl"
cbopen=$(gw_log | grep -c 'Circuit breaker CLOSED')
snap; pg1=$(stat purges)
nsx ep3 ip link set rx0 up
sleep 35                                   # the breaker's 30 s open interval
snap; h2=$(stat hit); m2=$(stat miss)
P7d='['
for c in $ep3c; do P7d="$P7d{\"rid\":\"e7d-$c\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":2}},"; done
client $PORT_CB run "$(plan e7d "${P7d%,}]")" | results > "$EVID/e7d.jsonl"
snap; h3=$(stat hit); m3=$(stat miss)
P7e='['
for c in $(seq 721 729); do P7e="$P7e{\"rid\":\"e7e-$c\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":1}},"; done
client $PORT_CB run "$(plan e7e "${P7e%,}]")" | results > "$EVID/e7e.jsonl"
re3=$(jget 'next((r["rid"].split("-")[1] for r in rs if r["ep"] == "ep3" and r["status"] == 200), "")' < "$EVID/e7e.jsonl")
relearn=none
if [ -n "$re3" ]; then
  client $PORT_CB run "$(plan e7f "[{\"rid\":\"e7f-$re3\",\"body\":{\"kind\":\"conv\",\"conv\":$re3,\"turns\":2}}]")" | results > "$EVID/e7f.jsonl"
  relearn=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else "status %d" % rs[0]["status"]' < "$EVID/e7f.jsonl")
fi
down_ok=$(jget 'len(rs) == 5 and all(r["status"] == 502 for r in rs)' < "$EVID/e7b.jsonl")
d_ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/e7d.jsonl")
if [ "$n3" -ge 2 ] && [ "$down_ok" = True ] && [ "$pg1" -ge $((pg0 + 1)) ] 2>/dev/null && \
   [ "$d_ok" = True ] && [ "$h3" = "$h2" ] && [ "$m3" -ge $((m2 + n3)) ] 2>/dev/null && [ "$relearn" = ep3 ]; then
  leg E3-cb/E7 PASS "$n3 conversations learned on ep3; ep3 down: breaker opened ($cbopen), purges $pg0 -> $pg1; ep3 back: their next turns hit $h2 -> $h3, miss $m2 -> $m3; a new conversation learned on ep3 and its next turn went to $relearn"
else
  leg E3-cb/E7 FAIL "learned on ep3: $n3; all 5 requests while down sent to ep3 and answered 502: $down_ok; breaker-open lines $cbopen; purges $pg0 -> $pg1; after return: 200 $d_ok, hit $h2 -> $h3, miss $m2 -> $m3 (expected +0 / +$n3); relearn on ep3: $relearn"
fi

# STICKY: a persistence pool keeps its selector's pick; radix counts the
# request as pinned and does not scan it.
snap; pn0=$(stat pinned); sk0=$(stat scans)
PST='[{"rid":"st-1","body":{"kind":"conv","conv":801,"turns":1}},{"rid":"st-2","body":{"kind":"conv","conv":801,"turns":2}},
      {"rid":"st-3","body":{"kind":"conv","conv":802,"turns":1}},{"rid":"st-4","body":{"kind":"conv","conv":802,"turns":2}}]'
client $PORT_STICKY run "$(plan sticky "$PST")" | results > "$EVID/sticky.jsonl"
snap; pn1=$(stat pinned); sk1=$(stat scans)
one=$(jget 'len(set(r["ep"] for r in rs)) == 1 and all(r["status"] == 200 for r in rs)' < "$EVID/sticky.jsonl")
if [ "$one" = True ] && [ "$pn1" -ge $((pn0 + 4)) ] && [ "$sk1" = "$sk0" ] 2>/dev/null; then leg STICKY PASS "4 requests on one endpoint (client-IP persistence); pinned $pn0 -> $pn1, scans unchanged ($sk0)"
else leg STICKY FAIL "one endpoint: $one; pinned $pn0 -> $pn1 (expected +4); scans $sk0 -> $sk1 (expected unchanged)"; fi

# E8: bypass inputs - chunked body and a body above 768 KiB
snap; c0=$(stat chunked); i0=$(stat inspect_size)
client $PORT_RR run "$(plan e8 '[{"rid":"e8-chunked","chunked":true,"body":{"kind":"conv","conv":701,"turns":2}},{"rid":"e8-big","body":{"kind":"big","bytes":800000}}]')" | results > "$EVID/e8.jsonl"
snap; c1=$(stat chunked); i1=$(stat inspect_size)
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/e8.jsonl")
if [ "$ok" = True ] && [ "$c1" -ge $((c0 + 1)) ] && [ "$i1" -ge $((i0 + 1)) ] 2>/dev/null; then leg E8 PASS "chunked $c0->$c1, inspect_size $i0->$i1, replies 200"
else leg E8 FAIL "replies 200: $ok; [RADIX_STATS] chunked $c0->$c1, inspect_size $i0->$i1"; fi

# TOKENS: a body above 8,192 JSON tokens is routed by radix (scanned, counted)
snap; sc0=$(stat scans)
client $PORT_RR run "$(plan d4b '[{"rid":"d4b-1","body":{"kind":"tokens","n":2000}},{"rid":"d4b-2","body":{"kind":"tokens","n":2000}}]')" | results > "$EVID/d4b.jsonl"
snap; sc1=$(stat scans)
ok=$(jget 'all(r["status"] == 200 for r in rs) and rs[0]["ep"] == rs[1]["ep"]' < "$EVID/d4b.jsonl")
if [ "$ok" = True ] && [ "$sc1" -ge $((sc0 + 1)) ] 2>/dev/null; then leg TOKENS PASS "2,000-message body scanned and routed to the learned endpoint; scans $sc0 -> $sc1"
else leg TOKENS FAIL "200 and same endpoint twice: $ok; [RADIX_STATS] scans $sc0 -> $sc1"; fi

# PIPE: HTTP/1.1 pipelining. Request N is held at its backend; request N+1
# is sent on the same connection before N's answer. N+1's head then begins
# while N's answer is owed. Neither request may use radix or learn: N+1
# counts reason `pipelined`, no learn happens in the pair, and the next turns
# of both conversations miss. Before the rule, N+1 was scanned at the
# keep-alive site and N's 2xx learned N+1's key (N+1's own 2xx then found the
# learn consumed).
for n in $EPS; do mock_admin "$n" /admin/delay/1500/1; done
snap; p0=$(stat pipelined); k0=$(stat learn.ok); n0=$(stat learn.none)
plan pipe '[{"rid":"pipe-P-t1","body":{"kind":"conv","conv":971,"turns":1}},
            {"rid":"pipe-Q-t1","body":{"kind":"conv","conv":972,"turns":1}}]' >/dev/null
client $PORT_RR pipe /opt/out/pipe.json 300 | results > "$EVID/pipe.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; done
snap; p1=$(stat pipelined); k1=$(stat learn.ok); n1=$(stat learn.none); h1=$(stat hit)
plan pipe2 '[{"rid":"pipe-P-t2","body":{"kind":"conv","conv":971,"turns":2}},
             {"rid":"pipe-Q-t2","body":{"kind":"conv","conv":972,"turns":2}}]' >/dev/null
client $PORT_RR run /opt/out/pipe2.json | results > "$EVID/pipe2.jsonl"
snap; h2=$(stat hit)
order=$(jget '" ".join("%s:%s:%s" % (r["rid"][5:], r.get("id"), r["status"]) for r in rs)' < "$EVID/pipe.jsonl")
inorder=$(jget 'len(rs) == 2 and all(r["status"] == 200 and r.get("id") == r["rid"] for r in rs)' < "$EVID/pipe.jsonl")
detail="answers $order (in order: $inorder); pipelined $p0 -> $p1; learn.ok $k0 -> $k1, learn.none $n0 -> $n1 in the pair; next turns: hit $h1 -> $h2"
if [ "$inorder" = True ] && [ "$p1" -ge $((p0 + 1)) ] 2>/dev/null && [ "$k1" = "$k0" ] && [ "$h2" = "$h1" ]; then
  leg PIPE PASS "$detail"
else
  leg PIPE FAIL "$detail"
fi

# E9: no request text in the gateway logs (debug level)
MARK=RX4MARKER7Q
client $PORT_RR run "$(plan e9 "[{\"rid\":\"e9-1\",\"body\":{\"kind\":\"marker\",\"marker\":\"$MARK\"}}]")" | results > "$EVID/e9.jsonl"
sleep 1
nmark=$(gw_log | grep -c "$MARK")
gw_log | grep "$MARK" | sed -E "s/$MARK.*/$MARK[...]/" | cut -c1-160 | head -3 > "$EVID/e9-lines.txt"
if [ "$nmark" = 0 ]; then leg E9 PASS "marker absent from the gateway logs"
else leg E9 FAIL "marker in $nmark gateway log line(s), e.g. $(cut -c1-100 "$EVID/e9-lines.txt" | head -1)"; fi

# The counters line itself
nst=$(stats_lines | wc -l)
leg STATS INFO "[RADIX_STATS] lines in the gateway log: $nst"
docker exec "${P}llb1" sh -c 'cp /var/log/loxilbdp.log /opt/radix-s4/loxilbdp-on.log 2>/dev/null; true'
say "legs: $(grep -c ' PASS ' "$LEGS") PASS, $(grep -c ' FAIL ' "$LEGS") FAIL, $(grep -c ' INFO ' "$LEGS") INFO"
# A failed leg fails the run (CI); the legs file keeps every result.
! grep -q ' FAIL ' "$LEGS"
