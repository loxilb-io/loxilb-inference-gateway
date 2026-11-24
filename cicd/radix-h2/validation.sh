#!/bin/bash
# validation.sh - the legs of radix-h2 (HTTP/2 non-P/D prefix routing).
#
# Two gateway arms on the same client and h2c mocks: OFF (switch unset) then
# ON (LLB_RADIX_POOLS=1). Each arm: gateway container, gateway, rules, the
# mandatory host check, then traffic. One line per leg in evidence/legs.txt:
#   LEG <id> PASS|FAIL|INFO <detail>
# Counters come from the [RADIX_STATS] line (names and counts only).
source "$(dirname "$0")/lib.sh"
LEGS=$EVID/legs.txt
: > "$LEGS"
leg() { echo "LEG $1 $2 $3" | tee -a "$LEGS"; }

snap() { sleep 8; stats_lines > "$EVID/stats.snap"; }
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
z() { [ "$1" -lt 0 ] 2>/dev/null && echo 0 || echo "$1"; }   # no line yet: 0

host_check() {
  "$SCN_DIR/hostcheck.sh" "$1" "$EVID/host" $NAMES | tee "$EVID/hostcheck-$1.txt"
  [ "${PIPESTATUS[0]}" = 0 ] || { say "host check $1 failed: stopping"; exit 3; }
}
badlines() { gw_log | grep -cE 'underflow protection|notify-pin-FAIL'; }

# E1: fresh connections (one stream each), so every request is a selection.
E1_PLAN='['
for t in 1 2 3; do for c in 1 2 3 4 5 6; do
  E1_PLAN="$E1_PLAN{\"rid\":\"e1-c$c-t$t\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":$t}},"
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
  docker exec "${P}llb1" sh -c 'cp /var/log/loxilbdp.log /opt/radix-s4/loxilbdp-'"$a"'.log 2>/dev/null; true'
}

# ------------------------------------------------------------------ OFF arm
arm off
docker rm -f -v "${P}llb1" >/dev/null

# ------------------------------------------------------------------ ON arm
arm on

# E1a: the ON arm answers every request of the E1 plan as the OFF arm does
# (status, SSE relayed). Endpoints are not compared: on HTTP/2 every stream is
# a selection, so in the ON arm radix routes the repeated turns. That the OFF
# arm is unchanged by this build is checked across images (the OFF arm's
# endpoints against a run on an image without HTTP/2 radix).
python3 - "$EVID/e1-off.jsonl" "$EVID/e1-on.jsonl" > "$EVID/e1-compare.txt" <<'EOF'
import json, sys
a = [json.loads(l) for l in open(sys.argv[1])]
b = [json.loads(l) for l in open(sys.argv[2])]
ok200 = all(x.get("status") == 200 for x in a + b)
sse = a[-1].get("sse") and b[-1].get("sse")
print("requests %d/%d, all 200: %s, SSE relayed in both: %s" % (len(a), len(b), ok200, sse))
sys.exit(0 if len(a) == len(b) == 20 and ok200 and sse else 1)
EOF
if [ $? = 0 ]; then leg E1a PASS "$(head -1 "$EVID/e1-compare.txt")"
else leg E1a FAIL "$(head -3 "$EVID/e1-compare.txt" | tr '\n' ' ')"; fi
n_on=$(grep -c '\[RADIX\] pool .*: on' "$RUN/llb1/loxilb-on.out" 2>/dev/null)
n_off=$(grep -c '\[RADIX\]' "$RUN/llb1/loxilb-off.out" 2>/dev/null)
npools=$(echo $POOL_PORTS | wc -w)
[ "${n_on:-0}" = "$npools" ] && [ "${n_off:-0}" = 0 ] && leg E1b PASS "switch: $npools pools with radix state in the ON arm, 0 [RADIX] lines in the OFF arm" \
  || leg E1b FAIL "switch: ON pools=$n_on OFF lines=$n_off (expected $npools and 0)"

# E2: turn 1 of six conversations, then turn 2 of each, each on a fresh
# connection: round robin sends turn 2 to the next endpoint, radix to turn 1's.
P2='['
for c in 101 102 103 104 105 106; do
  P2="$P2{\"rid\":\"e2-c$c-t1\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":1}},{\"rid\":\"e2-c$c-t2\",\"body\":{\"kind\":\"conv\",\"conv\":$c,\"turns\":2}},"
done
snap; h0=$(stat hit)
client $PORT_RR run "$(plan e2 "${P2%,}]")" | results > "$EVID/e2.jsonl"
same=$(jget 'sum(1 for i in range(0, len(rs), 2) if rs[i]["ep"] == rs[i+1]["ep"] and rs[i+1]["status"] == 200)' < "$EVID/e2.jsonl")
snap; h1=$(stat hit)
if [ "$same" = 6 ] && [ "$h1" -ge $((h0 + 6)) ] 2>/dev/null; then leg E2 PASS "6/6 turn-2 streams on turn 1's endpoint; hits $h0 -> $h1"
else leg E2 FAIL "turn 2 on turn 1's endpoint: $same/6; hit $h0 -> $h1"; fi

# MUX: conversations A and B learned on two endpoints (fresh connections,
# consecutive round robin picks); then their next turns as four streams on ONE
# connection, all sent before any answer: each stream decides for itself.
client $PORT_RR run "$(plan mx1 '[{"rid":"mx-A-t1","body":{"kind":"conv","conv":151,"turns":1}},{"rid":"mx-B-t1","body":{"kind":"conv","conv":152,"turns":1}}]')" | results > "$EVID/mux-1.jsonl"
snap; h0=$(stat hit)
client $PORT_RR mux "$(plan mx2 '[{"rid":"mx-A-t2","body":{"kind":"conv","conv":151,"turns":2}},{"rid":"mx-B-t2","body":{"kind":"conv","conv":152,"turns":2}},{"rid":"mx-A-t3","body":{"kind":"conv","conv":151,"turns":3}},{"rid":"mx-B-t3","body":{"kind":"conv","conv":152,"turns":3}}]')" | results > "$EVID/mux-2.jsonl"
snap; h1=$(stat hit)
A=$(jget 'rs[0]["ep"]' < "$EVID/mux-1.jsonl"); B=$(jget 'rs[1]["ep"]' < "$EVID/mux-1.jsonl")
okm=$(jget "len(rs) == 4 and len(set(r['stream'] for r in rs)) == 4 and all(r['status'] == 200 for r in rs) and [r['ep'] for r in rs] == ['$A', '$B', '$A', '$B']" < "$EVID/mux-2.jsonl")
ids=$(jget '" ".join("%s:%s:%s" % (r["rid"][3:], r["stream"], r["ep"]) for r in rs)' < "$EVID/mux-2.jsonl")
if [ "$A" != "$B" ] && [ "$okm" = True ] && [ "$h1" -ge $((h0 + 4)) ] 2>/dev/null; then leg MUX PASS "A on $A, B on $B; one connection, streams $ids; hit $h0 -> $h1"
else leg MUX FAIL "A on $A, B on $B; streams $ids; hit $h0 -> $h1"; fi

# RST: three streams on one connection, held 2 s at every endpoint; the
# client resets the second one only. The other two are answered.
for n in $EPS; do mock_admin "$n" /admin/delay/2000/3; done
b0=$(badlines)
client $PORT_RR mux "$(plan rst '[{"rid":"rst-1","body":{"kind":"conv","conv":171,"turns":1}},{"rid":"rst-2","rst":true,"body":{"kind":"conv","conv":172,"turns":1}},{"rid":"rst-3","body":{"kind":"conv","conv":173,"turns":1}}]')" | results > "$EVID/rst.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; done
sleep 3
b1=$(badlines); inf=$(inflight $PORT_RR)
okr=$(jget '[r["status"] for r in rs] == [200, 0, 200] and rs[1]["reset"] and not rs[0]["reset"] and not rs[2]["reset"]' < "$EVID/rst.jsonl")
if [ "$okr" = True ] && [ "$b1" = "$b0" ] && { [ "$inf" = 0 ] || [ "$inf" = n/a ]; }; then leg RST PASS "stream 2 reset by the client, 1 and 3 answered 200; underflow/notify-pin-FAIL lines $b0 -> $b1; in-flight $inf"
else leg RST FAIL "answers $(jget '[(r["status"], r["reset"]) for r in rs]' < "$EVID/rst.jsonl"); lines $b0 -> $b1; in-flight $inf"; fi

# E3-conv: a stream with x-conversation-id is pinned: counted, never scanned.
snap; p0=$(stat pinned); s0=$(stat scans)
client $PORT_RR run "$(plan e3c '[{"rid":"e3c-1","conv_id":"cv-1","body":{"kind":"conv","conv":201,"turns":1}},{"rid":"e3c-2","conv_id":"cv-1","body":{"kind":"conv","conv":201,"turns":2}}]')" | results > "$EVID/e3c.jsonl"
snap; p1=$(stat pinned); s1=$(stat scans)
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/e3c.jsonl")
if [ "$ok" = True ] && [ "$p1" = $(( $(z $p0) + 2 )) ] && [ "$s1" = "$s0" ]; then leg E3-conv PASS "2 streams with x-conversation-id: pinned $p0 -> $p1, scans unchanged ($s0)"
else leg E3-conv FAIL "200: $ok; pinned $p0 -> $p1; scans $s0 -> $s1"; fi

# E4: a short body and a miss, each under its own name.
snap; s0=$(stat scan.short); m0=$(stat miss)
client $PORT_RR run "$(plan e4 '[{"rid":"e4-short","body":{"kind":"short"}},{"rid":"e4-miss","body":{"kind":"conv","conv":301,"turns":1}}]')" | results > "$EVID/e4.jsonl"
snap; s1=$(stat scan.short); m1=$(stat miss)
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/e4.jsonl")
if [ "$ok" = True ] && [ "$s1" -ge $(( $(z $s0) + 1 )) ] && [ "$m1" -ge $((m0 + 1)) ] 2>/dev/null; then leg E4 PASS "scan.short $s0->$s1, miss $m0->$m1"
else leg E4 FAIL "200: $ok; scan.short $s0->$s1, miss $m0->$m1"; fi

# NOT-CHAT and NON-JSON: no scan, the selector's pick. The text/plain request
# names its model in x-model: without a JSON body the pool lookup has no
# other model to go by, and the stream is refused before any selection.
snap; n0=$(stat not_chat); b0=$(stat no_body); s0=$(stat scans)
client $PORT_RR run "$(plan nc '[{"rid":"nc-1","path":"/v1/completions","body":{"kind":"conv","conv":311,"turns":1}},{"rid":"nj-1","ctype":"text/plain","x_model":"rx-model","body":{"kind":"conv","conv":312,"turns":1}}]')" | results > "$EVID/nc.jsonl"
snap; n1=$(stat not_chat); b1=$(stat no_body); s1=$(stat scans)
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/nc.jsonl")
if [ "$ok" = True ] && [ "$n1" = $(( $(z $n0) + 1 )) ] && [ "$b1" = $(( $(z $b0) + 1 )) ] && [ "$s1" = "$s0" ]; then leg NOT-CHAT PASS "/v1/completions: not_chat $n0 -> $n1; text/plain: no_body $b0 -> $b1; scans unchanged ($s0)"
else leg NOT-CHAT FAIL "200: $ok; not_chat $n0 -> $n1; no_body $b0 -> $b1; scans $s0 -> $s1"; fi

# E5: a 500 is not learned; an SSE answer is.
for n in $EPS; do mock_admin "$n" /admin/status/500/1; done
snap; r0=$(stat learn.refused); k0=$(stat learn.ok)
client $PORT_RR run "$(plan e5a '[{"rid":"e5-500","body":{"kind":"conv","conv":401,"turns":1}}]')" | results > "$EVID/e5.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; done
client $PORT_RR run "$(plan e5b '[{"rid":"e5-sse","body":{"kind":"conv","conv":403,"turns":1,"stream":true}}]')" | results >> "$EVID/e5.jsonl"
snap; r1=$(stat learn.refused); k1=$(stat learn.ok)
ok=$(jget '[r["status"] for r in rs] == [500, 200] and rs[1]["sse"]' < "$EVID/e5.jsonl")
if [ "$ok" = True ] && [ "$r1" -ge $(( $(z $r0) + 1 )) ] && [ "$k1" -ge $((k0 + 1)) ] 2>/dev/null; then leg E5 PASS "500 relayed, not learned; SSE learned: refused $r0->$r1, ok $k0->$k1"
else leg E5 FAIL "500/SSE as sent: $ok; learn.refused $r0->$r1, learn.ok $k0->$k1"; fi

# E6: CHWBL pool, streams on kept connections and one reset: no underflow.
P6='['
for k in 1 2 3 4; do for t in 1 2 3 4 5; do
  P6="$P6{\"rid\":\"e6-k$k-$t\",\"conn\":\"c$k\",\"body\":{\"kind\":\"conv\",\"conv\":$((500 + k)),\"turns\":$t}},"
done; done
b0=$(badlines)
client $PORT_CHWBL run "$(plan e6a "${P6%,}]")" | results > "$EVID/e6.jsonl"
for n in $EPS; do mock_admin "$n" /admin/delay/1500/2; done
client $PORT_CHWBL mux "$(plan e6b '[{"rid":"e6-m1","body":{"kind":"conv","conv":511,"turns":1}},{"rid":"e6-m2","rst":true,"body":{"kind":"conv","conv":511,"turns":2}}]')" | results >> "$EVID/e6.jsonl"
for n in $EPS; do mock_admin "$n" /admin/reset; done
sleep 3
b1=$(badlines)
ok=$(jget 'sum(1 for r in rs if r["status"] == 200) == 21 and rs[-1]["reset"]' < "$EVID/e6.jsonl")
if [ "$ok" = True ] && [ "$b1" = "$b0" ]; then leg E6 PASS "21 CHWBL streams 200 on kept connections and one reset stream; underflow/notify-pin-FAIL lines $b0 -> $b1"
else leg E6 FAIL "streams as sent: $ok; lines $b0 -> $b1"; fi

# E6-move: on the CHWBL pool that admits one request per endpoint, a radix
# HIT on another endpoint than the CHWBL pick moves the stream's bounded-load
# unit, and an admission move after a HIT is noted. Y = CHWBL's pick for one
# system prompt (probe); while a slow stream holds Y, C1 and C2 (same system
# prompt) are moved off Y by admission and learned on X; once Y is free their
# next turns are CHWBL -> Y but radix -> X. Then X1 held: a HIT on X1 moved.
bgreq() {  # bgreq <name> <port> <plan-json>: one stream in the background, own connection
  plan "$1" "$3" >/dev/null
  docker exec -d "${P}h1" sh -c "python3 /opt/rxh2/h2_client.py $VIP $2 run /opt/out/$1.json > /opt/out/$1.jsonl"
}
u0=$(badlines)
client $PORT_MOVE run "$(plan m0 '[{"rid":"m-D-t1","body":{"kind":"conv","conv":951,"variant":1,"turns":1}}]')" | results > "$EVID/e6m-0.jsonl"
Y=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else ""' < "$EVID/e6m-0.jsonl")
if [ -n "$Y" ]; then
  mock_admin "$Y" /admin/delay/6000/1
  bgreq m1bg $PORT_MOVE '[{"rid":"m-D-t2-held","body":{"kind":"conv","conv":951,"variant":1,"turns":2}}]'
  sleep 1
  client $PORT_MOVE run "$(plan m2 '[{"rid":"m-C1-t1","body":{"kind":"conv","conv":951,"turns":1}},{"rid":"m-C2-t1","body":{"kind":"conv","conv":951,"variant":3,"turns":1}}]')" | results > "$EVID/e6m-2.jsonl"
  sleep 6; cp "$RUN/h1/m1bg.jsonl" "$EVID/e6m-1bg.jsonl" 2>/dev/null
  mock_admin "$Y" /admin/reset
  X1=$(jget 'rs[0]["ep"]' < "$EVID/e6m-2.jsonl")
  snap; mo0=$(stat moved)
  client $PORT_MOVE run "$(plan m4 '[{"rid":"m-C1-t2","body":{"kind":"conv","conv":951,"turns":2}},{"rid":"m-C2-t2","conn":"K","body":{"kind":"conv","conv":951,"variant":3,"turns":2}},{"rid":"m-C2-t3","conn":"K","body":{"kind":"conv","conv":951,"variant":3,"turns":3}}]')" | results > "$EVID/e6m-4.jsonl"
  mock_admin "$X1" /admin/delay/4000/1
  bgreq m6bg $PORT_MOVE '[{"rid":"m-C1-t4-held","body":{"kind":"conv","conv":951,"turns":4}}]'
  sleep 1
  client $PORT_MOVE run "$(plan m6 '[{"rid":"m-C1-t5-moved","body":{"kind":"conv","conv":951,"turns":5}}]')" | results > "$EVID/e6m-6.jsonl"
  sleep 5; cp "$RUN/h1/m6bg.jsonl" "$EVID/e6m-6bg.jsonl" 2>/dev/null
  mock_admin "$X1" /admin/reset
  sleep 3
  snap; mo1=$(stat moved)
fi
u1=$(badlines); infm=$(inflight $PORT_MOVE)
res=$(python3 - "$EVID" "${Y:-}" <<'PYEOF'
import json, sys
d, Y = sys.argv[1], sys.argv[2]
def rs(n):
    try:
        return [json.loads(l) for l in open("%s/e6m-%s.jsonl" % (d, n)) if l.startswith("{")]
    except OSError:
        return []
out, ok = [], bool(Y)
r1, r2, r4, r6, bg = rs("1bg"), rs(2), rs(4), rs(6), rs("6bg")
X1 = r2[0]["ep"] if r2 else None
X2 = r2[1]["ep"] if len(r2) > 1 else None
def need(cond, what):
    global ok
    out.append(("ok " if cond else "NO ") + what)
    ok = ok and bool(cond)
need(bool(Y), "probe: CHWBL pick Y=%s" % Y)
need(len(r1) == 1 and r1[0]["ep"] == Y and r1[0]["status"] == 200, "slow stream held Y: %s" % (r1[0]["ep"] if r1 else None))
need(X1 not in (None, Y) and X2 not in (None, Y) and all(r["status"] == 200 for r in r2), "C1, C2 moved off Y by admission and learned on %s, %s" % (X1, X2))
need(len(r4) == 3 and [r["ep"] for r in r4] == [X1, X2, X2] and all(r["status"] == 200 for r in r4),
     "radix off the CHWBL pick: fresh -> %s, one connection -> %s, %s" % tuple((r4 + [{"ep": None}] * 3)[k]["ep"] for k in range(3)))
need(len(bg) == 1 and bg[0]["ep"] == X1 and bg[0]["status"] == 200, "slow stream held X1: %s" % (bg[0]["ep"] if bg else None))
need(len(r6) == 1 and r6[0]["ep"] not in (None, X1) and r6[0]["status"] == 200, "admission moved the HIT off X1: %s" % (r6[0]["ep"] if r6 else None))
print(("PASS" if ok else "FAIL") + "|" + "; ".join(out))
PYEOF
)
verdict=${res%%|*}; detail=${res#*|}
if [ "$verdict" = PASS ] && [ "$u1" = "$u0" ] && [ "${mo1:-0}" -ge $(( $(z ${mo0:-0}) + 1 )) ] 2>/dev/null && { [ "$infm" = 0 ] || [ "$infm" = n/a ]; }; then
  leg E6-move PASS "$detail; underflow/notify-pin-FAIL lines $u0 -> $u1; moved ${mo0:-?} -> ${mo1:-?}; admission in-flight after: $infm"
else
  leg E6-move FAIL "$detail; lines $u0 -> $u1; moved ${mo0:-?} -> ${mo1:-?}; admission in-flight after: ${infm:-?}"
fi

# STICKY: a persistence pool is never overridden: pinned, not scanned.
snap; p0=$(stat pinned); s0=$(stat scans)
client $PORT_STICKY run "$(plan st '[{"rid":"st-1","body":{"kind":"conv","conv":601,"turns":1}},{"rid":"st-2","body":{"kind":"conv","conv":601,"turns":2}}]')" | results > "$EVID/sticky.jsonl"
snap; p1=$(stat pinned); s1=$(stat scans)
ok=$(jget 'all(r["status"] == 200 for r in rs)' < "$EVID/sticky.jsonl")
if [ "$ok" = True ] && [ "$p1" = $((p0 + 2)) ] && [ "$s1" = "$s0" ]; then leg STICKY PASS "pinned $p0 -> $p1, scans unchanged ($s0)"
else leg STICKY FAIL "200: $ok; pinned $p0 -> $p1; scans $s0 -> $s1"; fi

# E8: a body above 768 KiB: answered, counted inspect_size, not scanned.
snap; i0=$(stat inspect_size); s0=$(stat scans)
client $PORT_RR run "$(plan e8 '[{"rid":"e8-big","body":{"kind":"big","bytes":800000}}]')" | results > "$EVID/e8.jsonl"
snap; i1=$(stat inspect_size); s1=$(stat scans)
ok=$(jget 'rs[0]["status"] == 200' < "$EVID/e8.jsonl")
if [ "$ok" = True ] && [ "$i1" = $(( $(z $i0) + 1 )) ] && [ "$s1" = "$s0" ]; then leg E8 PASS "800 kB body answered; inspect_size $i0 -> $i1; scans unchanged"
else leg E8 FAIL "200: $ok; inspect_size $i0 -> $i1; scans $s0 -> $s1"; fi

# TOKENS: a body above 8,192 JSON tokens is routed by radix.
snap; s0=$(stat scans)
client $PORT_RR run "$(plan tk '[{"rid":"tk-1","body":{"kind":"tokens","n":2000}},{"rid":"tk-2","body":{"kind":"tokens","n":2000}}]')" | results > "$EVID/tokens.jsonl"
snap; s1=$(stat scans)
ok=$(jget 'all(r["status"] == 200 for r in rs) and rs[0]["ep"] == rs[1]["ep"]' < "$EVID/tokens.jsonl")
if [ "$ok" = True ] && [ "$s1" -ge $((s0 + 2)) ] 2>/dev/null; then leg TOKENS PASS "2,000-message body scanned, the second on the learned endpoint; scans $s0 -> $s1"
else leg TOKENS FAIL "200 and same endpoint: $ok; scans $s0 -> $s1"; fi

# GUARD legs, as in radix-h1: held streams sent one per second, each on its
# own connection, so each decision sees the earlier ones in flight.
hold4() {  # hold4 <tag> <ep> <conv>
  local i
  mock_admin "$2" /admin/delay/8000/4
  for i in 1 2 3 4; do
    bgreq "$1-h$i" $PORT_RR "[{\"rid\":\"$1-h$i\",\"body\":{\"kind\":\"conv\",\"conv\":$3,\"turns\":2}}]"
    sleep 1
  done
}
held() { cat "$RUN"/h1/$1-h1.jsonl "$RUN"/h1/$1-h2.jsonl "$RUN"/h1/$1-h3.jsonl "$RUN"/h1/$1-h4.jsonl 2>/dev/null | results; }
gu0=$(badlines)

client $PORT_RR run "$(plan gf1 '[{"rid":"gf-t1","body":{"kind":"conv","conv":821,"turns":1}}]')" | results > "$EVID/gf-1.jsonl"
X=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else ""' < "$EVID/gf-1.jsonl")
snap; gh0=$(stat hit); gs0=$(z $(stat balance))
if [ -n "$X" ]; then
  hold4 gf "$X" 821
  client $PORT_RR run "$(plan gf5 '[{"rid":"gf-5th","body":{"kind":"conv","conv":821,"turns":2}}]')" | results > "$EVID/gf-5.jsonl"
  sleep 9
  mock_admin "$X" /admin/reset
fi
snap; gh1=$(stat hit); gs1=$(z $(stat balance))
held gf > "$EVID/gf-held.jsonl"
okh=$(jget "len(rs) == 4 and all(r['ep'] == '$X' and r['status'] == 200 for r in rs)" < "$EVID/gf-held.jsonl" 2>/dev/null)
ep5=$(jget 'rs[0]["ep"] if rs and rs[0]["status"] == 200 else "none"' < "$EVID/gf-5.jsonl" 2>/dev/null)
detail="learned on ${X:-?}; held 4 on it: $okh; fifth answered by $ep5; hit $gh0 -> $gh1, spread $gs0 -> $gs1"
if [ -n "$X" ] && [ "$okh" = True ] && [ "$ep5" != none ] && [ "$gh1" = $((gh0 + 4)) ] && [ "$gs1" = $((gs0 + 1)) ] 2>/dev/null; then
  leg GUARD-FALLBACK PASS "$detail"
else
  leg GUARD-FALLBACK FAIL "$detail (want hit +4, spread +1)"
fi

client $PORT_RR run "$(plan ga1 '[{"rid":"ga-Y-t1","body":{"kind":"conv","conv":831,"turns":1}},{"rid":"ga-X-t1","body":{"kind":"conv","conv":832,"turns":1}}]')" | results > "$EVID/ga-1.jsonl"
Y=$(jget 'rs[0]["ep"] if rs[0]["status"] == 200 else ""' < "$EVID/ga-1.jsonl")
X=$(jget 'rs[1]["ep"] if rs[1]["status"] == 200 and rs[1]["ep"] != rs[0]["ep"] else ""' < "$EVID/ga-1.jsonl")
snap; ah0=$(stat hit); as0=$(z $(stat balance))
if [ -n "$Y" ] && [ -n "$X" ]; then
  hold4 ga "$Y" 831
  client $PORT_RR run "$(plan ga5 '[{"rid":"ga-X-t2","body":{"kind":"conv","conv":832,"turns":2}}]')" | results > "$EVID/ga-5.jsonl"
  sleep 9
  mock_admin "$Y" /admin/reset
fi
snap; ah1=$(stat hit); as1=$(z $(stat balance))
held ga > "$EVID/ga-held.jsonl"
okh=$(jget "len(rs) == 4 and all(r['ep'] == '$Y' and r['status'] == 200 for r in rs)" < "$EVID/ga-held.jsonl" 2>/dev/null)
epx=$(jget 'rs[0]["ep"] if rs and rs[0]["status"] == 200 else "none"' < "$EVID/ga-5.jsonl" 2>/dev/null)
detail="Y=${Y:-?} X=${X:-?}; held 4 on Y: $okh; X's prefix answered by $epx; hit $ah0 -> $ah1, spread $as0 -> $as1"
if [ -n "$X" ] && [ "$okh" = True ] && [ "$epx" = "$X" ] && [ "$ah1" = $((ah0 + 5)) ] && [ "$as1" = "$as0" ] 2>/dev/null; then
  leg GUARD-RULES-APART PASS "$detail"
else
  leg GUARD-RULES-APART FAIL "$detail (want X, hit +5, spread +0)"
fi

# QUIESCE: after everything, in-flight back to 0 on every pool used, and no
# underflow or notify-pin-FAIL line in the whole run.
sleep 2
allbad=$(badlines)
infs=""; zero=1
for p in $PORT_RR $PORT_CHWBL $PORT_MOVE $PORT_STICKY; do
  v=$(inflight $p); infs="$infs :$p=$v"
  { [ "$v" = 0 ] || [ "$v" = n/a ]; } || zero=0
done
if [ "$allbad" = 0 ] && [ "$zero" = 1 ]; then leg QUIESCE PASS "admission in-flight$infs; underflow + notify-pin-FAIL lines in the run: 0"
else leg QUIESCE FAIL "admission in-flight$infs; underflow + notify-pin-FAIL lines: $allbad"; fi

# E9: no request text in the gateway logs (debug level).
MARK=RX6MARKER7Q
client $PORT_RR run "$(plan e9 "[{\"rid\":\"e9-1\",\"body\":{\"kind\":\"marker\",\"marker\":\"$MARK\"}}]")" | results > "$EVID/e9.jsonl"
sleep 1
nmark=$(gw_log | grep -c "$MARK")
if [ "$nmark" = 0 ]; then leg E9 PASS "marker absent from the gateway logs"
else leg E9 FAIL "marker in $nmark gateway log line(s)"; fi

leg COOKIE INFO "cookie pin not driven here: it needs an L7 policy with HTTP_COOKIE persistence; covered by the source check in test_radix_wiring (listed as a gap)"
docker exec "${P}llb1" sh -c 'cp /var/log/loxilbdp.log /opt/radix-s4/loxilbdp-end.log 2>/dev/null; true'
nst=$(stats_lines | wc -l)
leg STATS INFO "[RADIX_STATS] lines in the gateway log: $nst"
say "legs: $(grep -c ' PASS ' "$LEGS") PASS, $(grep -c ' FAIL ' "$LEGS") FAIL, $(grep -c ' INFO ' "$LEGS") INFO"
! grep -q ' FAIL ' "$LEGS"
