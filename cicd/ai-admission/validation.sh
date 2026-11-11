#!/bin/bash
# Validates the capacity admission gate (see README.md for the row table).
source ../common.sh
source ./gw.sh
echo SCENARIO-ai-admission

require_host_tools jq curl python3 || { echo "SCENARIO-ai-admission [FAILED]"; exit 1; }

code=0; npass=0; nfail=0
chk() { # chk <id> <what> <want> <got>
  if [ "$3" == "$4" ]; then echo "  [PASS] $1 $2 ($4)"; npass=$((npass+1))
  else echo "  [FAIL] $1 $2: want '$3', got '$4'"; nfail=$((nfail+1)); code=1; fi
}
chk_has() { # chk_has <id> <what> <needle> <haystack>
  case "$4" in
    *"$3"*) echo "  [PASS] $1 $2"; npass=$((npass+1)) ;;
    *) echo "  [FAIL] $1 $2: '$3' not found in: $(printf '%s' "$4" | tr '\n' ' ' | cut -c1-200)"; nfail=$((nfail+1)); code=1 ;;
  esac
}
chk_le() { # chk_le <id> <what> <max> <got>
  if [ "$4" != "unreadable" ] && [ "$4" -le "$3" ] 2>/dev/null; then echo "  [PASS] $1 $2 ($4 <= $3)"; npass=$((npass+1))
  else echo "  [FAIL] $1 $2: want <= $3, got '$4'"; nfail=$((nfail+1)); code=1; fi
}
chk_ge() { # chk_ge <id> <what> <min> <got>
  if [ "$4" != "unreadable" ] && [ "$4" -ge "$3" ] 2>/dev/null; then echo "  [PASS] $1 $2 ($4 >= $3)"; npass=$((npass+1))
  else echo "  [FAIL] $1 $2: want >= $3, got '$4'"; nfail=$((nfail+1)); code=1; fi
}

# ── the gateway's metrics (from the client host, through the VIP) ───────────
metrics_raw() { $hexec l3h1 curl -s --max-time 8 "$API/metrics" 2>/dev/null; }
# msum <family> [label-substr ...] -> the sum of the family's samples whose
# line carries every given substring, or "unreadable" when the scrape failed.
msum() {
  local fam="$1"; shift
  local body
  body=$(metrics_raw)
  case "$body" in *loxilb_*) ;; *) echo "unreadable"; return ;; esac
  printf '%s\n' "$body" | awk -v fam="$fam" -v a="${1:-}" -v b="${2:-}" -v c="${3:-}" '
    $0 ~ "^" fam "([{ ]|$)" {
      if (a != "" && index($0, a) == 0) next
      if (b != "" && index($0, b) == 0) next
      if (c != "" && index($0, c) == 0) next
      v = $NF; if (v + 0 == v) { s += v }
    }
    END { printf "%.0f", s + 0 }'
}
# The collector republishes its store every 10 s, so a gauge is read by
# polling for the expected value, and the last value read is what the
# assertion reports on a timeout.
wait_metric() { # wait_metric <family> <want> <secs> [label-substr ...]
  local fam="$1" want="$2" secs="$3" got="" i; shift 3
  for i in $(seq 1 "$secs"); do
    got=$(msum "$fam" "$@")
    [ "$got" == "$want" ] && { echo "$got"; return; }
    sleep 1
  done
  echo "$got"
}
wait_metric_ge() { # wait_metric_ge <family> <min> <secs> [label-substr ...]
  local fam="$1" want="$2" secs="$3" got="" i; shift 3
  for i in $(seq 1 "$secs"); do
    got=$(msum "$fam" "$@")
    [ "$got" != "unreadable" ] && [ "$got" -ge "$want" ] 2>/dev/null && { echo "$got"; return; }
    sleep 1
  done
  echo "$got"
}
svc() { echo "service=\"$VIP:$1\""; }
inflight() { msum loxilb_ai_admission_inflight "$(svc "$1")" 'role="service"'; }
queued() { msum loxilb_ai_admission_queued "$(svc "$1")"; }
decisions() { msum loxilb_ai_admission_decisions_total "$(svc "$1")" "reason=\"$2\""; }
# Every refusal is also one request in loxilb_ai_requests_total{outcome="denied"},
# with the status the client got, and one response in the class counter (pulled
# every 10 s, so read by polling). Neither family is per service: a block reads
# them around its own requests only.
denied() { msum loxilb_ai_requests_total 'outcome="denied"' "status=\"$1\""; }
klass() { msum loxilb_proxy_http_responses_by_status_total "status_class=\"$1\""; }
denied_delta() { # denied_delta <status> <before> <n>
  echo $(( $(wait_metric loxilb_ai_requests_total $(($2+$3)) 25 'outcome="denied"' "status=\"$1\"") - $2 ))
}
# A refusal is never also a completion: no outcome="completed" with its status.
completed() { msum loxilb_ai_requests_total 'outcome="completed"' "status=\"$1\""; }
# A baseline read just after an earlier block's answers can miss the ones the
# next pull has yet to carry: it is taken once the counter has held still for
# a whole pull period.
klass_settled() { # klass_settled <class>
  local a b i
  b=$(klass "$1")
  for i in 1 2 3; do
    a="$b"; sleep 11; b=$(klass "$1")
    [ "$a" == "$b" ] && break
  done
  echo "$b"
}
klass_delta() { # klass_delta <class> <before> <n>
  echo $(( $(wait_metric loxilb_proxy_http_responses_by_status_total $(($2+$3)) 25 "status_class=\"$1\"") - $2 ))
}
# The gateway log lives at /var/log/loxilb<hostname>.log inside the container:
# always read it through the glob, and let the caller check it is non-empty.
gw_log() { docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null'; }
lb_get() { $hexec l3h1 curl -s -m 8 "$API/config/loadbalancer/all" | jq -c ".lbAttr[] | select(.serviceArguments.port == $1)"; }
# A rule is deleted by its FULL key: an AI rule carries host, path prefix, match
# mode and model name, and a delete that omits any of them matches nothing
# (404 no-rule error) while the rule and its waiters live on.
lb_delete() { $hexec l3h1 curl -s -m 8 -X DELETE "$API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$1/protocol/tcp?path_prefix=%2F&path_match_mode=prefix&model_name=${MODEL:-cap-model}"; }
# The data plane's live queued count through the rule's read-back: unlike the
# collector's 10 s store this reads the pool now, so a short wait can be seen.
wait_effective_queued() { # wait_effective_queued <port> <want> <secs>
  local got="" i
  for i in $(seq 1 $(( $3 * 2 ))); do
    got=$(lb_get "$1" | jq -r '.serviceArguments.fc_effective.queued // 0' 2>/dev/null)
    [ "$got" == "$2" ] && { echo "$got"; return; }
    sleep 0.5
  done
  echo "$got"
}
# A rule field read back until it holds a value: a replace POST reaches the
# data plane through the broker's queue, so a GET right after it may still
# see the old value.
wait_lb_field() { # wait_lb_field <port> <jq path> <want> <secs>
  local got="" i
  for i in $(seq 1 $(( $4 * 2 ))); do
    got=$(lb_get "$1" | jq -r "$2 // \"unreadable\"" 2>/dev/null)
    [ "$got" == "$3" ] && { echo "$got"; return; }
    sleep 0.5
  done
  echo "$got"
}
maint_put() { $hexec l3h1 curl -s -m 8 -X PUT "$API/maintenance" -H 'Content-Type: application/json' -d "{\"enabled\": $1}"; }
maint_get() { $hexec l3h1 curl -s -m 8 "$API/maintenance"; }

# ── the backends (from inside their namespace, never through the gateway) ───
be() { $hexec l3ep1 curl -s -m 5 "http://127.0.0.1:8080/$1" 2>/dev/null; }
receipts() { be "__receipts/$1" | jq -r '.count // "unreadable"'; }
order() { be "__order/$1" | jq -r '.order | join(" ")'; }
release() { be "__release/$1" >/dev/null; }
peak() { be "__peak/$1" | jq -r '.peak // "unreadable"'; }
peak_port() { be "__peak/$1" | jq -r ".ports[\"$2\"] // 0"; }
release_all() { be __release_all >/dev/null; }
wait_receipts() { # wait_receipts <nonce> <want> <secs>
  local got i
  for i in $(seq 1 "$3"); do got=$(receipts "$1"); [ "$got" == "$2" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
h2_receipts() { # sum of the h2c backends' receipts for <prefix>-0..<n-1>
  local prefix=$1 n=$2 s=0 i p c
  for i in $(seq 0 $((n-1))); do
    for p in 8090 8091; do
      c=$($hexec l3ep1 curl -s -m 3 --http2-prior-knowledge "http://127.0.0.1:$p/__receipts/$prefix-$i" 2>/dev/null)
      case "$c" in ''|*[!0-9]*) ;; *) s=$((s + c)) ;; esac
    done
  done
  echo "$s"
}

# ── the audit trail ─────────────────────────────────────────────────────────
trail() {
  docker exec llb1 sh -c "cd '$AUDIT_DIR' 2>/dev/null || exit 0; for f in *.jsonl; do [ -f \"\$f\" ] && cat \"\$f\"; done; for f in *.jsonl.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done" 2>/dev/null \
    | jq -c -R 'fromjson? | select(type=="object" and .event_type != null)'
}
denies_for() { trail | jq -c "select(.event_type==\"sec.ai.deny\" and (.request_id|startswith(\"$1\")))"; }

# ── drivers ─────────────────────────────────────────────────────────────────
BODY='{"model":"cap-model","messages":[{"role":"user","content":"x"}]}'
HDRS=(-H 'Content-Type: application/json')
# hold_burst <dir> <n> <nonce> <url> [curl args...]: n parallel requests the
# backend holds until released; each request's status lands in <dir>/<i>.code
# once it completes, its headers in <dir>/<i>.hdr.
hold_burst() {
  local dir=$1 n=$2 nonce=$3 url=$4 i; shift 4
  for i in $(seq 1 "$n"); do
    $hexec l3h1 curl -s -o "$dir/$i.body" -D "$dir/$i.hdr" -w '%{http_code}' --max-time 120 \
      "${HDRS[@]}" -H 'X-Test-Hold: 1' -H "X-Test-Nonce: $nonce" -H "X-Request-Id: $nonce-$i" \
      "$@" -d "$BODY" "$url" > "$dir/$i.code" 2>/dev/null &
  done
}
# hold_each <dir> <n> <nonce> <url>: like hold_burst, but every request has its
# own nonce (<nonce><i>) so the holds can be released one at a time.
hold_each() {
  local dir=$1 n=$2 nonce=$3 url=$4 i
  for i in $(seq 1 "$n"); do
    $hexec l3h1 curl -s -o "$dir/h$i.body" -D "$dir/h$i.hdr" -w '%{http_code}' --max-time 120 \
      "${HDRS[@]}" -H 'X-Test-Hold: 1' -H "X-Test-Nonce: $nonce$i" -H "X-Request-Id: $nonce$i" \
      -d "$BODY" "$url" > "$dir/h$i.code" 2>/dev/null &
  done
}
sum_receipts() { # sum_receipts <nonce> <n>: receipts of <nonce>1..<nonce><n>
  local s=0 i c
  for i in $(seq 1 "$2"); do c=$(receipts "$1$i"); case "$c" in ''|*[!0-9]*) ;; *) s=$((s + c)) ;; esac; done
  echo "$s"
}
wait_sum_receipts() { # wait_sum_receipts <nonce> <n> <want> <secs>
  local got i
  for i in $(seq 1 "$4"); do got=$(sum_receipts "$1" "$2"); [ "$got" == "$3" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
# queue_burst <dir> <n> <nonce> <url>: n requests sent one at a time, 300 ms
# apart, so their arrival order at the gateway is their number; nothing holds
# them at the backend, so once admitted each completes at once.
queue_burst() {
  local dir=$1 n=$2 nonce=$3 url=$4 i
  for i in $(seq 1 "$n"); do
    $hexec l3h1 curl -s -o "$dir/q$i.body" -D "$dir/q$i.hdr" -w '%{http_code}' --max-time 60 \
      "${HDRS[@]}" -H "X-Test-Nonce: $nonce" -H "X-Request-Id: $nonce-$i" \
      -d "$BODY" "$url" > "$dir/q$i.code" 2>/dev/null &
    sleep 0.3
  done
}
count_codes() { # count_codes <dir> <code>
  local dir=$1 want=$2 n=0 f
  for f in "$dir"/*.code; do [ -f "$f" ] && [ "$(cat "$f" 2>/dev/null)" == "$want" ] && n=$((n+1)); done
  echo "$n"
}
wait_codes() { # wait_codes <dir> <code> <want> <secs>
  local got i
  for i in $(seq 1 "$4"); do got=$(count_codes "$1" "$2"); [ "$got" == "$3" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
first_hdr_with() { # first_hdr_with <dir> <code> -> that response's headers
  local f
  for f in "$1"/*.code; do
    [ "$(cat "$f" 2>/dev/null)" == "$2" ] && { cat "${f%.code}.hdr"; return; }
  done
}
hdr_val() { printf '%s' "$1" | grep -i "^$2:" | head -n1 | cut -d: -f2- | tr -d ' \r'; }

H1_URL="http://$VIP:$PORT_H1/v1/chat/completions"
TLS_URL="https://$VIP:$PORT_TLS/v1/chat/completions"
Q_URL="http://$VIP:$PORT_Q/v1/chat/completions"

echo ""
echo "Pre: the gate is on and exported"
chk P1 "the pool reports enforce mode" 2 "$(wait_metric loxilb_ai_admission_mode 2 25 "$(svc $PORT_H1)")"
chk P2 "service ceiling exported"     "$FC_MAX_OUT" "$(msum loxilb_ai_admission_limit "$(svc $PORT_H1)" 'role="service"')"
chk P3 "endpoint ceiling exported"    "$FC_EP_CAP"  "$(msum loxilb_ai_admission_limit "$(svc $PORT_H1)" 'role="normal"')"
chk P4 "nothing in flight"            0 "$(inflight $PORT_H1)"
chk P5 "no anomaly yet"               0 "$(msum loxilb_ai_admission_anomalies_total)"

# ── A: below the ceiling ────────────────────────────────────────────────────
echo ""
echo "A: below the ceiling, requests pass and the gauge returns to zero"
adm0=$(decisions $PORT_H1 admitted)
ok=0
for i in 1 2 3 4; do
  c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${HDRS[@]}" \
        -H 'X-Test-Nonce: capA' -d "$BODY" "$H1_URL")
  [ "$c" == "200" ] && ok=$((ok+1))
done
chk A1 "four sequential requests answered 200" 4 "$ok"
chk A2 "four reached the backend"              4 "$(receipts capA)"
chk A3 "admitted decisions moved by four"      4 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((adm0+4)) 25 "$(svc $PORT_H1)" 'reason="admitted"') - adm0 ))"
chk A4 "gauge back to zero"                    0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── B: at the ceiling ───────────────────────────────────────────────────────
echo ""
echo "B: 12 held requests against a ceiling of $FC_MAX_OUT"
shed0=$(decisions $PORT_H1 capacity_shed); adm0=$(decisions $PORT_H1 admitted)
den0=$(denied 429); cmp0=$(completed 429); k4=$(klass_settled 4xx); k2=$(klass_settled 2xx)
DB=$(mktemp -d)
hold_burst "$DB" 12 capB "$H1_URL"
chk B1 "exactly $FC_MAX_OUT reached the backend"      "$FC_MAX_OUT" "$(wait_receipts capB $FC_MAX_OUT 15)"
chk B2 "the other four were refused with 429"        4 "$(wait_codes "$DB" 429 4 15)"
sleep 2
chk B3 "and none of them arrived later"              "$FC_MAX_OUT" "$(receipts capB)"
chk B4 "gauge shows $FC_MAX_OUT executing"           "$FC_MAX_OUT" "$(wait_metric loxilb_ai_admission_inflight $FC_MAX_OUT 25 "$(svc $PORT_H1)" 'role="service"')"
H=$(first_hdr_with "$DB" 429)
chk B5 "refusal carries the ceiling"                 "$FC_MAX_OUT" "$(hdr_val "$H" X-Loxilb-Admission-Limit)"
chk B6 "and the in-flight count"                     "$FC_MAX_OUT" "$(hdr_val "$H" X-Loxilb-Admission-Inflight)"
chk B7 "and an empty queue"                          0 "$(hdr_val "$H" X-Loxilb-Admission-Queued)"
chk B8 "and Retry-After"                             1 "$(hdr_val "$H" Retry-After)"
f=$(grep -l '^429$' "$DB"/*.code | head -n1); chk_has B9 "refusal body names the reason" admission_capacity "$(cat "${f%.code}.body" 2>/dev/null)"
chk_has B10 "with a jitter hint" jitter_hint_ms "$(cat "${f%.code}.body" 2>/dev/null)"
release_all; wait
chk B11 "the eight held requests completed 200"      "$FC_MAX_OUT" "$(count_codes "$DB" 200)"
chk B12 "gauge back to zero"                         0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
chk B13 "capacity_shed decisions moved by four"      4 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((shed0+4)) 25 "$(svc $PORT_H1)" 'reason="capacity_shed"') - shed0 ))"
chk B14 "admitted decisions moved by eight"          "$FC_MAX_OUT" "$(( $(decisions $PORT_H1 admitted) - adm0 ))"
chk B15 "requests_total{denied,429} moved by four"   4 "$(denied_delta 429 "$den0" 4)"
chk B16 "the 4xx class moved by four"                4 "$(klass_delta 4xx "$k4" 4)"
chk B16a "and none of the four counted as completed"  0 "$(( $(completed 429) - cmp0 ))"
chk B17 "the 2xx class moved by the eight served"    "$FC_MAX_OUT" "$(klass_delta 2xx "$k2" "$FC_MAX_OUT")"

# ── N: the endpoint ceiling ─────────────────────────────────────────────────
echo ""
echo "N: 12 held requests on a one-endpoint pool, endpoint ceiling $FC_EP_CAP"
DN=$(mktemp -d)
hold_burst "$DN" 12 capN "http://$VIP:$PORT_ONE/v1/chat/completions"
chk N1 "exactly $FC_EP_CAP reached the endpoint"      "$FC_EP_CAP" "$(wait_receipts capN $FC_EP_CAP 15)"
chk N2 "the other seven were refused with 429"       7 "$(wait_codes "$DN" 429 7 15)"
sleep 2
chk N3 "and none of them arrived later"              "$FC_EP_CAP" "$(receipts capN)"
H=$(first_hdr_with "$DN" 429)
chk N4 "refusal names the endpoint ceiling"          "$FC_EP_CAP" "$(hdr_val "$H" X-Loxilb-Admission-Limit)"
chk N5 "endpoint gauge shows $FC_EP_CAP executing"   "$FC_EP_CAP" "$(wait_metric loxilb_ai_admission_inflight $FC_EP_CAP 25 "$(svc $PORT_ONE)" 'role="normal"')"
release_all; wait
chk N6 "the five held requests completed 200"        "$FC_EP_CAP" "$(count_codes "$DN" 200)"
chk N7 "gauges back to zero"                         0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_ONE)")"

# ── C: concurrent acquisition ───────────────────────────────────────────────
echo ""
echo "C: 64 simultaneous requests, ceiling $FC_MAX_OUT: the backend never sees more than $FC_MAX_OUT at once"
DC=$(mktemp -d)
for i in $(seq 1 64); do
  $hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 60 "${HDRS[@]}" \
    -H 'X-Test-Delay-Ms: 2000' -H 'X-Test-Nonce: capC' -H "X-Request-Id: capC-$i" \
    -d "$BODY" "$H1_URL" > "$DC/$i.code" 2>/dev/null &
done
wait
n200=$(count_codes "$DC" 200); n429=$(count_codes "$DC" 429)
chk C1 "every request was answered 200 or 429"       64 "$((n200 + n429))"
chk C2 "peak concurrency at the backend == ceiling"  "$FC_MAX_OUT" "$(peak capC)"
chk_le C3 "endpoint :8080 never over its ceiling"    "$FC_EP_CAP" "$(peak_port capC 8080)"
chk_le C4 "endpoint :8081 never over its ceiling"    "$FC_EP_CAP" "$(peak_port capC 8081)"
chk C5 "receipts == admitted answers"                "$n200" "$(receipts capC)"
chk C6 "gauge back to zero"                          0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── D: keep-alive, one unit per request ─────────────────────────────────────
echo ""
echo "D: five requests on one keep-alive connection"
out=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}:%{num_connects}\n' --max-time 30 "${HDRS[@]}" \
        -H 'X-Test-Nonce: capD' -d "$BODY" "$H1_URL" -o /dev/null "$H1_URL" -o /dev/null "$H1_URL" \
        -o /dev/null "$H1_URL" -o /dev/null "$H1_URL")
chk D1 "five answers, one connection"  "200:1 200:0 200:0 200:0 200:0" "$(printf '%s' "$out" | tr '\n' ' ' | sed 's/ $//')"
chk D2 "five receipts"                 5 "$(receipts capD)"
chk D3 "gauge back to zero"            0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── E: HTTP/2, one unit per stream, released by RST_STREAM ──────────────────
echo ""
echo "E: 12 HTTP/2 streams on one connection, 3 cancelled mid-flight"
E=$(mktemp -d)
$hexec l3h1 python3 "$(pwd)/h2_admit.py" $VIP $PORT_H2 --streams 12 --delay-ms 40000 \
  --rst 3 --rst-after-s 15 --nonce-prefix capE > "$E/out" 2> "$E/err" &
sleep 2
chk E1 "gauge counts streams, not the connection" "$FC_MAX_OUT" "$(wait_metric loxilb_ai_admission_inflight $FC_MAX_OUT 25 "$(svc $PORT_H2)" 'role="service"')"
chk E2 "three cancelled streams handed their units back" $((FC_MAX_OUT-3)) "$(wait_metric loxilb_ai_admission_inflight $((FC_MAX_OUT-3)) 30 "$(svc $PORT_H2)" 'role="service"')"
wait
S=$(grep '"summary"' "$E/out" | head -n1)
chk E3 "four streams refused on their own stream" 4 "$(printf '%s' "$S" | jq -r '.refused')"
chk E4 "five streams answered 200"                5 "$(printf '%s' "$S" | jq -r '.admitted')"
chk E5 "three streams cancelled while live"       3 "$(printf '%s' "$S" | jq -r '.rst')"
chk E6 "no stream left unanswered"                0 "$(printf '%s' "$S" | jq -r '.other')"
chk E7 "a refused stream carries the ceiling"     "$FC_MAX_OUT" "$(grep '"429"' "$E/out" | head -n1 | jq -r '.headers["x-loxilb-admission-limit"] // empty')"
chk E8 "eight streams reached the h2c backends"   "$FC_MAX_OUT" "$(h2_receipts capE 12)"
chk E9 "gauge back to zero"                       0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H2)" 'role="service"')"

# ── F: the client vanishes while executing ──────────────────────────────────
echo ""
echo "F: four executing clients reset their connections"
$hexec l3h1 python3 "$(pwd)/h1_client.py" disconnect $VIP $PORT_H1 --n 4 --after-s 3 --nonce-prefix capF > /tmp/ai-admission-F.out 2>&1
chk F1 "all four had reached the backend" 4 "$(( $(receipts capF-0) + $(receipts capF-1) + $(receipts capF-2) + $(receipts capF-3) ))"
chk F2 "gauge back to zero with the backend still holding" 0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
release_all

# ── G + I: a kept backend leg is re-gated; a model listing bypasses capacity ─
echo ""
echo "G: the second request on a kept connection is gated like the first"
SIG=$(pwd)/.h1_signal; rm -f "$SIG"
$hexec l3h1 python3 "$(pwd)/h1_client.py" kept $VIP $PORT_H1 --signal "$SIG" --nonce-prefix capG --timeout 90 > /tmp/ai-admission-G.out 2>&1 &
for i in $(seq 1 20); do grep -q '"status": "200"' /tmp/ai-admission-G.out 2>/dev/null && break; sleep 1; done
chk G1 "first request on the connection answered 200" 1 "$(grep -c '"status": "200"' /tmp/ai-admission-G.out)"
DG=$(mktemp -d)
hold_burst "$DG" $FC_MAX_OUT capGfill "$H1_URL"
chk G2 "pool filled to the ceiling" "$FC_MAX_OUT" "$(wait_receipts capGfill $FC_MAX_OUT 15)"
echo "I: a model listing while the pool is full"
byp0=$(decisions $PORT_H1 bypass_non_inference)
# The pool is keyed by model, so a listing names it the way a client without a
# body can (X-Model); the gate then sees a non-inference request on that pool.
c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H 'X-Test-Nonce: capI' -H "X-Model: $MODEL" "http://$VIP:$PORT_H1/v1/models")
chk I1 "GET /v1/models answered 200 with the pool full" 200 "$c"
chk I2 "and reached the backend"                        1 "$(receipts capI)"
chk I3 "counted as a bypass, not an admission"          1 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((byp0+1)) 25 "$(svc $PORT_H1)" 'reason="bypass_non_inference"') - byp0 ))"
touch "$SIG"
for i in $(seq 1 30); do grep -q '"summary": "kept"' /tmp/ai-admission-G.out 2>/dev/null && break; sleep 1; done
chk G3 "second request on the SAME connection refused" 429 "$(grep '"summary": "kept"' /tmp/ai-admission-G.out | jq -r '.second')"
chk G4 "on the kept connection"                        true "$(grep '"summary": "kept"' /tmp/ai-admission-G.out | jq -r '.reused')"
chk G5 "and it never reached the backend"              0 "$(receipts capG-second)"
release_all; wait; rm -f "$SIG"
chk G6 "gauge back to zero" 0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"

# ── K: the refusals are on the audit trail ──────────────────────────────────
echo ""
echo "K: every capacity refusal is a sec.ai.deny record"
for i in $(seq 1 20); do [ "$(denies_for capB- | wc -l | tr -d ' ')" == "4" ] && break; sleep 1; done
D=$(denies_for capB-)
chk K1 "four deny records for the four 429s of B"  4 "$(printf '%s\n' "$D" | grep -c .)"
chk K2 "every one names the capacity stage"        4 "$(printf '%s\n' "$D" | jq -r '.detail.stage' | grep -c '^capacity$')"
chk K3 "with the status the client got"            4 "$(printf '%s\n' "$D" | jq -r '.outcome.status' | grep -c '^429$')"
chk K4 "an admission reason"                       4 "$(printf '%s\n' "$D" | jq -r '.outcome.reason' | grep -c '^admission$')"
chk K5 "the decision the body carried"             4 "$(printf '%s\n' "$D" | jq -r '.detail.decision' | grep -c '^admission_capacity$')"
chk K6 "the service"                               4 "$(printf '%s\n' "$D" | jq -r '.detail.service' | grep -c "^$VIP:$PORT_H1\$")"
chk K7 "and the model"                             4 "$(printf '%s\n' "$D" | jq -r '.detail.model' | grep -c "^$MODEL\$")"
chk K8 "security class, data stream"               4 "$(printf '%s\n' "$D" | jq -r '.class + "/" + .stream' | grep -c '^security/data$')"
chk K9 "admitted requests produced no deny record" 0 "$(denies_for capA | wc -l | tr -d ' ')"

# ── L: the TLS listener ─────────────────────────────────────────────────────
echo ""
echo "L: refusals and the reaper's stream cap are TLS records on a TLS listener"
DL=$(mktemp -d)
hold_burst "$DL" $FC_MAX_OUT capL "$TLS_URL" -k
chk L1 "TLS pool filled to the ceiling" "$FC_MAX_OUT" "$(wait_receipts capL $FC_MAX_OUT 20)"
c=$($hexec l3h1 curl -sk -o "$DL/x.body" -D "$DL/x.hdr" -w '%{http_code}' --max-time 20 "${HDRS[@]}" \
      -H 'X-Test-Nonce: capLx' -H 'X-Request-Id: capLx-1' -d "$BODY" "$TLS_URL"); rc=$?
chk L2 "the ninth request read a 429 through TLS"   429 "$c"
chk L3 "curl completed the TLS exchange (exit 0)"    0 "$rc"
chk L4 "the refusal carries the ceiling"            "$FC_MAX_OUT" "$(hdr_val "$(cat "$DL/x.hdr")" X-Loxilb-Admission-Limit)"
chk L5 "and never reached the backend"              0 "$(receipts capLx)"
release_all; wait
chk L6 "eight held TLS requests completed 200"      "$FC_MAX_OUT" "$(count_codes "$DL" 200)"
chk L7 "gauge back to zero"                         0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_TLS)" 'role="service"')"
echo "   an SSE stream that outlives the rule's ${SSE_CAP_SEC}s cap is ended by the reaper thread"
sse_log0=$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep -c 'SSE_CAP')
$hexec l3h1 curl -sk -N --max-time 25 "${HDRS[@]}" -H 'X-Test-Forever: 1' -H 'X-Test-Nonce: capLsse' \
  -d '{"model":"cap-model","stream":true,"messages":[{"role":"user","content":"x"}]}' "$TLS_URL" \
  > "$DL/sse.out" 2> "$DL/sse.err"; rc=$?
chk_has L8 "the client read the cap event through TLS" max_stream_duration_exceeded "$(cat "$DL/sse.out")"
chk L9 "the stream ended before the client's own deadline (curl exit 28 = it did not)" 0 "$([ "$rc" == "28" ] && echo 1 || echo 0)"
chk_has L10 "the reaper cut the stream" "1" "$([ "$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep -c 'SSE_CAP')" -gt "$sse_log0" ] && echo 1 || echo 0)"
chk_has L11 "and the socket's owner worker wrote the event" "written by the owner worker" \
  "$(docker exec llb1 sh -c 'cat /var/log/loxilb*.log 2>/dev/null' | grep '\[REAPER\]' | tail -n1)"
echo "   (curl exit $rc; stderr: $(head -c 160 "$DL/sse.err" | tr '\n' ' '))"

# ── J: the export before the reboot ─────────────────────────────────────────
echo ""
echo "J: the gate's accounting stayed consistent"
chk J1 "no accounting anomaly (underflow)"      0 "$(msum loxilb_ai_admission_anomalies_total 'kind="underflow"')"
chk J2 "no accounting anomaly (unknown permit)" 0 "$(msum loxilb_ai_admission_anomalies_total 'kind="unknown_permit"')"
chk J3 "no request was refused for no capacity" 0 "$(msum loxilb_ai_admission_decisions_total 'reason="no_healthy_capacity"')"
chk J4 "every pool is exported"                16 "$(metrics_raw | grep -c '^loxilb_ai_admission_mode{')"

# ── Q: the bounded queue, FIFO ──────────────────────────────────────────────
echo ""
echo "Q: 8 held on the queue pool, 4 wait in order, 2 more are refused"
q0=$(decisions $PORT_Q queued); qf0=$(decisions $PORT_Q queue_full); adm0=$(decisions $PORT_Q admitted)
wc0=$(msum loxilb_ai_admission_queue_wait_seconds_count "$(svc $PORT_Q)")
den0=$(denied 429); cmp0=$(completed 429); k4=$(klass_settled 4xx)
DQ=$(mktemp -d)
hold_each "$DQ" $FC_MAX_OUT capQh "$Q_URL"
chk Q1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_sum_receipts capQh $FC_MAX_OUT $FC_MAX_OUT 15)"
queue_burst "$DQ" $FC_Q_DEPTH capQq "$Q_URL"
chk Q2 "queued gauge shows $FC_Q_DEPTH waiting"        "$FC_Q_DEPTH" "$(wait_metric loxilb_ai_admission_queued $FC_Q_DEPTH 25 "$(svc $PORT_Q)")"
chk Q3 "none of them reached the backend"              0 "$(receipts capQq)"
chk Q4 "the depth is exported as the queue limit"      "$FC_Q_DEPTH" "$(msum loxilb_ai_admission_limit "$(svc $PORT_Q)" 'role="queue"')"
chk Q5 "queued decisions moved by $FC_Q_DEPTH"         "$FC_Q_DEPTH" "$(( $(wait_metric loxilb_ai_admission_decisions_total $((q0+FC_Q_DEPTH)) 25 "$(svc $PORT_Q)" 'reason="queued"') - q0 ))"
for i in 1 2; do
  $hexec l3h1 curl -s -o "$DQ/f$i.body" -D "$DQ/f$i.hdr" -w '%{http_code}' --max-time 20 "${HDRS[@]}" \
    -H 'X-Test-Nonce: capQf' -H "X-Request-Id: capQf-$i" -d "$BODY" "$Q_URL" > "$DQ/f$i.code" 2>/dev/null
done
chk Q6 "two more were refused with 429"                2 "$(count_codes "$DQ" 429)"
H=$(first_hdr_with "$DQ" 429)
chk Q7 "the refusal reports the full queue"            "$FC_Q_DEPTH" "$(hdr_val "$H" X-Loxilb-Admission-Queued)"
chk Q8 "and the ceiling"                               "$FC_MAX_OUT" "$(hdr_val "$H" X-Loxilb-Admission-Limit)"
chk_has Q9 "refusal body names the reason"             admission_capacity "$(cat "$DQ/f1.body" 2>/dev/null)"
chk Q10 "and they never reached the backend"           0 "$(receipts capQf)"
chk Q11 "queue_full decisions moved by two"            2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((qf0+2)) 25 "$(svc $PORT_Q)" 'reason="queue_full"') - qf0 ))"
chk Q11a "requests_total{denied,429} moved by two"     2 "$(denied_delta 429 "$den0" 2)"
chk Q11c "and neither counted as completed"            0 "$(( $(completed 429) - cmp0 ))"
# One held request completes: its unit wakes the head of the queue; that
# request completes at once and wakes the next, so the four drain in order.
release capQh1
chk Q12 "all four waiting requests reached the backend"  "$FC_Q_DEPTH" "$(wait_receipts capQq $FC_Q_DEPTH 20)"
chk Q13 "in the order they arrived"                    "capQq-1 capQq-2 capQq-3 capQq-4" "$(order capQq)"
chk Q14 "queued gauge back to zero"                    0 "$(wait_metric loxilb_ai_admission_queued 0 25 "$(svc $PORT_Q)")"
chk Q15 "the wait histogram: one sample per park, four"  4 "$(( $(wait_metric loxilb_ai_admission_queue_wait_seconds_count $((wc0+4)) 25 "$(svc $PORT_Q)") - wc0 ))"
release_all; wait
chk Q16 "the four waiting requests answered 200"       "$FC_Q_DEPTH" "$(count_codes "$DQ" 200 | awk -v h=$FC_MAX_OUT '{print $1 - h}')"
chk Q17 "admitted decisions moved by $((FC_MAX_OUT+FC_Q_DEPTH))" $((FC_MAX_OUT+FC_Q_DEPTH)) "$(( $(wait_metric loxilb_ai_admission_decisions_total $((adm0+FC_MAX_OUT+FC_Q_DEPTH)) 25 "$(svc $PORT_Q)" 'reason="admitted"') - adm0 ))"
chk Q18 "gauge back to zero"                           0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"
# Read after the queue has drained: the class counter lags by a pull, and a
# wait for it must not hold the queued requests past their window.
chk Q11b "the 4xx class moved by the two refused"      2 "$(klass_delta 4xx "$k4" 2)"

# ── T: the wait window ──────────────────────────────────────────────────────
echo ""
echo "T: two requests wait past ${FC_T_WAIT_MS} ms and are ended with 504"
to0=$(decisions $PORT_Q queue_timeout)
den0=$(denied 504); cmp0=$(completed 504); k5=$(klass_settled 5xx)
DT=$(mktemp -d)
# The wait window is shortened at runtime for this row: a replace POST of the
# same rule with the new wait, read back from the data plane before the burst.
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_T_WAIT_MS)" 8080 8081 >/dev/null
chk T0 "the wait window is changed at runtime"           "$FC_T_WAIT_MS" "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_wait_ms "$FC_T_WAIT_MS" 10)"
hold_burst "$DT" $FC_MAX_OUT capTh "$Q_URL"
chk T1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capTh $FC_MAX_OUT 15)"
queue_burst "$DT" 2 capTq "$Q_URL"
chk T2 "two are waiting (data-plane read-back)"        2 "$(wait_effective_queued $PORT_Q 2 10)"
chk T3 "both were ended with 504"                      2 "$(wait_codes "$DT" 504 2 20)"
chk_has T4 "the body names the timeout"                admission_queue_timeout "$(cat "$DT/q1.body" 2>/dev/null)"
chk_ge T5 "and carries the wait it spent (queued_ms)"  "$FC_T_WAIT_MS" "$(jq -r '.queued_ms // "unreadable"' "$DT/q1.body" 2>/dev/null)"
chk_ge T6 "with Retry-After"                           1 "$(hdr_val "$(cat "$DT/q1.hdr")" Retry-After)"
chk T7 "queue_timeout decisions moved by two"          2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((to0+2)) 25 "$(svc $PORT_Q)" 'reason="queue_timeout"') - to0 ))"
chk T7a "requests_total{denied,504} moved by two"      2 "$(denied_delta 504 "$den0" 2)"
chk T7b "the 5xx class moved by two"                   2 "$(klass_delta 5xx "$k5" 2)"
chk T7c "and neither counted as completed"             0 "$(( $(completed 504) - cmp0 ))"
chk T8 "queued gauge back to zero"                     0 "$(wait_metric loxilb_ai_admission_queued 0 25 "$(svc $PORT_Q)")"
release_all; wait
sleep 2
chk T9 "neither reached the backend, then or later"    0 "$(receipts capTq)"
chk T10 "gauge back to zero"                           0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk T11 "the wait window is restored"                  "$FC_Q_WAIT_MS" "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_wait_ms "$FC_Q_WAIT_MS" 10)"

# ── X: the client leaves while it waits ─────────────────────────────────────
echo ""
echo "X: two waiting clients reset their connections"
cx0=$(decisions $PORT_Q cancelled)
DX=$(mktemp -d)
hold_burst "$DX" $FC_MAX_OUT capXh "$Q_URL"
chk X1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capXh $FC_MAX_OUT 15)"
$hexec l3h1 python3 "$(pwd)/h1_client.py" disconnect $VIP $PORT_Q --n 2 --after-s 3 --nonce-prefix capXq > /tmp/ai-admission-X.out 2>&1 &
chk X2 "two are waiting (data-plane read-back)"        2 "$(wait_effective_queued $PORT_Q 2 10)"
wait %% 2>/dev/null
chk X3 "cancelled decisions moved by two"              2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((cx0+2)) 25 "$(svc $PORT_Q)" 'reason="cancelled"') - cx0 ))"
chk X4 "queued gauge back to zero"                     0 "$(wait_metric loxilb_ai_admission_queued 0 25 "$(svc $PORT_Q)")"
release_all; wait
sleep 2
chk X5 "neither ever reached the backend"              "0 0" "$(receipts capXq-0) $(receipts capXq-1)"
chk X6 "gauge back to zero"                            0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── W: the memory warning at apply ──────────────────────────────────────────
echo ""
echo "W: a depth of 65536 is applied with a warning; a depth of $FC_Q_DEPTH without"
chk_ge W1 "the gateway log is readable and non-empty"  1 "$(gw_log | wc -c | tr -d ' ')"
chk_ge W2 "the warning names the :$PORT_W rule and the two guards" 1 "$(gw_log | grep -c "$VIP:$PORT_W .*fc_max_queue_depth=65536 may park up to .*connectionLimit or LLB_PD_MAX_TOTAL_INFLIGHT")"
chk W3 "no warning for the :$PORT_Q rule"              0 "$(gw_log | grep "may park up to" | grep -c "$VIP:$PORT_Q ")"
chk W4 "the :$PORT_W pool is gated all the same"        65536 "$(msum loxilb_ai_admission_limit "$(svc $PORT_W)" 'role="queue"')"

# ── R: the fields are read back and changeable at runtime ───────────────────
echo ""
echo "R: GET reads the posted fields and the effective state; a replace POST changes them"
L=$(lb_get $PORT_Q)
chk R1 "fc_max_queue_depth read back"                  "$FC_Q_DEPTH"   "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_max_queue_depth')"
chk R2 "fc_max_queue_wait_ms read back"                "$FC_Q_WAIT_MS" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_max_queue_wait_ms')"
chk R3 "fc_effective.mode"                             enforce         "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.mode')"
chk R4 "fc_effective.max_outstanding"                  "$FC_MAX_OUT"   "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.max_outstanding')"
chk R5 "fc_effective.queue_depth"                      "$FC_Q_DEPTH"   "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queue_depth')"
chk R6 "fc_effective.queue_wait_ms"                    "$FC_Q_WAIT_MS" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queue_wait_ms')"
chk R7 "fc_effective.queue_memory_bound_mib = depth x 1 MiB" "$FC_Q_DEPTH" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queue_memory_bound_mib')"
chk R8 "fc_effective.queued is live"                   0 "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective.queued // 0')"
gw_add_rule $PORT_Q "$(gw_queue_json 2 $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk R9 "a replace POST with depth 2 is read back"      2 "$(wait_lb_field $PORT_Q .serviceArguments.fc_max_queue_depth 2 10)"
chk R10 "and the data plane holds it"                  2 "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_depth 2 10)"
chk R11 "and exports it"                               2 "$(wait_metric loxilb_ai_admission_limit 2 25 "$(svc $PORT_Q)" 'role="queue"')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk R12 "restored to $FC_Q_DEPTH"                      "$FC_Q_DEPTH" "$(wait_metric loxilb_ai_admission_limit $FC_Q_DEPTH 25 "$(svc $PORT_Q)" 'role="queue"')"
c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' -m 8 -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' \
      -d "{\"serviceArguments\": {\"externalIP\": \"$VIP\", \"port\": 2027, \"protocol\": \"tcp\", \"sel\": 0, \"mode\": 4, \"sse_mode\": true, \"fc_max_queue_depth\": 4}, \"endpoints\": [{\"endpointIP\": \"31.31.31.1\", \"targetPort\": 8080, \"weight\": 1}]}")
chk R13 "a depth without a wait window is refused"     400 "$c"
# A replace is judged on the rule it leaves: one carrying only a depth keeps
# the stored wait; one carrying only a zero wait would leave the stored depth
# without a window, and is refused with the stored rule untouched.
chk_has R14 "a replace carrying only a depth is accepted" Success "$(gw_add_rule $PORT_Q ', "fc_max_queue_depth": 2' 8080 8081)"
chk R15 "the depth is replaced"                        2 "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_depth 2 10)"
chk R16 "and the stored wait is kept"                  "$FC_Q_WAIT_MS" "$(lb_get $PORT_Q | jq -r '.serviceArguments.fc_max_queue_wait_ms')"
chk_has R17 "a replace leaving the depth without a wait is refused" '"code":400' "$(gw_add_rule $PORT_Q ', "fc_max_queue_wait_ms": 0' 8080 8081)"
chk R18 "and the stored rule is untouched"             "2 $FC_Q_WAIT_MS" "$(lb_get $PORT_Q | jq -r '.serviceArguments | "\(.fc_max_queue_depth) \(.fc_max_queue_wait_ms)"')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk R19 "restored to $FC_Q_DEPTH"                      "$FC_Q_DEPTH" "$(wait_lb_field $PORT_Q .serviceArguments.fc_effective.queue_depth "$FC_Q_DEPTH" 10)"

# ── S: a rule's own gate settings over the environment, with their sources ──
echo ""
echo "S: the :$PORT_P rule's ceiling ($FC_P_MAX) replaces the environment's ($FC_MAX_OUT); each value names its source"
P_URL="http://$VIP:$PORT_P/v1/chat/completions"
L=$(lb_get $PORT_P)
eff() { printf '%s' "$L" | jq -r ".serviceArguments.fc_effective.$1 // \"unreadable\""; }
chk S1 "fc_max_outstanding read back"                  "$FC_P_MAX" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_max_outstanding')"
chk S2 "fc_telemetry_stale_ms read back"               "$FC_P_STALE_MS" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_telemetry_stale_ms')"
chk S3 "the ceiling in force is the rule's"            "$FC_P_MAX rule" "$(eff max_outstanding) $(eff source.max_outstanding)"
chk S4 "the endpoint ceiling is the environment's"     "$FC_EP_CAP env" "$(eff ep_max_inflight) $(eff source.ep_max_inflight)"
chk S5 "the mode is the environment's"                 "enforce env" "$(eff mode) $(eff source.mode)"
chk S6 "no queue anywhere: the product default"        "0 default" "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_effective | "\(.queue_depth // 0) \(.source.queue_depth)"')"
chk S7 "the telemetry window is the rule's"            "$FC_P_STALE_MS rule" "$(eff telemetry_stale_ms) $(eff source.telemetry_stale_ms)"
chk S8 "an undeclared mode is not read back"           null "$(printf '%s' "$L" | jq -r '.serviceArguments.fc_mode')"
DP=$(mktemp -d)
hold_burst "$DP" 6 capP "$P_URL"
chk S9 "four reached the backend, not eight"           "$FC_P_MAX" "$(wait_receipts capP $FC_P_MAX 15)"
chk S10 "the other two were refused 429"               2 "$(wait_codes "$DP" 429 2 15)"
chk S11 "and never reached it"                         "$FC_P_MAX" "$(receipts capP)"
release_all; wait
chk S12 "the four answered 200"                        "$FC_P_MAX" "$(count_codes "$DP" 200)"
gw_add_rule $PORT_P ", \"fc_max_outstanding\": 0, \"fc_telemetry_stale_ms\": $FC_P_STALE_MS" 8080 8081 >/dev/null
chk S13 "an explicit 0 returns the ceiling to the environment" "env" "$(wait_lb_field $PORT_P .serviceArguments.fc_effective.source.max_outstanding env 10)"
chk S14 "whose value is in force"                      "$FC_MAX_OUT" "$(lb_get $PORT_P | jq -r '.serviceArguments.fc_effective.max_outstanding')"
gw_add_rule $PORT_P "$(gw_p_json)" 8080 8081 >/dev/null
chk S15 "restored to the rule's $FC_P_MAX"             "$FC_P_MAX" "$(wait_lb_field $PORT_P .serviceArguments.fc_effective.max_outstanding "$FC_P_MAX" 10)"
n=16
for bad in '"fc_max_outstanding": 100001' '"fc_mode": "yes"' '"fc_telemetry_stale_ms": 3600001' '"fc_ep_max_inflight": null'; do
  r=$(gw_add_rule $PORT_P ", $bad" 8080 8081 2>&1)
  case "$r" in *Success*) got=accepted ;; *) got=refused ;; esac
  chk "S$n" "a replace with $bad is refused"           refused "$got"
  n=$((n+1))
done
chk S20 "and the stored rule is untouched"             "$FC_P_MAX $FC_P_STALE_MS" "$(lb_get $PORT_P | jq -r '.serviceArguments | "\(.fc_max_outstanding) \(.fc_telemetry_stale_ms)"')"

# ── O: a rule switches the gate off under an enforcing environment ──────────
echo ""
echo "O: fc_mode off on the :$PORT_P rule admits past its ceiling; inherit returns it to the environment"
gw_add_rule $PORT_P "$(gw_p_json ', "fc_mode": "off"')" 8080 8081 >/dev/null
chk O1 "the mode in force is the rule's off"           "off" "$(wait_lb_field $PORT_P .serviceArguments.fc_effective.mode off 10)"
chk O2 "and says so"                                   "off rule" "$(lb_get $PORT_P | jq -r '.serviceArguments | "\(.fc_mode) \(.fc_effective.source.mode)"')"
DO=$(mktemp -d)
hold_burst "$DO" 6 capO "$P_URL"
chk O3 "all six reached the backend"                   6 "$(wait_receipts capO 6 15)"
release_all; wait
chk O4 "none was refused"                              0 "$(count_codes "$DO" 429)"
gw_add_rule $PORT_P "$(gw_p_json ', "fc_mode": "inherit"')" 8080 8081 >/dev/null
chk O5 "inherit returns the mode to the environment"   "enforce env" "$(wait_lb_field $PORT_P '.serviceArguments.fc_effective | "\(.mode) \(.source.mode)"' 'enforce env' 10)"
chk O6 "and is not read back as a declaration"         null "$(lb_get $PORT_P | jq -r '.serviceArguments.fc_mode')"

# ── U: a change that frees units wakes the waiters at once ──────────────────
echo ""
echo "U: four wait behind the :$PORT_U rule's ceiling of $FC_U_MAX; raising it to 6 admits all four at once"
U_URL="http://$VIP:$PORT_U/v1/chat/completions"
chk U1 "the ceiling in force is the rule's"            "$FC_U_MAX rule" "$(lb_get $PORT_U | jq -r '.serviceArguments.fc_effective | "\(.max_outstanding) \(.source.max_outstanding)"')"
DU=$(mktemp -d)
hold_burst "$DU" 6 capU "$U_URL"
chk U2 "two reached the backend"                       "$FC_U_MAX" "$(wait_receipts capU $FC_U_MAX 15)"
chk U3 "four wait"                                     4 "$(wait_effective_queued $PORT_U 4 15)"
gw_add_rule $PORT_U "$(gw_u_json 6)" 8080 8081 >/dev/null
chk U4 "the data plane holds the new ceiling"          6 "$(wait_lb_field $PORT_U .serviceArguments.fc_effective.max_outstanding 6 10)"
# Without the wake on reconfigure the once-a-second pass admits one waiter
# per second (three seconds or more for four); with it they go together.
t0=$(date +%s%3N); got=""
for i in $(seq 1 100); do got=$(receipts capU); [ "$got" == 6 ] && break; sleep 0.1; done
dt=$(( $(date +%s%3N) - t0 ))
chk U5 "all four waiters reached the backend"          6 "$got"
chk_le U6 "within 1500 ms of the new ceiling (ms)"     1500 "$dt"
chk U7 "the queue is empty"                            0 "$(wait_effective_queued $PORT_U 0 5)"
release_all; wait
chk U8 "all six answered 200"                          6 "$(count_codes "$DU" 200)"
chk U9 "none was drained by the replace"               0 "$(count_codes "$DU" 503)"
chk_ge U10 "the replace was applied in place"           1 "$(gw_log | grep -c "$VIP:$PORT_U .*updated")"
gw_add_rule $PORT_U "$(gw_u_json $FC_U_MAX)" 8080 8081 >/dev/null
chk U11 "restored to $FC_U_MAX"                         "$FC_U_MAX" "$(wait_lb_field $PORT_U .serviceArguments.fc_effective.max_outstanding "$FC_U_MAX" 10)"

# ── UE: going back to wait does not restart the clock ───────────────────────
# The endpoint ceiling is the binding one here: the service has units, so the
# once-a-second pass wakes the waiter every second, it meets the ceiling and
# goes back. Its wait stays bounded by the window it was first given.
echo ""
echo "UE: one waits behind the :$PORT_U endpoints' ceiling of 1 with a 3 s window; woken and sent back each second, it still ends at 3 s"
gw_add_rule $PORT_U ", \"fc_max_outstanding\": 8, \"fc_ep_max_inflight\": 1$(gw_queue_json $FC_Q_DEPTH 3000)" 8080 8081 >/dev/null
chk UE1 "the data plane holds ceiling 1, window 3 s"   "1 3000" "$(wait_lb_field $PORT_U '.serviceArguments.fc_effective | "\(.ep_max_inflight) \(.queue_wait_ms)"' '1 3000' 10)"
DUE=$(mktemp -d)
hold_burst "$DUE" 2 capUEh "$U_URL"
chk UE2 "each endpoint holds one"                     2 "$(wait_receipts capUEh 2 15)"
$hexec l3h1 curl -s -o "$DUE/w.body" -D "$DUE/w.hdr" -w '%{http_code}' --max-time 60 \
  "${HDRS[@]}" -H "X-Test-Nonce: capUEw" -H "X-Request-Id: capUEw-1" \
  -d "$BODY" "$U_URL" > "$DUE/w.code" 2>/dev/null &
chk UE3 "one waits"                                   1 "$(wait_effective_queued $PORT_U 1 5)"
t0=$(date +%s%3N); got=""
for i in $(seq 1 100); do got=$(cat "$DUE/w.code" 2>/dev/null); [ -n "$got" ] && break; sleep 0.1; done
dt=$(( $(date +%s%3N) - t0 ))
chk UE4 "it was ended with 504"                       504 "$got"
chk_has UE5 "the body names the timeout"              admission_queue_timeout "$(cat "$DUE/w.body" 2>/dev/null)"
chk_le UE6 "within its window and one reaper pass (ms)" 5000 "$dt"
chk UE7 "it never reached a backend"                  0 "$(receipts capUEw)"
release_all; wait
chk UE8 "both holders answered 200"                   2 "$(count_codes "$DUE" 200)"
gw_add_rule $PORT_U "$(gw_u_json $FC_U_MAX), \"fc_ep_max_inflight\": 0" 8080 8081 >/dev/null
chk UE9 "restored: the endpoint ceiling is the environment's" "$FC_EP_CAP env" "$(wait_lb_field $PORT_U '.serviceArguments.fc_effective | "\(.ep_max_inflight) \(.source.ep_max_inflight)"' "$FC_EP_CAP env" 10)"

# ── KA: a refusal keeps the connection ──────────────────────────────────────
echo ""
echo "KA: a 429 on a buffered request keeps the connection; the next request on it is admitted"
DK=$(mktemp -d)
hold_burst "$DK" $FC_MAX_OUT capKAh "$H1_URL"
chk KA1 "the pool filled to the ceiling"               "$FC_MAX_OUT" "$(wait_receipts capKAh $FC_MAX_OUT 15)"
SIG=$(pwd)/.h1_signal; rm -f "$SIG"
$hexec l3h1 python3 "$(pwd)/h1_client.py" shed_keepalive $VIP $PORT_H1 --signal "$SIG" --nonce-prefix capKA --timeout 90 > /tmp/ai-admission-KA.out 2>&1 &
for i in $(seq 1 20); do grep -q '"status": "429"' /tmp/ai-admission-KA.out 2>/dev/null && break; sleep 1; done
chk KA2 "the first request was refused with 429"       429 "$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out | jq -r '.status')"
chk KA3 "with Connection: keep-alive"                  keep-alive "$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out | jq -r '.connection')"
chk KA4 "and the socket stayed open"                   false "$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out | jq -r '.closed')"
release_all; wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"' >/dev/null
touch "$SIG"
for i in $(seq 1 30); do grep -q '"summary": "shed_keepalive"' /tmp/ai-admission-KA.out 2>/dev/null && break; sleep 1; done
chk KA5 "the second request on the SAME socket was admitted" 200 "$(grep '"summary": "shed_keepalive"' /tmp/ai-admission-KA.out | jq -r '.second')"
chk KA6 "on the kept connection"                       true "$(grep '"summary": "shed_keepalive"' /tmp/ai-admission-KA.out | jq -r '.reused')"
chk KA7 "the refused request never reached the backend" 0 "$(receipts capKA-first)"
chk KA8 "the admitted one did"                          1 "$(receipts capKA-second)"
wait; rm -f "$SIG"

# ── DL: the rule is deleted while requests wait ─────────────────────────────
echo ""
echo "DL: deleting the queue pool ends its two waiting requests with 503"
DD=$(mktemp -d)
hold_burst "$DD" $FC_MAX_OUT capDh "$Q_URL"
chk DL1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capDh $FC_MAX_OUT 15)"
queue_burst "$DD" 2 capDq "$Q_URL"
chk DL2 "two are waiting"                               2 "$(wait_metric loxilb_ai_admission_queued 2 25 "$(svc $PORT_Q)")"
chk_has DL2b "the rule is deleted by its full key"     Success "$(lb_delete $PORT_Q)"
chk DL2c "and the GET no longer lists it"             gone "$([ -z "$(lb_get $PORT_Q)" ] && echo gone || echo listed)"
chk DL3 "both waiting requests were ended with 503"     2 "$(wait_codes "$DD" 503 2 15)"
chk_has DL4 "the body names the drain"                  admission_drained "$(cat "$DD/q1.body" 2>/dev/null)"
release_all; wait
sleep 2
chk DL5 "neither reached the backend, then or later"    0 "$(receipts capDq)"
for i in $(seq 1 20); do [ "$(denies_for capDq- | wc -l | tr -d ' ')" == "2" ] && break; sleep 1; done
chk DL6 "both drains are on the audit trail"            2 "$(denies_for capDq- | jq -r '.detail.decision' | grep -c '^admission_drained$')"
gw_add_rule $PORT_Q "$(gw_queue_json $FC_Q_DEPTH $FC_Q_WAIT_MS)" 8080 8081 >/dev/null
chk DL7 "the pool is back, gated, with an empty queue"  2 "$(wait_metric loxilb_ai_admission_mode 2 25 "$(svc $PORT_Q)")"
chk DL8 "nothing in flight on it"                       0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── M: maintenance drains the data path ─────────────────────────────────────
echo ""
echo "M: entering maintenance refuses new requests, ends the waiting ones, lets executing ones finish"
dr0=$(decisions $PORT_Q drained); dg0=$(decisions $PORT_Q draining)
DM=$(mktemp -d)
hold_burst "$DM" $FC_MAX_OUT capMh "$Q_URL"
chk M1 "the pool filled to the ceiling"                "$FC_MAX_OUT" "$(wait_receipts capMh $FC_MAX_OUT 15)"
queue_burst "$DM" 2 capMq "$Q_URL"
chk M2 "two are waiting"                               2 "$(wait_metric loxilb_ai_admission_queued 2 25 "$(svc $PORT_Q)")"
chk M3 "maintenance entered"                           maintenance "$(maint_put true | jq -r '.state')"
S=$(maint_get)
chk M4 "the read-back says inference is refused"       true "$(printf '%s' "$S" | jq -r '.refusing_new_inference')"
chk M5 "and counts the $FC_MAX_OUT executing requests"  "$FC_MAX_OUT" "$(printf '%s' "$S" | jq -r '.in_flight_requests')"
chk M6 "both waiting requests were ended with 503"     2 "$(wait_codes "$DM" 503 2 15)"
chk_has M7 "the body names the drain"                  admission_drained "$(cat "$DM/q1.body" 2>/dev/null)"
c=$($hexec l3h1 curl -s -o "$DM/n.body" -D "$DM/n.hdr" -w '%{http_code}' --max-time 20 "${HDRS[@]}" -H 'X-Test-Nonce: capMn' -d "$BODY" "$Q_URL")
chk M8 "a new request is refused with 503"             503 "$c"
chk_has M9 "naming the maintenance drain"              gateway_draining "$(cat "$DM/n.body" 2>/dev/null)"
chk M9b "and closing the connection (traffic moves off the node)" close "$(hdr_val "$(cat "$DM/n.hdr" 2>/dev/null)" Connection)"
chk M9c "with Retry-After 5"                           5 "$(hdr_val "$(cat "$DM/n.hdr" 2>/dev/null)" Retry-After)"
chk M10 "and never reached the backend"                0 "$(receipts capMn)"
chk M11 "drained decisions moved by two"               2 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((dr0+2)) 25 "$(svc $PORT_Q)" 'reason="drained"') - dr0 ))"
chk M12 "draining decisions moved by one"              1 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((dg0+1)) 25 "$(svc $PORT_Q)" 'reason="draining"') - dg0 ))"
release_all; wait
chk M13 "the executing requests finished 200"          "$FC_MAX_OUT" "$(count_codes "$DM" 200)"
chk M14 "maintenance left"                             active "$(maint_put false | jq -r '.state')"
chk M15 "the read-back no longer claims a drain"       false "$(maint_get | jq -r '.refusing_new_inference')"
c=$($hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 20 "${HDRS[@]}" -H 'X-Test-Nonce: capMr' -d "$BODY" "$Q_URL")
chk M16 "admission is restored"                        200 "$c"
chk M17 "gauge back to zero"                           0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_Q)" 'role="service"')"

# ── AD: the adaptive ceiling on the endpoints' scraped queue depth ──────────
echo ""
echo "AD: the :$PORT_AD ceiling ($FC_AD_MAX) tightens on fresh waiting requests, holds on stale telemetry, recovers on fresh clear"
AD_URL="http://$VIP:$PORT_AD/v1/chat/completions"
adstate() { # adstate <port> -> "<effective ceiling> <state> <reason>" from the data plane now
  lb_get "$1" | jq -r '.serviceArguments.fc_effective | "\(.effective_max_outstanding) \(.adapt_state) \(.adapt_reason)"' 2>/dev/null
}
wait_adstate() { # wait_adstate <port> <want> <secs>
  local got="" i
  for i in $(seq 1 "$3"); do got=$(adstate "$1"); [ "$got" == "$2" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
wait_adwhy() { # wait_adwhy <port> "<state> <reason>" <secs>: whatever the ceiling
  local got="" i
  for i in $(seq 1 "$3"); do got=$(adstate "$1" | cut -d' ' -f2-3); [ "$got" == "$2" ] && { echo "$got"; return; }; sleep 1; done
  echo "$got"
}
be __waiting/0 >/dev/null; be __metrics/on >/dev/null
chk AD1 "declared on the rule and read back with its source" "on on rule" "$(lb_get $PORT_AD | jq -r '.serviceArguments | "\(.fc_adaptive) \(.fc_effective.adaptive) \(.fc_effective.source.adaptive)"')"
# Nothing has moved it yet: open at the configured ceiling.
chk AD2 "open at its ceiling while nothing waits" "$FC_AD_MAX open" "$(wait_adstate $PORT_AD "$FC_AD_MAX open none" 25 | cut -d' ' -f1-2)"
be __waiting/5 >/dev/null
# 10 -> 8 -> 6 -> 4 -> 3 -> 2: four fifths per second once the next scrape
# (every 10 s) reports the waiting requests, never under a quarter.
chk AD3 "fresh waiting requests tighten it to a quarter" "$FC_AD_FLOOR tightened queued" "$(wait_adstate $PORT_AD "$FC_AD_FLOOR tightened queued" 40)"
DAD=$(mktemp -d)
hold_burst "$DAD" 4 capAD "$AD_URL"
chk AD4 "the gate admits to the tightened ceiling: two of four" "$FC_AD_FLOOR" "$(wait_receipts capAD $FC_AD_FLOOR 15)"
chk AD5 "the other two refused with 429" 2 "$(wait_codes "$DAD" 429 2 15)"
release capAD
be __metrics/off >/dev/null
# The scrapes fail from now on: once the last good one is older than the
# pool's telemetry window the ceiling holds where it is and says why.
chk AD6 "stale telemetry freezes it where it is" "$FC_AD_FLOOR frozen stale" "$(wait_adstate $PORT_AD "$FC_AD_FLOOR frozen stale" 40)"
sleep 6
chk AD7 "and a stale second never widens it" "$FC_AD_FLOOR frozen stale" "$(adstate $PORT_AD)"
be __waiting/0 >/dev/null; be __metrics/on >/dev/null
chk AD8 "a fresh clear scrape gives it back, one unit a second" "$FC_AD_MAX open clear" "$(wait_adstate $PORT_AD "$FC_AD_MAX open clear" 40)"
chk_ge AD9 "the steps down are exported" 4 "$(wait_metric_ge loxilb_ai_admission_adapt_moves_total 4 25 "$(svc $PORT_AD)" 'direction="down"')"
chk_ge AD10 "and the steps up" 8 "$(wait_metric_ge loxilb_ai_admission_adapt_moves_total 8 25 "$(svc $PORT_AD)" 'direction="up"')"
chk AD11 "the state is exported as a state set" 1 "$(wait_metric loxilb_ai_admission_adapt_state 1 25 "$(svc $PORT_AD)" 'state="open"')"
# Switched off at runtime: a gate-only replace, applied in place, gives the
# configured ceiling back at once whatever the evidence.
be __waiting/5 >/dev/null
chk AD12 "tightened again" "tightened queued" "$(wait_adwhy $PORT_AD "tightened queued" 40)"
gw_add_rule $PORT_AD "$(gw_ad_json off)" 8084 8085 >/dev/null
chk AD13 "adaptive off: the configured ceiling at once" "$FC_AD_MAX off" "$(wait_adstate $PORT_AD "$FC_AD_MAX off none" 5 | cut -d' ' -f1-2)"
be __waiting/0 >/dev/null
gw_add_rule $PORT_AD "$(gw_ad_json on)" 8084 8085 >/dev/null

# ── TT: the adaptive ceiling on the time to first token ─────────────────────
echo ""
echo "TT: the :$PORT_TT ceiling ($FC_TT_MAX) tightens while streamed responses take over ${FC_TT_TARGET_MS} ms to their first token"
TT_URL="http://$VIP:$PORT_TT/v1/chat/completions"
SBODY='{"model":"cap-model","stream":true,"messages":[{"role":"user","content":"x"}]}'
tt_send() { # tt_send <n> <first-token delay ms> <body>: n requests one after another, their codes
  local i
  for i in $(seq 1 "$1"); do
    $hexec l3h1 curl -s -o /dev/null -w '%{http_code} ' --max-time 20 "${HDRS[@]}" \
      -H "X-Test-Delay-Ms: $2" -d "$3" "$TT_URL"
  done
}
chk TT1 "open at its ceiling" "$FC_TT_MAX open" "$(wait_adstate $PORT_TT "$FC_TT_MAX open" 40 | cut -d' ' -f1-2)"
# Buffered responses are never sampled: their first byte is the whole answer.
tt_send 4 1200 "$BODY" >/dev/null
sleep 3
chk TT2 "slow buffered responses leave it open" "$FC_TT_MAX open" "$(adstate $PORT_TT | cut -d' ' -f1-2)"
chk_has TT3 "three slow streams answered" "200 200 200" "$(tt_send 3 800 "$SBODY")"
chk TT4 "slow first tokens tighten it" "tightened ttft" "$(wait_adwhy $PORT_TT "tightened ttft" 6)"
# Fast streams bring the estimate under the target, an eighth per sample on
# each endpoint, and the ceiling climbs only while no endpoint is over it.
# Round robin gives each of the two endpoints twelve: 800 ms * (7/8)^12 is
# about 160 ms. Fourteen (seven each) leave both at about 314 ms, over 300.
tt_send 24 0 "$SBODY" >/dev/null
chk TT5 "fast first tokens give it back" "$FC_TT_MAX open" "$(wait_adstate $PORT_TT "$FC_TT_MAX open clear" 20 | cut -d' ' -f1-2)"
chk TT6 "the target is read back with its source" "$FC_TT_TARGET_MS rule" "$(lb_get $PORT_TT | jq -r '.serviceArguments.fc_effective | "\(.ttft_target_ms) \(.source.ttft_target_ms)"')"

# ── WU: an endpoint back in service ramps up ───────────────────────────────
echo ""
echo "WU: after a return to service each :$PORT_WU endpoint ramps from a quarter of its ceiling ($FC_WU_EP) over ${FC_WU_MS} ms"
WU_URL="http://$VIP:$PORT_WU/v1/chat/completions"
hoststate() { # hoststate <red|green>: both explicit endpoint tuples must return.
  local target
  for target in 8082 8083; do
    $hexec l3h1 curl -s -m 8 -X POST "$API/config/endpointhoststate" -H 'Content-Type: application/json' \
      -d "{\"hostName\": \"31.31.31.1\", \"epPort\": $target, \"epProto\": \"tcp\", \"state\": \"$1\"}"
  done
}
chk WU1 "the window is read back with its source" "$FC_WU_MS rule 0" "$(lb_get $PORT_WU | jq -r '.serviceArguments.fc_effective | "\(.warmup_ms) \(.source.warmup_ms) \(.warming_endpoints // 0)"')"
chk_has WU2 "the backends go red" Success "$(hoststate red)"
sleep 1
chk_has WU3 "and come back green" Success "$(hoststate green)"
chk WU4 "both endpoints are warming" 2 "$(wait_lb_field $PORT_WU '.serviceArguments.fc_effective.warming_endpoints' 2 5)"
DWU=$(mktemp -d)
hold_burst "$DWU" 8 capWU "$WU_URL"
chk WU5 "a quarter of each ceiling admitted: four of eight" 4 "$(wait_receipts capWU 4 10)"
chk WU6 "the other four refused with 429" 4 "$(wait_codes "$DWU" 429 4 10)"
chk_le WU7 "no endpoint above its ramp" 2 "$(( $(peak_port capWU 8082) > $(peak_port capWU 8083) ? $(peak_port capWU 8082) : $(peak_port capWU 8083) ))"
release capWU
sleep $(( FC_WU_MS / 1000 + 1 ))
chk WU8 "the window over, nothing is warming" 0 "$(wait_lb_field $PORT_WU '(.serviceArguments.fc_effective | select(. != null) | (.warming_endpoints // 0))' 0 5)"
DWU2=$(mktemp -d)
hold_burst "$DWU2" 8 capWU2 "$WU_URL"
chk WU9 "the whole ceiling again: all eight admitted" 8 "$(wait_receipts capWU2 8 10)"
# The process valve is exported, and with no bound it counts nothing: the
# accept path stays byte-identical, so eight held requests still read 0.
chk_has WU10 "unbounded, connection contexts are not counted" "loxilb_proxy_context_inflight 0" "$(metrics_raw)"
chk_has WU11 "the valve is unbounded and says so" "loxilb_proxy_accept_bound 0" "$(metrics_raw)"
release capWU2

# ── TS / TW: the tenant share ───────────────────────────────────────────────
# Two keyed pools; a key per tenant. A tenant holds at most half of each
# pool's ceiling (and of its queue); every other tenant keeps admitting.
TS_URL="http://$VIP:$PORT_TS/v1/chat/completions"
TQ_URL="http://$VIP:$PORT_TQ/v1/chat/completions"
mk_key() { # mk_key <tenant> -> the raw key of a new key for that tenant
  $hexec l3h1 curl -s -m 10 -X POST "$API/config/ai/apikey" -H 'Content-Type: application/json' \
    -d "{\"tenant_id\": \"$1\", \"name\": \"$1-key\", \"allowed_models\": [\"$MODEL\"],
         \"rate_limit_rps\": 1000, \"burst_size\": 1000, \"enabled\": true}" | jq -r '.raw_key // empty'
}
# hold_key <dir> <name> <nonce> <url> <key>: one request as that key's
# tenant, held at the backend until its nonce is released.
hold_key() {
  $hexec l3h1 curl -s -o "$1/$2.body" -D "$1/$2.hdr" -w '%{http_code}' --max-time 120 \
    "${HDRS[@]}" -H "X-Api-Key: $5" -H 'X-Test-Hold: 1' -H "X-Test-Nonce: $3" -H "X-Request-Id: $3" \
    -d "$BODY" "$4" > "$1/$2.code" 2>/dev/null &
}
# send_key <dir> <name> <nonce> <url> <key>: one request, not held, waited for.
send_key() {
  $hexec l3h1 curl -s -o "$1/$2.body" -D "$1/$2.hdr" -w '%{http_code}' --max-time 20 \
    "${HDRS[@]}" -H "X-Api-Key: $5" -H "X-Test-Nonce: $3" -H "X-Request-Id: $3" \
    -d "$BODY" "$4" > "$1/$2.code" 2>/dev/null
  cat "$1/$2.code"
}
KEY_A=$(mk_key share-a); KEY_B=$(mk_key share-b); KEY_C=$(mk_key share-c)
echo ""
echo "TS: tenant A holds its share of the :$PORT_TS ceiling ($FC_TS_MAX at $FC_TS_PCT %); its next is refused, tenant B still admits"
chk TS0 "three tenant keys issued" 3 "$(for k in "$KEY_A" "$KEY_B" "$KEY_C"; do [ -n "$k" ] && echo; done | wc -l | tr -d ' ')"
ts0=$(decisions $PORT_TS tenant_share)
DTS=$(mktemp -d)
hold_key "$DTS" a1 capTSa1 "$TS_URL" "$KEY_A"
hold_key "$DTS" a2 capTSa2 "$TS_URL" "$KEY_A"
chk TS1 "tenant A's two reached the backend"       2 "$(wait_sum_receipts capTSa 2 2 15)"
chk TS2 "A's third answered 429"                   429 "$(send_key "$DTS" a3 capTSa3 "$TS_URL" "$KEY_A")"
chk_has TS3 "naming the tenant share"              admission_tenant_share "$(cat "$DTS/a3.body" 2>/dev/null)"
chk TS4 "it never reached the backend"             0 "$(receipts capTSa3)"
hold_key "$DTS" b1 capTSb1 "$TS_URL" "$KEY_B"
hold_key "$DTS" b2 capTSb2 "$TS_URL" "$KEY_B"
chk TS5 "tenant B's two admitted beside A's"       2 "$(wait_sum_receipts capTSb 2 2 15)"
chk TS6 "the data plane counts two tenants"        2 "$(wait_lb_field $PORT_TS '(.serviceArguments.fc_effective.tenants_active // 0)' 2 10)"
chk TS7 "the share in force, from the rule"        "$FC_TS_PCT rule" "$(lb_get $PORT_TS | jq -r '.serviceArguments.fc_effective | "\(.tenant_max_share_pct) \(.source.tenant_max_share_pct)"')"
chk TS8 "tenant_share decisions moved by one"      1 "$(( $(wait_metric loxilb_ai_admission_decisions_total $((ts0+1)) 25 "$(svc $PORT_TS)" 'reason="tenant_share"') - ts0 ))"
for n in capTSa1 capTSa2 capTSb1 capTSb2; do release $n; done; wait
chk TS9 "the four held answered 200"               4 "$(count_codes "$DTS" 200)"
chk TS10 "no tenant holds anything now"            0 "$(wait_lb_field $PORT_TS '(.serviceArguments.fc_effective.tenants_active // 0)' 0 10)"

echo ""
echo "TW: on the :$PORT_TQ queue (ceiling $FC_TQ_MAX, a unit and two waiters a tenant) A's waiters hold nobody up"
DTW=$(mktemp -d)
tq0=$(decisions $PORT_TQ queued)
hold_key "$DTW" a1 capTWa1 "$TQ_URL" "$KEY_A"
chk TW1 "A's first executes"                        1 "$(wait_receipts capTWa1 1 15)"
hold_key "$DTW" a2 capTWa2 "$TQ_URL" "$KEY_A"; sleep 0.3
hold_key "$DTW" a3 capTWa3 "$TQ_URL" "$KEY_A"
chk TW2 "A's next two wait"                         2 "$(wait_effective_queued $PORT_TQ 2 10)"
chk TW3 "A's fourth is refused at its queue share"  429 "$(send_key "$DTW" a4 capTWa4 "$TQ_URL" "$KEY_A")"
chk_has TW4 "naming the tenant share"               admission_tenant_share "$(cat "$DTW/a4.body" 2>/dev/null)"
# Both waiters are A's, and A is at its share: B takes the free unit at once
# instead of waiting behind them.
hold_key "$DTW" b1 capTWb1 "$TQ_URL" "$KEY_B"
chk TW5 "B is admitted past A's waiters"            1 "$(wait_receipts capTWb1 1 8)"
hold_key "$DTW" c1 capTWc1 "$TQ_URL" "$KEY_C"
chk TW6 "the ceiling full, C waits behind A's two"  3 "$(wait_effective_queued $PORT_TQ 3 10)"
# B's unit comes back: A heads the queue but is at its share, so the turn is C's.
release capTWb1
chk TW7 "the freed unit went to C"                  1 "$(wait_receipts capTWc1 1 10)"
chk TW8 "not to A's head waiter"                    0 "$(receipts capTWa2)"
# A's own unit comes back: now A's head waiter runs, in arrival order.
release capTWa1
chk TW9 "A's own unit went to A's head waiter"      1 "$(wait_receipts capTWa2 1 10)"
chk TW10 "A's second still waits"                   0 "$(receipts capTWa3)"
release capTWc1
release capTWa2
chk TW11 "then A's second"                          1 "$(wait_receipts capTWa3 1 10)"
release capTWa3; wait
chk TW12 "the five admitted answered 200"           5 "$(count_codes "$DTW" 200)"
chk TW13 "the queue is empty"                       0 "$(wait_effective_queued $PORT_TQ 0 10)"
chk TW14 "no tenant holds anything now"             0 "$(wait_lb_field $PORT_TQ '(.serviceArguments.fc_effective.tenants_active // 0)' 0 10)"
# TW5 alone cannot tell "admitted at once" from "parked, then woken": the
# 1 Hz pass wakes the first waiter that can run, so a B parked behind A's
# waiters still reaches the backend within a second. The decisions can: only
# A's two and C ever waited. Read once the count arrives, and again one
# republish later so a fourth has had its chance to show.
wait_metric_ge loxilb_ai_admission_decisions_total $((tq0 + 3)) 25 "$(svc $PORT_TQ)" 'reason="queued"' >/dev/null
sleep 11
tq1=$(decisions $PORT_TQ queued)
chk TW15 "only A's two and C ever waited"           3 "$( [ "$tq1" -ge 0 ] 2>/dev/null && echo $((tq1 - tq0)) || echo "$tq1")"

# ── XH / XH2: the admission headers on admitted responses ──────────────────
# :PORT_XH exposes them (ceiling FC_XH_MAX); :PORT_H1 runs on the environment,
# which leaves them off. Values are read against the pool as the request
# finds it: two held there, the request itself the third.
XH_URL="http://$VIP:$PORT_XH/v1/chat/completions"
xh_send() { # xh_send <dir> <name> <body> [curl args...]: one request, waited for; its code
  local dir=$1 name=$2 body=$3; shift 3
  $hexec l3h1 curl -s -N -o "$dir/$name.body" -D "$dir/$name.hdr" -w '%{http_code}' --max-time 20 \
    "${HDRS[@]}" -H "X-Test-Nonce: capXH$name" -H "X-Request-Id: capXH$name" "$@" \
    -d "$body" "$XH_URL" > "$dir/$name.code" 2>/dev/null
  cat "$dir/$name.code"
}
xh_vals() { # xh_vals <hdr file> -> "<inflight> <queued> <limit>"
  local h; h=$(cat "$1" 2>/dev/null)
  echo "$(hdr_val "$h" X-Loxilb-Admission-Inflight) $(hdr_val "$h" X-Loxilb-Admission-Queued) $(hdr_val "$h" X-Loxilb-Admission-Limit)"
}
xh_lines() { grep -ci '^x-loxilb-admission-' "$1" 2>/dev/null || true; }
echo ""
echo "XH: :$PORT_XH puts the pool's counts on every admitted response head (ceiling $FC_XH_MAX, two held)"
DXH=$(mktemp -d)
hold_burst "$DXH" 2 capXHheld "$XH_URL"
chk XH1 "two held on the pool"                              2 "$(wait_receipts capXHheld 2 15)"
chk XH2 "a plain request is admitted"                       200 "$(xh_send "$DXH" plain "$BODY")"
chk XH3 "its head carries inflight 3, queued 0, limit $FC_XH_MAX" "3 0 $FC_XH_MAX" "$(xh_vals "$DXH/plain.hdr")"
chk_has XH4 "its body is the backend's"                     '"backend_port"' "$(cat "$DXH/plain.body" 2>/dev/null)"
SSE_BODY='{"model":"cap-model","stream":true,"messages":[{"role":"user","content":"x"}]}'
chk XH5 "a streamed request is admitted"                    200 "$(xh_send "$DXH" sse "$SSE_BODY")"
chk XH6 "its head carries the same three"                   "3 0 $FC_XH_MAX" "$(xh_vals "$DXH/sse.hdr")"
chk_has XH7 "the head is still an event stream"             text/event-stream "$(cat "$DXH/sse.hdr" 2>/dev/null)"
# Every event and the terminator arrive whole: the chunks after the head
# were moved, not rewritten.
chk XH8 "every event arrived, the terminator last"          "t0 t1 t2 [DONE]" "$(grep -o '"content": "t[0-9]\|\[DONE\]' "$DXH/sse.body" 2>/dev/null | sed 's/.*"t/t/' | tr '\n' ' ' | sed 's/ $//')"
chk XH9 "a backend's own admission field is replaced"       200 "$(xh_send "$DXH" spoof "$BODY" -H 'X-Test-Spoof-Admission: 1')"
chk XH10 "one of each, the gateway's values"                "3 3 0 $FC_XH_MAX" "$(xh_lines "$DXH/spoof.hdr") $(xh_vals "$DXH/spoof.hdr")"
$hexec l3h1 curl -s -o /dev/null -D "$DXH/off.hdr" --max-time 20 "${HDRS[@]}" -H 'X-Test-Nonce: capXHoff' \
  -d "$BODY" "$H1_URL" >/dev/null 2>&1
chk XH11 "a pool left on the environment adds none"         0 "$(xh_lines "$DXH/off.hdr")"
chk XH12 "the rule reads back on, in force from the rule"   "on on rule" "$(lb_get $PORT_XH | jq -r '.serviceArguments | "\(.fc_expose_headers) \(.fc_effective.expose_headers) \(.fc_effective.source.expose_headers)"')"
# The generated model's enum check refuses it first (its own code, not 400).
chk_has XH13 "a switch value other than on/off/inherit is refused, naming the field" 'fc_expose_headers in body should be one of' "$(gw_add_rule $PORT_XH ', "fc_expose_headers": "yes"' 8080 8081)"
# Turned off with the two still held: a gate-only change, applied in place,
# so the held requests keep running and nothing is drained.
gw_add_rule $PORT_XH "$(gw_xh_json off)" 8080 8081 >/dev/null
chk XH14 "turned off, the rule reads back off"              "off off rule" "$(wait_lb_field $PORT_XH '.serviceArguments | "\(.fc_expose_headers) \(.fc_effective.expose_headers) \(.fc_effective.source.expose_headers)"' "off off rule" 10)"
chk XH15 "the next admitted response carries none"          "200 0" "$(xh_send "$DXH" after "$BODY") $(xh_lines "$DXH/after.hdr")"
release capXHheld; wait
chk XH16 "the two held through the change answered 200"     "200 200" "$(cat "$DXH/1.code" 2>/dev/null) $(cat "$DXH/2.code" 2>/dev/null)"
gw_add_rule $PORT_XH "$(gw_xh_json on)" 8080 8081 >/dev/null

echo ""
echo "XH2: :$PORT_XH2 puts them on every admitted HTTP/2 stream's response headers"
XH2_OUT=$($hexec l3h1 python3 "$(pwd)/h2_admit.py" $VIP $PORT_XH2 --streams 3 --delay-ms 2000 --nonce-prefix capXH2 2>&1)
chk XH2a "three streams admitted"                           3 "$(printf '%s\n' "$XH2_OUT" | jq -r 'select(.summary) | .admitted' 2>/dev/null)"
printf '%s\n' "$XH2_OUT" | jq -c 'select(.stream) | {stream, status, headers}' 2>/dev/null | sed 's/^/    /'
# Each stream's values are read as its own response head goes out, while it
# holds its unit: a stream whose answer already ended has handed its unit
# back, so a later head may count fewer. Every head carries all three; the
# first sees all three streams.
chk XH2b "every admitted stream carries the three, queued 0, limit $FC_XH_MAX" 3 "$(printf '%s\n' "$XH2_OUT" | jq -c "select(.status == \"200\" and (.headers[\"x-loxilb-admission-inflight\"] // \"\" | test(\"^[1-3]$\")) and .headers[\"x-loxilb-admission-queued\"] == \"0\" and .headers[\"x-loxilb-admission-limit\"] == \"$FC_XH_MAX\")" 2>/dev/null | wc -l | tr -d ' ')"
chk XH2c "the first head counted all three streams"         3 "$(printf '%s\n' "$XH2_OUT" | jq -r 'select(.status == "200") | .headers["x-loxilb-admission-inflight"] // "0"' 2>/dev/null | sort -n | tail -1)"
chk XH2d "no unit left held"                                0 "$(wait_lb_field $PORT_XH2 '(.serviceArguments.fc_effective | if . == null then "none" else (.inflight // 0) end)' 0 10)"

# ── RI / OS / NEG / F2: the refusal contract on the wire ────────────────────
# What a client reads to tell a refusal of the gateway from an answer of a
# backend, and one request from another (docs/load-balancing/27):
#   X-Loxilb-Refusal-Stage  the stage that refused, before any request byte
#                           reached a backend; "queue" for a wait that ended
#                           (its audit record is at stage capacity)
#   X-Request-Id            on an answer the gateway wrote: this request's ID
# The expected value of every check is the one written here, before the run.
# RI and most of OS read the answers the rows above already collected: every
# refusal shape of this scenario was sent with an X-Request-Id of its own and
# its head was kept.
hdr_of() { cat "$1" 2>/dev/null; }
mark_stage() { hdr_val "$(hdr_of "$1")" X-Loxilb-Refusal-Stage; }
mark_rid() { hdr_val "$(hdr_of "$1")" X-Request-Id; }
mark_lines() { grep -ci '^x-loxilb-refusal-' "$1" 2>/dev/null || true; }   # the family, whoever sent it
rid_lines() { grep -ci '^x-request-id:' "$1" 2>/dev/null || true; }
# deny_field <request id> <jq path>: that field of the request's sec.ai.deny
# records (one line, space separated), polled while the trail catches up.
deny_field() {
  local got="" i
  for i in $(seq 1 20); do
    got=$(trail | jq -r --arg r "$1" "select(.event_type==\"sec.ai.deny\" and .request_id==\$r) | $2" 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//')
    [ -n "$got" ] && break
    sleep 1
  done
  echo "$got"
}
# mark_row <id> <what> <hdr file> <request id sent> <stage on the wire> <stage of the deny record>
mark_row() {
  chk "$1a" "$2: X-Loxilb-Refusal-Stage"                    "$5" "$(mark_stage "$3")"
  chk "$1b" "$2: X-Request-Id is the one the client sent"   "$4" "$(mark_rid "$3")"
  chk "$1c" "$2: its sec.ai.deny record, by that ID, is at" "$6" "$(deny_field "$4" .detail.stage)"
}
not_congestion() { case "$1" in capacity|queue) echo congestion ;; "") echo unmarked ;; *) echo "not congestion" ;; esac; }

echo ""
echo "RI: every refusal names its request (X-Request-Id) and the trail has it under the same ID"
f=$(grep -l '^429$' "$DB"/*.code 2>/dev/null | head -n1); bi=$(basename "${f%.code}")
mark_row RI1 "429 admission_capacity (row B)"            "$DB/$bi.hdr"  "capB-$bi" capacity capacity
mark_row RI2 "429 admission_tenant_share (row TS)"       "$DTS/a3.hdr"  capTSa3    capacity capacity
mark_row RI3 "504 admission_queue_timeout (row T)"       "$DT/q1.hdr"   capTq-1    queue    capacity
mark_row RI4 "503 admission_drained, rule delete (DL)"   "$DD/q1.hdr"   capDq-1    queue    capacity
mark_row RI5 "503 admission_drained, maintenance (M)"    "$DM/q1.hdr"   capMq-1    queue    capacity
mark_row RI6 "429 through TLS (row L)"                   "$DL/x.hdr"    capLx-1    capacity capacity
# M's new request carried no X-Request-Id: the gateway minted one, and the
# answer and the deny record name the same minted ID.
MINT=$(mark_rid "$DM/n.hdr")
chk RI7a "503 gateway_draining (row M): X-Loxilb-Refusal-Stage" capacity "$(mark_stage "$DM/n.hdr")"
chk RI7b "a request sent without an ID is answered with a minted one" minted "$([ -n "$MINT" ] && echo minted || echo absent)"
chk RI7c "and the trail has the refusal under that minted ID" "capacity gateway_draining" "$([ -n "$MINT" ] && echo "$(deny_field "$MINT" .detail.stage) $(deny_field "$MINT" .detail.decision)")"
# A refusal that keeps the connection (row KA), read by the raw client.
KA1=$(grep '"nonce": "capKA-first"' /tmp/ai-admission-KA.out 2>/dev/null | head -n1)
chk RI8a "429 on a kept connection (row KA): the stage" capacity "$(printf '%s' "$KA1" | jq -r '.headers["x-loxilb-refusal-stage"] // "absent"')"
chk RI8b "and the request's own ID" capKA-first "$(printf '%s' "$KA1" | jq -r '.headers["x-request-id"] // "absent"')"
# Two requests on ONE connection (row G): the first was forwarded and
# answered by the backend, the second refused. The refusal names the second.
G2=$(grep '"nonce": "capG-second"' /tmp/ai-admission-G.out 2>/dev/null | head -n1)
chk RI9a "second request on a kept connection (row G): the stage" capacity "$(printf '%s' "$G2" | jq -r '.headers["x-loxilb-refusal-stage"] // "absent"')"
chk RI9b "the echo is the SECOND request's ID, not the first's" capG-second "$(printf '%s' "$G2" | jq -r '.headers["x-request-id"] // "absent"')"
chk RI9c "and its deny record is under that ID" capacity "$(deny_field capG-second .detail.stage)"
chk RI9d "the first request, which was served, has no deny record" 0 "$(trail | jq -c 'select(.event_type=="sec.ai.deny" and .request_id=="capG-first")' | wc -l | tr -d ' ')"
# The same two requests, the second WITHOUT an ID of its own: whatever its
# refusal names is the gateway's minted ID for it, never the first request's.
SIG=$(pwd)/.h1_signal; rm -f "$SIG"
$hexec l3h1 python3 "$(pwd)/h1_client.py" kept $VIP $PORT_H1 --signal "$SIG" --nonce-prefix capRIk --second-no-rid --timeout 90 > /tmp/ai-admission-RIk.out 2>&1 &
for i in $(seq 1 20); do grep -q '"status": "200"' /tmp/ai-admission-RIk.out 2>/dev/null && break; sleep 1; done
DRI=$(mktemp -d)
hold_burst "$DRI" $FC_MAX_OUT capRIfill "$H1_URL"
chk RI10a "the first request was served, the pool then filled" "1 $FC_MAX_OUT" "$(grep -c '"status": "200"' /tmp/ai-admission-RIk.out) $(wait_receipts capRIfill $FC_MAX_OUT 15)"
touch "$SIG"
for i in $(seq 1 30); do grep -q '"summary": "kept"' /tmp/ai-admission-RIk.out 2>/dev/null && break; sleep 1; done
K2=$(grep '"nonce": "capRIk-second"' /tmp/ai-admission-RIk.out 2>/dev/null | head -n1)
K2RID=$(printf '%s' "$K2" | jq -r '.headers["x-request-id"] // ""')
chk RI10b "the second, sent with no ID, refused on the same connection" "429 true" "$(grep '"summary": "kept"' /tmp/ai-admission-RIk.out | jq -r '"\(.second) \(.reused)"')"
chk RI10c "its refusal names an ID" minted "$([ -n "$K2RID" ] && echo minted || echo absent)"
chk RI10d "which is not the first request's" other "$([ "$K2RID" == "capRIk-first" ] && echo "the first's" || echo other)"
chk RI10e "and the trail has the refusal under that ID" capacity "$([ -n "$K2RID" ] && deny_field "$K2RID" .detail.stage)"
release_all; wait; rm -f "$SIG"
chk RI10f "gauge back to zero" 0 "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
# HTTP/2 (row E): a stream refused on its own stream.
E429=$(grep '"429"' "$E/out" 2>/dev/null | head -n1)
chk RI11a "a refused HTTP/2 stream (row E): x-loxilb-refusal-stage" capacity "$(printf '%s' "$E429" | jq -r '.headers["x-loxilb-refusal-stage"] // "absent"')"
chk RI11b "and x-request-id is that stream's own" "$(printf '%s' "$E429" | jq -r '.nonce')" "$(printf '%s' "$E429" | jq -r '.headers["x-request-id"] // "absent"')"

echo ""
echo "OS: only the gateway's own refusals carry a stage; a backend's answer never does"
DOS=$(mktemp -d)
os_send() { # os_send <name> <url> [curl args...]: one request with X-Request-Id capOS<name>; its code
  local name=$1 url=$2; shift 2
  $hexec l3h1 curl -s -o "$DOS/$name.body" -D "$DOS/$name.hdr" -w '%{http_code}' --max-time 20 \
    "${HDRS[@]}" -H "X-Test-Nonce: capOS$name" -H "X-Request-Id: capOS$name" "$@" \
    -d "$BODY" "$url" > "$DOS/$name.code" 2>/dev/null
  cat "$DOS/$name.code"
}
# A backend that refuses on its own, the way an OpenAI-compatible engine
# does: 429, an {"error": {...}} object, its own Retry-After. On :PORT_XH
# (admission headers on) the relayed answer carries the pool's counts, and
# nothing says the gateway refused it.
be admin/answer-429-object >/dev/null
chk OS1 "a backend's own 429 is relayed"                       429 "$(os_send b429 "$XH_URL")"
chk OS2 "the request did reach the backend"                    1 "$(receipts capOSb429)"
chk OS3 "no X-Loxilb-Refusal-* on it"                          0 "$(mark_lines "$DOS/b429.hdr")"
chk OS4 "the admission triple is there (inflight 1, queued 0, limit $FC_XH_MAX)" "3 1 0 $FC_XH_MAX" "$(xh_lines "$DOS/b429.hdr") $(xh_vals "$DOS/b429.hdr")"
chk OS5 "the body is the backend's object, untouched"          "rate_limit_error rate_limit_exceeded" "$(jq -r '.error | "\(.type) \(.code)"' "$DOS/b429.body" 2>/dev/null)"
chk OS6 "and so is its Retry-After"                            7 "$(hdr_val "$(hdr_of "$DOS/b429.hdr")" Retry-After)"
chk OS7 "the gateway recorded no refusal for it"               0 "$(sleep 3; trail | jq -c 'select(.event_type=="sec.ai.deny" and .request_id=="capOSb429")' | wc -l | tr -d ' ')"
# A backend that sends the gateway's own header: removed from the head.
be admin/echo-spoof-headers >/dev/null
chk OS8 "a backend 200 that claims X-Loxilb-Refusal-Stage: capacity is relayed" 200 "$(os_send spoof "$XH_URL")"
chk OS9 "without the header"                                   0 "$(mark_lines "$DOS/spoof.hdr")"
chk OS10 "and with the gateway's admission values, one of each" "3 1 0 $FC_XH_MAX" "$(xh_lines "$DOS/spoof.hdr") $(xh_vals "$DOS/spoof.hdr")"
# Both at once: the backend's own 429 dressed as a gateway capacity refusal.
be admin/answer-429-object >/dev/null; be admin/echo-spoof-headers >/dev/null
chk OS11 "a backend 429 that claims the capacity stage is relayed as 429" 429 "$(os_send both "$XH_URL")"
chk OS12 "without the stage: a client does not read it as gateway congestion" 0 "$(mark_lines "$DOS/both.hdr")"
chk OS13 "its body still the backend's object"                 rate_limit_error "$(jq -r '.error.type' "$DOS/both.body" 2>/dev/null)"
# The strip does not depend on the admission headers being on (:PORT_H1 is off).
be admin/echo-spoof-headers >/dev/null
chk OS14 "on a pool without admission headers the claim is removed too" "200 0" "$(os_send spoofoff "$H1_URL") $(mark_lines "$DOS/spoofoff.hdr")"
# An outage is not a refusal: no stage, ever. Whether it names the request
# depends on who writes it. The 502 for an endpoint that refuses the
# connection is written from the connect event, after the request was handed
# to the connect: it carries no X-Request-Id (a documented residual; the
# trail has the request, as a completion). The 503 for a pool with no
# healthy endpoint is written while the request is still being placed, and
# names it (OS23 on).
chk OS15 "a request whose only endpoint refuses the connection is answered 502" 502 "$(os_send dead "http://$VIP:$PORT_DEAD/v1/chat/completions")"
chk_has OS16 "naming the outage"                               backend_unreachable "$(cat "$DOS/dead.body" 2>/dev/null)"
chk OS17 "no stage on an outage"                               0 "$(mark_lines "$DOS/dead.hdr")"
chk OS18 "and no X-Request-Id on this one (written from the connect event)" 0 "$(rid_lines "$DOS/dead.hdr")"
chk OS19 "an outage is recorded as a completion, not a refusal" 0 "$(trail | jq -c 'select(.event_type=="sec.ai.deny" and .request_id=="capOSdead")' | wc -l | tr -d ' ')"
# After the request was forwarded the gateway no longer holds its ID for the
# answer: a backend that resets without answering gives a 502 with neither.
chk OS20 "a backend that resets after taking the request: 502" 502 "$(os_send reset "$H1_URL" -H 'X-Test-Reset: 1')"
chk OS21 "it had reached the backend"                          1 "$(receipts capOSreset)"
chk OS22 "no stage, and no X-Request-Id (the documented post-dispatch case)" "0 0" "$(mark_lines "$DOS/reset.hdr") $(rid_lines "$DOS/reset.hdr")"
# The outage that does name the request: the pool's only endpoint marked down
# through the API, so the request is answered while it is being placed.
dead_state() { $hexec l3h1 curl -s -m 8 -X POST "$API/config/endpointhoststate" -H 'Content-Type: application/json' \
  -d "{\"hostName\": \"31.31.31.1\", \"epPort\": $DEAD_TARGET, \"epProto\": \"tcp\", \"state\": \"$1\"}"; }
chk_has OS23 "the :$PORT_DEAD endpoint is marked down"            Success "$(dead_state red)"
sleep 1
chk OS24 "a request on a pool with no healthy endpoint is answered 503" 503 "$(os_send down "http://$VIP:$PORT_DEAD/v1/chat/completions")"
chk OS25 "naming the outage"                                   no_healthy_backend "$(jq -r '.error // "unreadable"' "$DOS/down.body" 2>/dev/null)"
chk OS26 "no stage on an outage"                               0 "$(mark_lines "$DOS/down.hdr")"
chk OS27 "and the request's own X-Request-Id"                  capOSdown "$(mark_rid "$DOS/down.hdr")"
chk OS28 "recorded as a completion, not a refusal"             0 "$(trail | jq -c 'select(.event_type=="sec.ai.deny" and .request_id=="capOSdown")' | wc -l | tr -d ' ')"
chk_has OS29 "the endpoint is marked up again"                 Success "$(dead_state green)"

echo ""
echo "NEG: refusals that are not congestion, reproduced on this bed, each with its stage"
DNG=$(mktemp -d)
neg_send() { # neg_send <name> [curl args...]: one request on the keyed pool, X-Request-Id capNG<name>
  local name=$1; shift
  $hexec l3h1 curl -s -o "$DNG/$name.body" -D "$DNG/$name.hdr" -w '%{http_code}' --max-time 20 \
    "${HDRS[@]}" -H "X-Test-Nonce: capNG$name" -H "X-Request-Id: capNG$name" "$@" \
    -d "$BODY" "$TS_URL" > "$DNG/$name.code" 2>/dev/null
  cat "$DNG/$name.code"
}
neg_key() { # neg_key <name> <allowed_models json> <rps> <burst> -> the raw key
  $hexec l3h1 curl -s -m 10 -X POST "$API/config/ai/apikey" -H 'Content-Type: application/json' \
    -d "{\"tenant_id\": \"neg-$1\", \"name\": \"neg-$1\", \"allowed_models\": $2,
         \"rate_limit_rps\": $3, \"burst_size\": $4, \"enabled\": true}" | jq -r '.raw_key // empty'
}
# neg_row <id> <what> <name> <status> <error> <stage>
neg_row() {
  chk "$1a" "$2: status"                                  "$4" "$(cat "$DNG/$3.code" 2>/dev/null)"
  chk "$1b" "$2: error"                                   "$5" "$(jq -r '.error // "unreadable"' "$DNG/$3.body" 2>/dev/null)"
  chk "$1c" "$2: X-Loxilb-Refusal-Stage"                  "$6" "$(mark_stage "$DNG/$3.hdr")"
  chk "$1d" "$2: a client does not read it as congestion" "not congestion" "$(not_congestion "$(mark_stage "$DNG/$3.hdr")")"
  chk "$1e" "$2: X-Request-Id is the one sent"            "capNG$3" "$(mark_rid "$DNG/$3.hdr")"
  chk "$1f" "$2: the deny record, by that ID, is at"      "$6" "$(deny_field "capNG$3" .detail.stage)"
  chk "$1g" "$2: it never reached a backend"              0 "$(receipts "capNG$3")"
}
neg_send nokey >/dev/null
neg_row NEG1 "no API key" nokey 401 invalid_api_key auth
KEY_M=$(neg_key model '["some-other-model"]' 1000 1000)
neg_send model -H "X-Api-Key: $KEY_M" >/dev/null
neg_row NEG2 "a key that may not use this model" model 403 model_not_allowed auth
# A key with one request a second and a burst of one: of four sent back to
# back the first passes, and at least one of the rest is over the rate.
KEY_R=$(neg_key rate "[\"$MODEL\"]" 1 1)
rl=""
for i in 1 2 3 4; do
  c=$(neg_send "rate$i" -H "X-Api-Key: $KEY_R")
  [ -z "$rl" ] && [ "$c" == "429" ] && rl="rate$i"
done
chk NEG3 "two keys issued; the rate-limited key was refused within four requests" "2 refused" "$(for k in "$KEY_M" "$KEY_R"; do [ -n "$k" ] && echo; done | wc -l | tr -d ' ') $([ -n "$rl" ] && echo refused || echo "never refused")"
neg_row NEG4 "the key's own request rate" "${rl:-rate4}" 429 rate_limit_exceeded ratelimit
chk_ge NEG4h "with Retry-After" 1 "$(hdr_val "$(hdr_of "$DNG/${rl:-rate4}.hdr")" Retry-After)"
# The store goes away: a key the gateway has never seen cannot be checked.
# The answer is a 503 at the auth stage with Retry-After 5 — a 5xx WITH a
# stage, on purpose: the gateway refused before dispatch, and it is not
# congestion. The store container runs --rm, so the stop removes it; it is
# started again, empty, for the reboot of row H (its keyed rules need it).
KEY_COLD=$(neg_key cold "[\"$MODEL\"]" 1000 1000)
docker stop "$PG_NAME" >/dev/null 2>&1
sleep 2
neg_send store -H "X-Api-Key: $KEY_COLD" >/dev/null
chk NEG5 "a cold key was issued before the store stopped" issued "$([ -n "$KEY_COLD" ] && echo issued || echo none)"
neg_row NEG6 "the policy store is unreachable" store 503 policy_store_unavailable auth
chk NEG6h "with Retry-After 5" 5 "$(hdr_val "$(hdr_of "$DNG/store.hdr")" Retry-After)"
chk NEG7 "the store is started again for the rows below" up "$(gw_pg_start >/dev/null 2>&1 && echo up || echo down)"

echo ""
echo "F2: does an Endpoint Picker fixture set X-Request-Id on an immediate answer?"
# No rule of this scenario runs an Endpoint Picker. The one EPP fixture the
# repository has is the fake in pkg/epp/epptest (driven by
# cicd/k3d-incluster-inference-epp); its immediate answers go out through the
# sender that adds the gateway's X-Request-Id. If the fake ever sets that
# header itself the answer would carry two, and this row turns red so the
# one-header assertion is added where the fake runs.
EPP_FAKE=../../pkg/epp/epptest/fake.go
chk F2a "the EPP fixture's source is readable" readable "$([ -r "$EPP_FAKE" ] && echo readable || echo missing)"
chk F2b "it sets no X-Request-Id on any answer of its own (0 = nothing to assert on the wire)" 0 "$(grep -ci 'hv("x-request-id"' "$EPP_FAKE" 2>/dev/null || true)"
echo "   headers the fixture sets on its immediate answers: $(grep -A6 'ImmediateResponse{' "$EPP_FAKE" 2>/dev/null | grep -o 'hv("[^"]*"' | sort -u | tr '\n' ' ')"

# ── H: observe mode ─────────────────────────────────────────────────────────
echo ""
echo "H: the same load in observe mode is admitted and only counted"
if gw_restart observe; then
  chk H1 "the pool reports observe mode" 1 "$(wait_metric loxilb_ai_admission_mode 1 25 "$(svc $PORT_H1)")"
  DH=$(mktemp -d)
  hold_burst "$DH" 12 capH "$H1_URL"
  chk H2 "all twelve reached the backend"     12 "$(wait_receipts capH 12 20)"
  chk H3 "gauge shows twelve executing"       12 "$(wait_metric loxilb_ai_admission_inflight 12 25 "$(svc $PORT_H1)" 'role="service"')"
  chk H4 "nothing was refused"                0  "$(count_codes "$DH" 429)"
  release_all; wait
  chk H5 "twelve answered 200"                12 "$(count_codes "$DH" 200)"
  # Nothing is refused, so every unit lands: 12 on a service ceiling of 8 is 4
  # over, and 6 per endpoint on a ceiling of 5 is 1 over on each of the two.
  # The decision is counted at each ceiling that would have refused it.
  chk H6 "six would have been shed (4 at the service ceiling, 1 per endpoint)" 6 "$(wait_metric loxilb_ai_admission_decisions_total 6 25 "$(svc $PORT_H1)" 'reason="observe_would_shed"')"
  chk H7 "twelve counted admitted"            12 "$(decisions $PORT_H1 admitted)"
  chk H8 "no capacity_shed decision"          0  "$(decisions $PORT_H1 capacity_shed)"
  chk H9 "gauge back to zero"                 0  "$(wait_metric loxilb_ai_admission_inflight 0 25 "$(svc $PORT_H1)" 'role="service"')"
  chk H10 "no anomaly"                        0  "$(msum loxilb_ai_admission_anomalies_total)"
  # The rules are configuration each instance is given: the new process,
  # given the same rules, resolves the rule's own values the same way, and
  # what the rule left to the environment follows the new environment.
  chk HA1 "the :$PORT_P ceiling is still the rule's"   "$FC_P_MAX rule" "$(wait_lb_field $PORT_P '.serviceArguments.fc_effective | "\(.max_outstanding) \(.source.max_outstanding)"' "$FC_P_MAX rule" 10)"
  chk HA2 "and its telemetry window"                   "$FC_P_STALE_MS rule" "$(lb_get $PORT_P | jq -r '.serviceArguments.fc_effective | "\(.telemetry_stale_ms) \(.source.telemetry_stale_ms)"')"
  chk HA3 "while its mode follows the new environment" "observe env" "$(lb_get $PORT_P | jq -r '.serviceArguments.fc_effective | "\(.mode) \(.source.mode)"')"
else
  echo "  [FAIL] H0 the gateway did not come back in observe mode"; nfail=$((nfail+1)); code=1
fi


# ── VA: the process accept valve bites, and says so ─────────────────────────
echo ""
# Every listener holds a connection context of its own, so the bound is set
# one above the listeners this scenario serves: the first held request takes
# the last context and the rest wait in the listen backlog. A fixed bound
# would stop meaning that the moment the scenario gained a rule.
VA_BOUND=$(( $($hexec l3h1 curl -s -m 8 "$API/config/loadbalancer/all" | jq '.lbAttr | length' 2>/dev/null || echo 0) + 1 ))
echo "VA: a gateway with a connection-context bound of $VA_BOUND (its listeners + 1) holds accepts back past it"
DVA=$(mktemp -d)
if GW_EXTRA_ENV="LLB_PD_MAX_TOTAL_INFLIGHT=$VA_BOUND" gw_restart enforce; then
  chk VA1 "the bound is exported" $VA_BOUND "$(wait_metric loxilb_proxy_accept_bound $VA_BOUND 25)"
  hold_burst "$DVA" 10 capVA "http://$VIP:$PORT_WU/v1/chat/completions"
  chk_ge VA2 "accepts were held back at the bound" 1 "$(wait_metric_ge loxilb_proxy_accept_blocked_total 1 25)"
  # Every held request is a client and a backend context; the valve holds
  # accepts back once the count reaches the bound.
  chk_ge VA3 "connection contexts held are counted, up to the bound" $VA_BOUND "$(wait_metric_ge loxilb_proxy_context_inflight $VA_BOUND 25)"
  # At the bound the valve pauses the listener instead of leaving its backlog
  # to be reported on every poll round (which counted hundreds of thousands of
  # hold-backs a second and spun a core). The window spans two republishes of
  # the collector, so a counter that moves is seen moving.
  blk0=$(msum loxilb_proxy_accept_blocked_total); sleep 22
  chk_le VA4 "the listener is paused at the bound, not polled (hold-backs in 22 s)" 100 \
    "$(awk -v a="$blk0" -v b="$(msum loxilb_proxy_accept_blocked_total)" 'BEGIN { if (a + 0 != a || b + 0 != b) print "unreadable"; else printf "%.0f", b - a }')"
  # The room the released requests leave re-arms the listener: the requests
  # still waiting in its backlog are accepted and answered as well.
  release capVA
  chk VA5 "every held request is answered once released" 10 "$(wait_codes "$DVA" 200 10 30)"
  release_all
else
  echo "  [FAIL] VA0 the gateway did not come back with the valve bound"; nfail=$((nfail+1)); code=1
fi

rm -rf "${DXH:-/nonexistent}" "${DTS:-/nonexistent}" "${DTW:-/nonexistent}" "${DRI:-/nonexistent}" "${DOS:-/nonexistent}" "${DNG:-/nonexistent}" "$DB" "$DN" "$DC" "$E" "$DG" "$DL" "$DQ" "$DT" "$DX" "$DK" "$DD" "$DM" "$DP" "$DO" "$DU" "$DAD" "$DWU" "$DWU2" "$DVA" "${DH:-/nonexistent}" 2>/dev/null

echo ""
if [ "$code" -eq 0 ]; then
  echo "SCENARIO-ai-admission [OK] ($npass pass)"
else
  echo "SCENARIO-ai-admission [FAILED] ($nfail fail, $npass pass)"
fi
exit $code
