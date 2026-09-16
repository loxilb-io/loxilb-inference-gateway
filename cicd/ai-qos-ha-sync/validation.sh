#!/bin/bash
# validation.sh — ai-qos-ha-sync
#
# The AI-QoS rate-limiter HA sync path, asserted at both ends.
#
# The shape every quota case takes
# --------------------------------
# One identity spends at the node that holds the traffic, is refused there,
# and is then asked the same question at the OTHER node. The claim is that
# the second node refuses too — a caller must not buy fresh quota by
# arriving somewhere else. Three things guard each verdict:
#
#   * a CONTROL identity, bounded identically and never driven, which must
#     still be admitted at the second node. Without it, "refused at llb2"
#     is equally well explained by a node that refuses everything.
#   * the backend RECEIPT counter, read from inside the backend's own
#     namespace and never through the gateway, so a denial is proved to
#     have reached no backend rather than merely to have returned 429.
#   * an explicit sync-liveness precondition (SYNC-1), because every
#     "still refused" result below is equally consistent with a sync
#     channel that never carried anything and a standby that simply has
#     no quota configured.
#
# Nothing here reads a log line as evidence of sync. "XSync connected" says
# a channel exists; it says nothing about the rate limiter's state having
# crossed it.

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0
CASES=""

VIP1=10.10.10.254
VIP2=20.20.20.254
BODY='{"model":"qos-ha-model","messages":[{"role":"user","content":"hi"}]}'
# The keyless service declares its own model_name, and the rule key is
# (host, path prefix, model) — a body naming the keyed model would not
# match that rule at all and the gateway would answer 503, which reads
# exactly like a quota refusal that arrived at the wrong number.
BODY_KEYLESS='{"model":"qos-ha-keyless","messages":[{"role":"user","content":"hi"}]}'

note_case() { CASES="$CASES$1"$'\n'; }
ok()   { note_case "$1"; echo "  [PASS] $1${2:+ ($2)}"; PASS=$((PASS + 1)); }
bad()  { note_case "$1"; echo "  [FAIL] $1${2:+ — $2}";  FAIL=$((FAIL + 1)); }

# ---------------------------------------------------------------- identities

# key_raw <name> / key_id <name> — from the ids config.sh recorded.
key_raw() { awk -F: -v n="$1" '$1==n{print $3}' "${CFGDIR}/.keys"; }
key_id()  { awk -F: -v n="$1" '$1==n{print $2}' "${CFGDIR}/.keys"; }

[ -s "${CFGDIR}/.keys" ] || { echo "FATAL: ${CFGDIR}/.keys is missing; run config.sh first"; exit 1; }
# Every quota case spends an identity down to its bound, and a 12-token
# charge against a 10/min limit takes 72 seconds to drain — longer than
# this suite runs. Re-running against a bed that has already been driven
# would report the previous run's exhausted buckets as this run's failures.
if [ ! -f "${CFGDIR}/.fresh" ]; then
  echo "FATAL: this bed has already been driven by a previous validation.sh."
  echo "       Re-run config.sh first (./rmconfig.sh && ./config.sh); the quota"
  echo "       buckets from the last run take ~72s to drain and would be"
  echo "       reported as failures of this one."
  exit 1
fi
rm -f "${CFGDIR}/.fresh"

# ---------------------------------------------------------------- the client

NONCE_SEQ=0
LAST_NONCE=""
# new_nonce MUST be called from the caller's own shell, never from inside
# req: every call site captures req's status with $( ), which runs it in a
# SUBSHELL, so a nonce minted there is discarded with that subshell and the
# parent keeps whatever it had. The receipt lookups would then all ask about
# a nonce the backend has never seen, read 0, and turn every "the denial
# delivered nothing" assertion into a vacuous pass.
new_nonce() { NONCE_SEQ=$((NONCE_SEQ + 1)); LAST_NONCE="qha-$$-$NONCE_SEQ"; }

# req <vip> <port> <key-raw|-> -> prints the HTTP status
# Every request carries its own nonce, so each call site gets an independent
# backend receipt without having to ask for one. The data-plane credential
# is X-Api-Key: Authorization is the MANAGEMENT plane's header, and sending
# a data-plane key there is answered 401 by a gateway that is working
# perfectly — a harness fault that reads as an enforcement result.
req() {
  local vip=$1 port=$2 raw=$3
  local auth=() body="$BODY"
  if [ -z "$LAST_NONCE" ]; then
    echo "000"   # no nonce minted: refuse to run a request with no receipt oracle
    return
  fi
  if [ "$raw" != "-" ]; then
    auth=(-H "X-Api-Key: $raw")
  else
    body="$BODY_KEYLESS"
  fi
  # -w so the status is asserted for EQUALITY rather than searched for as a
  # substring: curl's own report cannot be satisfied by three digits inside
  # a body, and 000 keeps meaning "never completed".
  $hexec l3h1 curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
    -H 'Content-Type: application/json' -H "X-Test-Nonce: $LAST_NONCE" \
    "${auth[@]}" --data "$body" "http://$vip:$port/v1/chat/completions" 2>/dev/null
}

# receipts <nonce> — how many requests carrying this nonce reached the
# backend. Read inside the backend's namespace, never through the gateway,
# so the path under test cannot produce the number.
receipts() {
  local out
  out=$($hexec l3ep1 curl -s --max-time 5 "http://127.0.0.1:8080/__receipts/$1" 2>/dev/null)
  case "$out" in
    ''|*[!0-9]*) echo "unreadable" ;;
    *) echo "$out" ;;
  esac
}

# chk_code <case> <want> <got>
chk_code() {
  if [ "$3" = "$2" ]; then ok "$1" "HTTP $3"; else bad "$1" "HTTP ${3:-<none>}, want $2"; fi
}

# chk_receipts <case> <want>
# An unreadable counter is NOT a counter that read zero: reporting "no
# receipts" there would turn a broken oracle into a passing denial.
chk_receipts() {
  local got; got=$(receipts "$LAST_NONCE")
  if [ "$got" = "unreadable" ]; then
    bad "$1" "backend receipt counter unreadable; that is not proof of $2 deliveries"
  elif [ "$got" = "$2" ]; then
    ok "$1" "backend receipts=$got"
  else
    bad "$1" "backend receipts=$got, want $2"
  fi
}

# ---------------------------------------------------------------- the nodes

# metric <node> <family> [label-substring] — the summed value of every
# series in the family (optionally filtered), or "unreadable". Summed
# rather than pinned to one label set so a family that gains a label does
# not silently start reading zero.
# An ABSENT counter family is zero, not unreadable: a counter nothing has
# incremented yet has no series at all. Only a scrape that produced nothing
# is a lost measurement, and the two are told apart by whether the endpoint
# answered — never by whether the family was found.
metric() {
  local node=$1 fam=$2 lab=${3:-}
  local page out
  page=$($hexec "$node" curl -s --max-time 8 "http://localhost:11111/netlox/v1/metrics" 2>/dev/null)
  if [ -z "$page" ]; then
    echo "unreadable"; return
  fi
  out=$(printf '%s\n' "$page" |
    awk -v fam="$fam" -v lab="$lab" '
      $0 ~ "^" fam "([{ ]|$)" {
        if (lab != "" && index($0, lab) == 0) next
        v = $NF; if (v + 0 == v) { s += v; n++ }
      }
      END { if (n > 0) printf "%.6f", s; else print "0" }')
  case "$out" in
    '') echo "0" ;;
    *) echo "$out" ;;
  esac
}

# master_node — which node keepalived elected. The rate-limiter push is
# role-gated (peersFn returns nil unless this node holds a MASTER cluster
# instance), so which node SENDS is not a detail: it decides which
# direction the state can travel at all.
master_node() {
  local n out
  for n in llb1 llb2; do
    out=$($hexec "$n" curl -s --max-time 5 \
      "http://localhost:11111/netlox/v1/config/cistate/all" 2>/dev/null)
    case "$out" in
      *'"state":"MASTER"'*|*'"state": "MASTER"'*) echo "$n"; return ;;
    esac
  done
  echo ""
}

other_node() { [ "$1" = "llb1" ] && echo "llb2" || echo "llb1"; }
node_vip()   { [ "$1" = "llb1" ] && echo "$VIP1" || echo "$VIP2"; }

echo "#########################################"
echo "ai-qos-ha-sync validation"
echo "#########################################"

MASTER=$(master_node)
if [ -z "$MASTER" ]; then
  echo "FATAL: neither node reports a MASTER cluster instance; the rate-limiter"
  echo "       push is role-gated off on both, so nothing below could sync."
  exit 1
fi
STANDBY=$(other_node "$MASTER")
MVIP=$(node_vip "$MASTER")
SVIP=$(node_vip "$STANDBY")
echo "  elected MASTER=$MASTER ($MVIP)  STANDBY=$STANDBY ($SVIP)"

##############################################################################
echo ""
echo "--- SYNC-1 / QOS-HA-001: rate-limiter state actually crosses the wire ---"
##############################################################################
# peer_up is NOT the oracle here. Six sites write that gauge, most of them on
# the session-sync path, so a peer_up of 1 is consistent with a
# RateLimiterSync that has never been attempted. The discriminating series is
# the push-latency histogram's per-RPC count: only sendRateLimiterBatch
# observes it with rpc="RateLimiterSync", and only after the RPC returned.

RL_BEFORE=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
# Give the master some quota state to push: without a charged bucket
# ExportState is empty and the push loop short-circuits before the RPC.
new_nonce; code=$(req "$MVIP" 2020 "$(key_raw ha-seed-key)")
chk_code "SYNC-1a seed request admitted on the master" 200 "$code"

RL_AFTER="unreadable"
for _ in $(seq 1 30); do
  RL_AFTER=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  if [ "$RL_AFTER" != "unreadable" ] && [ "$RL_BEFORE" != "unreadable" ]; then
    awk -v a="$RL_AFTER" -v b="$RL_BEFORE" 'BEGIN{exit !(a>b)}' && break
  fi
  sleep 1
done
if [ "$RL_BEFORE" = "unreadable" ] || [ "$RL_AFTER" = "unreadable" ]; then
  bad "SYNC-1 RateLimiterSync push counter readable" \
      "the sync-liveness precondition is unreadable, so no cross-node verdict below is interpretable"
elif awk -v a="$RL_AFTER" -v b="$RL_BEFORE" 'BEGIN{exit !(a>b)}'; then
  ok "SYNC-1 RateLimiterSync pushes completed from $MASTER" "count $RL_BEFORE -> $RL_AFTER"
else
  bad "SYNC-1 RateLimiterSync pushes completed from $MASTER" \
      "count stayed at $RL_AFTER after 30s of driven state; the rate-limiter half of xsync is dark"
fi

# The reverse direction is expected to be SILENT in A-P: peersFn returns nil
# on a node with no MASTER instance, so the standby has no peers to push to.
# Asserted rather than assumed, because a standby that pushes absolute
# snapshots INTO a serving master is a different system from the documented
# one, and everything downstream would inherit the difference.
RL_REV=$(metric "$STANDBY" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
if [ "$RL_REV" = "unreadable" ]; then
  ok "SYNC-2 the standby sent no RateLimiterSync push" "no such series on $STANDBY"
elif awk -v v="$RL_REV" 'BEGIN{exit !(v==0)}'; then
  ok "SYNC-2 the standby sent no RateLimiterSync push" "count=0 on $STANDBY"
else
  bad "SYNC-2 the standby sent no RateLimiterSync push" \
      "$STANDBY pushed $RL_REV RateLimiterSync RPCs while holding no MASTER instance"
fi

##############################################################################
echo ""
echo "--- QOS-HA-010/011: the cold-start warm-up window ---"
##############################################################################
# The token-quota store arms its cold-start warm-up lazily, at the FIRST AI
# request a node serves, not at boot. Inside that window every request that
# resolves any quota bound is denied 429 with token_quota_warming — which is
# the designed behaviour, and is also indistinguishable at the status line
# from the quota denials every case below is about. Running the quota cases
# without waiting for the window is how a suite reports "the first request
# was refused on the master" as a product failure.
#
# The probe identity carries a bound far larger than the probe can spend, so
# the only thing that can refuse it is the warming gate.
warm_wait() { # <node> <vip> -> prints "<saw_warming> <seconds> <final code>"
  local node=$1 vip=$2 raw body code i saw=0
  raw=$(key_raw ha-warm-key)
  for i in $(seq 1 60); do
    # Its OWN nonce namespace, not new_nonce. warm_wait runs inside $( ),
    # so any NONCE_SEQ it advanced would be discarded with that subshell —
    # and the parent would go on minting nonces this loop has already
    # spent, so later receipt counts would include these probe requests.
    LAST_NONCE="qha-warm-$$-$1-$i"
    body=$($hexec l3h1 curl -s -w '\n%{http_code}' --max-time 10 -X POST \
      -H 'Content-Type: application/json' -H "X-Test-Nonce: $LAST_NONCE" \
      -H "X-Api-Key: $raw" --data "$BODY" \
      "http://$vip:2020/v1/chat/completions" 2>/dev/null)
    code=$(printf '%s' "$body" | tail -1)
    case "$body" in *token_quota_warming*) saw=1 ;; esac
    if [ "$code" = "200" ]; then echo "$saw $i $code"; return; fi
    sleep 1
  done
  echo "$saw 60 $code"
}

for pair in "$MASTER $MVIP" "$STANDBY $SVIP"; do
  set -- $pair
  read -r W_SAW W_SECS W_CODE <<EOF
$(warm_wait "$1" "$2")
EOF
  if [ "$W_CODE" != "200" ]; then
    bad "QOS-HA-011 $1 leaves the warm-up window" \
        "still answering $W_CODE after ${W_SECS}s; the window is documented as bounded"
  elif [ "$W_SECS" -gt 30 ]; then
    bad "QOS-HA-011 $1 leaves the warm-up window" \
        "took ${W_SECS}s, far beyond the bounded cold-start window"
  else
    ok "QOS-HA-011 $1 leaves the warm-up window" "admitting after ${W_SECS}s"
  fi
  # Whether the window was OBSERVED is reported, not asserted: the node may
  # already have served a request and armed the window before this probe
  # ran, and demanding to see it would make the case depend on ordering
  # rather than on behaviour.
  if [ "$W_SAW" = "1" ]; then
    echo "       (QOS-HA-010: $1 answered token_quota_warming inside the window)"
  fi
done

##############################################################################
# quota_crosses <case-prefix> <key-name> <control-key-name>
#
# Spend the identity at the master until it is refused there, then ask the
# same question at the standby. Every step is asserted, including the ones
# that only set up the next: a leg whose FIRST request was already refused
# would otherwise "pass" without ever proving anything crossed.
##############################################################################
quota_crosses() {
  local case_prefix=$1 keyname=$2 ctlname=$3 raw ctl code
  raw=$(key_raw "$keyname"); ctl=$(key_raw "$ctlname")
  if [ -z "$raw" ] || [ -z "$ctl" ]; then
    bad "$case_prefix identities present" "missing raw key for $keyname or $ctlname"
    return
  fi

  # 1. First request at the master: admitted, and its settle charges 12
  #    tokens against a 10-token bound, putting the bucket in debt.
  new_nonce; code=$(req "$MVIP" 2020 "$raw")
  chk_code "$case_prefix a: first request admitted on $MASTER" 200 "$code"
  chk_receipts "$case_prefix a: it reached the backend" 1

  # 2. Second request at the master: refused, and nothing reaches the
  #    backend. This is the local bound working — the precondition for
  #    asking anything about the other node.
  new_nonce; code=$(req "$MVIP" 2020 "$raw")
  chk_code "$case_prefix b: second request refused on $MASTER" 429 "$code"
  chk_receipts "$case_prefix b: the refusal delivered nothing" 0

  # 3. Wait for the PUSH, not for the clock. A fixed sleep guesses at a
  #    cadence; this waits until the master has actually completed several
  #    more RateLimiterSync RPCs since the debt was created, so the verdict
  #    below is read after the state had a chance to travel. Polling the
  #    standby's ANSWER instead would be unsound: the first admitted poll
  #    would charge the bucket locally and every later poll would refuse,
  #    turning a real gap into a pass.
  local push_mark push_now waited
  push_mark=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  waited=0
  for waited in $(seq 1 30); do
    push_now=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
    [ "$push_now" = "unreadable" ] && break
    awk -v a="$push_now" -v b="$push_mark" 'BEGIN{exit !(a>=b+3)}' && break
    sleep 1
  done
  if [ "$push_now" = "unreadable" ]; then
    bad "$case_prefix pre: the master's push counter stayed readable" \
        "the scrape failed, so the cross-node verdict below is not interpretable"
    return
  fi
  if ! awk -v a="$push_now" -v b="$push_mark" 'BEGIN{exit !(a>=b+3)}'; then
    bad "$case_prefix pre: the master pushed after the debt was created" \
        "count went $push_mark -> $push_now in ${waited}s; nothing could have travelled, so the verdict below would be about the channel, not the quota"
    return
  fi
  ok "$case_prefix pre: the master pushed after the debt was created" \
     "count $push_mark -> $push_now in ${waited}s"

  # 4. The control identity is bounded identically and has never spent. If
  #    it is refused at the standby too, the standby is refusing for a
  #    reason that is not this identity's debt, and the subject verdict
  #    below means nothing.
  new_nonce; code=$(req "$SVIP" 2020 "$ctl")
  chk_code "$case_prefix c: control identity admitted on $STANDBY" 200 "$code"

  # 5. The subject.
  new_nonce; code=$(req "$SVIP" 2020 "$raw")
  chk_code "$case_prefix d: the spent identity is refused on $STANDBY" 429 "$code"
  chk_receipts "$case_prefix d: the cross-node refusal delivered nothing" 0
}

echo ""
echo "--- QOS-HA-002: per-tenant token quota ---"
quota_crosses "QOS-HA-002" ha-tenant-key ha-ctl-002-key

echo ""
echo "--- QOS-HA-003: per-tenant-per-model token quota ---"
quota_crosses "QOS-HA-003" ha-tenant-model-key ha-ctl-003-key

echo ""
echo "--- QOS-HA-004: per-key token quota ---"
# The key-TPM bucket is keyed on the key id, which config.sh proved is the
# same id on both nodes. Its tenant carries no row of its own, so a refusal
# here can only be the key rung.
quota_crosses "QOS-HA-004" ha-key-tpm ha-ctl-004-key

##############################################################################
echo ""
echo "--- QOS-HA-006: the per-VIP shared keyless bucket ---"
##############################################################################
# Keyless traffic carries no tenant, so the VIP bucket is the only thing
# bounding it. The bucket is keyed "v:<service ident>" and the service
# ident is the node's OWN vip:port — so the two nodes hold two different
# keys and the standby's bucket can never learn from the master's. That is
# a property of the scope, not a failure of sync, and the case states it in
# that direction rather than asserting a cross-node refusal that the key
# space makes impossible.
new_nonce; code=$(req "$MVIP" 2021 -)
chk_code "QOS-HA-006a keyless request admitted on $MASTER" 200 "$code"
new_nonce; code=$(req "$MVIP" 2021 -)
chk_code "QOS-HA-006b keyless request refused on $MASTER once the bucket is in debt" 429 "$code"
chk_receipts "QOS-HA-006b the refusal delivered nothing" 0
sleep 3
V_STANDBY=$(metric "$STANDBY" loxilb_ai_token_quota_utilization)
new_nonce; code=$(req "$SVIP" 2021 -)
if [ "$code" = "200" ]; then
  ok "QOS-HA-006c the standby's own VIP bucket is independent" \
     "keyless traffic is bounded per node ident, not per cluster (HTTP 200)"
else
  bad "QOS-HA-006c the standby's own VIP bucket is independent" \
      "HTTP $code — a v: bucket the standby never charged refused, which the key space does not explain"
fi

##############################################################################
echo ""
echo "--- QOS-METRIC-1: the tenant quota series carries tenants only ---"
##############################################################################
# Every ladder scope has now been charged on the master, so if the
# scrape-time collector still published keys and services as tenants this
# is where it would show. Read the label values, not just the family total:
# a mislabelled row moves a family by exactly as much as a correct one.
LEAK=$($hexec "$MASTER" curl -s --max-time 8 "http://localhost:11111/netlox/v1/metrics" 2>/dev/null |
  grep -E '^loxilb_ai_token_quota_(model_)?(utilization|limit_tokens|model_limit_tokens)\{' |
  grep -cE 'tenant="(k|u|t|tm|uq|um|kq|v|ver):' || true)
TOTAL=$($hexec "$MASTER" curl -s --max-time 8 "http://localhost:11111/netlox/v1/metrics" 2>/dev/null |
  grep -cE '^loxilb_ai_token_quota_(model_)?(utilization|limit_tokens|model_limit_tokens)\{' || true)
if [ "${TOTAL:-0}" -eq 0 ]; then
  bad "QOS-METRIC-1 tenant quota series carry no scope-prefixed identity" \
      "the family is absent entirely, so a zero leak count proves nothing"
elif [ "${LEAK:-0}" -eq 0 ]; then
  ok "QOS-METRIC-1 tenant quota series carry no scope-prefixed identity" \
     "$TOTAL series, 0 carrying a k:/u:/t:/tm:/uq:/um:/kq:/v: tenant label"
else
  bad "QOS-METRIC-1 tenant quota series carry no scope-prefixed identity" \
      "$LEAK of $TOTAL series publish a non-tenant identity in the tenant label"
fi

##############################################################################
echo ""
echo "--- QOS-HA-SNAP-1: a peer snapshot must not refill the receiver's RPS ---"
##############################################################################
# The receiving node's own per-key RATE limit must survive the master's
# absolute snapshots, which arrive every 200ms in A-P.
#
# The oracle is a COUNT over a window, not a single request after a wait.
# A single late request cannot distinguish a refill from the bucket's own
# legitimate refill: at rps=1 a token returns every second, so any wait long
# enough to cover several push intervals is also long enough to make an
# admission correct. Counting instead prices the defect directly — each
# snapshot that replaced the receiver's limiter map handed the bucket a
# fresh full burst, so admissions scale with the push rate rather than with
# the configured rate.
#
# Budget: rps=1, burst=1 over a 4s window admits at most 1 (the initial
# burst) + 4 (refill) = 5. The allowance of 7 covers scheduler jitter and a
# partial second at each end. Under the defect the window contains ~20
# snapshots, so the two populations are not close.
RPS_KEY=$(key_raw ha-rps-key)
kid=$(key_id ha-rps-key)
resp=$($hexec "$STANDBY" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X PATCH \
  "http://localhost:11111/netlox/v1/config/ai/apikey/$kid" \
  -H 'Content-Type: application/json' -d '{"rate_limit_rps":1,"burst_size":1,"tokens_per_min":0}')
case "$resp" in
  *http_code=2*) ok "QOS-HA-SNAP-1 setup: the rate bound was applied on $STANDBY" ;;
  *) bad "QOS-HA-SNAP-1 setup: the rate bound was applied on $STANDBY" "PATCH refused: $resp" ;;
esac
sleep 1

# drive_window <seconds> <key> -> "<admitted> <total>"
drive_window() {
  local secs=$1 raw=$2 deadline admitted=0 total=0 c
  deadline=$(( $(date +%s) + secs ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    new_nonce
    c=$(req "$SVIP" 2020 "$raw")
    total=$((total + 1))
    [ "$c" = "200" ] && admitted=$((admitted + 1))
    # An empty or 000 code is a lost measurement, not a refusal: it means
    # curl never completed, so the window no longer describes the gateway.
    if [ -z "$c" ] || [ "$c" = "000" ]; then
      echo "-1 $total"; return
    fi
  done
  echo "$admitted $total"
}

read -r ADMITTED TOTAL <<EOF
$(drive_window 4 "$RPS_KEY")
EOF
if [ "$ADMITTED" = "-1" ]; then
  bad "QOS-HA-SNAP-1 the standby's rate limit holds across peer snapshots" \
      "a request never completed; the window is not a measurement of the gateway"
elif [ "$TOTAL" -lt 10 ]; then
  bad "QOS-HA-SNAP-1 the standby's rate limit holds across peer snapshots" \
      "only $TOTAL requests fitted in the 4s window; the driver cannot outpace a rate of 1/s, so a low admission count proves nothing"
elif [ "$ADMITTED" -le 7 ]; then
  ok "QOS-HA-SNAP-1 the standby's rate limit holds across peer snapshots" \
     "$ADMITTED admitted of $TOTAL in 4s against rps=1 (budget 7)"
else
  bad "QOS-HA-SNAP-1 the standby's rate limit holds across peer snapshots" \
      "$ADMITTED admitted of $TOTAL in 4s against rps=1; the budget is 7, and peer snapshots arrive five times a second"
fi

# Put the key back the way the rest of the suite expects to find it.
$hexec "$STANDBY" curl -s -m 5 -o /dev/null -X PATCH \
  "http://localhost:11111/netlox/v1/config/ai/apikey/$kid" \
  -H 'Content-Type: application/json' -d '{"rate_limit_rps":0,"burst_size":0,"tokens_per_min":0}'

##############################################################################
echo ""
echo "#########################################"
echo "ai-qos-ha-sync: $PASS passed, $FAIL failed"
echo "#########################################"
##############################################################################
# Declared-vs-executed: a case that silently stopped running is the failure
# mode a pass count cannot show.
EXECUTED=$(printf '%s' "$CASES" | grep -c . || true)
echo "  cases executed: $EXECUTED"
if [ "$EXECUTED" -lt 20 ]; then
  echo "  [FAIL] declared-vs-executed: only $EXECUTED case verdicts were recorded;"
  echo "         a leg that returned early is indistinguishable from one that passed"
  FAIL=$((FAIL + 1))
fi

if [ "$FAIL" -ne 0 ]; then
  echo "ai-qos-ha-sync FAILED"
  exit 1
fi
echo "ai-qos-ha-sync OK"
