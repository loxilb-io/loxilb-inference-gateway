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

LAST_NONCE=""
# The nonce counter lives in a FILE, not a shell variable, and that is the
# whole point.
#
# A shell variable could not survive the way this suite drives traffic. Every
# call site captures a status with $( ), and two driving loops run entirely
# inside one, so a counter incremented there is discarded with the subshell
# and the parent goes on minting nonces those loops already spent. Both
# failure modes are silent and both produce PASSES: a receipt lookup for a
# nonce the backend never saw reads 0 and makes every "the denial delivered
# nothing" assertion vacuous, and a REUSED nonce reads the earlier request's
# deliveries and makes a clean single delivery look like a double.
#
# That trap has now been struck three times in this one file. A rule that
# every future caller has to remember has already failed; a counter that
# cannot be rewound by a subshell cannot be got wrong. LAST_NONCE is still
# shell-local — it is read by the same shell that minted it, which is the
# one thing about the old scheme that always worked.
NONCE_FILE=$(mktemp -t qha-nonce.XXXXXX) || { echo "FATAL: cannot create the nonce counter"; exit 1; }
echo 0 > "$NONCE_FILE"
# partition_clear is defined further down; the trap resolves it when it
# fires, and it must run even on the paths that exit early — a scenario that
# aborts mid-partition would otherwise hand the next run a bed whose nodes
# cannot see each other, and config.sh has no reason to look.
trap 'partition_clear >/dev/null 2>&1; rm -f "$NONCE_FILE"' EXIT
new_nonce() {
  local n
  n=$(( $(cat "$NONCE_FILE") + 1 ))
  echo "$n" > "$NONCE_FILE"
  LAST_NONCE="qha-$$-$n"
}

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

# is_master <node> — true when this node holds a MASTER cluster instance.
is_master() {
  local out
  out=$($hexec "$1" curl -s --max-time 5 \
    "http://localhost:11111/netlox/v1/config/cistate/all" 2>/dev/null)
  case "$out" in
    *'"state":"MASTER"'*|*'"state": "MASTER"'*) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------- partitions
#
# Two cases below cut ONE protocol between the nodes and leave the other
# running, which is the only way to separate "the cluster lost its peer"
# from "the cluster kept its peer and lost its quota channel". The nodes
# reach each other over the docker bridge; config.sh recorded both bridge
# addresses precisely so a fault could be keyed on the peer rather than on
# an interface that also carries the client and backend nets.
#
# Keying bluntly is safe HERE and it is worth saying why, because it is not
# safe in general: 3784, 22222 and 22223 are dedicated to BFD and xsync, so
# a DROP on one of them cannot also be counting somebody else's packets.
# Nothing below uses a count-based match, which is the form that goes wrong
# when a port has more than one dialler.
#
# The rules live in a chain of this scenario's own, jumped to from INPUT and
# OUTPUT, so the packet counters belong to this fault alone — and the chain
# ends in RETURN, which is the witness. A DROP count of zero means one of
# two completely different things, and only the RETURN count tells them
# apart: traffic traversed the chain and none of it was the protocol we cut
# (the fault is aimed wrong), or nothing traversed the chain at all (the
# chain is not on the path and the fault is not armed). Reporting either as
# "the partition held" is how a scenario scores a fault that never happened.
PART_CHAIN=QHAPART
LLB1_BIP=$(cat "${CFGDIR}/.llb1-bridge-ip" 2>/dev/null)
LLB2_BIP=$(cat "${CFGDIR}/.llb2-bridge-ip" 2>/dev/null)
node_bip()   { [ "$1" = "llb1" ] && echo "$LLB1_BIP" || echo "$LLB2_BIP"; }

# partition_arm <proto> <port> [port...] — cut these ports between the nodes.
partition_arm() {
  local proto=$1; shift
  local n peer p
  for n in llb1 llb2; do
    peer=$(node_bip "$(other_node "$n")")
    $hexec "$n" iptables -N "$PART_CHAIN" >/dev/null 2>&1
    $hexec "$n" iptables -F "$PART_CHAIN" >/dev/null 2>&1
    for p in "$@"; do
      # Both directions: inbound from the peer on that port, and our own
      # outbound to it. Dropping only one side leaves a half-open channel
      # whose behaviour is neither the partition nor the healthy case.
      $hexec "$n" iptables -A "$PART_CHAIN" -p "$proto" -s "$peer" --dport "$p" -j DROP >/dev/null 2>&1
      $hexec "$n" iptables -A "$PART_CHAIN" -p "$proto" -d "$peer" --dport "$p" -j DROP >/dev/null 2>&1
    done
    $hexec "$n" iptables -A "$PART_CHAIN" -j RETURN >/dev/null 2>&1
    $hexec "$n" iptables -I INPUT  1 -j "$PART_CHAIN" >/dev/null 2>&1
    $hexec "$n" iptables -I OUTPUT 1 -j "$PART_CHAIN" >/dev/null 2>&1
  done
}

# part_counts <node> -> "<dropped> <fell-through>"
part_counts() {
  $hexec "$1" iptables -L "$PART_CHAIN" -v -n -x 2>/dev/null |
    awk '$3=="DROP"{d+=$1} $3=="RETURN"{r+=$1} END{printf "%d %d", d+0, r+0}'
}

# partition_witness <case> — scores whether the fault is actually armed and
# actually intercepting, from the chain's own counters on both nodes.
partition_witness() {
  local n d r td=0 tr=0 detail=""
  for n in llb1 llb2; do
    read -r d r <<EOF
$(part_counts "$n")
EOF
    td=$((td + d)); tr=$((tr + r)); detail="$detail $n:drop=$d,through=$r"
  done
  if [ "$tr" -eq 0 ] && [ "$td" -eq 0 ]; then
    bad "$1" "the partition chain saw no packets at all —$detail; it is not on the path, so nothing below is a partition result"
  elif [ "$td" -eq 0 ]; then
    bad "$1" "the chain is live but dropped nothing —$detail; the fault is aimed at a port this cluster does not use"
  else
    ok "$1" "dropped $td packets, $tr fell through"
  fi
}

partition_clear() {
  local n
  for n in llb1 llb2; do
    while $hexec "$n" iptables -D INPUT  -j "$PART_CHAIN" >/dev/null 2>&1; do :; done
    while $hexec "$n" iptables -D OUTPUT -j "$PART_CHAIN" >/dev/null 2>&1; do :; done
    $hexec "$n" iptables -F "$PART_CHAIN" >/dev/null 2>&1
    $hexec "$n" iptables -X "$PART_CHAIN" >/dev/null 2>&1
  done
}

# partition_healed <case> — a fault left armed does not announce itself; it
# silently turns every later case into a partition case. Assert the removal
# rather than trusting the delete's exit status.
partition_healed() {
  local n left=""
  for n in llb1 llb2; do
    if $hexec "$n" iptables -L "$PART_CHAIN" -n >/dev/null 2>&1; then
      left="$left $n"
    fi
  done
  if [ -n "$left" ]; then
    bad "$1" "the partition chain still exists on$left; every case after this one would be running under a fault"
  else
    ok "$1" "the partition chain is gone from both nodes"
  fi
}

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
echo "--- SYNC-3: a master with no quota state must push nothing ---"
##############################################################################
# peer_up is NOT the oracle here. Six sites write that gauge, most of them on
# the session-sync path, so a peer_up of 1 is consistent with a
# RateLimiterSync that has never been attempted. The discriminating series is
# the push-latency histogram's per-RPC count: only sendRateLimiterBatch
# observes it with rpc="RateLimiterSync", and only after the RPC returned.

RL_BEFORE=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')

# SYNC-3 first, because it can only be asked BEFORE any AI request is served
# and the answer is destroyed by the seed below.
#
# config.sh has already written a dozen tenant, user and key rate limits, and
# each of those writes builds a live RPS limiter on the spot. None of them is
# quota state: an RPS bucket's rate and burst have no field on the sync wire
# at all, so a peer receiving one gets a name and a timestamp and skips it.
# With no bucket yet charged there is therefore nothing to replicate, and a
# master that pushes anyway is pushing rows its peer will drop — five times a
# second, for the life of the process, at the cost of real RPCs.
#
# Zero is read as an assertion and not as an absence: the metric helper
# reports an absent counter family as 0 and a failed scrape as "unreadable",
# so a dark node cannot pass this by being unmeasurable.
if [ "$RL_BEFORE" = "unreadable" ]; then
  bad "SYNC-3 no quota state means no push" \
      "the master's push counter is unreadable before the first request"
elif awk -v v="$RL_BEFORE" 'BEGIN{exit !(v==0)}'; then
  ok "SYNC-3 no quota state means no push" "count=0 with $MASTER holding only RPS limiter rows"
else
  bad "SYNC-3 no quota state means no push" \
      "$MASTER completed $RL_BEFORE RateLimiterSync RPCs before any bucket was charged; every row in them is one the receiver drops"
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
    # Safe inside $( ) now that the counter is file-backed: the nonce this
    # mints is spent by this loop and can never be handed out again.
    new_nonce
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
echo ""
echo "--- SYNC-1 / QOS-HA-001: rate-limiter state actually crosses the wire ---"
##############################################################################
# peer_up is NOT the oracle here. Six sites write that gauge, most of them on
# the session-sync path, so a peer_up of 1 is consistent with a
# RateLimiterSync that has never been attempted. The discriminating series is
# the push-latency histogram's per-RPC count: only sendRateLimiterBatch
# observes it with rpc="RateLimiterSync", and only after the RPC returned.
#
# This runs AFTER the warm-up wait above, and that ordering is load-bearing.
# The seed identity carries a quota bound so that serving it charges a
# bucket — which also puts it squarely inside the cold-start warming gate,
# and a request denied 429 token_quota_warming is indistinguishable at the
# status line from a sync failure. Seeding before the window closed reported
# the warm-up as "the seed request was refused on the master".
#
# What that ordering costs, stated rather than glossed: the warm-up probe
# charges a bucket of its own, so pushes are already running by the time the
# mark below is taken and this case no longer proves that the SEED started
# them. It proves liveness — the master is completing RateLimiterSync RPCs —
# which is all any case downstream needs from it, and it still fails against
# a build whose push loop never dials. The causal claim moved up to SYNC-3,
# which is the only point in the run where "no quota state yet" is true.

RL_BEFORE=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
# Give the master some quota state to push. The seed identity carries a
# tokens-per-minute bound far larger than it could ever spend: large enough
# that the seed can never be refused, present so that serving it CHARGES a
# quota bucket. A seed whose tenant has no bound at all charges nothing —
# AllowTokens returns before it creates an entry — so it would leave the
# store with no quota state and this precondition would be asserting the
# push of rows that carry none.
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
echo "--- QOS-HA-005: a tenant holding BOTH scopes syncs both ---"
##############################################################################
# QOS-HA-002 and -003 each configure one scope on its own, so between them
# they never answer the question a real tenant poses: when an aggregate bound
# and a per-model carve-out exist together, does the rung that actually
# refused still cross?
#
# Two arms, identical except for which of the two bounds is the small one.
# The other is 100000 — far beyond anything either arm spends — so in each
# arm exactly one rung can possibly be responsible for a refusal at the far
# node, and it is a different rung in each. A wire mapping that dropped the
# aggregate scope passes the second arm and fails the first; one that
# dropped the composite scope does the reverse. Either way the pair says
# WHICH, where one arm could only say "something crossed".
quota_crosses "QOS-HA-005a aggregate rung" ha-agg-only-key   ha-ctl-005a-key
echo ""
quota_crosses "QOS-HA-005b model rung"     ha-model-only-key ha-ctl-005b-key

##############################################################################
echo ""
echo "--- QOS-HA-007: peer state must not mint phantom headroom ---"
##############################################################################
# The declared case is "no double reservation, lost release or phantom
# headroom". Phantom headroom is the half a two-container bed can see:
# whether the snapshots arriving at a node change what a caller who has
# spent NOTHING there is allowed.
#
# The reservation half — a lost release stranding a claim — turns on a peer's
# activity minute LEADING the local one, and both containers here read one
# host clock, so the window is a boundary race a few milliseconds wide. A
# case built on it would be a timing test wearing a quota test's name, which
# is the same reason this suite drives the standby directly instead of moving
# a VIP. It is covered where it can be made deterministic, in the Go tests
# for the store's receive path.
#
# The oracle is a COUNT, driven at the standby while the master pushes. A
# single request cannot see headroom shrink; it can only see it gone.
PHANTOM_KEY=$(key_raw ha-phantom-key)
if [ -z "$PHANTOM_KEY" ]; then
  bad "QOS-HA-007 identity present" "missing raw key for ha-phantom-key"
else
  # Precondition: the master must be pushing, or "nothing changed at the
  # standby" is a statement about a silent channel and not about snapshots.
  PH_MARK=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  PH_ADMITTED=0
  PH_TOTAL=0
  for _ in $(seq 1 8); do
    new_nonce
    c=$(req "$SVIP" 2020 "$PHANTOM_KEY")
    PH_TOTAL=$((PH_TOTAL + 1))
    [ "$c" = "200" ] && PH_ADMITTED=$((PH_ADMITTED + 1))
  done
  PH_NOW=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  if [ "$PH_MARK" = "unreadable" ] || [ "$PH_NOW" = "unreadable" ]; then
    bad "QOS-HA-007 pre: snapshots were arriving during the window" \
        "the master's push counter is unreadable, so the window carried no proven peer state"
  elif ! awk -v a="$PH_NOW" -v b="$PH_MARK" 'BEGIN{exit !(a>b)}'; then
    bad "QOS-HA-007 pre: snapshots were arriving during the window" \
        "the master completed no push during the window ($PH_MARK -> $PH_NOW); nothing arrived to mint headroom from"
  else
    ok "QOS-HA-007 pre: snapshots were arriving during the window" \
       "master push count $PH_MARK -> $PH_NOW"
  fi
  # 12 tokens a request against 100000/min: all eight must be admitted. The
  # bound exists only so the tenant resolves a quota at all — a tenant with
  # no bound is never consulted and the case would pass vacuously.
  if [ "$PH_ADMITTED" -eq "$PH_TOTAL" ]; then
    ok "QOS-HA-007 an unspent identity keeps its full allowance at $STANDBY" \
       "$PH_ADMITTED/$PH_TOTAL admitted against a 100000/min bound"
  else
    bad "QOS-HA-007 an unspent identity keeps its full allowance at $STANDBY" \
        "only $PH_ADMITTED/$PH_TOTAL admitted; this identity has spent nothing anywhere, so peer state has taken headroom it never used"
  fi
fi

##############################################################################
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
echo "--- QOS-HA-009: a snapshot larger than one RPC ---"
##############################################################################
# LAST on purpose: it adds several hundred limiter rows to the master, and
# every push after that point carries them. A case that ran afterwards would
# be measuring this one's setup.
#
# A push is chunked at a fixed ceiling and each chunk is its own RPC. What
# fills those chunks is the question. The store's snapshot walks the keyed
# RPS limiter table FIRST and appends the quota rows LAST — and a per-key row
# is one no receiver can act on: the wire message has no rate and no burst
# field, so both merge paths skip it. A gateway holding more keyed limiters
# than the ceiling therefore spent whole RPCs, five times a second, per peer,
# carrying nothing, and the quota rows — the only rows a failover needs —
# rode in the chunk behind them.
#
# The oracle is the push-latency histogram's count, which sendRateLimiterBatch
# observes once per RPC. Rate, not total: the same window is measured before
# and after the limiter table grows, so the reading is "did the RPC cost scale
# with rows nobody can use", with the node's own cadence as its baseline.

RPC_WINDOW=6
rpc_rate() { # -> RPCs completed by the master over RPC_WINDOW seconds
  local a b
  a=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  sleep "$RPC_WINDOW"
  b=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  if [ "$a" = "unreadable" ] || [ "$b" = "unreadable" ]; then echo "unreadable"; return; fi
  awk -v a="$a" -v b="$b" 'BEGIN{printf "%d", b-a}'
}

RPC_BASE=$(rpc_rate)
# A baseline too small to halve cannot show a doubling. Asserted, not
# assumed: if the master is not pushing at its documented cadence the
# comparison below has no scale and must not be scored.
if [ "$RPC_BASE" = "unreadable" ]; then
  bad "QOS-HA-009 pre: the master's push rate is readable" \
      "the scrape failed, so the chunking measurement has no baseline"
elif [ "$RPC_BASE" -lt 10 ]; then
  bad "QOS-HA-009 pre: the master pushes at its A-P cadence" \
      "only $RPC_BASE RPCs in ${RPC_WINDOW}s; at 200ms a tick that is far below cadence, and a 2x change could not be told from noise"
else
  ok "QOS-HA-009 pre: the master pushes at its A-P cadence" \
     "$RPC_BASE RPCs in ${RPC_WINDOW}s"
fi

# Grow the keyed limiter table past the chunk ceiling. A per-user rate limit
# creates its bucket in the same call that stores it (NetUserRateLimitSet
# resets the live bucket), so this needs no traffic at all — which is what
# keeps the measurement about chunking rather than about load.
CHUNK_ROWS=560
ROWS_OK=0
for i in $(seq 1 $CHUNK_ROWS); do
  c=$($hexec "$MASTER" curl -s -m 5 -o /dev/null -w '%{http_code}' -X POST \
    "http://localhost:11111/netlox/v1/config/ai/user/ratelimit" \
    -H 'Content-Type: application/json' \
    -d '{"tenant_id":"ha-bulk-tenant","user_id":"bulk-'"$i"'","rps":5,"burst_size":5}' 2>/dev/null)
  case "$c" in 2*) ROWS_OK=$((ROWS_OK + 1)) ;; esac
done
# Drive shape before verdict. The claim under test is about a snapshot that
# EXCEEDS one chunk; if the rows were refused there is no such snapshot and
# any reading below describes a different experiment.
if [ "$ROWS_OK" -lt 510 ]; then
  bad "QOS-HA-009 drive shape: the limiter table exceeds one chunk" \
      "only $ROWS_OK of $CHUNK_ROWS per-user limits were accepted; the ceiling is 499 rows per RPC, so the snapshot under test was never built"
else
  ok "QOS-HA-009 drive shape: the limiter table exceeds one chunk" \
     "$ROWS_OK per-user limiter rows, ceiling 499 per RPC"
fi

RPC_BIG=$(rpc_rate)
if [ "$RPC_BIG" = "unreadable" ]; then
  bad "QOS-HA-009 the RPC cost does not scale with rows no peer can use" \
      "the scrape failed after the limiter table grew"
elif [ "$RPC_BASE" = "unreadable" ] || [ "$RPC_BASE" -lt 10 ]; then
  bad "QOS-HA-009 the RPC cost does not scale with rows no peer can use" \
      "no usable baseline; measured $RPC_BIG RPCs in ${RPC_WINDOW}s"
elif awk -v a="$RPC_BIG" -v b="$RPC_BASE" 'BEGIN{exit !(a > b*1.5)}'; then
  bad "QOS-HA-009 the RPC cost does not scale with rows no peer can use" \
      "$RPC_BASE -> $RPC_BIG RPCs per ${RPC_WINDOW}s after adding $ROWS_OK per-key rows; the extra RPCs carry rows both merge paths skip"
else
  ok "QOS-HA-009 the RPC cost does not scale with rows no peer can use" \
     "$RPC_BASE -> $RPC_BIG RPCs per ${RPC_WINDOW}s across $ROWS_OK added limiter rows"
fi

# And the claim that actually matters: with the limiter table over the
# ceiling, quota debt still crosses. Same helper, same controls as every
# other rung — the only thing changed is the size of the snapshot carrying
# it, which is the point.
quota_crosses "QOS-HA-009" ha-chunk-key ha-ctl-009-key

##############################################################################
echo ""
echo "--- QOS-HA-008: the legacy tenant scopes round-trip unambiguously ---"
##############################################################################
# The two tenant scopes pre-date scope prefixing, so their map keys carry no
# prefix and the wire mapping INFERS which of the two a key is from whether
# it contains "|": "tenant" exports as "t:tenant", "tenant|model" as
# "tm:tenant|model", and the receiver strips whichever it finds.
#
# QOS-HA-002, -003 and -005 drive both scopes across that mapping and show
# they arrive. What none of them can show is why the inference is SAFE,
# because the inference is only unambiguous while no identity can contain the
# delimiter. A tenant that could be named "acme|gpt-4" would share one bucket
# with tenant "acme"'s gpt-4 carve-out — one tenant's spend refusing another,
# through a wire mapping that did exactly what it was told.
#
# So the case asserts the guard rather than re-driving the path: the config
# surface must refuse the delimiter. Both orders are checked, because a guard
# that only rejects a leading or trailing "|" would pass a one-sided probe.
scope_guard() { # <case> <tenant-id>
  local resp code
  resp=$($hexec "$MASTER" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X POST \
    "http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit" \
    -H 'Content-Type: application/json' \
    -d '{"tenant_id":"'"$2"'","rps":0,"tokens_per_min":10}' 2>/dev/null)
  code=$(printf '%s' "$resp" | sed -n 's/^http_code=//p')
  case "$code" in
    4*) ok "$1" "HTTP $code" ;;
    2*) bad "$1" "accepted (HTTP $code); this identity aliases another tenant's per-model bucket through the sync wire mapping" ;;
    *)  bad "$1" "HTTP ${code:-<none>} — neither a refusal nor an acceptance, so the guard is not under test" ;;
  esac
}
scope_guard "QOS-HA-008a the delimiter is refused inside a tenant id"  "ha-alias|qos-ha-model"
scope_guard "QOS-HA-008b the delimiter is refused at the end"          "ha-alias2|"
# Control: the same call with a legal id must be ACCEPTED. Without it, three
# refusals are equally well explained by a surface refusing everything.
resp=$($hexec "$MASTER" curl -s -m 5 -w '\nhttp_code=%{http_code}' -X POST \
  "http://localhost:11111/netlox/v1/config/ai/tenant/ratelimit" \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"ha-alias-control","rps":0,"tokens_per_min":10}' 2>/dev/null)
case "$(printf '%s' "$resp" | sed -n 's/^http_code=//p')" in
  2*) ok "QOS-HA-008c control: a legal tenant id is still accepted" ;;
  *)  bad "QOS-HA-008c control: a legal tenant id is still accepted" \
          "the surface refused a legal id too ($resp), so the refusals above are not about the delimiter" ;;
esac

##############################################################################
echo ""
echo "--- QOS-HA-013: the quota channel dies while both nodes keep serving ---"
##############################################################################
# BFD stays up, so there is no election and no failover: both nodes hold the
# roles they had and both keep answering on their own VIP. Only xsync is cut.
# That is the fault the whole feature exists to survive, and nothing tested
# it — a dead quota channel is silent by construction, and silence is what a
# harness reads as success.
#
# Three separate claims, and only two of them are the product's to keep:
#
#   * the node must SAY the channel is dead. peer_up is the series an
#     operator already watches and sendRateLimiterBatch writes 0 to it on a
#     real push failure. A partition an operator cannot see is worse than
#     one they can.
#   * the divergence itself is MEASURED, not asserted. With the channel cut
#     the far node cannot know what was spent here, so it admitting a second
#     full allowance is arithmetic, not a defect to be scored green.
#   * what IS an invariant is that the divergence does not outlive the
#     partition. The backlog must reach the far node once the channel comes
#     back, and that is asserted on an identity the far node has never
#     served — otherwise its refusal would be its own spend answering.
if [ -z "$LLB1_BIP" ] || [ -z "$LLB2_BIP" ]; then
  bad "QOS-HA-013 the peer addresses are known" \
      "config.sh did not record both bridge IPs; a partition cannot be keyed on the peer"
else
  XP_KEY=$(key_raw ha-xpart-key); XD_KEY=$(key_raw ha-xdiv-key)
  XC_KEY=$(key_raw ha-ctl-013-key)
  if [ -z "$XP_KEY" ] || [ -z "$XD_KEY" ] || [ -z "$XC_KEY" ]; then
    bad "QOS-HA-013 identities present" "missing raw key for ha-xpart-key, ha-xdiv-key or ha-ctl-013-key"
  else
    partition_arm tcp 22222 22223
    # Armed BEFORE anything is spent, and proven armed before anything is
    # spent, because the debt below drains in about a minute and every
    # second spent establishing the fault is a second off the window the
    # heal has to land in.
    sleep 6
    partition_witness "QOS-HA-013 a: the xsync partition is armed and intercepting"

    # The master notices. Polled rather than read once: the push that fails
    # is on its own cadence and the first one after the cut may still be in
    # flight.
    PU="unreadable"
    for _ in $(seq 1 20); do
      PU=$(metric "$MASTER" loxilb_sockproxy_sync_peer_up)
      [ "$PU" = "unreadable" ] && break
      awk -v v="$PU" 'BEGIN{exit !(v==0)}' && break
      sleep 1
    done
    if [ "$PU" = "unreadable" ]; then
      bad "QOS-HA-013 b: $MASTER reports the peer down" \
          "peer_up is unreadable, so whether the node noticed cannot be decided"
    elif awk -v v="$PU" 'BEGIN{exit !(v==0)}'; then
      ok "QOS-HA-013 b: $MASTER reports the peer down" "peer_up=0"
    else
      bad "QOS-HA-013 b: $MASTER reports the peer down" \
          "peer_up=$PU with the quota channel cut; a cluster that is not replicating looks exactly like one that is"
    fi

    # The measurement. Spend an identity at the master, then ask the far
    # node the same question while the channel is down. This one is
    # reported, not scored: see the header above.
    new_nonce; code=$(req "$MVIP" 2020 "$XD_KEY")
    chk_code "QOS-HA-013 c: divergence probe admitted once on $MASTER" 200 "$code"
    new_nonce; code=$(req "$MVIP" 2020 "$XD_KEY")
    chk_code "QOS-HA-013 d: divergence probe refused on $MASTER" 429 "$code"
    new_nonce; DIV=$(req "$SVIP" 2020 "$XD_KEY")
    echo "       (QOS-HA-013: with the quota channel cut, $STANDBY answered HTTP $DIV"
    echo "        to an identity already exhausted on $MASTER — a second full"
    echo "        allowance per node is the documented cost of the partition)"

    # The subject. Spent at the master, never driven at the standby, so
    # nothing the standby does to it can be the standby's own spend.
    new_nonce; code=$(req "$MVIP" 2020 "$XP_KEY")
    chk_code "QOS-HA-013 e: the subject identity is admitted once on $MASTER" 200 "$code"
    new_nonce; code=$(req "$MVIP" 2020 "$XP_KEY")
    chk_code "QOS-HA-013 f: the subject identity is refused on $MASTER" 429 "$code"

    partition_clear
    partition_healed "QOS-HA-013 g: the partition is lifted"

    # Wait for the CHANNEL, on the channel's own series, before asking the
    # far node anything. peer_up goes to 1 in exactly one place — after a
    # RateLimiterSync batch returned without error — so a 1 here is a push
    # that completed since the heal, which is the mechanism the assertion
    # below is about. Waiting on a clock instead would make the case a race
    # between the reconnect and the debt's 60-second drain.
    PU="unreadable"
    for _ in $(seq 1 25); do
      PU=$(metric "$MASTER" loxilb_sockproxy_sync_peer_up)
      [ "$PU" = "unreadable" ] && break
      awk -v v="$PU" 'BEGIN{exit !(v>0)}' && break
      sleep 1
    done
    if [ "$PU" != "unreadable" ] && awk -v v="$PU" 'BEGIN{exit !(v>0)}'; then
      ok "QOS-HA-013 h: peer_up recovers on $MASTER after the heal" "peer_up=$PU"
    else
      bad "QOS-HA-013 h: peer_up recovers on $MASTER after the heal" \
          "peer_up=$PU; the series that reported the outage never reports the recovery, so it cannot be used to clear an alert"
    fi

    # Now the invariant, and it is asked EXACTLY ONCE.
    #
    # This was a polling loop, and the loop made the assertion vacuous — it
    # could not fail. The far node has its own bound, so the first poll is
    # admitted and CHARGES it, and the second poll is refused by the debt
    # that first poll just created. The 429 that came back was the node's
    # own spend answering, not anything that crossed the wire, and a twin
    # with the heal removed passed it just as happily. Retrying a question
    # whose asking changes the answer is not polling; it is driving the
    # state you are trying to measure.
    #
    # One request, after the channel has been proven back: a node that
    # learned nothing admits it, and the case reddens.
    new_nonce; HEAL=$(req "$SVIP" 2020 "$XP_KEY")
    if [ "$HEAL" = "429" ]; then
      ok "QOS-HA-013 i: the spend made during the partition reaches $STANDBY after the heal" "HTTP 429"
    else
      bad "QOS-HA-013 i: the spend made during the partition reaches $STANDBY after the heal" \
          "HTTP ${HEAL:-<none>} — $STANDBY never served this identity, so a full allowance here is $MASTER's backlog never arriving; the divergence outlived the partition"
    fi
    chk_receipts "QOS-HA-013 i: that refusal delivered nothing" 0

    # The control has never been driven anywhere. Without it, the 429 above
    # is equally well explained by a node that came out of the partition
    # refusing everything.
    new_nonce; code=$(req "$SVIP" 2020 "$XC_KEY")
    chk_code "QOS-HA-013 j: control identity still admitted on $STANDBY" 200 "$code"
  fi
fi


##############################################################################
echo ""
echo "--- QOS-HA-014: BFD is partitioned and both nodes promote ---"
##############################################################################
# The other half of the same fault: cut the election traffic and leave the
# quota channel up. Each node stops hearing the other, each concludes it is
# alone, and both promote — split-brain, two masters pushing absolute
# snapshots at each other for as long as it lasts. The push is role-gated to
# a node holding a MASTER instance, so this is the ONLY configuration in
# which the receive path runs in both directions at once.
#
# The claim under test is the merge's: quota folds with take-the-max on the
# drain time, so an arriving snapshot can make a node more conservative and
# never less. Bidirectional push is where that stops being obvious — each
# node is now importing a view of the same bucket that lags its own, and a
# merge that installed the peer's value instead of the larger of the two
# would hand the spender its quota back on the next tick. Nothing exercised
# that direction before.
if [ -z "$LLB1_BIP" ] || [ -z "$LLB2_BIP" ]; then
  bad "QOS-HA-014 the peer addresses are known" \
      "config.sh did not record both bridge IPs; a partition cannot be keyed on the peer"
else
  SP_KEY=$(key_raw ha-split-key); SC_KEY=$(key_raw ha-ctl-014-key)
  if [ -z "$SP_KEY" ] || [ -z "$SC_KEY" ]; then
    bad "QOS-HA-014 identities present" "missing raw key for ha-split-key or ha-ctl-014-key"
  else
    # Pre-state, asserted on BOTH nodes. "One master" is the condition the
    # case changes, and a bed that was already split would make every
    # verdict below describe nothing.
    if is_master "$MASTER" && ! is_master "$STANDBY"; then
      ok "QOS-HA-014 a: exactly one master before the partition" "$MASTER MASTER, $STANDBY not"
    else
      bad "QOS-HA-014 a: exactly one master before the partition" \
          "$MASTER master=$(is_master "$MASTER" && echo yes || echo no), $STANDBY master=$(is_master "$STANDBY" && echo yes || echo no)"
    fi
    # The standby's push counter, marked here and re-read below. A node that
    # holds no MASTER instance has no peers to push to, so this number is
    # frozen for as long as it stays a backup — which makes its movement the
    # feature's own evidence that a promotion happened.
    S_MARK=$(metric "$STANDBY" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')

    partition_arm udp 3784
    # BFD detects in about 300ms (100ms interval, 3 retries), so a few
    # seconds is already generous; the wait is for the promotion to be
    # written, not for the fault to be noticed.
    sleep 6
    partition_witness "QOS-HA-014 b: the BFD partition is armed and intercepting"

    SPLIT=0
    for _ in $(seq 1 30); do
      if is_master "$MASTER" && is_master "$STANDBY"; then SPLIT=1; break; fi
      sleep 1
    done
    if [ "$SPLIT" = "1" ]; then
      ok "QOS-HA-014 c: both nodes hold a MASTER instance" "split-brain reached"
    else
      bad "QOS-HA-014 c: both nodes hold a MASTER instance" \
          "$MASTER master=$(is_master "$MASTER" && echo yes || echo no), $STANDBY master=$(is_master "$STANDBY" && echo yes || echo no) 30s after BFD was cut; the condition every assertion below names was never reached"
    fi

    # The promotion, proven by the push rather than by the role read-back. A
    # cistate read proves the control plane changed its mind; this proves
    # the rate limiter acted on it.
    S_NOW="$S_MARK"
    for _ in $(seq 1 30); do
      S_NOW=$(metric "$STANDBY" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
      [ "$S_NOW" = "unreadable" ] && break
      awk -v a="$S_NOW" -v b="$S_MARK" 'BEGIN{exit !(a>b)}' && break
      sleep 1
    done
    if [ "$S_MARK" = "unreadable" ] || [ "$S_NOW" = "unreadable" ]; then
      bad "QOS-HA-014 d: the promoted $STANDBY starts pushing" \
          "the push counter is unreadable, so the reverse direction cannot be decided"
    elif awk -v a="$S_NOW" -v b="$S_MARK" 'BEGIN{exit !(a>b)}'; then
      ok "QOS-HA-014 d: the promoted $STANDBY starts pushing" "count $S_MARK -> $S_NOW"
    else
      bad "QOS-HA-014 d: the promoted $STANDBY starts pushing" \
          "count stayed at $S_NOW; only one direction is live, so the mutual-import condition this case is about is not in effect"
    fi

    # The subject. Spend at one node while both are masters.
    new_nonce; code=$(req "$MVIP" 2020 "$SP_KEY")
    chk_code "QOS-HA-014 e: admitted once on $MASTER during the split" 200 "$code"
    new_nonce; code=$(req "$MVIP" 2020 "$SP_KEY")
    chk_code "QOS-HA-014 f: refused on $MASTER during the split" 429 "$code"

    # It must cross, even with the election broken — xsync is untouched.
    #
    # Wait on the PUSH, then ask once. The far node has its own bound, so a
    # retry loop here would admit the first request, charge it, and read its
    # own debt back as "the spend crossed" — the same vacuity QOS-HA-013's
    # heal assertion was built with. Pushes that completed after the spend
    # are the mechanism that could have carried it, and the histogram counts
    # exactly those.
    X_MARK=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
    X_NOW="$X_MARK"
    for _ in $(seq 1 30); do
      X_NOW=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
      [ "$X_NOW" = "unreadable" ] && break
      awk -v a="$X_NOW" -v b="$X_MARK" 'BEGIN{exit !(a>=b+5)}' && break
      sleep 1
    done
    if [ "$X_MARK" = "unreadable" ] || [ "$X_NOW" = "unreadable" ] ||
       ! awk -v a="$X_NOW" -v b="$X_MARK" 'BEGIN{exit !(a>=b+5)}'; then
      bad "QOS-HA-014 g: the spend crosses to $STANDBY while both are masters" \
          "$MASTER completed no pushes after the spend (count $X_MARK -> $X_NOW); nothing could have carried it and the far node's answer would be about something else"
    else
      new_nonce; XOVER=$(req "$SVIP" 2020 "$SP_KEY")
      chk_code "QOS-HA-014 g: the spend crosses to $STANDBY while both are masters" 429 "$XOVER"
    fi

    new_nonce; code=$(req "$SVIP" 2020 "$SC_KEY")
    chk_code "QOS-HA-014 h: control identity still admitted on $STANDBY" 200 "$code"

    # The retraction question, and the reason this case exists. Both nodes
    # are now exporting the same bucket and importing each other's view of
    # it. A merge that took the peer's drain time instead of the larger one
    # would refund the spender here, on the very next tick.
    sleep 4
    new_nonce; code=$(req "$MVIP" 2020 "$SP_KEY")
    chk_code "QOS-HA-014 i: the spender is still refused after importing its peer's snapshot" 429 "$code"
    chk_receipts "QOS-HA-014 i: that refusal delivered nothing" 0

    partition_clear
    partition_healed "QOS-HA-014 j: the BFD partition is lifted"

    # The cluster has to come back to one master, and which one it picks is
    # not ours to predict — so it is re-resolved rather than assumed. Every
    # case after this one addresses the nodes by role.
    ONE=0
    for _ in $(seq 1 45); do
      if is_master llb1 && ! is_master llb2; then ONE=1; break; fi
      if is_master llb2 && ! is_master llb1; then ONE=1; break; fi
      sleep 1
    done
    if [ "$ONE" = "1" ]; then
      MASTER=$(master_node); STANDBY=$(other_node "$MASTER")
      MVIP=$(node_vip "$MASTER"); SVIP=$(node_vip "$STANDBY")
      ok "QOS-HA-014 k: the split resolves to a single master" "MASTER=$MASTER STANDBY=$STANDBY"
    else
      bad "QOS-HA-014 k: the split resolves to a single master" \
          "llb1 master=$(is_master llb1 && echo yes || echo no), llb2 master=$(is_master llb2 && echo yes || echo no) 45s after BFD was restored; two masters outliving the partition is the split-brain, not the recovery"
    fi
  fi
fi


##############################################################################
echo ""
echo "--- QOS-HA-012: the active node is killed ---"
##############################################################################
# LAST, and it has to be: it takes a node away and nothing after it could
# run. Everything above has already been scored.
#
# Spend an identity at the node holding the traffic, prove the debt reached
# the other one, then stop that node and ask the survivor the same question.
# `docker stop` rather than `kill`: these containers carry
# `--restart unless-stopped`, so a kill would bring the node back mid-case
# and the run would be scoring a race instead of a failover.
#
# What this case does NOT prove, stated up front because its name promises
# more than it delivers. The subject assertion — the survivor still refuses
# the spent identity — was already true before the kill, because the debt had
# synced; that is what the cross-node cases above establish. Delete the
# `docker stop` and it still passes. So the role transfer is asserted
# separately below, and the parts that need a live peer are not asserted
# here at all:
#
#   * "a promoted node starts pushing" is the feature's own lever for a real
#     transfer, and it CANNOT be used here. The push loop needs a gRPC
#     client, and dialForRateLimiterPush cannot build one to a container
#     that has stopped — so it returns early and the push histogram never
#     observes. On a two-node bed the promoted survivor has no peer left to
#     push to, and a flat counter after this promotion is correct behaviour.
#     That lever is exercised where it works: the split-brain case above
#     promotes a node while its peer is still answering.
#   * what IS asserted here instead: the standby's push counter is frozen
#     while it is a backup (the same property, in the direction this
#     topology can still measure), the stopped node really stops answering
#     on its VIP, and a FRESH identity — never spent anywhere — is enforced
#     at the survivor after promotion. Preserved state and live enforcement
#     are different claims and only the second one needs the promotion.
KILL_KEY=$(key_raw ha-kill-key)
KILL_CTL=$(key_raw ha-ctl-012-key)
KILL_FRESH=$(key_raw ha-fresh-012-key)
if [ -z "$KILL_KEY" ] || [ -z "$KILL_CTL" ] || [ -z "$KILL_FRESH" ]; then
  bad "QOS-HA-012 identities present" "missing raw key for ha-kill-key, ha-ctl-012-key or ha-fresh-012-key"
else
  # Roles before the kill, on BOTH nodes. "The survivor was promoted" is a
  # statement about a change, and a node that already held MASTER cannot be
  # said to have been promoted by anything this case did.
  if is_master "$MASTER" && ! is_master "$STANDBY"; then
    ok "QOS-HA-012 pre-a: $MASTER holds MASTER and $STANDBY does not"
  else
    bad "QOS-HA-012 pre-a: $MASTER holds MASTER and $STANDBY does not" \
        "$MASTER master=$(is_master "$MASTER" && echo yes || echo no), $STANDBY master=$(is_master "$STANDBY" && echo yes || echo no); the promotion below would not be a change of role"
  fi

  # The backup pushes nothing, asserted here and not inherited from SYNC-2:
  # the split-brain case promoted this node and demoted it again in between,
  # so its counter is no longer zero and the standing "count=0" result no
  # longer covers the state this case starts in. Frozen over an interval is
  # the property that survives that history.
  B_MARK=$(metric "$STANDBY" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  sleep 4
  B_HOLD=$(metric "$STANDBY" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  if [ "$B_MARK" = "unreadable" ] || [ "$B_HOLD" = "unreadable" ]; then
    bad "QOS-HA-012 pre-b: the backup pushes nothing while it is a backup" \
        "the push counter is unreadable on $STANDBY"
  elif [ "$B_MARK" = "$B_HOLD" ]; then
    ok "QOS-HA-012 pre-b: the backup pushes nothing while it is a backup" "count held at $B_HOLD over 4s"
  else
    bad "QOS-HA-012 pre-b: the backup pushes nothing while it is a backup" \
        "count moved $B_MARK -> $B_HOLD on a node holding no MASTER instance; the role gate is not holding and this bed is already split"
  fi

  new_nonce; code=$(req "$MVIP" 2020 "$KILL_KEY")
  chk_code "QOS-HA-012 a: first request admitted on $MASTER" 200 "$code"
  new_nonce; code=$(req "$MVIP" 2020 "$KILL_KEY")
  chk_code "QOS-HA-012 b: second request refused on $MASTER" 429 "$code"

  # The debt must have travelled BEFORE the node goes away. Afterwards there
  # is no sender left to ask, and a survivor that refuses would be
  # indistinguishable from one that never learned anything and refuses for
  # its own reasons.
  K_MARK=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
  K_NOW="$K_MARK"
  for _ in $(seq 1 30); do
    K_NOW=$(metric "$MASTER" loxilb_sockproxy_sync_push_latency_seconds_count 'rpc="RateLimiterSync"')
    [ "$K_NOW" = "unreadable" ] && break
    awk -v a="$K_NOW" -v b="$K_MARK" 'BEGIN{exit !(a>=b+3)}' && break
    sleep 1
  done
  if [ "$K_NOW" = "unreadable" ] || ! awk -v a="$K_NOW" -v b="$K_MARK" 'BEGIN{exit !(a>=b+3)}'; then
    bad "QOS-HA-012 pre: the debt was pushed before the node was stopped" \
        "push count $K_MARK -> $K_NOW; the survivor's answer below would be about its own state, not the failover"
  else
    ok "QOS-HA-012 pre: the debt was pushed before the node was stopped" "count $K_MARK -> $K_NOW"

    KILLED=$MASTER
    docker stop "$KILLED" >/dev/null 2>&1
    # Elapsed time, not the loop counter. `for PROMOTE_SECS in $(seq 1 45)`
    # is read on the iteration that BREAKS, before that iteration's sleep —
    # so a promotion seen on the first poll reported "after 1s" no matter
    # how long the cistate call itself took, and a slow bed could report a
    # number smaller than the time it actually spent.
    T0=$(date +%s)
    PROMOTED=0
    for _ in $(seq 1 45); do
      if is_master "$STANDBY"; then PROMOTED=1; break; fi
      sleep 1
    done
    PROMOTE_SECS=$(( $(date +%s) - T0 ))
    if [ "$PROMOTED" = "1" ]; then
      ok "QOS-HA-012 c: $STANDBY promoted after $KILLED was stopped" "after ${PROMOTE_SECS}s"
    else
      bad "QOS-HA-012 c: $STANDBY promoted after $KILLED was stopped" \
          "still holds no MASTER instance ${PROMOTE_SECS}s after the other node went away"
    fi

    # The kill has to have landed on the DATA path, not merely on the
    # container list. Without this, a case that stopped nothing — or stopped
    # something that kept forwarding — reads exactly like a clean failover,
    # because every question below is asked of the other node anyway.
    #
    # The seed identity, not a control: this probe is EXPECTED to go
    # unanswered, but if the node is in fact still serving it must come back
    # 200, and only an identity that can never be refused makes that
    # distinction. An exhausted one would answer 429 and let a node that is
    # very much alive be scored as gone.
    new_nonce; code=$(req "$MVIP" 2020 "$(key_raw ha-seed-key)")
    if [ "$code" = "200" ]; then
      bad "QOS-HA-012 c2: the stopped node's VIP no longer answers" \
          "$MVIP still answered HTTP 200 after $KILLED was stopped; nothing was taken away"
    else
      ok "QOS-HA-012 c2: the stopped node's VIP no longer answers" "HTTP ${code:-<none>} on $MVIP"
    fi

    # The control has never spent anywhere. If the survivor refuses it too,
    # the survivor is refusing for a reason that is not this identity's debt
    # — it has just lost a peer, which is its own kind of reason — and the
    # subject verdict below would mean nothing.
    new_nonce; code=$(req "$SVIP" 2020 "$KILL_CTL")
    chk_code "QOS-HA-012 d: control identity admitted on the survivor" 200 "$code"

    new_nonce; code=$(req "$SVIP" 2020 "$KILL_KEY")
    chk_code "QOS-HA-012 e: the spent identity is still refused on the survivor" 429 "$code"
    chk_receipts "QOS-HA-012 e: the refusal delivered nothing" 0

    # Live enforcement, not preserved state. Everything above asks the
    # survivor to remember something; this asks it to DO something, with an
    # identity that has never been spent on either node, after it took the
    # role. A promoted node that had come back with an empty quota store and
    # was serving fail-open would pass every assertion above and fail this
    # one.
    new_nonce; code=$(req "$SVIP" 2020 "$KILL_FRESH")
    chk_code "QOS-HA-012 f: a fresh identity is admitted once on the survivor" 200 "$code"
    new_nonce; code=$(req "$SVIP" 2020 "$KILL_FRESH")
    chk_code "QOS-HA-012 f: the survivor enforces it on the second request" 429 "$code"
    chk_receipts "QOS-HA-012 f: that refusal delivered nothing" 0
  fi
fi

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
if [ "$EXECUTED" -lt 96 ]; then
  echo "  [FAIL] declared-vs-executed: only $EXECUTED case verdicts were recorded;"
  echo "         a leg that returned early is indistinguishable from one that passed"
  FAIL=$((FAIL + 1))
fi

if [ "$FAIL" -ne 0 ]; then
  echo "ai-qos-ha-sync FAILED"
  exit 1
fi
echo "ai-qos-ha-sync OK"
