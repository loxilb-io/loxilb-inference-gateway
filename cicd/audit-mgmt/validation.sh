#!/bin/bash
# Validates the management-plane audit trail (stage 1a):
#
#   T-GW-1  /audit/status reports the writer, never the trail's content
#   T-GW-3  the log-archive API refuses an audit segment by name
#   T25     the delegated originator: recorded on every record of the
#           request, trusted only for an account marked delegation_allowed,
#           never promoted to actor.user, malformed values dropped and counted
#   TM      the named management routes each leave an intent+result pair
#   T22     the side-effecting OAuth GETs: healthy start (redirect + pair),
#           unknown-state callback, refresh with tokens in the query string;
#           all three refused with 503 while the writer is wedged
#   T15     canary secrets appear in no segment (active, sealed, compressed)
#           and in no error body, after first proving they were sent
#   T11     actor conformance: with --userservice every successful result
#           names a principal; without it every record says auth=none
#   T20     a crash between a durable intent and its result is reported at
#           the next boot as exactly one sys.intent.orphaned, never guessed
#   T3      the gate fails closed: 503 audit_unavailable through a generated
#           route, a raw route and a named route, with the authoritative
#           state unchanged; the un-wedged repeat leaves a pair sharing one
#           event_id
#   T19     a full audit filesystem is visible on /metrics and in the
#           operational log while the writer writes nothing, and the
#           retroactive sys.writer.write_failed record follows recovery
#
# The scenario restarts the gateway process (tiers.sh pattern) to change
# flag sets and to crash it; every boot's records stay readable because the
# segments of a previous boot are sealed and compressed, not removed.
#
# Rules: every refusal asserts the reason, not just the status; state
# oracles are independent reads of the authoritative store, never the HTTP
# answer; observed values are printed with the verdicts; a count that could
# be satisfied by an empty trail is paired with a floor.

cd "$(dirname "$0")"
source ../common.sh
source .state
echo SCENARIO-audit-mgmt
code=0

require_host_tools jq || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }

API=http://127.0.0.1:11111/netlox/v1
GW_BIN=/root/loxilb-io/loxilb/loxilb
WEDGE_DIR=/var/log/loxilb/audit-wedge
WORK=$(mktemp -d)
REQLOG=$WORK/requests.log      # the harness's own record of what it sent
ERRBODIES=$WORK/error-bodies.log
trap 'rm -rf "$WORK"' EXIT

# ── verdict helpers ─────────────────────────────────────────────────────────
ok()  { echo "  [$1] $2 [OK]"; }
bad() { echo "  [$1] $2 [FAILED] — $3"; code=1; }
chk()     { if [[ "$4" == "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "expected '$3' got '$4'"; fi; }
chk_ne()  { if [[ "$4" != "$3" ]]; then ok "$1" "$2 = '$4'"; else bad "$1" "$2" "must not be '$3'"; fi; }
chk_has() { if [[ "$4" == *"$3"* ]]; then ok "$1" "$2"; else bad "$1" "$2" "no '$3' in: ${4:0:240}"; fi; }
chk_ge()  { if [[ "$4" =~ ^[0-9]+$ && "$4" -ge "$3" ]]; then ok "$1" "$2 = $4 (>= $3)"; else bad "$1" "$2" "expected >= $3 got '$4'"; fi; }
chk_gt()  { if [[ "$4" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$4" -gt "$3" ]]; then ok "$1" "$2 = $4 (> $3)"; else bad "$1" "$2" "expected > $3 got '$4'"; fi; }
chk_nonempty() { if [[ -n "$3" ]]; then ok "$1" "$2 = '${3:0:80}'"; else bad "$1" "$2" "empty"; fi; }

# ── requests ────────────────────────────────────────────────────────────────
# api <method> <path> [curl args...]  → RESP_CODE, RESP_BODY
# Every call is logged with its arguments: that log is the proof T15 needs
# that a canary was actually sent. Error bodies are kept for the same sweep.
api() {
  local method=$1 path=$2 out; shift 2
  printf '%s %s %s\n' "$method" "$path" "$*" >> "$REQLOG"
  out=$(docker exec llb1 curl -s -m 25 -w '\n%{http_code}' -X "$method" "$API$path" "$@")
  RESP_CODE=${out##*$'\n'}
  RESP_BODY=${out%$'\n'*}
  [[ "$RESP_BODY" == "$out" ]] && RESP_BODY=""
  if [[ "$RESP_CODE" =~ ^[45] ]]; then
    # The body only: the request line would carry the very canaries the
    # sweep looks for (a refresh route takes its tokens in the query).
    printf '%s %s %s %s\n' "$method" "${path%%\?*}" "$RESP_CODE" "$RESP_BODY" >> "$ERRBODIES"
  fi
}
# api_headers <path> [curl args...] → response headers (for the redirect arm)
api_headers() {
  local path=$1; shift
  printf 'GET %s %s\n' "$path" "$*" >> "$REQLOG"
  docker exec llb1 curl -s -m 25 -o /dev/null -D - "$API$path" "$@"
}
json() { printf '%s' "$RESP_BODY" | jq -r "$1" 2>/dev/null; }

login() { # login <user> <password> → token on stdout; retries while the store warms
  local i tok
  for i in $(seq 1 10); do
    api POST /auth/login -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}"
    tok=$(json '.token // empty')
    [[ -n "$tok" ]] && { printf '%s' "$tok"; return 0; }
    sleep 2
  done
  return 1
}

lb_body() { # lb_body <port> → a plain TCP rule on the VIP
  printf '{"serviceArguments":{"externalIP":"10.10.10.254","port":%s,"protocol":"tcp","sel":0,"mode":0,"inactiveTimeOut":60},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]}' "$1"
}
rule_count() { # rule_count <port> → how many rules the gateway holds on that port (the state oracle)
  api GET /config/loadbalancer/all "${AUTH[@]}"
  json "[.lbAttr[]? | select(.serviceArguments.port == $1)] | length"
}
user_id() { # user_id <username> → the account id from the listing (the store)
  api GET /auth/users "${AUTH[@]}"
  json "if type==\"array\" then (.[] | select(.username==\"$1\") | .id) else empty end"
}

# ── the trail ───────────────────────────────────────────────────────────────
# trail [dir...] → every record of every segment (active, sealed, gzipped)
# as one JSON object per line. Segment headers and footers (lines carrying
# "kind") and any line that is not JSON are dropped here; T19-6 counts the
# latter separately, because a torn line inside a segment is a finding.
trail_raw() {
  local d dirs=("$@")
  [[ ${#dirs[@]} -eq 0 ]] && dirs=("$AUDIT_DIR" "$WEDGE_DIR")
  for d in "${dirs[@]}"; do
    docker exec llb1 sh -c "cd '$d' 2>/dev/null || exit 0; for f in *.jsonl; do [ -f \"\$f\" ] && cat \"\$f\"; done; for f in *.jsonl.gz; do [ -f \"\$f\" ] && zcat \"\$f\"; done" 2>/dev/null
  done
}
trail() { trail_raw "$@" | jq -c -R 'fromjson? | select(type=="object" and .event_type != null)'; }
# records <jq filter> [dir...] → the matching records, oldest first
records() { local f=$1; shift; trail "$@" | jq -c "select($f)"; }
# count <jq filter> [dir...]
count() { records "$@" | wc -l | tr -d ' '; }
# wait_result <event_id> → waits (bounded) for the result phase of a pair;
# the result is appended asynchronously after the handler answers.
wait_result() {
  local i
  for i in $(seq 1 30); do
    [[ "$(count ".event_id==\"$1\" and .phase==\"result\"")" -ge 1 ]] && return 0
    sleep 0.5
  done
  return 1
}
# pair_of <jq filter for the intent> → the event_id of the newest such intent
newest_intent() { local f=$1; shift; records ".phase==\"intent\" and ($f)" "$@" | tail -n1 | jq -r '.event_id'; }

astatus() { docker exec llb1 curl -s -m 5 "${AUTH[@]}" "$API/audit/status"; }
metric_val() { # metric_val <family> [<label substring>] → the sample value
  local fam=$1 lab=${2:-}
  docker exec llb1 curl -s -m 5 "${AUTH[@]}" "$API/metrics" 2>/dev/null |
    awk -v f="$fam" -v l="$lab" '($1 ~ ("^" f "(\\{|$)")) && (l == "" || index($1, l)) { print $2; exit }'
}
gw_log_grep() { # gw_log_grep <pattern> → matching operational log lines
  docker exec llb1 sh -c 'cat /var/log/loxilb.log /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null' | grep -a -- "$1"
}

# ── the gateway process (tiers.sh pattern) ──────────────────────────────────
gw_wait_dead() {
  local i
  for i in $(seq 1 "$1"); do
    docker exec llb1 pgrep -f "$GW_BIN" >/dev/null 2>&1 || return 0
    sleep 1
  done
  return 1
}
gw_stop() { # orderly: SIGTERM, then escalate; the writer closes its segment
  docker exec llb1 pkill -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 15 && return 0
  echo "  (old gateway survived SIGTERM for 15s; escalating to SIGKILL)"
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10 && return 0
  echo "  FATAL: the old gateway process would not die"; return 1
}
gw_crash() { # SIGKILL only: no shutdown hook runs, which is the crash T20 needs
  docker exec llb1 pkill -9 -f "$GW_BIN" >/dev/null 2>&1
  gw_wait_dead 10
}
gw_start() { # gw_start <flags...>: datapath cleanup, start, wait for the API and the boot freeze
  local i ifc
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
  # Appending, not truncating: T19 reads the failure line out of this log
  # and the boots before it are part of the evidence.
  docker exec -d llb1 bash -c "ulimit -l unlimited; $GW_BIN -p --loglevel debug $* >> /tmp/loxilb.out 2>> /tmp/loxilb.err"
  for i in $(seq 1 40); do
    docker exec llb1 curl -sf -m 3 "$API/version" >/dev/null 2>&1 && break
    sleep 2
  done
  if ! docker exec llb1 curl -sf -m 3 "$API/version" >/dev/null 2>&1; then
    echo "  gateway did not come back; stderr tail:"
    docker exec llb1 tail -20 /tmp/loxilb.err
    return 1
  fi
  # The boot config replay freezes mutations for a while after the listener
  # answers; a write that cannot apply (empty body) probes the freeze.
  for i in $(seq 1 40); do
    if ! docker exec llb1 curl -s -m 3 -X POST "$API/config/loadbalancer" -H 'Content-Type: application/json' -d '{}' | grep -qE 'boot config replay settles|frozen while a snapshot restore is in progress'; then
      return 0
    fi
    sleep 2
  done
  echo "  boot config replay never settled"
  return 1
}

# ── canaries ────────────────────────────────────────────────────────────────
CANARY_PW='cnry-pw-Zq7!Aa1x'
CANARY_BEARER='cnry-bearer-4f1e77'
CANARY_LIC='cnry-lic-77aa0-9f'
CANARY_OAT='cnry-oat-1a2b3c'
CANARY_ORT='cnry-ort-9z8y7x'
AGENT_PW='Ag3nt-cnry-pw!1a'
AGENT_PW2='Ag3nt-cnry-pw!2b'
WATCHER_PW='W4tch-cnry-pw!3c'
SENT_CANARIES=("$ADMIN_PW" "$CANARY_PW" "$CANARY_BEARER" "$CANARY_LIC" "$CANARY_OAT" "$CANARY_ORT" "$AGENT_PW" "$AGENT_PW2" "$WATCHER_PW")
RECEIVED_CANARIES=()   # secrets the gateway minted for us: raw API key, OAuth state

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "Boot 1: --userservice, OAuth routes, audit at $AUDIT_DIR"
echo "════════════════════════════════════════════════════════════════════════"
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW") || { echo "  FATAL: administrator login failed"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")
CT=(-H 'Content-Type: application/json')
B1=$(astatus | jq -r '.boot_id')
echo "  boot_id $B1"

# ── T-GW-1: the status endpoint ──────────────────────────────────────────────
echo ""
echo "T-GW-1: GET /audit/status reports the writer"
ST=$(astatus)
chk     T-GW-1-1 "available"           true "$(printf '%s' "$ST" | jq -r '.available')"
chk     T-GW-1-2 "running"             true "$(printf '%s' "$ST" | jq -r '.running')"
chk_nonempty T-GW-1-3 "boot_id"        "$(printf '%s' "$ST" | jq -r '.boot_id // empty')"
chk_ge  T-GW-1-4 "seq_high"            1    "$(printf '%s' "$ST" | jq -r '.seq_high // 0')"
chk_ge  T-GW-1-5 "accepted.mgmt"       1    "$(printf '%s' "$ST" | jq -r '.accepted.mgmt // 0')"
chk_nonempty T-GW-1-6 "segment.uuid"   "$(printf '%s' "$ST" | jq -r '.segment.uuid // empty')"
chk     T-GW-1-7 "status carries no record content (no event_type key)" 0 "$(printf '%s' "$ST" | jq '[.. | objects | has("event_type")] | map(select(.)) | length')"
FIRST=$(records ".boot_id==\"$B1\"" | head -n1 | jq -r '.event_type')
chk     T-GW-1-8 "first record of the boot is sys.writer.start" sys.writer.start "$FIRST"

# ── T-GW-3: the log-archive API never serves an audit segment ───────────────
echo ""
echo "T-GW-3: GET /log-archives/audit.jsonl is refused"
api GET /log-archives/audit.jsonl "${AUTH[@]}"
chk_ne  T-GW-3-1 "status is not 200" 200 "$RESP_CODE"
chk     T-GW-3-2 "no record leaked in the body" 0 "$(printf '%s' "$RESP_BODY" | grep -c '"event_type"')"

# ── T25: the delegated originator ───────────────────────────────────────────
echo ""
echo "T25: X-Loxilb-Originator is recorded, trusted only for delegation_allowed accounts"
ORIG_DROP0=$(metric_val loxilb_audit_originator_dropped_total)
DELEG0=$(metric_val loxilb_audit_delegation_lookups_total)

api POST /auth/users "${AUTH[@]}" "${CT[@]}" -d "{\"username\":\"agent\",\"password\":\"$AGENT_PW\",\"role\":\"admin\"}"
chk     T25-0a "create account agent (admin role)" 200 "$RESP_CODE"
api POST /auth/users "${AUTH[@]}" "${CT[@]}" -d "{\"username\":\"watcher\",\"password\":\"$WATCHER_PW\",\"role\":\"viewer\"}"
chk     T25-0b "create account watcher (viewer role)" 200 "$RESP_CODE"
AGENT_ID=$(user_id agent); WATCHER_ID=$(user_id watcher)
chk_nonempty T25-0c "agent id from the listing" "$AGENT_ID"
api PUT "/auth/users/$AGENT_ID" "${AUTH[@]}" "${CT[@]}" -d "{\"username\":\"agent\",\"password\":\"$AGENT_PW2\",\"delegation_allowed\":true}"
chk     T25-0d "mark agent delegation_allowed" 200 "$RESP_CODE"
api GET /auth/users "${AUTH[@]}"
chk     T25-0e "the store reports agent delegation_allowed" true "$(json '.[] | select(.username=="agent") | .delegation_allowed')"
UPD_ID=$(newest_intent '.event_type=="mgmt.user.update"')
wait_result "$UPD_ID"
chk_has T25-0f "the update record names delegation_allowed among changed_fields" delegation_allowed \
  "$(records ".event_id==\"$UPD_ID\" and .phase==\"result\"" | jq -c '.detail.changed_fields')"

ATOKEN=$(login agent "$AGENT_PW2") || echo "  (agent login failed)"
WTOKEN=$(login watcher "$WATCHER_PW") || echo "  (watcher login failed)"

# arm 1: a delegating account
api POST /config/loadbalancer -H "Authorization: Bearer $ATOKEN" -H 'X-Loxilb-Originator: mcp:ops-agent' "${CT[@]}" -d "$(lb_body 2041)"
chk     T25-1a "agent + originator: mutation accepted" 200 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer" and .actor.delegated=="mcp:ops-agent"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
I=$(records ".event_id==\"$EID\" and .phase==\"intent\"")
chk     T25-1b "result actor.user is the authenticated account" agent "$(printf '%s' "$R" | jq -r '.actor.user')"
chk     T25-1c "result actor.delegated"          mcp:ops-agent "$(printf '%s' "$R" | jq -r '.actor.delegated')"
chk     T25-1d "result delegation_trusted"       true       "$(printf '%s' "$R" | jq -r '.actor.delegation_trusted')"
chk     T25-1e "intent carries the claim untrusted (no principal yet)" false "$(printf '%s' "$I" | jq -r '.actor.delegation_trusted')"
chk     T25-1f "intent is the provisional view"  true       "$(printf '%s' "$I" | jq -r '.actor.provisional')"

# arm 2: an account that may not delegate
api POST /config/loadbalancer "${AUTH[@]}" -H 'X-Loxilb-Originator: mcp:ops-agent' "${CT[@]}" -d "$(lb_body 2042)"
chk     T25-2a "admin + originator: mutation accepted" 200 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer" and .actor.delegated=="mcp:ops-agent"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T25-2b "result actor.user"               "$ADMIN_USER" "$(printf '%s' "$R" | jq -r '.actor.user')"
chk     T25-2c "claim recorded as evidence"      mcp:ops-agent    "$(printf '%s' "$R" | jq -r '.actor.delegated')"
chk     T25-2d "claim not trusted"               false         "$(printf '%s' "$R" | jq -r '.actor.delegation_trusted')"

# arm 3: a refusal carries the claim too
api POST /config/loadbalancer -H "Authorization: Bearer $WTOKEN" -H 'X-Loxilb-Originator: mcp:ops-agent' "${CT[@]}" -d "$(lb_body 2043)"
chk     T25-3a "viewer + originator: refused" 403 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer" and .actor.delegated=="mcp:ops-agent"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T25-3b "refusal re-typed as a security decision" sec.mgmt.authz_denied "$(printf '%s' "$R" | jq -r '.event_type')"
chk     T25-3c "result_of names the intent type"  mgmt.config.mutate "$(printf '%s' "$R" | jq -r '.result_of')"
chk     T25-3d "outcome.reason"                  authz      "$(printf '%s' "$R" | jq -r '.outcome.reason')"
chk     T25-3e "refusal names the principal"     watcher    "$(printf '%s' "$R" | jq -r '.actor.user')"
chk     T25-3f "refusal carries the claim"       mcp:ops-agent "$(printf '%s' "$R" | jq -r '.actor.delegated')"
chk     T25-3g "the rule was not created (state oracle)" 0 "$(rule_count 2043)"

# arm 4: a malformed claim is dropped and counted, never stored
api POST /config/loadbalancer "${AUTH[@]}" -H 'X-Loxilb-Originator: not-a-scheme' "${CT[@]}" -d "$(lb_body 2044)"
chk     T25-4a "malformed originator: mutation still accepted" 200 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer"')
wait_result "$EID"
chk     T25-4b "no delegated field on the pair" 0 "$(count ".event_id==\"$EID\" and (.actor.delegated != null)")"
chk_gt  T25-4c "loxilb_audit_originator_dropped_total rose" "${ORIG_DROP0:-0}" "$(metric_val loxilb_audit_originator_dropped_total)"
chk_ge  T25-4d "/audit/status originator_dropped" 1 "$(astatus | jq -r '.originator_dropped // 0')"
chk     T25-5  "the claim is never promoted to actor.user" 0 "$(count '.actor.user=="mcp:ops-agent"')"
chk_gt  T25-6  "loxilb_audit_delegation_lookups_total rose" "${DELEG0:-0}" "$(metric_val loxilb_audit_delegation_lookups_total)"

# ── TM: the named management routes ─────────────────────────────────────────
echo ""
echo "TM: named routes leave an intent+result pair with their own event type"
tm_pair() { # tm_pair <id> <label> <event_type> <extra jq on the result>
  local eid
  eid=$(newest_intent ".event_type==\"$3\"")
  if [[ -z "$eid" || "$eid" == null ]]; then bad "$1" "$2" "no intent of type $3"; return; fi
  if ! wait_result "$eid"; then bad "$1" "$2" "intent $eid has no result"; return; fi
  local r; r=$(records ".event_id==\"$eid\" and .phase==\"result\"")
  local got; got=$(printf '%s' "$r" | jq -r "$4")
  if [[ "$got" == "true" ]]; then ok "$1" "$2 (event $eid)"; else bad "$1" "$2" "result did not satisfy [$4]: $(printf '%s' "$r" | cut -c1-300)"; fi
}
api POST /config/persist "${AUTH[@]}" "${CT[@]}" -d '{}'
echo "  POST /config/persist -> $RESP_CODE"
tm_pair TM-1 "mgmt.snapshot.persist names the file it wrote" mgmt.snapshot.persist '.outcome.ok==true and (.detail.filename|length)>0 and .detail.bytes>0 and (.detail.checksum|length)>0'
api GET /config/export "${AUTH[@]}"
echo "  GET /config/export -> $RESP_CODE"
tm_pair TM-2 "read.config.export reports what it served, never the content" read.config.export '.class=="read" and .outcome.ok==true and .detail.bytes>0 and .detail.secrets_included==false'
api PUT /maintenance "${AUTH[@]}" "${CT[@]}" -d '{"enabled":true}'
echo "  PUT /maintenance enabled -> $RESP_CODE"
api PUT /maintenance "${AUTH[@]}" "${CT[@]}" -d '{"enabled":false}'
echo "  PUT /maintenance disabled -> $RESP_CODE"
tm_pair TM-3 "mgmt.maintenance carries active_from/active_to" mgmt.maintenance '.outcome.ok==true and (.detail.active_from|length)>0 and (.detail.active_to|length)>0'
api POST /auth/token/upgrade "${AUTH[@]}" "${CT[@]}" -d "{\"license_key\":\"$CANARY_LIC\"}"
echo "  POST /auth/token/upgrade -> $RESP_CODE"
tm_pair TM-4 "mgmt.auth.token_upgrade fingerprints the token" mgmt.auth.token_upgrade '(.detail.token_fingerprint_sha256|length)==64 or .outcome.ok==false'
api POST /auth/logout -H "Authorization: Bearer $WTOKEN"
echo "  POST /auth/logout (watcher) -> $RESP_CODE"
tm_pair TM-5 "mgmt.auth.logout names the session owner" mgmt.auth.logout '.outcome.ok==true and .actor.user=="watcher"'
api GET /auth/users -H "Authorization: Bearer $WTOKEN"
# Whether an already-issued token dies with the logout is the auth plane's
# contract (ai-authsep), not the trail's; observed, not scored here.
echo "  [TM-5b] NOTE a GET with the logged-out token answers $RESP_CODE"
api GET /auth/users "${AUTH[@]}"
tm_list=$(records '.event_type=="read.credential.list" and (.detail.resource|startswith("user")) and .outcome.ok==true' | tail -n1)
if [[ -n "$tm_list" ]]; then ok TM-6 "read.credential.list (users) is one result-only record with a count: $(printf '%s' "$tm_list" | jq -c '{count:.detail.count,user:.actor.user}')"; else bad TM-6 "read.credential.list (users)" "no record"; fi
api POST /config/ai/apikey "${AUTH[@]}" "${CT[@]}" -d '{"tenant_id":"audit-tenant","name":"audit-key-1","allowed_models":["m1"],"rate_limit_rps":5,"burst_size":10,"tokens_per_min":1000,"enabled":true}'
RAW_KEY=$(json '.raw_key // empty'); KEY_ID=$(json '.key_id // empty')
chk     TM-7a "create an API key" 201 "$RESP_CODE"
[[ -n "$RAW_KEY" ]] && RECEIVED_CANARIES+=("$RAW_KEY")
tm_pair TM-7 "the key create is a mgmt.config.mutate pair with field names only" mgmt.config.mutate '.outcome.ok==true and .detail.path=="/netlox/v1/config/ai/apikey" and (.detail.changed_fields|index("name")!=null)'
api GET "/config/ai/apikey/$KEY_ID" "${AUTH[@]}"
tm_key=$(records '.event_type=="read.credential.list" and (.detail.resource|startswith("apikey"))' | tail -n1)
if [[ -n "$tm_key" ]]; then ok TM-8 "read.credential.list (apikey get) recorded: $(printf '%s' "$tm_key" | jq -c '{count:.detail.count,tenant:.detail.tenant}')"; else bad TM-8 "read.credential.list (apikey)" "no record"; fi
api DELETE "/auth/users/$WATCHER_ID" "${AUTH[@]}"
echo "  DELETE /auth/users/$WATCHER_ID -> $RESP_CODE"
tm_pair TM-9 "mgmt.user.delete" mgmt.user.delete '.outcome.ok==true and .actor.user=="admin"'
tm_pair TM-10 "mgmt.user.create names the account and role" mgmt.user.create '.outcome.ok==true and .detail.username=="watcher" and .detail.role=="viewer"'

# ── T15 (send phase): the canaries that need a request of their own ─────────
echo ""
echo "T15: sending the remaining canaries"
api POST /auth/login "${CT[@]}" -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$CANARY_PW\"}"
chk     T15-s1 "wrong password refused" 401 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.auth.login"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T15-s1b "failed login is sec.mgmt.authn_failed" sec.mgmt.authn_failed "$(printf '%s' "$R" | jq -r '.event_type')"
chk     T15-s1c "result_of mgmt.auth.login" mgmt.auth.login "$(printf '%s' "$R" | jq -r '.result_of')"
chk     T15-s1d "reason login_failed" login_failed "$(printf '%s' "$R" | jq -r '.outcome.reason')"
chk     T15-s1e "the claimed name is kept, the password is not" "$ADMIN_USER" "$(printf '%s' "$R" | jq -r '.actor.username_claimed')"
api POST /config/loadbalancer -H "Authorization: Bearer $CANARY_BEARER" "${CT[@]}" -d "$(lb_body 2045)"
chk     T15-s2 "bearer canary refused" 401 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T15-s2b "refused mutation is sec.mgmt.authn_failed" sec.mgmt.authn_failed "$(printf '%s' "$R" | jq -r '.event_type')"
chk     T15-s2c "reason auth" auth "$(printf '%s' "$R" | jq -r '.outcome.reason')"

# ── T22 (healthy boot): the side-effecting OAuth GETs ───────────────────────
echo ""
echo "T22: OAuth start / callback / refresh on a healthy writer"
HDRS=$(api_headers /oauth/google)
OSTATUS=$(printf '%s' "$HDRS" | head -n1 | awk '{print $2}')
LOCATION=$(printf '%s' "$HDRS" | grep -i '^location:' | tr -d '\r' | cut -d' ' -f2-)
OSTATE=$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
chk     T22-1a "start answers a redirect" 307 "$OSTATUS"
chk_nonempty T22-1b "redirect carries a state token" "$OSTATE"
[[ -n "$OSTATE" ]] && RECEIVED_CANARIES+=("$OSTATE")
EID=$(newest_intent '.event_type=="mgmt.auth.oauth_start"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T22-1c "start pair: result ok"      true   "$(printf '%s' "$R" | jq -r '.outcome.ok')"
chk     T22-1d "start pair: action"         start  "$(printf '%s' "$R" | jq -r '.detail.action')"
chk     T22-1e "start pair: provider"       google "$(printf '%s' "$R" | jq -r '.detail.provider')"
chk     T22-1f "state recorded as a fingerprint (64 hex)" 64 "$(printf '%s' "$R" | jq -r '.detail.state_token_fingerprint | length')"
chk     T22-1g "the route is unauthenticated: actor stays provisional" true "$(printf '%s' "$R" | jq -r '.actor.provisional')"
api GET "/oauth/google/callback?state=not-a-minted-state&code=x"
chk     T22-2a "callback with an unknown state refused" 400 "$RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.auth.oauth_callback"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T22-2b "callback pair: status" 400 "$(printf '%s' "$R" | jq -r '.outcome.status')"
chk     T22-2c "callback pair: action" login "$(printf '%s' "$R" | jq -r '.detail.action')"
api GET "/oauth/google/token?token=$CANARY_OAT&refreshtoken=$CANARY_ORT"
echo "  GET /oauth/google/token -> $RESP_CODE"
EID=$(newest_intent '.event_type=="mgmt.auth.oauth_token_refresh"')
wait_result "$EID"
R=$(records ".event_id==\"$EID\" and .phase==\"result\"")
chk     T22-3a "refresh pair: action" refresh "$(printf '%s' "$R" | jq -r '.detail.action')"
chk     T22-3b "refresh pair: the path carries no query string" "/netlox/v1/oauth/{provider}/token" "$(printf '%s' "$R" | jq -r '.detail.path')"

# ── T11 arm 1: attribution with --userservice ───────────────────────────────
echo ""
echo "T11 arm 1: every successful result of boot 1 names a principal"
# The rule, stated once: a result whose outcome is ok must carry a real
# principal. Two shapes are exempt by design and are counted separately so
# the exemption cannot swallow the rule: the loopback bootstrap of the first
# account (actor.bootstrap), and the unauthenticated OAuth start whose
# result inherits the provisional view (actor.provisional).
OK_RESULTS=$(count ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true)")
UNATTRIBUTED=$(count ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true) and ((.actor.user // \"\")==\"\" or .actor.auth==\"none\")")
chk_ge  T11-1a "successful, attributable results in boot 1" 12 "$OK_RESULTS"
chk     T11-1b "of which without a principal or with auth=none" 0 "$UNATTRIBUTED"
chk     T11-1c "bootstrap results (the first account only)" 1 "$(count ".boot_id==\"$B1\" and .phase==\"result\" and .actor.bootstrap==true")"
chk     T11-1d "every successful session result says auth=session" 0 "$(count ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true) and .actor.auth!=\"session\"")"
if [[ "$UNATTRIBUTED" != 0 ]]; then
  echo "  offending records:"; records ".boot_id==\"$B1\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true and (.actor.bootstrap!=true) and (.actor.provisional!=true) and ((.actor.user // \"\")==\"\" or .actor.auth==\"none\")" | cut -c1-300 | sed 's/^/    /'
fi

# ── T20: crash between intent and result ────────────────────────────────────
echo ""
echo "T20: a crash after the durable intent leaves exactly one orphan report"
# A fresh login makes sure the store pool holds a live connection; the
# paused store then keeps the handler waiting on that connection instead of
# failing fast on a connect timeout, which would have written a result.
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW"); AUTH=(-H "Authorization: Bearer $TOKEN")
docker pause "$PG_NAME"
printf 'POST /auth/users (ghost, store paused)\n' >> "$REQLOG"
docker exec llb1 curl -s -m 90 -o /dev/null -w '%{http_code}' -X POST "$API/auth/users" "${AUTH[@]}" "${CT[@]}" \
  -d '{"username":"ghost","password":"Gh0st-pass!7q","role":"viewer"}' > "$WORK/t20.code" 2>/dev/null &
T20PID=$!
sleep 4
OPEN_INTENTS=$(trail | jq -s -r '[.[] | select(.phase=="result") | .event_id] as $done
  | .[] | select(.event_type=="mgmt.user.create" and .phase=="intent" and ((.event_id as $i | $done | index($i)) == null)) | .event_id')
ORPHAN_ID=$(printf '%s\n' "$OPEN_INTENTS" | tail -n1)
chk     T20-0a "exactly one user-create intent is open while the store is paused" 1 "$(printf '%s\n' "$OPEN_INTENTS" | grep -c .)"
chk_nonempty T20-0b "its event_id" "$ORPHAN_ID"
gw_crash || echo "  (gateway did not die within 10s)"
wait $T20PID 2>/dev/null
echo "  the blocked request ended with HTTP '$(cat "$WORK/t20.code" 2>/dev/null)' (connection cut by the crash)"
docker unpause "$PG_NAME"
sleep 2
echo "  restarting (boot 2, same flags)"
gw_start $MGMT_ARGS $AIKEY_ARGS $OAUTH_ARGS --audit-dir "$AUDIT_DIR" --audit-required || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW"); AUTH=(-H "Authorization: Bearer $TOKEN")
B2=$(astatus | jq -r '.boot_id')
echo "  boot_id $B2"
ORPHANS=$(records ".boot_id==\"$B2\" and .event_type==\"sys.intent.orphaned\"")
chk     T20-1a "one sys.intent.orphaned record at boot 2" 1 "$(printf '%s' "$ORPHANS" | grep -c .)"
chk     T20-1b "it names the orphaned intent" "$ORPHAN_ID" "$(printf '%s' "$ORPHANS" | jq -r '.detail.intent_event_id' | head -n1)"
echo "  config_generation_at_boot: $(printf '%s' "$ORPHANS" | jq -r '.detail.config_generation_at_boot // "0 (omitted)"' | head -n1)"
chk     T20-2a "loxilb_audit_orphaned_intents_total" 1 "$(metric_val loxilb_audit_orphaned_intents_total)"
chk     T20-2b "/audit/status orphaned_intents" 1 "$(astatus | jq -r '.orphaned_intents // 0')"
chk     T20-2c "/audit/status last_orphan_event_id" "$ORPHAN_ID" "$(astatus | jq -r '.last_orphan_event_id')"
chk     T20-3  "no result was synthesised for the orphan" 0 "$(count ".event_id==\"$ORPHAN_ID\" and .phase==\"result\"")"
chk_ge  T20-4  "boot 1's unsealed segment was recovered" 1 "$(count ".boot_id==\"$B2\" and .event_type==\"sys.segment.recovered\"")"
api GET /auth/users "${AUTH[@]}"
echo "  (the store $(json '[.[]|select(.username=="ghost")]|length' | sed 's/^0$/does not hold/;s/^1$/holds/') the ghost account; the trail does not guess either way)"

# ── Boot 3: the wedge ───────────────────────────────────────────────────────
echo ""
echo "Boot 3: audit directory on a 1 MiB tmpfs, then filled — T3, T19, T22 wedged arms"
echo "════════════════════════════════════════════════════════════════════════"
gw_stop || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
docker exec llb1 sh -c "mkdir -p $WEDGE_DIR && mount -t tmpfs -o size=1m,mode=0700 tmpfs $WEDGE_DIR && chmod 0700 $WEDGE_DIR" || { echo "  FATAL: cannot mount the wedge tmpfs"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
gw_start $MGMT_ARGS $AIKEY_ARGS $OAUTH_ARGS --audit-dir "$WEDGE_DIR" --audit-required || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
TOKEN=$(login "$ADMIN_USER" "$ADMIN_PW") || { echo "  FATAL: login on boot 3 failed"; echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")
B3=$(astatus | jq -r '.boot_id')
echo "  boot_id $B3"
api POST /config/ai/apikey "${AUTH[@]}" "${CT[@]}" -d '{"tenant_id":"audit-tenant","name":"audit-key-2","allowed_models":["m1"],"rate_limit_rps":5,"burst_size":10,"tokens_per_min":1000,"enabled":true}'
KEY2=$(json '.key_id // empty'); RAW2=$(json '.raw_key // empty')
[[ -n "$RAW2" ]] && RECEIVED_CANARIES+=("$RAW2")
chk_nonempty T3-0 "a key to PATCH through the raw route" "$KEY2"
W0=$(metric_val loxilb_audit_write_failures_total)
echo "  before the fill: write_failures_total=$W0"

# Fill to the last byte: a page-sized dd leaves the tail of the last page,
# a byte-sized one closes it. The writer's next append gets ENOSPC.
docker exec llb1 sh -c "dd if=/dev/zero of=$WEDGE_DIR/fill bs=4096 >/dev/null 2>&1; dd if=/dev/zero of=$WEDGE_DIR/fill2 bs=1 >/dev/null 2>&1; df -k $WEDGE_DIR | tail -n1"

echo ""
echo "T3: the gate fails closed while the writer cannot append"
api POST /config/loadbalancer "${AUTH[@]}" "${CT[@]}" -d "$(lb_body 2051)"
chk     T3-1a "generated route: 503" 503 "$RESP_CODE"
chk_has T3-1b "generated route: reason audit_unavailable" audit_unavailable "$RESP_BODY"
chk_has T3-1c "generated route: the class of failure is named" "durable write failed" "$RESP_BODY"
chk     T3-1d "generated route: the rule table is unchanged (state oracle)" 0 "$(rule_count 2051)"
api PATCH "/config/ai/apikey/$KEY2" "${AUTH[@]}" "${CT[@]}" -d '{"enabled":false}'
chk     T3-2a "raw route (PATCH apikey): 503" 503 "$RESP_CODE"
chk_has T3-2b "raw route: reason audit_unavailable" audit_unavailable "$RESP_BODY"
api GET "/config/ai/apikey/$KEY2" "${AUTH[@]}"
chk     T3-2c "raw route: the key is still enabled (state oracle)" true "$(json '.enabled')"
api POST /auth/users "${AUTH[@]}" "${CT[@]}" -d '{"username":"ghost2","password":"Gh0st-pass!8r","role":"viewer"}'
chk     T3-3a "named route (POST /auth/users): 503" 503 "$RESP_CODE"
api GET /auth/users "${AUTH[@]}"
chk     T3-3b "named route: the account was not created (state oracle)" 0 "$(json '[.[]|select(.username=="ghost2")]|length')"
chk     T3-3c "named route: the listing itself is still served (R-list)" 200 "$RESP_CODE"

echo ""
echo "T22: the OAuth GETs are refused before any side effect while wedged"
api GET /oauth/google
chk     T22-4a "start: 503" 503 "$RESP_CODE"
chk_has T22-4b "start: reason audit_unavailable" audit_unavailable "$RESP_BODY"
api GET "/oauth/google/callback?state=not-a-minted-state&code=x"
chk     T22-5  "callback: 503 before any exchange" 503 "$RESP_CODE"
api GET "/oauth/google/token?token=$CANARY_OAT&refreshtoken=$CANARY_ORT"
chk     T22-6  "refresh: 503 before any exchange" 503 "$RESP_CODE"

echo ""
echo "T19: the failure is visible outside the writer while it writes nothing"
W1=$(metric_val loxilb_audit_write_failures_total)
chk_gt  T19-1a "loxilb_audit_write_failures_total rose" "${W0:-0}" "$W1"
chk_ge  T19-1b "/audit/status write_failures" 1 "$(astatus | jq -r '.write_failures // 0')"
chk     T19-1c "the writer goroutine is still up (running)" true "$(astatus | jq -r '.running')"
chk     T19-1d "loxilb_audit_writer_up" 1 "$(metric_val loxilb_audit_writer_up)"
chk_ge  T19-2  "the operational log carries the fallback line" 1 "$(gw_log_grep 'audit: write failed (' | wc -l | tr -d ' ')"
L0=$(metric_val loxilb_audit_last_write_timestamp_seconds)
N0=$(count ".boot_id==\"$B3\"")
echo "  waiting 35 s across one heartbeat interval so staleness is measurable (last_write=$L0, records=$N0)"
sleep 35
chk     T19-3a "loxilb_audit_last_write_timestamp_seconds did not advance" "$L0" "$(metric_val loxilb_audit_last_write_timestamp_seconds)"
chk_gt  T19-3b "the failing heartbeat added to write_failures_total" "$W1" "$(metric_val loxilb_audit_write_failures_total)"
chk     T19-3c "no record of this boot landed while wedged" "$N0" "$(count ".boot_id==\"$B3\"")"

echo ""
echo "Un-wedge: free the filesystem, repeat the calls"
docker exec llb1 sh -c "rm -f $WEDGE_DIR/fill $WEDGE_DIR/fill2; df -k $WEDGE_DIR | tail -n1"
api POST /config/loadbalancer "${AUTH[@]}" "${CT[@]}" -d "$(lb_body 2051)"
chk     T3-4a "generated route after un-wedge: accepted" 200 "$RESP_CODE"
chk     T3-4b "the rule now exists" 1 "$(rule_count 2051)"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.path=="/netlox/v1/config/loadbalancer"' "$WEDGE_DIR")
wait_result "$EID" || true
chk     T3-4c "intent and result share one event_id" 2 "$(count ".event_id==\"$EID\" and (.phase==\"intent\" or .phase==\"result\")" "$WEDGE_DIR")"
chk     T3-4d "the intent was written before the result (seq order)" true \
  "$(records ".event_id==\"$EID\"" "$WEDGE_DIR" | jq -s -r 'sort_by(.seq) | (.[0].phase=="intent" and .[1].phase=="result")')"
api PATCH "/config/ai/apikey/$KEY2" "${AUTH[@]}" "${CT[@]}" -d '{"enabled":false}'
chk     T3-5a "raw route after un-wedge: accepted" 204 "$RESP_CODE"
api GET "/config/ai/apikey/$KEY2" "${AUTH[@]}"
chk     T3-5b "the key is now disabled" false "$(json '.enabled')"
EID=$(newest_intent '.event_type=="mgmt.config.mutate" and .detail.raw==true' "$WEDGE_DIR")
wait_result "$EID" || true
chk     T3-5c "raw pair: route_class raw" raw "$(records ".event_id==\"$EID\" and .phase==\"result\"" "$WEDGE_DIR" | jq -r '.detail.route_class')"
chk     T3-5d "raw pair: path template" "/netlox/v1/config/ai/apikey/{key_id}" "$(records ".event_id==\"$EID\" and .phase==\"result\"" "$WEDGE_DIR" | jq -r '.detail.path')"

WF=$(records '.event_type=="sys.writer.write_failed"' "$WEDGE_DIR" | tail -n1)
chk_nonempty T19-4a "retroactive sys.writer.write_failed record" "$WF"
chk_nonempty T19-4b "errno_class" "$(printf '%s' "$WF" | jq -r '.detail.errno_class // empty')"
chk_ge  T19-4c "count of failed appends in the interval" 3 "$(printf '%s' "$WF" | jq -r '.detail.count // 0')"
chk     T19-4d "first_ts <= last_ts" true "$(printf '%s' "$WF" | jq -r '(.detail.first_ts <= .detail.last_ts)')"
chk_ge  T19-4e "the operational log notes the resumption" 1 "$(gw_log_grep 'audit: writing resumed after' | wc -l | tr -d ' ')"
chk     T19-5  "/audit/status write_failures agrees with the metric" "$(metric_val loxilb_audit_write_failures_total)" "$(astatus | jq -r '.write_failures')"
TORN=$(trail_raw "$WEDGE_DIR" | jq -R 'fromjson? | 1' | wc -l | tr -d ' ')
RAWN=$(trail_raw "$WEDGE_DIR" | grep -c .)
chk     T19-6  "every line of the wedged segment parses ($RAWN lines; a torn line mid-segment is a finding)" "$RAWN" "$TORN"

# ── Boot 4: T11 arm 2, no user service ──────────────────────────────────────
echo ""
echo "Boot 4: no --userservice — the trail says auth=none rather than inventing an actor"
echo "════════════════════════════════════════════════════════════════════════"
gw_stop || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
gw_start $AIKEY_ARGS --audit-dir "$AUDIT_DIR" --audit-required || { echo "SCENARIO-audit-mgmt [FAILED]"; exit 1; }
AUTH=()
B4=$(astatus | jq -r '.boot_id')
echo "  boot_id $B4"
api POST /config/loadbalancer "${CT[@]}" -d "$(lb_body 2061)"
echo "  POST /config/loadbalancer -> $RESP_CODE"
api PUT /maintenance "${CT[@]}" -d '{"enabled":true}'
api PUT /maintenance "${CT[@]}" -d '{"enabled":false}'
api POST /config/persist "${CT[@]}" -d '{}'
api GET /config/export
api POST /auth/users "${CT[@]}" -d '{"username":"nobody","password":"N0body-pass!5t","role":"viewer"}'
echo "  POST /auth/users (no user service) -> $RESP_CODE"
# One heartbeat interval, so the liveness record of a healthy writer is in
# the trail deterministically (the other boots are too short to promise one).
echo "  waiting 32 s for a heartbeat"
sleep 32
MG4=$(count ".boot_id==\"$B4\" and .stream==\"mgmt\"")
chk_ge  T11-2a "mgmt records in boot 4" 6 "$MG4"
chk     T11-2b "every one says auth=none" "$MG4" "$(count ".boot_id==\"$B4\" and .stream==\"mgmt\" and .actor.auth==\"none\"")"
chk     T11-2c "none names a user" 0 "$(count ".boot_id==\"$B4\" and .stream==\"mgmt\" and (.actor.user != null)")"
chk_ge  T11-2d "the mutations themselves succeeded (ok results)" 3 "$(count ".boot_id==\"$B4\" and .stream==\"mgmt\" and .phase==\"result\" and .outcome.ok==true")"
HB=$(records ".boot_id==\"$B4\" and .event_type==\"sys.heartbeat\"" | tail -n1)
chk_nonempty T11-2e "a heartbeat record of a healthy writer" "$(printf '%s' "$HB" | jq -c '.detail.heartbeat | {seq_high, accepted, write_failures_total}')"
chk     T11-2f "the heartbeat's accepted.mgmt agrees with the boot's mgmt record count" "$MG4" "$(printf '%s' "$HB" | jq -r '.detail.heartbeat.accepted.mgmt')"

# ── T15: canaries are absent everywhere ─────────────────────────────────────
echo ""
echo "T15: canary secrets are absent from every segment and every error body"
chk_ge  T15-0a "segments exist in both directories" 2 "$(docker exec llb1 sh -c "ls $AUDIT_DIR/*.jsonl* $WEDGE_DIR/*.jsonl* 2>/dev/null | wc -l" | tr -d ' ')"
chk_ge  T15-0b "at least one compressed segment is part of the sweep" 1 "$(docker exec llb1 sh -c "ls $AUDIT_DIR/*.jsonl.gz 2>/dev/null | wc -l" | tr -d ' ')"
SWEEP=$WORK/sweep.txt
trail_raw "$AUDIT_DIR" "$WEDGE_DIR" > "$SWEEP"
docker exec llb1 sh -c 'cat /var/log/loxilb.log /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null' > "$WORK/gwlog.txt"
n=0
for c in "${SENT_CANARIES[@]}"; do
  n=$((n+1))
  if grep -qF -- "$c" "$REQLOG"; then ok "T15-1.$n" "canary $n was sent (harness request log)"; else bad "T15-1.$n" "canary $n was sent" "not found in the request log"; fi
done
n=0
for c in "${SENT_CANARIES[@]}" "${RECEIVED_CANARIES[@]}"; do
  n=$((n+1))
  if grep -qF -- "$c" "$SWEEP"; then bad "T15-2.$n" "canary $n absent from every segment" "found: $(grep -F -- "$c" "$SWEEP" | head -n1 | cut -c1-200)"; else ok "T15-2.$n" "canary $n absent from every segment"; fi
  if grep -qF -- "$c" "$ERRBODIES"; then bad "T15-3.$n" "canary $n absent from every error body" "found: $(grep -F -- "$c" "$ERRBODIES" | head -n1 | cut -c1-200)"; else ok "T15-3.$n" "canary $n absent from every error body"; fi
  # The operational log runs at debug on this bed, which the product does
  # not ship; a hit here is reported for the reader, not scored.
  if grep -qF -- "$c" "$WORK/gwlog.txt"; then echo "  [T15-4.$n] NOTE canary $n appears in the debug operational log: $(grep -F -- "$c" "$WORK/gwlog.txt" | head -n1 | cut -c1-160)"; fi
done
chk     T15-5 "no record carries a password field" 0 "$(jq -R 'fromjson? | select(type=="object") | .. | objects | select(has("password"))' "$SWEEP" | grep -c .)"
chk     T15-6 "no query string survived into any recorded path" 0 "$(jq -R -r 'fromjson? | select(type=="object") | .detail.path // empty' "$SWEEP" | grep -c '[?#]')"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "Trail summary:"
echo "  records: $(trail "$AUDIT_DIR" "$WEDGE_DIR" | wc -l | tr -d ' ') across boots $B1 $B2 $B3 $B4"
trail "$AUDIT_DIR" "$WEDGE_DIR" | jq -r '.event_type' | sort | uniq -c | sort -rn | sed 's/^/  /'
echo ""
if [[ $code == 0 ]]; then
  echo "SCENARIO-audit-mgmt [OK]"
else
  echo "SCENARIO-audit-mgmt [FAILED]"
fi
exit $code
