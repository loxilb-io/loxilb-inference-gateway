#!/bin/bash
# backcompat.sh — the upgrade contract, asserted.
#
# The per-service key policy changed what a service's configuration MEANS:
# enforcement used to be a rider on the streaming flag, and now it is an
# explicit declaration. This suite pins what an operator upgrading across
# that change is promised, using only artifacts a pre-upgrade deployment
# could have produced:
#
#   Phase A  a rule body captured BEFORE the field existed still installs,
#            resolves to the documented default (disabled), keeps
#            byte-identical proxying (the client's X-Api-Key reaches the
#            backend unchanged — non-AI backends legitimately consume their
#            own), and a quota configured while nothing enforces draws the
#            loud operator warning instead of pretending to protect.
#   Phase B  the operator's one-line upgrade (adding the policy to the same
#            rule) arms enforcement end to end: keyless denied, credential
#            stripped upstream, quotas live; removing the line rolls it back.
#   Phase C  what the API exports, the API re-imports: the full rule list
#            round-trips through a gateway restart with verdicts unchanged.
#
# Requires ./config.sh first (same topology as validation.sh). Safe to run
# after validation.sh or standalone; it restarts the gateway into a known
# flag set and installs only its own rules (:2030, :2031).

cd "$(dirname "$0")" || exit 1
PASS=0; FAIL=0
API=http://localhost:11111/netlox/v1
VIP=10.10.10.254

if [ ! -f .state ]; then
  echo "  FATAL: .state missing — run ./config.sh first"
  echo "SCENARIO-ai-authsep-backcompat [FAILED]"
  exit 1
fi
# shellcheck disable=SC1091
source .state

chk() { # chk <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  [PASS] $1 (got $3)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 expected=$2 got=$3"; FAIL=$((FAIL + 1))
  fi
}
chk_not() { # chk_not <name> <forbidden> <actual>
  if [ "$2" != "$3" ]; then
    echo "  [PASS] $1 (got $3, not $2)"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 must not be $2"; FAIL=$((FAIL + 1))
  fi
}
chk_has() { # chk_has <name> <needle> <haystack>
  if [ "${3#*$2}" != "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — did not find '$2' in: $(echo "$3" | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}

lcurl() { docker exec llb1 curl -s -m 30 "$@"; }
vip_code() { docker exec l3h1 curl -s -o /dev/null -m 20 -w '%{http_code}' "$@"; }
vip_body() { docker exec l3h1 curl -s -m 20 "$@"; }
jf() { echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" 2>/dev/null; }
wait_log() { # wait_log <needle> <seconds>
  local i
  for i in $(seq 1 "$2"); do
    docker exec llb1 grep -qF "$1" /tmp/loxilb.out /tmp/loxilb.err 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

# Same restart discipline as validation.sh, for the same reasons: datapath
# state outlives the process, and a surviving old process silently runs the
# legs against the previous flag set.
restart_gw() { # restart_gw <flags...>
  docker exec llb1 pkill -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
  for _ in $(seq 1 15); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
  done
  if docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
    echo "  (old gateway survived SIGTERM for 15s; escalating to SIGKILL)"
    docker exec llb1 pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
    for _ in $(seq 1 10); do
      docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
      sleep 1
    done
  fi
  if docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
    echo "  FATAL: the old gateway process would not die; refusing to run legs against it"
    return 1
  fi
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
  docker exec -d llb1 bash -c "ulimit -l unlimited; /root/loxilb-io/loxilb/loxilb $* > /tmp/loxilb.out 2> /tmp/loxilb.err"
  for _ in $(seq 1 40); do
    if docker exec llb1 curl -sf -m 3 $API/version >/dev/null 2>&1; then
      sleep 25
      return 0
    fi
    sleep 2
  done
  echo "  gateway did not come back; stderr tail:"
  docker exec llb1 tail -20 /tmp/loxilb.err
  return 1
}

# The exact rule shape a pre-upgrade deployment would replay from its own
# backups: streaming on, nothing said about authentication. The absence of
# the policy field is the artifact under test — do not "fix" it.
OLD_RULE_BODY() { # OLD_RULE_BODY <port>
  echo "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":$1,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":true,\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}"
}
PLAIN_RULE_BODY() { # PLAIN_RULE_BODY <port> — no streaming, no policy: not an AI service at all
  echo "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":$1,\"protocol\":\"tcp\",\"mode\":4,\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}"
}
NEW_RULE_BODY() { # NEW_RULE_BODY <port> <policy>
  echo "{\"serviceArguments\":{\"externalIP\":\"$VIP\",\"port\":$1,\"protocol\":\"tcp\",\"mode\":4,\"sse_mode\":true,\"api_key_auth\":\"$2\",\"inactiveTimeOut\":60,\"host\":\"$VIP\"},\"endpoints\":[{\"endpointIP\":\"31.31.31.1\",\"targetPort\":8080,\"weight\":1}]}"
}
resolved_policy() { # resolved_policy <port>
  lcurl "$API/config/loadbalancer/all" | python3 -c "
import sys, json
for a in json.load(sys.stdin).get('lbAttr', []):
    s = a.get('serviceArguments', {})
    if int(s.get('port', 0)) == $1:
        print(s.get('api_key_auth', ''))
        break
"
}
warn_count() {
  docker exec llb1 grep -c "quota configured but NO service has api_key_auth=required" /tmp/loxilb.out 2>/dev/null | tr -d '[:space:]'
}
backend_line() { # backend_line <marker>
  docker exec l3ep1 grep "$1" /tmp/backend_reqs.log 2>/dev/null | head -1
}

BODY='{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'

echo "===== backcompat: gateway into the store-configured flag set ====="
# Whatever suite ran before may have left a persisted snapshot; the gateway
# restores it at boot (deliberately — that restore surviving a store outage
# is itself a gated property), which would smuggle that suite's rules into
# this one and break the "nothing enforces" phase. This suite owns the
# topology now: clear the snapshot, boot clean, and PROVE the slate.
docker exec llb1 rm -f /etc/loxilb/snapshot.json 2>/dev/null
restart_gw $AIKEY_ARGS || exit 1

NRULES=$(lcurl "$API/config/loadbalancer/all" | grep -o '"port"' | wc -l | tr -d '[:space:]')
chk "A0 the slate is clean: no rules survive into this suite" "0" "$NRULES"

echo ""
echo "===== PHASE A: a pre-upgrade deployment's artifacts, replayed ====="

CODE=$(lcurl -o /dev/null -w '%{http_code}' -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(OLD_RULE_BODY 2030)")
chk "A1 a rule body with no policy field still installs" "200" "$CODE"
lcurl -o /dev/null -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(OLD_RULE_BODY 2031)"
sleep 3

chk "A2 an undeclared policy stays undeclared in the export view" "" "$(resolved_policy 2030)"

# The one verdict that MOVES across the upgrade, asserted on purpose: this
# rule streamed, so before the change it enforced keys as a side effect.
# Enforcement is now an explicit declaration, so the same body serves
# keyless — and the warning asserted below is the operator's signal.
chk "A3 the old sse-riding shape serves keyless (the documented delta)" "200" \
  "$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")"

# The streaming shape was AI-declared before the change too — it stripped
# the credential then and must keep stripping now. The service that never
# said anything AI at all is the one promised byte-identical proxying:
# the client's X-Api-Key belongs to the backend's own credential
# namespace and must arrive. The backend's log is the judge for both.
lcurl -o /dev/null -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(PLAIN_RULE_BODY 2032)"
sleep 3
docker exec l3ep1 sh -c ': > /tmp/backend_reqs.log'
vip_code -X POST "http://$VIP:2030/v1/chat/completions?probe=bc-a4-sse" \
  -H 'Content-Type: application/json' -H 'X-Api-Key: not-ours-passthrough' -d "$BODY" >/dev/null
vip_code -X POST "http://$VIP:2032/v1/chat/completions?probe=bc-a4-plain" \
  -H 'Content-Type: application/json' -H 'X-Api-Key: not-ours-passthrough' -d "$BODY" >/dev/null
sleep 1
chk_has "A4 the old streaming shape still strips the key (unchanged behaviour)" "x_api_key=False" "$(backend_line probe=bc-a4-sse)"
chk_has "A4 a service that declared nothing forwards the key untouched" "x_api_key=True" "$(backend_line probe=bc-a4-plain)"

# Pre-upgrade management bodies: the minimal field set that era's clients sent.
R_OLD=$(lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d '{"tenant_id":"bc-tenant","name":"bc-old-shape","rate_limit_rps":200,"tokens_per_min":0,"enabled":true}')
K_OLD=$(jf "$R_OLD" raw_key)
if [ -n "$K_OLD" ]; then
  echo "  [PASS] A5 a pre-upgrade key-create body still mints a key"; PASS=$((PASS + 1))
else
  echo "  [FAIL] A5 pre-upgrade key-create body refused: $(echo "$R_OLD" | head -c 200)"; FAIL=$((FAIL + 1))
fi

# Quota against nothing that enforces: rules EXIST (:2030, :2031), none
# declares the policy. Silence here is how an operator ships believing a
# limit protects them; the warning is the upgrade's designed mitigation.
W0=$(warn_count)
CODE=$(lcurl -o /dev/null -w '%{http_code}' -X POST $API/config/ai/tenant/ratelimit \
  -H 'Content-Type: application/json' -d '{"tenant_id":"bc-tenant","rps":1000,"tokens_per_min":60}')
chk "A6 the pre-upgrade quota body is accepted" "204" "$CODE"
sleep 1
W1=$(warn_count)
if [ "$W1" -gt "$W0" ] 2>/dev/null; then
  echo "  [PASS] A7 a quota nothing enforces is warned about, out loud"; PASS=$((PASS + 1))
else
  echo "  [FAIL] A7 no warning for a quota no service enforces (before=$W0 after=$W1)"; FAIL=$((FAIL + 1))
fi

echo ""
echo "===== PHASE B: the one-line upgrade, and the road back ====="

CODE=$(lcurl -o /dev/null -w '%{http_code}' -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(NEW_RULE_BODY 2030 required)")
chk "B1 adding the policy to the same rule is accepted" "200" "$CODE"
sleep 3

chk "B2 keyless is now denied" "401" \
  "$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")"
chk_has "B2 and the denial names the credential, not the store" "invalid_api_key" \
  "$(vip_body -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")"

docker exec l3ep1 sh -c ': > /tmp/backend_reqs.log'
chk "B3 the pre-upgrade key authenticates on the upgraded service" "200" \
  "$(vip_code -X POST "http://$VIP:2030/v1/chat/completions?probe=bc-b3" -H 'Content-Type: application/json' -H "X-Api-Key: $K_OLD" -d "$BODY")"
sleep 1
chk_has "B3 and is stripped before the backend" "x_api_key=False" "$(backend_line probe=bc-b3)"

# The same quota write must go quiet now that something enforces.
W2=$(warn_count)
lcurl -o /dev/null -X POST $API/config/ai/tenant/ratelimit \
  -H 'Content-Type: application/json' -d '{"tenant_id":"bc-tenant","rps":1000,"tokens_per_min":60}'
sleep 1
W3=$(warn_count)
chk "B4 the same quota write no longer warns" "$W2" "$W3"

# Enforcement is live end to end, not just at the door: a key limited to one
# request per second draws a rate-limit verdict inside a six-request burst.
R_SLOW=$(lcurl -X POST $API/config/ai/apikey -H 'Content-Type: application/json' \
  -d '{"tenant_id":"bc-tenant","name":"bc-slow","rate_limit_rps":1,"burst_size":1,"tokens_per_min":0,"enabled":true}')
K_SLOW=$(jf "$R_SLOW" raw_key)
CODES=""
for _ in 1 2 3 4 5 6; do
  CODES="$CODES $(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_SLOW" -d "$BODY")"
done
chk_has "B5 the upgraded service rate-limits (a 429 in the burst)" "429" "$CODES"

# Omission never disarms: replaying a pre-upgrade backup over a secured
# service is refused loudly, and enforcement stays. A body that merely
# lacks the field cannot silently strip protection off a service an
# operator deliberately armed.
CODE=$(lcurl -o /dev/null -w '%{http_code}' -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(OLD_RULE_BODY 2030)")
chk "B6 replaying the old body over an enforcing rule is refused" "409" "$CODE"
sleep 1
chk "B6 and enforcement stays armed" "401" \
  "$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")"
# The road back exists, but it is explicit: declaring "disabled" is a
# statement, not an accident of an old file.
lcurl -o /dev/null -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(NEW_RULE_BODY 2030 disabled)"
sleep 3
chk "B7 declaring disabled explicitly rolls enforcement off" "200" \
  "$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")"

echo ""
echo "===== PHASE C: what the API exports, the API re-imports ====="

# Re-arm one of the two so the export carries both a declared and an
# undeclared service — the round-trip must preserve both shapes.
lcurl -o /dev/null -X POST $API/config/loadbalancer \
  -H 'Content-Type: application/json' -d "$(NEW_RULE_BODY 2030 required)"
sleep 3

vec() { # the verdict vector the round-trip must preserve
  echo "$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY") \
$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -H "X-Api-Key: $K_OLD" -d "$BODY") \
$(vip_code -X POST http://$VIP:2031/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY") \
$(vip_code -X POST http://$VIP:2032/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")"
}
VEC_BEFORE=$(vec)
EXPORT=$(lcurl "$API/config/loadbalancer/all")

# Delete this suite's rules through the API — the same tool an operator's
# restore procedure starts with — and prove the services are actually dead
# before crediting the replay with reviving them.
for p in 2030 2031 2032; do
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/externalipaddress/$VIP/port/$p/protocol/tcp" 2>/dev/null
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$p/protocol/tcp" 2>/dev/null
done
sleep 2
DEAD=$(vip_code -X POST http://$VIP:2030/v1/chat/completions -H 'Content-Type: application/json' -d "$BODY")
chk_not "C0 the delete took: the service is dead before the replay" "200" "$DEAD"

# Replay the export exactly as captured. The parsing runs on the host — the
# gateway image carries no interpreter, and the replay must not depend on
# one being there.
echo "$EXPORT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d.get('lbAttr', []):
    print(json.dumps({'serviceArguments': a['serviceArguments'],
                      'endpoints': a['endpoints']}))
" | while IFS= read -r rule; do
  lcurl -o /dev/null -X POST $API/config/loadbalancer \
    -H 'Content-Type: application/json' -d "$rule"
done
sleep 3

VEC_AFTER=$(vec)
chk "C1 the exported rule set replays to the same verdicts" "$VEC_BEFORE" "$VEC_AFTER"
chk "C2 and the vector is the enforced one, not blanket 200s" "401 200 200 200" "$(echo $VEC_AFTER | tr -s ' ')"
chk "C3 the declared policy survived the round-trip" "required" "$(resolved_policy 2030)"
chk "C4 the undeclared shape survived it too" "" "$(resolved_policy 2031)"
# Fidelity where it bites: after the round-trip, the never-declared service
# must still forward the client's key. A lossy export would have come back
# declared-disabled and started stripping traffic it used to pass.
docker exec l3ep1 sh -c ': > /tmp/backend_reqs.log'
vip_code -X POST "http://$VIP:2032/v1/chat/completions?probe=bc-c5" \
  -H 'Content-Type: application/json' -H 'X-Api-Key: not-ours-passthrough' -d "$BODY" >/dev/null
sleep 1
chk_has "C5 the round-trip did not turn passthrough into stripping" "x_api_key=True" "$(backend_line probe=bc-c5)"

# Leave nothing behind for whoever runs next.
for p in 2030 2031 2032; do
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/externalipaddress/$VIP/port/$p/protocol/tcp" 2>/dev/null
  lcurl -o /dev/null -X DELETE "$API/config/loadbalancer/hosturl/$VIP/externalipaddress/$VIP/port/$p/protocol/tcp" 2>/dev/null
done

echo ""
echo "===== SUMMARY: pass=$PASS fail=$FAIL ====="
if [ "$FAIL" -eq 0 ]; then
  echo "SCENARIO-ai-authsep-backcompat [OK]"
  exit 0
else
  echo "SCENARIO-ai-authsep-backcompat [FAILED]"
  exit 1
fi
