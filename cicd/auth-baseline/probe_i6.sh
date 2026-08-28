#!/bin/bash
# Step I-6 — re-run the I-0b management-plane baselines against the current
# tree (PR 1 + PR 2 applied), BEFORE any PR 2b fix is written.
#
# This is a recording instrument, not a pass/fail gate on the product: at I-6
# the pre-registered expectation is that the defects are STILL THERE, so a leg
# that reproduces is the run working as designed. Each leg therefore carries
# its own expectation, and the script exits non-zero only when an observation
# DEVIATES from it — because a leg that stops reproducing, or starts, is the
# thing a human has to look at.
#
#   AUTHSEP_EXPECT=red    (default) I-6: B-2/B-3/B-4 expected to reproduce
#   AUTHSEP_EXPECT=green            I-9: the same legs expected to be repaired
#
# Ground truth is read from the management store, which is PostgreSQL from I-8
# onward (schema aigw_mgmt in database loxilb). The I-6 evidence was recorded
# against MariaDB; this probe was ported rather than frozen because its whole
# purpose is to be re-run under the opposite expectation. up.sh and probe_i4.sh
# stay frozen at the old flags for the reason given in their own headers.
#
# The same instrument serves both steps, so the I-9 gate cannot be produced by
# softening this one — the expectation is named, not edited.
#
# Read the failure, not just the status code: the management-auth fixes
# changed how failures render on these routes, so a leg can keep the defect and
# change its wording.
#
# exit 0  every leg matched its pre-registered expectation
# exit 1  at least one leg deviated
# exit 2  a harness precondition failed (the run decided nothing)

source /root/authsep-baseline.env
API=http://localhost:11111/netlox/v1
TREE=${AUTHSEP_TREE:-/root/loxilb-igw-authsep}
EXPECT=${AUTHSEP_EXPECT:-red}

# Ground truth comes from the management store. At I-8 that store is PostgreSQL
# — schema aigw_mgmt inside database loxilb — and the MariaDB container this
# probe first read is gone with the driver.
#
# Read as the bootstrap superuser and fully qualify the schema, deliberately:
# aigw_mgmt_user carries search_path as a role attribute and holds grants that
# are themselves under test, so a ground-truth read that could fail for a
# permission reason would be indistinguishable from the product defect this
# probe is measuring.
#
# Errors are NOT swallowed. The MariaDB helper sent stderr to /dev/null, so a
# store that had gone away returned the empty string and every leg reading it
# silently decided against a value that was never fetched — a dead fixture
# rendering as a product defect. A failed query now returns a sentinel and the
# caller turns it into exit 2, "the run decided nothing".
PG_CT=${AUTHSEP_PG_CT:-aikey-pg}
PG_ROLE=${AUTHSEP_PG_ROLE:-oamuser}
PG_DB=${AUTHSEP_PG_DB:-loxilb}

pgq() {
  local out
  if ! out=$(docker exec "$PG_CT" psql -U "$PG_ROLE" -d "$PG_DB" \
               -At -q -v ON_ERROR_STOP=1 -c "$1" 2>&1); then
    printf 'PGQ_ERROR: %s' "$(printf '%s' "$out" | tr '\n' ' ')"
    return 1
  fi
  printf '%s' "$out"
}

# pgq_ok <value> <what> — stop the run when a ground-truth read failed.
pgq_ok() {
  case "$1" in
    PGQ_ERROR:*) echo "  management store read failed ($2): ${1#PGQ_ERROR: }"; exit 2 ;;
  esac
}

# mgmt <timeout> <curl args...> — sets MSTATUS and MBODY.
#
# Deliberately NOT a command substitution: `docker exec llb1 curl -o /tmp/x`
# writes the body inside the container, so reading it back on the host silently
# yields nothing and every body-shaped assertion becomes vacuous. Status and
# body come back through the same stdout and are split here.
MSTATUS=""; MBODY=""
mgmt() {
  local t=$1; shift
  local out
  out=$(docker exec llb1 curl -s -m "$t" -w $'\nI6STATUS=%{http_code}' "$@")
  MSTATUS=$(printf '%s' "$out" | sed -n 's/^I6STATUS=//p' | tail -1)
  MBODY=$(printf '%s' "$out" | sed '$d')
}

case "$EXPECT" in
  red)   EXP_B2=repro; EXP_B3=repro; EXP_B4=repro ;;
  green) EXP_B2=fixed; EXP_B3=fixed; EXP_B4=fixed ;;
  *) echo "AUTHSEP_EXPECT must be red or green"; exit 2 ;;
esac
# B-5 is the cross-plane shape, and the management-auth work already
# answered it. Its
# expectation is 'fixed' at I-6 too; it is re-run because the I-4 repoint moved
# data-plane keys out of UserService.Cache entirely, which is the mechanism the
# original panic depended on.
EXP_B5=fixed

DEV=0; LEGS=0
verdict() { # verdict <id> <observed> <expected> <note>
  LEGS=$((LEGS + 1))
  if [ "$2" = "$3" ]; then
    printf '  [as expected] %-6s observed=%-14s expected=%-14s %s\n' "$1" "$2" "$3" "$4"
  else
    DEV=$((DEV + 1))
    printf '  [DEVIATION  ] %-6s observed=%-14s expected=%-14s %s\n' "$1" "$2" "$3" "$4"
  fi
}

echo "==================== step I-6 baseline re-run ===================="
echo "expectation set: AUTHSEP_EXPECT=$EXPECT   image=$(docker inspect -f '{{.Config.Image}}' llb1)"
echo

########################## harness preconditions ##########################
echo "---- preconditions ----"
mgmt 10 "$API/version"; VER=$MSTATUS
[ "$VER" = "200" ] || { echo "  management API not serving (status $VER)"; exit 2; }
# Prove the fixture before reading it. A store that answers but carries no
# aigw_mgmt.users is not a baseline with zero users — it is no baseline at all,
# and the difference decides whether the legs below mean anything.
STORE_OK=$(pgq "SELECT to_regclass('aigw_mgmt.users') IS NOT NULL")
pgq_ok "$STORE_OK" "aigw_mgmt.users presence"
[ "$STORE_OK" = "t" ] || { echo "  aigw_mgmt.users does not exist in $PG_CT/$PG_DB"; exit 2; }
echo "  management store reachable, aigw_mgmt.users present"
NUSERS=$(pgq 'SELECT COUNT(*) FROM aigw_mgmt.users;')
pgq_ok "$NUSERS" "user count"
echo "  users table rows: $NUSERS"
[ "$NUSERS" = "1" ] || { echo "  expected exactly the bootstrapped admin; got $NUSERS"; exit 2; }
[ -n "$TOKEN" ]   || { echo "  no admin token in /root/authsep-baseline.env"; exit 2; }
[ -n "$RAW_KEY" ] || { echo "  no raw data-plane key in /root/authsep-baseline.env"; exit 2; }
echo "  admin token and a data-plane key are both present"
echo

########################## B-3-r ##########################
echo "---- B-3-r: GET /auth/users with a user present ----"
mgmt 15 -H "Authorization: Bearer $TOKEN" "$API/auth/users"; S3=$MSTATUS; B3=$MBODY
echo "  status=$S3"
echo "  body=$B3"
if [ "$S3" = "200" ] && echo "$B3" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if isinstance(d,list) and len(d)>=1 else 1)' 2>/dev/null; then
  O3=fixed
else
  O3=repro
fi
verdict B-3-r "$O3" "$EXP_B3" "$(echo "$B3" | head -c 160)"
echo

########################## B-4-r ##########################
echo "---- B-4-r: password material in the list body ----"
# Single quotes, not double: MySQL read "admin" as a string literal, PostgreSQL
# reads it as an identifier and errors. Left unported this returns nothing, the
# grep below matches the empty string, and the leg reports the stored hash
# present in every body it is shown.
HASH_PREFIX=$(pgq "SELECT LEFT(password,20) FROM aigw_mgmt.users WHERE username='admin';")
pgq_ok "$HASH_PREFIX" "stored hash prefix"
[ -n "$HASH_PREFIX" ] || { echo "  no admin row in aigw_mgmt.users"; exit 2; }
echo "  stored hash prefix: $HASH_PREFIX"
if [ "$O3" = "fixed" ] && echo "$B3" | grep -qF "$HASH_PREFIX"; then
  O4=repro; NOTE4="hash material observed in the live body"
elif [ "$O3" = "fixed" ]; then
  O4=fixed; NOTE4="list returned and it carries no stored hash"
else
  # Not observable on the wire while B-3 fails first — decide it from the code,
  # which is exactly the shadowed state pre-registered for this leg: the list
  # endpoint fails before any body can be inspected.
  MDL=$(grep -c 'Password \*string `json:"password"`' "$TREE/api/models/user.go")
  HDL=$(grep -c 'tmpUser.Password = &user.Password' "$TREE/api/restapi/handler/user.go")
  echo "  code check: api/models/user.go carries json:\"password\" -> $MDL"
  echo "  code check: handler/user.go assigns the stored hash -> $HDL"
  grep -n 'tmpUser.Password = &user.Password' "$TREE/api/restapi/handler/user.go" | sed 's/^/    /'
  if [ "$MDL" -ge 1 ] && [ "$HDL" -ge 1 ]; then
    O4=repro; NOTE4="latent behind B-3; model+handler still serialise the stored hash"
  else
    O4=fixed; NOTE4="model or handler no longer carries the stored hash"
  fi
fi
verdict B-4-r "$O4" "$EXP_B4" "$NOTE4"
echo

########################## B-5-r ##########################
echo "---- B-5-r: data-plane key hash as a management Bearer ----"
BODY='{"model":"test-model","messages":[{"role":"user","content":"hi"}],"max_tokens":8}'
VIPS=$(docker exec l3h1 curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST \
  http://10.10.10.254:2020/v1/chat/completions -H "Content-Type: application/json" \
  -H "X-Api-Key: $RAW_KEY" -d "$BODY")
echo "  key used once on the VIP: status=$VIPS"
KHASH=$(printf "%s" "$RAW_KEY" | sha256sum | cut -d" " -f1)
mgmt 15 -H "Authorization: Bearer $KHASH" "$API/auth/users"; S5=$MSTATUS; B5=$MBODY
echo "  sha256hex(rawKey) as management Bearer: status=$S5"
echo "  body=$(echo "$B5" | head -c 200)"
# The control that makes "indistinguishable" a measurement rather than a claim:
# an unknown token that was never a data-plane key. These two answers
# disagreeing is what turned the management listener into an oracle for live
# data-plane key hashes.
mgmt 15 -H "Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000" \
  "$API/auth/users"; SU=$MSTATUS; BU=$MBODY
echo "  control, an unknown token of the same shape: status=$SU"
echo "  body=$(echo "$BU" | head -c 200)"
mgmt 10 "$API/version"; SURV=$MSTATUS
echo "  gateway still serving after it: /version=$SURV"
if [ "$S5" = "000" ] || [ -z "$S5" ]; then
  O5=repro; NOTE5="connection killed — the I-0 panic shape"
elif [ "$S5" = "401" ] && [ "$SURV" = "200" ] && [ "$S5" = "$SU" ] && [ "$B5" = "$BU" ]; then
  O5=fixed; NOTE5="declined; status and body byte-identical to an unknown token, no panic"
elif [ "$S5" = "401" ] && [ "$SURV" = "200" ]; then
  O5=other; NOTE5="401 but distinguishable from an unknown token ($S5/$SU) — an oracle for live key hashes"
else
  O5=other; NOTE5="neither the I-0 panic nor a 401 — status $S5"
fi
verdict B-5-r "$O5" "$EXP_B5" "$NOTE5"
echo

########################## B-2-r ##########################
# Last, because it is the only leg that tries to mutate the admin credential.
echo "---- B-2-r: PUT /auth/users/{id} password change ----"
ADMIN_ID=$(pgq "SELECT id FROM aigw_mgmt.users WHERE username='admin';")
pgq_ok "$ADMIN_ID" "admin id"
HB=$(pgq "SELECT LEFT(password,20) FROM aigw_mgmt.users WHERE username='admin';")
pgq_ok "$HB" "hash before"
# Without an id the PUT below addresses /auth/users/ and the leg measures
# routing, not the password change it is named for.
[ -n "$ADMIN_ID" ] && [ -n "$HB" ] || { echo "  admin row unreadable before the attempt"; exit 2; }
echo "  admin id=$ADMIN_ID  hash before: $HB"
T0=$(date +%s)
mgmt 30 -X PUT "$API/auth/users/$ADMIN_ID" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"admin","password":"NewPass456!"}'
T1=$(date +%s)
S2=$MSTATUS; B2=$MBODY
HA=$(pgq "SELECT LEFT(password,20) FROM aigw_mgmt.users WHERE username='admin';")
pgq_ok "$HA" "hash after"
# HA empty would compare unequal to HB and read as "hash rotated" — the fixed
# verdict, produced by a failed read. Refuse to decide instead.
[ -n "$HA" ] || { echo "  admin row unreadable after the attempt"; exit 2; }
echo "  status=$S2  elapsed=$((T1 - T0))s"
echo "  body=$B2"
echo "  hash after:  $HA"
NEWTOK=$(docker exec llb1 curl -s -m 10 -X POST "$API/auth/login" \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"NewPass456!"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
OLDTOK=$(docker exec llb1 curl -s -m 10 -X POST "$API/auth/login" \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin123!"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
echo "  login with the NEW password: $([ -n "$NEWTOK" ] && echo "token issued" || echo "no token")"
echo "  login with the OLD password: $([ -n "$OLDTOK" ] && echo "token issued" || echo "no token")"
if [ "$HA" = "$HB" ] && [ -z "$NEWTOK" ] && [ -n "$OLDTOK" ]; then
  O2=repro;  NOTE2="hash unchanged, old password still valid, elapsed $((T1 - T0))s"
elif [ "$HA" != "$HB" ] && [ -n "$NEWTOK" ] && [ -z "$OLDTOK" ]; then
  O2=fixed;  NOTE2="hash rotated and only the new password authenticates"
else
  O2=other;  NOTE2="partial: hash changed=$([ "$HA" != "$HB" ] && echo yes || echo no) new=$([ -n "$NEWTOK" ] && echo yes || echo no) old=$([ -n "$OLDTOK" ] && echo yes || echo no)"
fi
verdict B-2-r "$O2" "$EXP_B2" "$NOTE2"
echo "  --- gateway log around the attempt (the retry ladder is the signature) ---"
LOGF=$(docker exec llb1 sh -c 'ls -t /var/log/loxilb*.log 2>/dev/null | head -1')
if [ -n "$LOGF" ]; then
  docker exec llb1 sh -c "grep -nE 'destination arguments|Failed to query previous password|Password validation failed|parsing time' $LOGF | tail -12" | sed 's/^/    /'
else
  echo "    no gateway log file found"
fi
echo

echo "==================== summary ===================="
echo "legs=$LEGS deviations=$DEV expectation=$EXPECT"
if [ "$DEV" -eq 0 ]; then
  echo "RESULT: every leg matched its pre-registered expectation"
  exit 0
fi
echo "RESULT: $DEV leg(s) deviated — read the observation above before changing anything"
exit 1
