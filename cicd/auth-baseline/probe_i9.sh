#!/bin/bash
# Step I-9 — PR 2b validation on the testbed.
#
# probe_i6.sh re-runs the four B-baselines under the opposite expectation and
# answers "are the recorded reds repaired?". It does not cover the rest of what
# the plan assigns to I-9: MGMT-6 … MGMT-8 and MGMT-11 … MGMT-18, none of which
# has an instrument anywhere in this directory. probe_i1/probe_i2 cover
# MGMT-1 … MGMT-5, MGMT-9, MGMT-10 and the authorizer half of MGMT-15; this
# file covers the remainder, so that "I-9 green" means the row, not one script.
#
# Unlike probe_i6.sh there is no red/green switch. These are forward gates: the
# behaviour under test is specified by §1.17 and every leg has exactly one
# correct answer. A leg that cannot be decided reports 'undecided' and counts
# as a failure — never as a pass — because the failure mode this campaign keeps
# hitting is a green produced by an assertion that never executed.
#
#   ./probe_i9.sh            run every leg
#   AUTHSEP_ONLY=6,13        run only the named legs (debugging aid)
#
# Preconditions: a topology from up_i6.sh, with its /root/authsep-baseline.env.
# Run it against a FRESH bring-up: probe_i6.sh's B-2-r leg rotates the admin
# password, and from I-8 a password change revokes every session in the same
# transaction, so a token minted before it is deliberately dead afterwards.
#
# exit 0  every leg met its specified verdict
# exit 1  at least one leg failed or could not be decided
# exit 2  a harness precondition failed (the run decided nothing)

API=http://localhost:11111/netlox/v1
PG_CT=${AUTHSEP_PG_CT:-aikey-pg}
PG_ROLE=${AUTHSEP_PG_ROLE:-oamuser}
PG_DB=${AUTHSEP_PG_DB:-loxilb}
ONLY=${AUTHSEP_ONLY:-}

# ---------------------------------------------------------------- helpers ----

# Ground truth from the management store, read as the bootstrap superuser and
# fully qualified. Errors are surfaced, never swallowed: a query that failed
# must not return the empty string and let a leg decide against a value that
# was never fetched. See the same reasoning in probe_i6.sh.
pgq() {
  local out
  if ! out=$(docker exec "$PG_CT" psql -U "$PG_ROLE" -d "$PG_DB" \
               -At -q -v ON_ERROR_STOP=1 -c "$1" 2>&1); then
    printf 'PGQ_ERROR: %s' "$(printf '%s' "$out" | tr '\n' ' ')"
    return 1
  fi
  printf '%s' "$out"
}
pgq_bad() { case "$1" in PGQ_ERROR:*) return 0 ;; *) return 1 ;; esac; }

# mgmt <timeout> <curl args...> — sets MSTATUS, MBODY and MTIME (seconds,
# floating point). Not a command substitution around a container-side -o, for
# the reason recorded in probe_i6.sh: the body would be written inside the
# container and every body assertion would go vacuous.
MSTATUS=""; MBODY=""; MTIME=""
mgmt() {
  local t=$1; shift
  local out
  out=$(docker exec llb1 curl -s -m "$t" -w $'\nI9STATUS=%{http_code} I9TIME=%{time_total}' "$@")
  local tail_line
  tail_line=$(printf '%s' "$out" | tail -1)
  MSTATUS=$(printf '%s' "$tail_line" | sed -n 's/.*I9STATUS=\([0-9]*\).*/\1/p')
  MTIME=$(printf '%s' "$tail_line" | sed -n 's/.*I9TIME=\([0-9.]*\).*/\1/p')
  MBODY=$(printf '%s' "$out" | sed '$d')
}

FAIL=0; LEGS=0; SKIPPED=""
# verdict <id> <pass|fail|undecided> <note>
verdict() {
  LEGS=$((LEGS + 1))
  case "$2" in
    pass) printf '  [PASS      ] %-8s %s\n' "$1" "$3" ;;
    fail) FAIL=$((FAIL + 1)); printf '  [FAIL      ] %-8s %s\n' "$1" "$3" ;;
    *)    FAIL=$((FAIL + 1)); printf '  [UNDECIDED ] %-8s %s\n' "$1" "$3" ;;
  esac
}
# want <id> — is this leg selected?
want() { [ -z "$ONLY" ] && return 0; case ",$ONLY," in *",$1,"*) return 0 ;; *) SKIPPED="$SKIPPED $1"; return 1 ;; esac; }

# under <time> <limit> — float compare without bc, which the image may not have.
under() { python3 -c "import sys; sys.exit(0 if float('$1') < float('$2') else 1)" 2>/dev/null; }

jsonget() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1" 2>/dev/null; }

login() { # login <user> <pass> -> token on stdout, empty on failure
  docker exec llb1 curl -s -m 10 -X POST "$API/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jsonget token
}

mkuser() { # mkuser <user> <pass> <role> -> status on stdout
  mgmt 15 -X POST "$API/auth/users" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"username\":\"$1\",\"password\":\"$2\",\"role\":\"$3\"}"
  printf '%s' "$MSTATUS"
}

uid_of() { pgq "SELECT id FROM aigw_mgmt.users WHERE username='$1';"; }

# fd/conn census, for the leak leg.
#
# NOT /proc/1/fd. The CI image's entrypoint is /bin/bash and loxilb runs as a
# child, so pid 1 is a shell holding 4 descriptors that never move: reading it
# reports "+0 growth" no matter what the gateway does, and the leak leg passes
# without having looked at the process under test. Find the pid by cmdline, and
# make its absence undecidable rather than zero.
loxilb_pid() {
  docker exec llb1 sh -c 'for p in /proc/[0-9]*; do
      case "$(tr "\0" " " < $p/cmdline 2>/dev/null)" in
        */loxilb\ *|*/loxilb) echo "${p#/proc/}"; exit 0 ;;
      esac
    done; exit 1' 2>/dev/null
}
fdcount() {
  local pid; pid=$(loxilb_pid)
  [ -n "$pid" ] || { echo ""; return 1; }
  docker exec llb1 sh -c "ls /proc/$pid/fd 2>/dev/null | wc -l"
}
conncount() { pgq "SELECT count(*) FROM pg_stat_activity WHERE usename='aigw_mgmt_user';"; }

# ---------------------------------------------------------- preconditions ----
echo "==================== step I-9 management-plane validation ===================="
echo "image=$(docker inspect -f '{{.Config.Image}}' llb1 2>/dev/null)"
echo
echo "---- preconditions ----"
mgmt 10 "$API/version"
[ "$MSTATUS" = "200" ] || { echo "  management API not serving (status $MSTATUS)"; exit 2; }

STORE_OK=$(pgq "SELECT to_regclass('aigw_mgmt.users') IS NOT NULL")
pgq_bad "$STORE_OK" && { echo "  store unreadable: ${STORE_OK#PGQ_ERROR: }"; exit 2; }
[ "$STORE_OK" = "t" ] || { echo "  aigw_mgmt.users absent in $PG_CT/$PG_DB"; exit 2; }
echo "  management store reachable, aigw_mgmt.users present"

# Authenticate this run rather than trusting a token from the env file: whether
# the recorded one is still valid depends on what ran before us, and from I-8 a
# password change revokes it on purpose. Both passwords are tried so the run
# works after a probe_i6.sh green as well as on a fresh bring-up, but one of
# them must work — an unauthenticated run must stop, not report failures.
TOKEN=$(login admin 'Admin123!')
ADMIN_PW='Admin123!'
if [ -z "$TOKEN" ]; then
  TOKEN=$(login admin 'NewPass456!'); ADMIN_PW='NewPass456!'
fi
[ -n "$TOKEN" ] || { echo "  cannot authenticate as admin with either known password"; exit 2; }
echo "  authenticated as admin (password: $ADMIN_PW)"
echo

# ------------------------------------------------------------------ MGMT-6 ----
if want 6; then
echo "---- MGMT-6: unknown Bearer token -> 401 in < 1 s ----"
# The point of this leg is the latency, not the code: F-AUTH-8 retried a
# deterministic failure three times with a trailing sleep, so an unknown token
# cost ~10 s and an unauthenticated caller could occupy a serving goroutine.
UNK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
mgmt 20 -H "Authorization: Bearer $UNK" "$API/auth/users"
echo "  status=$MSTATUS elapsed=${MTIME}s"
echo "  body=$(printf '%s' "$MBODY" | head -c 160)"
if [ "$MSTATUS" != "401" ]; then
  verdict MGMT-6 fail "expected 401, got $MSTATUS"
elif [ -z "$MTIME" ]; then
  verdict MGMT-6 undecided "no timing captured — the assertion would be vacuous"
elif under "$MTIME" 1.0; then
  verdict MGMT-6 pass "401 in ${MTIME}s"
else
  verdict MGMT-6 fail "401 but took ${MTIME}s, the retry ladder is still there"
fi
echo
fi

# ------------------------------------------------------------------ MGMT-7 ----
if want 7; then
echo "---- MGMT-7: wrong password on POST /auth/login -> 401 in < 1 s ----"
mgmt 20 -X POST "$API/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"definitely-not-the-password"}'
echo "  status=$MSTATUS elapsed=${MTIME}s"
echo "  body=$(printf '%s' "$MBODY" | head -c 160)"
if [ "$MSTATUS" != "401" ]; then
  verdict MGMT-7 fail "expected 401, got $MSTATUS"
elif [ -z "$MTIME" ]; then
  verdict MGMT-7 undecided "no timing captured"
elif under "$MTIME" 1.0; then
  verdict MGMT-7 pass "401 in ${MTIME}s"
else
  verdict MGMT-7 fail "401 but took ${MTIME}s"
fi
echo
fi

# ----------------------------------------------------------------- MGMT-15 ----
if want 15; then
echo "---- MGMT-15: unknown roles refused at write time ----"
# The authorizer half (a hand-inserted bad role is denied) gated I-2. This is
# the write-time half, which the plan assigns to Phase 5c.7 and therefore here.
#
# The assertion is the PROPERTY, not one status code. The closed set is enforced
# at two layers and they answer differently: the schema enum rejects a non-empty
# unknown role at the API boundary with 422, while an empty role reaches the
# store layer and is rejected there with 400 by authz.IsValidRole. Both are
# refusals at write time, which is what this baseline is about; asserting a
# literal 400 would have failed a correct product, and asserting "not 2xx" would
# have passed a 500. So: the status must be a client refusal from the closed set
# {400, 422}, AND no row may exist afterwards — the second is the half that
# cannot be satisfied by a status code alone.
M15=pass; M15N=""
for R in operator Viewer2 ""; do
  U="i9role_$(printf '%s' "$R" | tr -c 'a-zA-Z0-9' '_')"
  pgq "DELETE FROM aigw_mgmt.users WHERE username='$U';" >/dev/null
  S=$(mkuser "$U" 'Rolecheck1!' "$R")
  ROWS=$(pgq "SELECT count(*) FROM aigw_mgmt.users WHERE username='$U';")
  echo "  role='$R' -> POST status=$S  rows afterwards=$ROWS"
  case "$S" in
    400|422) ;;
    *) M15=fail; M15N="$M15N role='$R' gave $S (not a client refusal);" ;;
  esac
  if pgq_bad "$ROWS"; then
    M15=undecided; M15N="$M15N role='$R' row count unreadable;"
  elif [ "$ROWS" != "0" ]; then
    M15=fail; M15N="$M15N role='$R' was REFUSED BUT STORED ($ROWS rows);"
  fi
done
# The update path is separate code from the create path.
UPD_ID=$(uid_of admin)
if pgq_bad "$UPD_ID" || [ -z "$UPD_ID" ]; then
  M15=undecided; M15N="$M15N could not read admin id for the update half;"
else
  mgmt 15 -X PUT "$API/auth/users/$UPD_ID" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"username":"admin","role":"operator"}'
  AROLE=$(pgq "SELECT role FROM aigw_mgmt.users WHERE username='admin';")
  echo "  update admin role='operator' -> status=$MSTATUS  stored role now='$AROLE'"
  case "$MSTATUS" in
    400|422) ;;
    *) M15=fail; M15N="$M15N update gave $MSTATUS (not a client refusal);" ;;
  esac
  if pgq_bad "$AROLE"; then
    M15=undecided; M15N="$M15N admin role unreadable after the update;"
  elif [ "$AROLE" != "admin" ]; then
    M15=fail; M15N="$M15N admin role was CHANGED to '$AROLE';"
  fi
fi
verdict MGMT-15 "$M15" "${M15N:-refused at write time on create and update (422 schema enum / 400 store layer), nothing stored, admin role unchanged}"
echo
fi

# ----------------------------------------------------------------- MGMT-16 ----
if want 16; then
echo "---- MGMT-16: two concurrent creates of the same username ----"
RACE=i9race
pgq "DELETE FROM aigw_mgmt.users WHERE username='$RACE';" >/dev/null
docker exec llb1 sh -c "for i in 1 2; do curl -s -o /tmp/i9race\$i.out -w '%{http_code}' \
  -X POST $API/auth/users -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer $TOKEN' \
  -d '{\"username\":\"$RACE\",\"password\":\"Racecheck1!\",\"role\":\"viewer\"}' > /tmp/i9race\$i.code & done; wait"
C1=$(docker exec llb1 cat /tmp/i9race1.code 2>/dev/null)
C2=$(docker exec llb1 cat /tmp/i9race2.code 2>/dev/null)
B1=$(docker exec llb1 cat /tmp/i9race1.out 2>/dev/null)
B2=$(docker exec llb1 cat /tmp/i9race2.out 2>/dev/null)
ROWS=$(pgq "SELECT count(*) FROM aigw_mgmt.users WHERE username='$RACE';")
echo "  statuses: $C1 / $C2   rows afterwards: $ROWS"
echo "  body1=$(printf '%s' "$B1" | head -c 120)"
echo "  body2=$(printf '%s' "$B2" | head -c 120)"
LOSER=$(printf '%s\n%s' "$B1" "$B2" | grep -iv '^\s*$' | grep -i 'exist' | head -1)
RAWDRV=$(printf '%s %s' "$B1" "$B2" | grep -ciE 'pq:|sql:|duplicate key|violates unique constraint')
if pgq_bad "$ROWS"; then
  verdict MGMT-16 undecided "row count unreadable: ${ROWS#PGQ_ERROR: }"
elif [ "$ROWS" != "1" ]; then
  verdict MGMT-16 fail "expected exactly one row, found $ROWS"
elif [ "$RAWDRV" != "0" ]; then
  verdict MGMT-16 fail "one row, but a raw driver error reached the caller"
elif [ -n "$LOSER" ]; then
  verdict MGMT-16 pass "one row; loser told the username exists"
else
  verdict MGMT-16 fail "one row, but the loser's message does not say the username exists"
fi
echo
fi

# ----------------------------------------------------------------- MGMT-11 ----
if want 11; then
echo "---- MGMT-11: create -> change password -> login new/old ----"
U11=i9cycle; P11A='Cycle1pass!'; P11B='Cycle2pass!'
pgq "DELETE FROM aigw_mgmt.users WHERE username='$U11';" >/dev/null
S=$(mkuser "$U11" "$P11A" viewer)
ID11=$(uid_of "$U11")
echo "  create status=$S id=$ID11"
if [ "$S" != "200" ] || [ -z "$ID11" ] || pgq_bad "$ID11"; then
  verdict MGMT-11 undecided "could not create the fixture user (status $S)"
else
  T11A=$(login "$U11" "$P11A")
  mgmt 20 -X PUT "$API/auth/users/$ID11" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"username\":\"$U11\",\"password\":\"$P11B\"}"
  echo "  password change status=$MSTATUS elapsed=${MTIME}s"
  T11B=$(login "$U11" "$P11B")
  T11C=$(login "$U11" "$P11A")
  echo "  login new password: $([ -n "$T11B" ] && echo 'token issued' || echo 'no token')"
  echo "  login old password: $([ -n "$T11C" ] && echo 'token issued' || echo 'no token')"
  if [ "$MSTATUS" = "200" ] && [ -n "$T11B" ] && [ -z "$T11C" ]; then
    verdict MGMT-11 pass "change accepted, only the new password authenticates"
  else
    verdict MGMT-11 fail "change=$MSTATUS new=$([ -n "$T11B" ] && echo ok || echo no) old=$([ -n "$T11C" ] && echo ok || echo no)"
  fi
  # MGMT-14's revocation half rides on this: the token minted before the change
  # must be dead after it.
  if [ -n "$T11A" ]; then
    mgmt 15 -H "Authorization: Bearer $T11A" "$API/auth/users"
    echo "  pre-change token after the change: status=$MSTATUS"
    if [ "$MSTATUS" = "401" ]; then
      verdict MGMT-14a pass "password change revoked the live session"
    else
      verdict MGMT-14a fail "pre-change token still answers $MSTATUS"
    fi
  else
    verdict MGMT-14a undecided "no pre-change token was issued to test revocation with"
  fi
fi
echo
fi

# ----------------------------------------------------------------- MGMT-13 ----
if want 13; then
echo "---- MGMT-13: GET /auth/users body carries no password material ----"
pgq "DELETE FROM aigw_mgmt.users WHERE username IN ('i9list1','i9list2');" >/dev/null
mkuser i9list1 'Listcheck1!' viewer >/dev/null
mkuser i9list2 'Listcheck2!' viewer >/dev/null
NU=$(pgq "SELECT count(*) FROM aigw_mgmt.users;")
mgmt 15 -H "Authorization: Bearer $TOKEN" "$API/auth/users"
S13=$MSTATUS; B13=$MBODY
echo "  users in store: $NU   list status=$S13"
echo "  body=$(printf '%s' "$B13" | head -c 300)"
# Assert on the wire against the stored hashes themselves, not on the model:
# a response model can be correct and a handler still add the field back.
HASHES=$(pgq "SELECT password FROM aigw_mgmt.users;")
LEAK=0
if ! pgq_bad "$HASHES"; then
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    case "$B13" in *"$h"*) LEAK=1 ;; esac
    # also the prefix, in case the body truncates or re-encodes
    case "$B13" in *"$(printf '%s' "$h" | head -c 20)"*) LEAK=1 ;; esac
  done <<EOF
$HASHES
EOF
fi
HASKEY=$(printf '%s' "$B13" | grep -ci '"password"')
if [ "$S13" != "200" ]; then
  verdict MGMT-13 fail "expected 200, got $S13"
elif [ "$NU" -lt 3 ] 2>/dev/null; then
  verdict MGMT-13 undecided "fewer than three users present ($NU) — the leg's premise is absent"
elif pgq_bad "$HASHES"; then
  verdict MGMT-13 undecided "could not read the stored hashes to compare against"
elif [ "$HASKEY" != "0" ]; then
  verdict MGMT-13 fail "body contains a password key"
elif [ "$LEAK" != "0" ]; then
  verdict MGMT-13 fail "body contains stored hash material"
else
  verdict MGMT-13 pass "200 with $NU users, no password key and no hash material on the wire"
fi
echo
fi

# ----------------------------------------------------------------- MGMT-17 ----
if want 17; then
echo "---- MGMT-17: unknown user vs wrong password, 100 logins each ----"
# Two things are asserted: the bodies are byte-identical (an attacker must not
# be able to enumerate usernames from the reply) and the timing distributions
# overlap (nor from the clock). Compare medians rather than means so one
# scheduling outlier does not decide the leg.
UNKB=$(docker exec llb1 curl -s -m 10 -X POST "$API/auth/login" \
  -H "Content-Type: application/json" -d '{"username":"nosuchuser-i9","password":"whatever1!"}')
WRGB=$(docker exec llb1 curl -s -m 10 -X POST "$API/auth/login" \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"whatever1!"}')
echo "  unknown-user body: $(printf '%s' "$UNKB" | head -c 140)"
echo "  wrong-password body: $(printf '%s' "$WRGB" | head -c 140)"
TIMES=$(docker exec llb1 sh -c "
  for i in \$(seq 1 100); do
    curl -s -o /dev/null -w '%{time_total} ' -X POST $API/auth/login \
      -H 'Content-Type: application/json' -d '{\"username\":\"nosuchuser-i9\",\"password\":\"whatever1!\"}'
  done; echo;
  for i in \$(seq 1 100); do
    curl -s -o /dev/null -w '%{time_total} ' -X POST $API/auth/login \
      -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"whatever1!\"}'
  done; echo")
STAT=$(printf '%s' "$TIMES" | python3 -c '
import sys, statistics
lines=[l.split() for l in sys.stdin.read().strip().split("\n") if l.strip()]
if len(lines)<2: print("UNDECIDED no-samples"); raise SystemExit
a=[float(x) for x in lines[0]]; b=[float(x) for x in lines[1]]
if len(a)<50 or len(b)<50: print("UNDECIDED too-few %d/%d"%(len(a),len(b))); raise SystemExit
ma,mb=statistics.median(a),statistics.median(b)
hi=max(ma,mb); lo=min(ma,mb)
ratio = hi/lo if lo>0 else 999
print("OK median_unknown=%.4f median_wrongpw=%.4f ratio=%.2f n=%d/%d"%(ma,mb,ratio,len(a),len(b)))
' 2>/dev/null)
echo "  timing: $STAT"
if [ "$UNKB" != "$WRGB" ]; then
  verdict MGMT-17 fail "reply bodies differ between an unknown user and a wrong password"
elif [ -z "$STAT" ] || [ "${STAT%% *}" = "UNDECIDED" ]; then
  verdict MGMT-17 undecided "timing samples unusable: $STAT"
else
  RATIO=$(printf '%s' "$STAT" | sed -n 's/.*ratio=\([0-9.]*\).*/\1/p')
  # Both paths must do the same bcrypt work; a real enumeration oracle shows up
  # as one path skipping it entirely, which is a large multiple, not a few %.
  if under "$RATIO" 2.0; then
    verdict MGMT-17 pass "identical bodies; median ratio $RATIO within noise"
  else
    verdict MGMT-17 fail "identical bodies but median ratio $RATIO — a timing oracle"
  fi
fi
echo
fi

# ----------------------------------------------------------------- MGMT-14 ----
if want 14; then
echo "---- MGMT-14: delete a logged-in user, then reuse their token ----"
U14=i9del
pgq "DELETE FROM aigw_mgmt.users WHERE username='$U14';" >/dev/null
S=$(mkuser "$U14" 'Delcheck1!' viewer)
ID14=$(uid_of "$U14")
T14=$(login "$U14" 'Delcheck1!')
echo "  create=$S id=$ID14 token=$([ -n "$T14" ] && echo issued || echo none)"
if [ -z "$T14" ] || [ -z "$ID14" ] || pgq_bad "$ID14"; then
  verdict MGMT-14 undecided "could not establish a logged-in user to delete"
else
  NTOK_BEFORE=$(pgq "SELECT count(*) FROM aigw_mgmt.token WHERE username='$U14';")
  mgmt 15 -X DELETE "$API/auth/users/$ID14" -H "Authorization: Bearer $TOKEN"
  echo "  delete status=$MSTATUS  token rows before=$NTOK_BEFORE"
  mgmt 15 -H "Authorization: Bearer $T14" "$API/auth/users"
  echo "  deleted user's token reused: status=$MSTATUS elapsed=${MTIME}s"
  if [ "$MSTATUS" = "401" ]; then
    verdict MGMT-14 pass "token refused immediately after the delete"
  else
    verdict MGMT-14 fail "deleted user's token still answers $MSTATUS"
  fi
  # F-AUTH-42 was exactly this: the store looked right because CASCADE had
  # already erased the rows, while the peers were never told. Assert the
  # publish, not just the row count.
  LOGF=$(docker exec llb1 sh -c 'ls -t /var/log/loxilb*.log 2>/dev/null | head -1')
  if [ -n "$LOGF" ]; then
    PUB=$(docker exec llb1 sh -c "grep -icE 'revoke|invalidate' $LOGF" 2>/dev/null)
    echo "  revocation/invalidation lines in the gateway log: $PUB"
    if [ "${PUB:-0}" -gt 0 ] 2>/dev/null; then
      verdict MGMT-14b pass "the revocation path ran and logged ($PUB lines)"
    else
      verdict MGMT-14b fail "no revocation was logged — the peers would not have been told (F-AUTH-42 shape)"
    fi
  else
    verdict MGMT-14b undecided "no gateway log to inspect for the publish"
  fi
  echo "  NOTE: the HA-peer half of MGMT-14 needs a second node; this topology"
  echo "        has one, so the publish is asserted at the sender, not the receiver."
fi
echo
fi

# ----------------------------------------------------------------- MGMT-18 ----
if want 18; then
echo "---- MGMT-18: full CRUD cycle with users present ----"
U18=i9crud; P18A='Crud1pass!'; P18B='Crud2pass!'
pgq "DELETE FROM aigw_mgmt.users WHERE username='$U18';" >/dev/null
STEP=0; OK=0
S=$(mkuser "$U18" "$P18A" viewer);            STEP=$((STEP+1)); [ "$S" = "200" ] && OK=$((OK+1)); echo "  1 create              -> $S"
ID18=$(uid_of "$U18")
mgmt 15 -H "Authorization: Bearer $TOKEN" "$API/auth/users"
STEP=$((STEP+1)); [ "$MSTATUS" = "200" ] && OK=$((OK+1)); echo "  2 list                -> $MSTATUS"
T18A=$(login "$U18" "$P18A")
STEP=$((STEP+1)); [ -n "$T18A" ] && OK=$((OK+1)); echo "  3 login (initial)     -> $([ -n "$T18A" ] && echo token || echo none)"
mgmt 20 -X PUT "$API/auth/users/$ID18" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" -d "{\"username\":\"$U18\",\"password\":\"$P18B\"}"
STEP=$((STEP+1)); [ "$MSTATUS" = "200" ] && OK=$((OK+1)); echo "  4 change password     -> $MSTATUS"
T18B=$(login "$U18" "$P18B")
STEP=$((STEP+1)); [ -n "$T18B" ] && OK=$((OK+1)); echo "  5 login (new)         -> $([ -n "$T18B" ] && echo token || echo none)"
T18C=$(login "$U18" "$P18A")
STEP=$((STEP+1)); [ -z "$T18C" ] && OK=$((OK+1)); echo "  6 login (old)         -> $([ -n "$T18C" ] && echo 'token — WRONG' || echo 'refused')"
mgmt 15 -X DELETE "$API/auth/users/$ID18" -H "Authorization: Bearer $TOKEN"
STEP=$((STEP+1)); [ "$MSTATUS" = "200" ] && OK=$((OK+1)); echo "  7 delete              -> $MSTATUS"
mgmt 15 -H "Authorization: Bearer $T18B" "$API/auth/users"
STEP=$((STEP+1)); [ "$MSTATUS" = "401" ] && OK=$((OK+1)); echo "  8 reuse token         -> $MSTATUS"
if [ "$OK" = "$STEP" ]; then
  verdict MGMT-18 pass "all $STEP steps returned their fixed verdict"
else
  verdict MGMT-18 fail "$OK/$STEP steps correct"
fi
echo
fi

# ------------------------------------------------------------------ MGMT-8 ----
# Infrastructure-disruptive legs last: they stop the shared PostgreSQL server,
# which is also the data plane's key store.
if want 8; then
echo "---- MGMT-8: store down, uncached token -> 503 ----"
FDB=$(fdcount)
docker stop "$PG_CT" >/dev/null 2>&1
sleep 2
# A token that is certainly not in the local cache. With the store down the
# gateway cannot know whether it is unknown or valid, so 401 would be a claim it
# is not entitled to make; 503 is the honest answer. 500/502/504 mean the
# outage escaped as a generic failure.
UNC=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
mgmt 25 -H "Authorization: Bearer $UNC" "$API/auth/users"
S8=$MSTATUS; B8=$MBODY
echo "  status=$S8 elapsed=${MTIME}s"
echo "  body=$(printf '%s' "$B8" | head -c 200)"
docker start "$PG_CT" >/dev/null 2>&1
for i in $(seq 1 60); do
  docker exec "$PG_CT" pg_isready -h 127.0.0.1 -U "$PG_ROLE" -d "$PG_DB" >/dev/null 2>&1 && break
  sleep 1
done
echo "  store back up after $i s"
case "$S8" in
  503) verdict MGMT-8 pass "503 while the store was down" ;;
  401) verdict MGMT-8 fail "401 — claimed the token was unknown with no store to check against" ;;
  500|502|504) verdict MGMT-8 fail "$S8 — the outage escaped as a generic failure" ;;
  "" ) verdict MGMT-8 undecided "no status captured" ;;
  *)   verdict MGMT-8 fail "expected 503, got $S8" ;;
esac
echo
fi

# ----------------------------------------------------------------- MGMT-12 ----
if want 12; then
echo "---- MGMT-12: flap the store 5x across the 10 s ticker, then hold it down 60 s ----"
LPID=$(loxilb_pid)
[ -n "$LPID" ] || echo "  !! loxilb process not found — the fd census cannot measure anything"
FD0=$(fdcount)
CN0=$(conncount)
echo "  baseline: loxilb pid=$LPID fds=$FD0 mgmt-conns=$CN0"
for i in 1 2 3 4 5; do
  docker stop "$PG_CT" >/dev/null 2>&1
  sleep 6
  docker start "$PG_CT" >/dev/null 2>&1
  sleep 8
  echo "  flap $i: fds=$(fdcount)"
done
# The reconnect ticker is 10 s, so a 60 s hold is six attempts with nothing to
# connect to — the exact loop that produced the F-AUTH-13 leak.
docker stop "$PG_CT" >/dev/null 2>&1
sleep 60
FD_DOWN=$(fdcount)
echo "  after the 60 s hold: fds=$FD_DOWN"
docker start "$PG_CT" >/dev/null 2>&1
for i in $(seq 1 60); do
  docker exec "$PG_CT" pg_isready -h 127.0.0.1 -U "$PG_ROLE" -d "$PG_DB" >/dev/null 2>&1 && break
  sleep 1
done
sleep 15
FD1=$(fdcount)
CN1=$(conncount)
echo "  recovered: fds=$FD1 mgmt-conns=$CN1"
mgmt 15 -H "Authorization: Bearer $TOKEN" "$API/auth/users"
echo "  service after recovery: GET /auth/users -> $MSTATUS"
if [ -z "$FD0" ] || [ -z "$FD1" ] || [ "$FD0" = "0" ]; then
  verdict MGMT-12 undecided "fd census unavailable (fd0=$FD0 fd1=$FD1) — nothing was measured"
else
  GROWTH=$((FD1 - FD0))
  DGROWTH=$((FD_DOWN - FD0))
  echo "  fd growth: +$GROWTH after recovery, +$DGROWTH at the bottom of the outage"
  # A leak on a 10 s ticker over 5 flaps plus a 60 s hold is tens of fds; a
  # bounded pool moves by a handful as connections are re-established.
  if [ "$GROWTH" -le 10 ] && [ "$DGROWTH" -le 10 ] && [ "$MSTATUS" = "200" ]; then
    verdict MGMT-12 pass "fds bounded (+$GROWTH) and the gateway serves again"
  elif [ "$MSTATUS" != "200" ]; then
    verdict MGMT-12 fail "fds +$GROWTH but the gateway does not serve after recovery ($MSTATUS)"
  else
    verdict MGMT-12 fail "fd count grew by $GROWTH across the flap — the leak is still there"
  fi
fi
echo
fi

# ------------------------------------------------------------------ cleanup ---
pgq "DELETE FROM aigw_mgmt.users WHERE username LIKE 'i9%';" >/dev/null 2>&1

echo "==================== summary ===================="
[ -n "$SKIPPED" ] && echo "skipped legs (AUTHSEP_ONLY=$ONLY):$SKIPPED"
echo "legs=$LEGS failures=$FAIL"
if [ "$FAIL" -eq 0 ] && [ "$LEGS" -gt 0 ]; then
  echo "RESULT: every leg met its specified verdict"
  exit 0
fi
[ "$LEGS" -eq 0 ] && { echo "RESULT: no leg ran — the run decided nothing"; exit 2; }
echo "RESULT: $FAIL leg(s) failed or could not be decided"
exit 1
