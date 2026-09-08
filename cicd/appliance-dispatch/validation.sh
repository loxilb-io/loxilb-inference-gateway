#!/bin/bash
# validation.sh — appliance-dispatch: the CLI's host-lifecycle dispatcher is
# the subject; the backend fixture's recorded argv/env/stdin is the oracle.
#
# Discipline:
#  * Exit status is asserted FIRST, before any output is read. Half these
#    cases exist because a command that prints an error and exits 0 turns a
#    refused host mutation into a recorded success.
#  * "The CLI said it refused" proves nothing. Every pre-spawn refusal is
#    cross-checked against the fixture's spawn counter: if the counter moved,
#    the refusal happened after exec and the guarantee is not what it claims.
#  * The fixture is installed at the REAL compiled-in path. The CLI repo's own
#    tests relocate that path via -ldflags, so this suite is the only place the
#    shipped binary's default libexec layout is exercised.
#
# Two legs assert the published contract against behaviour that does not yet
# implement it (see README "Known-red legs"). They are red on purpose.

source ../common.sh
echo SCENARIO-appliance-dispatch

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
ART="${CFGDIR}/artifacts"
mkdir -p "$ART"

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }
skip() { echo "  [SKIPPED] $1"; }

echo "  CLI under test: $(cat "${CFGDIR}/.cli-under-test" 2>/dev/null || echo unknown)"

BACKEND=/usr/libexec/loxilb-appliance/loxilb-appliance-backend
FAKEROOT=/opt/appliance-fake

set_mode() { $dexec llb1 sh -c "echo $1 > $FAKEROOT/mode"; }
spawns()   { $dexec llb1 sh -c "cat $FAKEROOT/rec/count 2>/dev/null || echo 0" | tr -d '\r'; }
rec()      { $dexec llb1 sh -c "cat $FAKEROOT/rec/$1 2>/dev/null" ; }

# run <artifact-label> <loxicmd args...> -- captures streams host-side and
# leaves the status in RC. docker exec without -t: stdin/stdout are pipes, so
# the console-only guard sees a non-terminal, which is the case under test.
run() {
    local label="$1"; shift
    $dexec llb1 loxicmd "$@" > "$ART/$label.out" 2> "$ART/$label.err"
    RC=$?
}
# run_env <artifact-label> <VAR=VAL> <loxicmd args...>
run_env() {
    local label="$1" var="$2"; shift 2
    sudo docker exec -i -e "$var" llb1 loxicmd "$@" > "$ART/$label.out" 2> "$ART/$label.err"
    RC=$?
}

# Structural envelope checks. Full JSON-Schema validation of CommandResult
# lives in the CLI repository, next to the schema itself; duplicating the
# schema here would just create a second copy to drift. Set APPL_SCHEMA to a
# checkout's contracts/command-result.schema.json to add real validation.
envelope_ok() { # envelope_ok <file> <expected .command> <expected .code>
    local f="$1" want_cmd="$2" want_code="$3"
    jq -e --arg c "$want_cmd" --arg k "$want_code" '
        .apiVersion == "loxilb.io/appliance/v1"
        and .kind == "CommandResult"
        and .command == $c
        and .code == $k
        and (.success == ($k == "OK"))
        and (.message | type) == "string"
        and (.correlationId | type) == "string"
        and (.data | type) == "object"
        and (.warnings | type) == "array"
        and ([paths as $p | getpath($p)] | map(select(. == null)) | length) == 0
    ' < "$f" >/dev/null 2>&1
}
schema_validate() { # schema_validate <file>
    [[ -n "$APPL_SCHEMA" && -r "$APPL_SCHEMA" ]] || return 2
    python3 - "$APPL_SCHEMA" "$1" <<'PY' 2>/dev/null
import json,sys
try: import jsonschema
except ImportError: sys.exit(2)
s=json.load(open(sys.argv[1])); d=json.load(open(sys.argv[2]))
e=list(jsonschema.Draft202012Validator(s).iter_errors(d))
sys.exit(1 if e else 0)
PY
}

set_mode ok

#################################################################################
echo "=== dispatch: the shipped binary reaches the real libexec path ==="
#################################################################################
run ad01 appliance status
[[ $RC -eq 0 ]] && pass "AD-01: status exited 0" || fail "AD-01: status exited $RC"
grep -q "fixture backend ok: status" "$ART/ad01.out" \
    && pass "AD-01: the backend's human output is passed through verbatim" \
    || fail "AD-01: human passthrough: $(head -1 "$ART/ad01.out")"

run ad02 appliance status -o json
[[ $RC -eq 0 ]] && pass "AD-02: status -o json exited 0" || fail "AD-02: exited $RC"
if envelope_ok "$ART/ad02.out" "appliance.status" "OK"; then
    pass "AD-02: the envelope is well-formed (no nulls, success agrees with code)"
else
    fail "AD-02: malformed envelope: $(tr -d '\n' < "$ART/ad02.out" | head -c 300)"
fi
jq -e '.data.backend.fixture == true' < "$ART/ad02.out" >/dev/null 2>&1 \
    && pass "AD-02: the backend's own JSON document is preserved under .data.backend" \
    || fail "AD-02: .data.backend did not carry the backend document"
schema_validate "$ART/ad02.out"; sv=$?
case $sv in
0) pass "AD-02: envelope validates against contracts/command-result.schema.json" ;;
1) fail "AD-02: envelope FAILS contracts/command-result.schema.json" ;;
*) skip "AD-02 schema validation (set APPL_SCHEMA to a CLI checkout's command-result.schema.json)" ;;
esac

# The correlation id is the join between the CLI's output and the host journal.
# Asserting it is non-empty proves nothing; it has to be the SAME id the
# backend was invoked with.
cid=$(jq -r '.correlationId' < "$ART/ad02.out" 2>/dev/null)
[[ -n "$cid" && "$cid" != "null" ]] \
    && pass "AD-03: the envelope reports a correlation id ($cid)" \
    || fail "AD-03: no correlation id in the envelope"
rec argv | grep -q -- "$cid" \
    && pass "AD-03: the backend was invoked with that same id" \
    || fail "AD-03: backend argv does not carry $cid: $(rec argv)"

#################################################################################
echo "=== availability: the family works with the gateway stopped ==="
#################################################################################
# The contract clause that makes this family worth having: it must keep working
# while the gateway container is stopped or unhealthy.
$dexec llb1 pkill -x loxilb >/dev/null 2>&1
sleep 3
if $dexec llb1 sh -c 'pgrep -x loxilb >/dev/null 2>&1'; then
    skip "AD-04 (the gateway process did not stay down; the leg would prove nothing)"
else
    run ad04 appliance status -o json
    [[ $RC -eq 0 ]] && pass "AD-04: appliance status works with the gateway process stopped" \
                    || fail "AD-04: exited $RC with the gateway down: $(head -1 "$ART/ad04.err")"
    run ad04b appliance network validate
    [[ $RC -eq 0 ]] && pass "AD-04: network validate works with the gateway process stopped" \
                    || fail "AD-04: network validate exited $RC with the gateway down"
fi

#################################################################################
echo "=== backend availability and the contract handshake ==="
#################################################################################
$dexec llb1 mv "$BACKEND" "$BACKEND.hidden"
run ad05 appliance status -o json
[[ $RC -eq 5 ]] && pass "AD-05: an absent backend is UNAVAILABLE (5)" \
                || fail "AD-05: absent backend exited $RC, want 5"
jq -e '.data.componentCode == "BACKEND_UNAVAILABLE" and .data.origin == "backend"' \
    < "$ART/ad05.out" >/dev/null 2>&1 \
    && pass "AD-05: componentCode is BACKEND_UNAVAILABLE with origin=backend" \
    || fail "AD-05: origin/componentCode: $(jq -c '.data' < "$ART/ad05.out" 2>/dev/null)"
$dexec llb1 mv "$BACKEND.hidden" "$BACKEND"

set_mode badmajor
before=$(spawns)
run ad06 appliance public-address configure 203.0.113.10
[[ $RC -eq 6 ]] && pass "AD-06: a wrong contract major is CONTRACT_MISMATCH (6)" \
                || fail "AD-06: exited $RC, want 6"
[[ "$(spawns)" -eq $((before + 1)) ]] \
    && pass "AD-06: only the handshake ran; the mutating call never spawned" \
    || fail "AD-06: spawn count $before -> $(spawns) (want exactly one, the handshake)"

set_mode nocmd
run ad07 appliance backup key-create --key-file /root/ad07.key
[[ $RC -eq 6 ]] && pass "AD-07: an unadvertised command is CONTRACT_MISMATCH (6)" \
                || fail "AD-07: exited $RC, want 6"
grep -q "does not provide" "$ART/ad07.err" \
    && pass "AD-07: the refusal names the missing capability" \
    || fail "AD-07: refusal wording: $(head -1 "$ART/ad07.err")"

# Read-only commands are documented to proceed without a handshake -- the
# invocation itself is the availability probe.
set_mode nohandshake
run ad08 appliance status
[[ $RC -eq 0 ]] \
    && pass "AD-08: read-only dispatch does not require the handshake" \
    || fail "AD-08: read-only exited $RC when the handshake fails"

set_mode prose
run ad09 appliance status -o json
[[ $RC -eq 6 ]] && pass "AD-09: prose in JSON mode is CONTRACT_MISMATCH (6)" \
                || fail "AD-09: exited $RC, want 6"
jq -e '.data.componentCode == "contract-invalid"' < "$ART/ad09.out" >/dev/null 2>&1 \
    && pass "AD-09: componentCode is contract-invalid" \
    || fail "AD-09: componentCode: $(jq -c '.data.componentCode' < "$ART/ad09.out" 2>/dev/null)"

set_mode exitfail
run ad10 appliance status
[[ $RC -eq 7 ]] && pass "AD-10: a backend refusal is FAILED (7)" \
                || fail "AD-10: exited $RC, want 7"
grep -q "backend-exit-42" "$ART/ad10.err" || \
  $dexec llb1 loxicmd appliance status -o json 2>/dev/null | grep -q "backend-exit-42"
[[ $? -eq 0 ]] && pass "AD-10: the backend's own exit status is preserved verbatim" \
              || fail "AD-10: backend exit status not preserved"
[[ $(wc -l < "$ART/ad10.err") -le 2 ]] \
    && pass "AD-10: only the first stderr line reaches the terminal (no flood)" \
    || fail "AD-10: stderr flooded with $(wc -l < "$ART/ad10.err") lines"
set_mode ok

#################################################################################
echo "=== pre-spawn refusals: rejected before a process ever starts ==="
#################################################################################
# Each of these must be refused CLI-side. The spawn counter is the proof: if it
# moved, the refusal happened after exec and the "never reaches the backend"
# guarantee is not real.
prespawn() { # prespawn <label> <want-exit> <args...>
    local label="$1" want="$2"; shift 2
    local before; before=$(spawns)
    run "$label" "$@"
    [[ $RC -eq $want ]] \
        && pass "$label: exited $want" \
        || fail "$label: exited $RC, want $want ($(head -1 "$ART/$label.err"))"
    [[ "$(spawns)" -eq "$before" ]] \
        && pass "$label: no process was spawned" \
        || fail "$label: the backend was spawned anyway ($before -> $(spawns))"
}
prespawn AD-11 2 appliance public-address configure 203.0.113.010
prespawn AD-12 2 appliance logs kernel --redact
prespawn AD-13 2 appliance logs gateway --redact --since 200h
prespawn AD-14 2 appliance logs gateway --redact --lines 20000
prespawn AD-15 2 appliance diagnostics create
prespawn AD-16 2 appliance backup create relative/path.tar --key-file /root/k

# Shell metacharacters must travel as one literal argv token. The archive path
# is absolute, so it clears the CLI's own path check and actually reaches exec
# -- so the leg measures how the token is handed to the process, rather than
# stopping at argument validation.
$dexec llb1 sh -c 'rm -f /tmp/PWNED; printf secret > /root/ad17.key; chmod 0600 /root/ad17.key'
run ad17 appliance backup create '/tmp/arch;touch /tmp/PWNED' --key-file /root/ad17.key
if $dexec llb1 test -e /tmp/PWNED; then
    fail "AD-17: shell metacharacters were INTERPRETED — /tmp/PWNED was created"
else
    pass "AD-17: shell metacharacters were not interpreted (no shell in the path)"
fi
rec argv | grep -q 'arch;touch' \
    && pass "AD-17: the metacharacters reached the backend as one literal token" \
    || fail "AD-17: the literal token did not reach the backend: $(rec argv)"

#################################################################################
echo "=== the child environment is fixed by the CLI, not inherited ==="
#################################################################################
run_env ad18 "LOXILB_QA_CANARY=must-not-propagate" appliance status
[[ $RC -eq 0 ]] || fail "AD-18: status exited $RC"
if rec env | grep -q "must-not-propagate"; then
    fail "AD-18: the caller's environment reached the backend (it can redirect product root/state)"
else
    pass "AD-18: the caller's environment did not reach the backend"
fi

#################################################################################
echo "=== secrets travel on stdin only ==="
#################################################################################
$dexec llb1 sh -c 'printf correcthorsebatterystaple > /root/ok.pass; chmod 0600 /root/ok.pass
                   printf loose > /root/loose.pass; chmod 0644 /root/loose.pass
                   ln -sf /root/ok.pass /root/link.pass'
prespawn AD-19 4 appliance gateway register-local --username admin --password-file /root/loose.pass
grep -qi "owner-only" "$ART/AD-19.err" \
    && pass "AD-19: the refusal names the owner-only requirement" \
    || fail "AD-19: refusal wording: $(head -1 "$ART/AD-19.err")"
prespawn AD-20 4 appliance gateway register-local --username admin --password-file /root/link.pass

run ad21 appliance gateway register-local --username admin --password-file /root/ok.pass -o json
[[ $RC -eq 0 ]] && pass "AD-21: register-local dispatched" || fail "AD-21: exited $RC"
rec stdin | grep -q correcthorsebatterystaple \
    && pass "AD-21: the secret reached the backend on stdin" \
    || fail "AD-21: the secret never reached stdin"
leaked=0
rec argv | grep -q correcthorse && { fail "AD-21: the secret leaked into argv"; leaked=1; }
rec env  | grep -q correcthorse && { fail "AD-21: the secret leaked into the environment"; leaked=1; }
grep -q correcthorse "$ART/ad21.out" && { fail "AD-21: the secret leaked into stdout"; leaked=1; }
[[ $leaked -eq 0 ]] && pass "AD-21: the secret appears in no other channel"

prespawn AD-22 2 appliance credentials bootstrap -o json
prespawn AD-23 4 appliance credentials bootstrap
grep -qi "console" "$ART/AD-23.err" \
    && pass "AD-23: the refusal names the console requirement" \
    || fail "AD-23: refusal wording: $(head -1 "$ART/AD-23.err")"

# Backup key files are opened by the BACKEND, not by the CLI, so the CLI checks
# the path without reading it (CheckSecretPath). Both directions matter: a key
# that would be overwritten, and a key loose enough for another user to read.
$dexec llb1 sh -c 'printf existing > /root/ad28.key; chmod 0600 /root/ad28.key
                   printf loose > /root/ad29.key; chmod 0644 /root/ad29.key'
prespawn AD-28 4 appliance backup key-create --key-file /root/ad28.key
grep -qi "already exists" "$ART/AD-28.err" \
    && pass "AD-28: the refusal says the key would be overwritten" \
    || fail "AD-28: refusal wording: $(head -1 "$ART/AD-28.err")"
prespawn AD-29 4 appliance backup create /tmp/ad29.tar --key-file /root/ad29.key
grep -qi "owner-only" "$ART/AD-29.err" \
    && pass "AD-29: a group-readable key file is refused by the same secret rules" \
    || fail "AD-29: refusal wording: $(head -1 "$ART/AD-29.err")"

#################################################################################
echo "=== functions this release does not provide are refused, never stubbed ==="
#################################################################################
for u in restore update rollback factory-reset; do
    run "ad24-$u" appliance "$u"
    [[ $RC -eq 6 ]] \
        && pass "AD-24: appliance $u is refused with CONTRACT_MISMATCH (6)" \
        || fail "AD-24: appliance $u exited $RC, want 6 (a successful stub is the failure mode)"
done

#################################################################################
echo "=== known-red legs: the published contract vs today's behaviour ==="
#################################################################################
# These assert contracts/host-backend-contract.md and contracts/exit-codes.md.
# They are expected to FAIL until the dispatcher implements them. Setting
# APPL_TOLERATE_KNOWN_DEFECTS=1 downgrades them to warnings so the suite can be
# wired into CI before the fixes land -- that is a scheduling decision, not a
# coverage one, and the legs still print what they found.
known() { # known <message>
    if [[ "$APPL_TOLERATE_KNOWN_DEFECTS" == "1" ]]; then
        echo "  [KNOWN-DEFECT] $1"
    else
        fail "$1"
    fi
}

# exit-codes.md rule 5 names "timeout mid-mutation" as the PARTIAL case;
# host-backend-contract.md requires exit 8 with the backend's operation id in
# data.operationId. A mutating command killed mid-flight is that case exactly.
set_mode hang
$dexec llb1 timeout 45 loxicmd -t 2 appliance backup create /tmp/ad25.tar \
    --key-file /root/ad17.key -o json > "$ART/ad25.out" 2> "$ART/ad25.err"
RC=$?
$dexec llb1 pkill -x sleep >/dev/null 2>&1
if [[ $RC -eq 8 ]]; then
    pass "AD-25: a mutation killed mid-flight is PARTIAL (8)"
    jq -e '.data.operationId != null' < "$ART/ad25.out" >/dev/null 2>&1 \
        && pass "AD-25: the envelope carries data.operationId for recovery" \
        || known "AD-25: exit 8 but no data.operationId to drive recovery with"
else
    known "AD-25: a mutation killed mid-flight exited $RC, want 8 (PARTIAL). Exit 7 tells automation the operation is safe to retry; exit-codes.md rule 4 forbids auto-retrying 8"
fi
set_mode ok

# --timeout is the only thing standing between automation and a wedged host
# backend. cmd/appliance/appliance.go says so in as many words: "so a wedged
# backend cannot hang automation forever". A backend that FORKS a child -- which
# is every real one, the moment it shells out to tar, pg_dump, systemctl or
# journalctl -- inherits the pipes into the grandchild, and killing the direct
# child alone does not end the invocation.
#
# This leg bounds ITSELF host-side, because the whole point is that the CLI does
# not. Without the backstop a regression here wedges the suite instead of
# reporting.
set_mode hangfork
if ! $dexec llb1 sh -c 'command -v timeout >/dev/null'; then
    skip "AD-27 (no timeout(1) in the image for the host-side backstop)"
else
    t0=$(date +%s)
    $dexec llb1 timeout 45 loxicmd -t 2 appliance backup create /tmp/ad27.tar \
        --key-file /root/ad17.key -o json > "$ART/ad27.out" 2> "$ART/ad27.err"
    RC=$?
    elapsed=$(( $(date +%s) - t0 ))
    # Release the orphaned grandchild whatever happened, or it outlives the run.
    $dexec llb1 pkill -x sleep >/dev/null 2>&1
    if [[ $elapsed -le 10 ]]; then
        pass "AD-27: --timeout bounded a forking backend (${elapsed}s, exit $RC)"
    else
        known "AD-27: --timeout 2 did NOT bound a forking backend — the call ran ${elapsed}s (exit $RC). exec.CommandContext kills only the direct child; the grandchild keeps stdout open and cmd.Run() blocks. A wedged backend CAN hang automation forever, which is what appliance.go's requestContext comment says it cannot"
    fi
fi
set_mode ok

# exit-codes.md defines 3 (AUTH) as covering "OS privilege insufficient".
$dexec llb1 chmod 0600 "$BACKEND"
run ad26 appliance status
if grep -qi "permission denied" "$ART/ad26.err"; then
    [[ $RC -eq 3 ]] \
        && pass "AD-26: a privilege failure is AUTH (3)" \
        || known "AD-26: a privilege failure exited $RC, want 3 (AUTH). Exit 5 tells automation to retry with backoff, which can never succeed for an under-privileged caller"
else
    skip "AD-26 (could not produce a permission-denied exec here; the leg would prove nothing)"
fi
$dexec llb1 chmod 0755 "$BACKEND"

# Leave the fixture in a sane state for anyone poking at the container.
set_mode ok
echo "appliance-dispatch validation done (code=$code)"
exit $code
