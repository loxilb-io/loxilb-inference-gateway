#!/bin/sh
# Stand-in for the Product-owned host lifecycle backend, installed at the real
# path the CLI compiles in. It implements only the invocation contract
# (contracts/host-backend-contract.md + backend-contract.schema.json) -- never
# any lifecycle behaviour -- because this suite measures the DISPATCHER, not
# the backend.
#
# Every invocation records its argv, environment and stdin so the suite can
# assert what actually crossed the process boundary rather than trusting the
# CLI's own report of what it sent.
#
# MODE (read fresh on every call from $ROOT/mode) selects the contract-level
# condition under test. Default "ok".
ROOT=/opt/appliance-fake
REC="$ROOT/rec"
MODE=$(cat "$ROOT/mode" 2>/dev/null || echo ok)

mkdir -p "$REC"
# One record per invocation, plus a monotonic spawn counter. The counter is
# what proves a CLI-side refusal never reached exec: a leg asserts it did not
# advance.
n=$(cat "$REC/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$REC/count"
printf '%s\n' "$*" > "$REC/argv"
env > "$REC/env"
: > "$REC/stdin"
# Only the secret-bearing subcommand is given a stdin to drain; reading it
# unconditionally would block every other call.
case "$1 $2" in
"gateway register-local") cat > "$REC/stdin" ;;
esac

emit_contract() {
    # apiVersion major is what the CLI gates on; MODE flips it to prove the
    # gate fires. "nocmd" drops the mutating command from the advertisement.
    api="loxilb.io/appliance-backend/v1"
    [ "$MODE" = "badmajor" ] && api="loxilb.io/appliance-backend/v99"
    cmds='{"name":"status","readOnly":true,"capabilities":[]},
          {"name":"network validate","readOnly":true,"capabilities":[]},
          {"name":"public-address configure","readOnly":false,"capabilities":[]},
          {"name":"gateway register-local","readOnly":false,"capabilities":[]},
          {"name":"credentials bootstrap","readOnly":false,"capabilities":[]},
          {"name":"diagnostics create","readOnly":false,"capabilities":[]},
          {"name":"logs","readOnly":false,"capabilities":[]},
          {"name":"backup key-create","readOnly":false,"capabilities":[]},
          {"name":"backup create","readOnly":false,"capabilities":[]},
          {"name":"backup verify","readOnly":false,"capabilities":[]}'
    [ "$MODE" = "nocmd" ] && cmds='{"name":"status","readOnly":true,"capabilities":[]}'
    cat <<JSON
{"apiVersion":"$api","kind":"BackendContract","backendVersion":"fake-1.0.0",
 "productRelease":"qa-fixture","schemaVersion":1,"commands":[$cmds]}
JSON
}

if [ "$1" = "contract-version" ]; then
    # "nohandshake" makes the handshake itself fail, which must classify as
    # UNAVAILABLE and must NOT block the read-only set.
    [ "$MODE" = "nohandshake" ] && { echo "handshake refused" >&2; exit 3; }
    emit_contract
    exit 0
fi

# Is --json among the argv? The contract says stdout is either human output or
# exactly one JSON document -- never both, never prose in JSON mode.
json=no
for a in "$@"; do [ "$a" = "--json" ] && json=yes; done

case "$1 $2" in
"backup create")
    case "$MODE" in
    hang)
        # The ambiguity case: work starts, then the process is killed
        # mid-flight by the CLI's own --timeout. The taxonomy calls this
        # PARTIAL. `exec` REPLACES sh with sleep, so the CLI's kill reaches
        # the process actually holding the pipes -- which isolates "what exit
        # code does it report" from "does it return at all".
        echo "backup started, operation id op-fixture-0001"
        exec sleep 60
        ;;
    hangfork)
        # The same wedge, but sh FORKS sleep and waits on it. The grandchild
        # inherits stdout/stderr, so killing the direct child alone does not
        # end the invocation. This is what every real backend does the moment
        # it shells out to tar, pg_dump, systemctl or journalctl -- so it is
        # the shape that decides whether --timeout actually bounds anything.
        echo "backup started, operation id op-fixture-0002"
        sleep 60
        ;;
    esac
    ;;
esac

if [ "$MODE" = "prose" ] && [ "$json" = yes ]; then
    echo "this is not a JSON document"
    exit 0
fi
if [ "$MODE" = "exitfail" ]; then
    echo "backend refused: fixture failure line 1" >&2
    echo "stack frame that must not flood the terminal" >&2
    exit 42
fi

if [ "$json" = yes ]; then
    echo '{"fixture":true,"subcommand":"'"$1"'"}'
else
    echo "fixture backend ok: $*"
fi
exit 0
