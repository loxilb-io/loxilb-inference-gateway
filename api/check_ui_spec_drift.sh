#!/bin/bash
# Compare the gateway API spec vendored by the UI dashboard
# (loxilb-io/loxilb-ui, api-spec/gateway-swagger*.yml) against the spec in
# this repository. The dashboard builds its API client from its vendored
# copy, so the two must be compared with the vendored copy as the baseline:
# surface the vendored copy relies on that this repository no longer
# declares (or declares differently) breaks the dashboard and fails this
# check; additions on our side are staleness the UI picks up at its next
# vendoring refresh, and are logged without failing.
#
# Usage: check_ui_spec_drift.sh <ui-api-spec-dir> [gateway-api-dir]
#   <ui-api-spec-dir>  checkout of loxilb-ui's api-spec/ directory
#   [gateway-api-dir]  this repo's api/ directory (default: script's own dir)
#
# Requires go-swagger's `swagger` on PATH (override with $SWAGGER).
# NOTE: the codegen toolchain pin (0.30.3, api/build_api.sh) panics in
# `swagger diff` on these specs (nil schema node on schema-less responses);
# diffing needs >= v0.36.x.

set -u

SWAGGER="${SWAGGER:-swagger}"
UI_DIR="${1:?usage: $0 <ui-api-spec-dir> [gateway-api-dir]}"
GW_DIR="${2:-$(cd "$(dirname "$0")" && pwd)}"

require_file() {
    if [ ! -f "$1" ]; then
        echo "ERROR: missing input $1 — a comparison that cannot reach its input must fail, not pass" >&2
        exit 2
    fi
}

require_file "$UI_DIR/gateway-swagger.yml"
require_file "$UI_DIR/gateway-swagger-extras.yml"
require_file "$GW_DIR/swagger.yml"
require_file "$GW_DIR/swagger-extras.yml"

if ! command -v "$SWAGGER" >/dev/null 2>&1; then
    echo "ERROR: go-swagger binary '$SWAGGER' not found on PATH" >&2
    exit 2
fi

if [ -f "$UI_DIR/SOURCES.json" ]; then
    echo "== UI vendoring manifest ($UI_DIR/SOURCES.json) =="
    cat "$UI_DIR/SOURCES.json"
    echo ""
fi

fail=0

# swagger diff <old> <new>: "breaking" means a client built against <old>
# is broken by a server serving <new>. The vendored copy is what the UI
# client is built against, so it is always the <old> side.
compare() {
    local label="$1" vendored="$2" release="$3"
    local out rc
    echo ""
    echo "== $label: vendored (UI) vs release (this repo) =="
    out="$("$SWAGGER" diff "$vendored" "$release" 2>&1)"
    rc=$?
    echo "$out"
    case "$out" in
    *"No changes identified"*)
        echo "-- $label: in sync"
        ;;
    *"compatibility test OK"*)
        echo "-- $label: release is ahead, additions only — UI refresh owed at its next vendoring"
        ;;
    *"compatibility test FAILED"*)
        echo "-- $label: BREAKING drift — the vendored spec relies on surface this repo does not declare, or declares differently"
        fail=1
        ;;
    *)
        echo "-- $label: swagger diff produced no verdict (rc=$rc) — failing closed"
        fail=1
        ;;
    esac
}

compare "swagger.yml" "$UI_DIR/gateway-swagger.yml" "$GW_DIR/swagger.yml"
compare "swagger-extras.yml" "$UI_DIR/gateway-swagger-extras.yml" "$GW_DIR/swagger-extras.yml"

echo ""
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL — breaking drift or comparison error; see the per-file verdicts above"
else
    echo "RESULT: OK"
fi
exit "$fail"
