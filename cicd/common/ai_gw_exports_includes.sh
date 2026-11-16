#!/bin/bash
# ai_gw_exports_includes.sh — pkg/loxinet/ai_gw_exports.h reads sockproxy_ai_gw.h as written.
# Until WP-D the wrapper read that header with const defined away (DECISIONS.md row 72, S0-1); the datapath
# then dropped the three const a Go export cannot spell, and the define went. This check fails when:
#   - the wrapper defines or undefines const (or any other C keyword) anywhere;
#   - the wrapper does not include "sockproxy_ai_gw.h";
#   - a prototype of sockproxy_ai_gw.h has a const parameter again (its exports are compared with
#     their qualifiers now, so such a prototype would fail the Go build; this says why, earlier).
# usage: cicd/common/ai_gw_exports_includes.sh [repo root]   (exit 0 = consistent)
set -uo pipefail
ROOT=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
WRAP=$ROOT/pkg/loxinet/ai_gw_exports.h
HDR=$ROOT/loxilb-ebpf/common/sockproxy_ai_gw.h
KW='auto|break|case|char|const|continue|default|do|double|else|enum|extern|float|for|goto|if|inline|int|long|register|restrict|return|short|signed|sizeof|static|struct|switch|typedef|union|unsigned|void|volatile|while'

bad=0
if grep -nE "^[[:space:]]*#[[:space:]]*(define|undef)[[:space:]]+($KW)\b" "$WRAP"; then
  echo "FAIL: the wrapper redefines a C keyword; sockproxy_ai_gw.h must be read as written"; bad=1
fi
grep -qE '^[[:space:]]*#[[:space:]]*include[[:space:]]*"sockproxy_ai_gw.h"' "$WRAP" || {
  echo "FAIL: the wrapper does not include \"sockproxy_ai_gw.h\""; bad=1; }
# The header's code with its comments removed.
if perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$HDR" | grep -nE '\bconst\b'; then
  echo "FAIL: sockproxy_ai_gw.h has a const outside a comment; a Go export cannot spell it"; bad=1
fi
[ $bad = 0 ] || exit 1
echo "ok: the wrapper includes sockproxy_ai_gw.h as written; no const in its prototypes"
