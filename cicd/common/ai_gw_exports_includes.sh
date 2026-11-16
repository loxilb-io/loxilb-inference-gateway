#!/bin/bash
# ai_gw_exports_includes.sh — pkg/loxinet/ai_gw_exports.h reads sockproxy_ai_gw.h with const defined away.
# Only that header's own text may be read that way. This check fails when:
#   - a header that sockproxy_ai_gw.h includes, directly or through a datapath header it includes, is not
#     included by the wrapper as written, before "#define const";
#   - anything other than one #include "sockproxy_ai_gw.h" stands between "#define const" and "#undef const".
# Datapath headers ("...") are resolved in loxilb-ebpf/common and followed; system headers (<...>) are names.
# usage: cicd/common/ai_gw_exports_includes.sh [repo root]   (exit 0 = consistent)
set -uo pipefail
ROOT=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
COMMON=$ROOT/loxilb-ebpf/common
WRAP=$ROOT/pkg/loxinet/ai_gw_exports.h
HDR=sockproxy_ai_gw.h

incs() { sed -nE 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*([<"][^>"]+[>"]).*/\1/p' "$1"; }

# the headers sockproxy_ai_gw.h reaches: its own #includes and, through datapath headers, theirs
need=(); seen=" "
queue=("\"$HDR\"")
while [ ${#queue[@]} -gt 0 ]; do
  cur=${queue[0]}; queue=("${queue[@]:1}")
  case "$cur" in
    \"*\") f=$COMMON/${cur//\"/}; [ -f "$f" ] || { echo "FAIL: $cur not found in loxilb-ebpf/common"; exit 1; } ;;
    *) continue ;;
  esac
  while read -r i; do
    [ -z "$i" ] && continue
    case "$seen" in *" $i "*) continue ;; esac
    seen="$seen$i "; need+=("$i"); queue+=("$i")
  done < <(incs "$f")
done

# the wrapper: what it includes before the define, and what stands between the define and the undef
d=$(grep -nE '^[[:space:]]*#[[:space:]]*define[[:space:]]+const[[:space:]]*$' "$WRAP" | cut -d: -f1)
u=$(grep -nE '^[[:space:]]*#[[:space:]]*undef[[:space:]]+const[[:space:]]*$' "$WRAP" | cut -d: -f1)
[ "$(echo "$d" | grep -c .)" = 1 ] && [ "$(echo "$u" | grep -c .)" = 1 ] && [ "$d" -lt "$u" ] || {
  echo "FAIL: the wrapper must have exactly one '#define const' followed by one '#undef const'"; exit 1; }
pre=" $(head -n $((d - 1)) "$WRAP" | incs /dev/stdin | tr '\n' ' ') "
between=$(sed -n "$((d + 1)),$((u - 1))p" "$WRAP" | grep -vE '^[[:space:]]*$')
[ "$between" = "#include \"$HDR\"" ] || {
  echo "FAIL: between '#define const' and '#undef const' only #include \"$HDR\" may stand; found:"; echo "$between"; exit 1; }

bad=0
for i in "${need[@]}"; do
  [ "$i" = "\"$HDR\"" ] && continue
  case "$pre" in *" $i "*) ;; *) echo "FAIL: $HDR reaches #include $i; the wrapper does not include it before '#define const'"; bad=1 ;; esac
done
[ $bad = 0 ] || exit 1
echo "ok: $HDR reaches ${#need[@]} header(s) (${need[*]}); each is read as written before '#define const'"
