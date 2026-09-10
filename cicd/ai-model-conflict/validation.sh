#!/bin/bash
# ai-model-conflict validation.
#
# Contract under test (enforcing VIPs): ONE effective-model resolution,
# body-first, consumed by BOTH authorization and routing; body/header
# disagreement is a 400 model_conflict, never a silent steer.
#
# Born red: against the pre-fix binary T2 shows a llama-only key landing on
# the mistral pool (auth checked the body model, routing obeyed X-Model),
# and T3 shows routing acting on a header model auth never examined. Those
# failures are the proof this suite can detect the defect; do not soften an
# assert to make a run pass.
#
# T6 pins the OTHER half of the contract: non-enforcing VIPs keep the
# legacy header-first routing unchanged (green before AND after the fix).
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-ai-model-conflict

PASS=0
FAIL=0
VIP=10.10.10.254

if [ ! -f .state ]; then
  echo "  FATAL: .state missing — run ./config.sh first"
  echo "SCENARIO-ai-model-conflict [FAILED]"
  exit 1
fi
# shellcheck disable=SC1091
source .state

chk_has() { # chk_has <name> <needle> <haystack>
  if [ "${3#*$2}" != "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — did not find '$2' in: $(echo "$3" | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}
chk_not_has() { # chk_not_has <name> <forbidden> <haystack>
  if [ "${3#*$2}" = "$3" ]; then
    echo "  [PASS] $1"; PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 — found forbidden '$2' in: $(echo "$3" | head -c 300)"; FAIL=$((FAIL + 1))
  fi
}

body_llama='{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}'

req() { # req <port> <extra curl args...> — POST body_llama with the key
  local port=$1; shift
  $hexec l3h1 curl -s -i --max-time 8 -X POST \
    -H "Content-Type: application/json" \
    -H "X-Api-Key: $RAW_KEY" \
    "$@" \
    -d "$body_llama" \
    "http://$VIP:$port/v1/chat/completions"
}

echo ""
echo "T1: control — body model only, authorized → llama pool serves"
r=$(req 2030)
chk_has     "T1 llama pool answers"      "server-llama" "$r"
chk_not_has "T1 no conflict on agreement" "model_conflict" "$r"

echo ""
echo "T2: body llama-70b + X-Model mistral-7b (authorized model in body ONLY)"
echo "    → 400 model_conflict; the llama-only key must never reach mistral"
r=$(req 2030 -H "X-Model: mistral-7b")
chk_has     "T2 400 status"          "400" "$(echo "$r" | head -1)"
chk_has     "T2 model_conflict body" "model_conflict" "$r"
chk_not_has "T2 mistral pool NOT reached (authz bypass)" "server-mistral" "$r"

echo ""
echo "T3: body llama-70b + X-Model ghost-model (no such pool)"
echo "    → 400 model_conflict (routing must not act on a model auth never checked)"
r=$(req 2030 -H "X-Model: ghost-model")
chk_has     "T3 400 status"          "400" "$(echo "$r" | head -1)"
chk_has     "T3 model_conflict body" "model_conflict" "$r"
chk_not_has "T3 no model_unavailable steer" "model_unavailable" "$r"

echo ""
echo "T4: body llama-70b + X-Model llama-70b (both present, equal) → no false conflict"
r=$(req 2030 -H "X-Model: llama-70b")
chk_has     "T4 llama pool answers"  "server-llama" "$r"
chk_not_has "T4 agreement is not a conflict" "model_conflict" "$r"

echo ""
echo "T5: no key on the enforcing VIP → 401 (conflict check never masks auth)"
r=$($hexec l3h1 curl -s -i --max-time 8 -X POST \
  -H "Content-Type: application/json" \
  -H "X-Model: mistral-7b" \
  -d "$body_llama" \
  "http://$VIP:2030/v1/chat/completions")
chk_has "T5 401 status" "401" "$(echo "$r" | head -1)"

echo ""
echo "T6: non-enforcing VIP keeps LEGACY behavior — header steers, no 400"
echo "    (green before and after; enforcing-only is the deliberate scope)"
r=$($hexec l3h1 curl -s -i --max-time 8 -X POST \
  -H "Content-Type: application/json" \
  -H "X-Model: mistral-7b" \
  -d "$body_llama" \
  "http://$VIP:2031/v1/chat/completions")
chk_has     "T6 mistral pool answers (legacy header-first)" "server-mistral" "$r"
chk_not_has "T6 no conflict on none-mode"                   "model_conflict" "$r"

echo ""
if [ $FAIL -ne 0 ]; then
  echo "SCENARIO-ai-model-conflict [FAILED] ($PASS pass, $FAIL fail)"
  exit 1
fi
echo "SCENARIO-ai-model-conflict [OK] ($PASS pass)"
exit 0
