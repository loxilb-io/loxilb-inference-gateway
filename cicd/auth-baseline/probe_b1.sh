#!/bin/bash
# B-1: does a DENIED (401) keyless request still reach the backend?
#
# The positive control runs first: without proof that a keyed request does move
# the backend counter, a zero delta on the denial test would be meaningless.
source /root/authsep-baseline.env
VIP="http://10.10.10.254:2020/v1/chat/completions"
BODY='{"model":"test-model","messages":[{"role":"user","content":"hello"}],"max_tokens":16}'
cnt() { docker exec l3ep1 sh -c "wc -l < /tmp/backend_reqs.log" 2>/dev/null | tr -d " "; }

echo "===== B-1: denied request vs backend counter ====="
echo "--- POSITIVE CONTROL: valid keyed request (expect 200 and backend +1) ---"
C0=$(cnt)
OUT=$(docker exec l3h1 curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$VIP" \
  -H "Content-Type: application/json" -H "X-Api-Key: $RAW_KEY" -d "$BODY")
sleep 1
C1=$(cnt)
echo "keyed: client_status=$OUT  backend_count $C0 -> $C1  (delta=$((C1 - C0)))"

echo "--- DENIAL TEST: ${N:-30} keyless requests (expect 401 each) ---"
docker exec l3ep1 sh -c ": > /tmp/backend_reqs.log"
n401=0
for i in $(seq 1 "${N:-30}"); do
  S=$(docker exec l3h1 curl -s -m 10 -o /dev/null -w "%{http_code}" -X POST "$VIP" \
    -H "Content-Type: application/json" -d "$BODY")
  [ "$S" = "401" ] && n401=$((n401 + 1))
done
sleep 2
LEAK=$(cnt)
echo "client 401 count=$n401/${N:-30} ; backend received (leaked) = $LEAK"
echo "----- VERDICT INPUT: keyless sent=${N:-30}, client 401=$n401, backend delta=$LEAK -----"
echo "--- leaked request lines ---"
docker exec l3ep1 cat /tmp/backend_reqs.log
