#!/bin/bash
# k3d-incluster-inference-svc — assertions.
# What Service annotations promised, proven on the wire (REST), in the kernel
# (bound socket), and on traffic (which pod served, via X-Served-By).
# Sentinel: SCENARIO-k3d-incluster-inference-svc [OK] / [FAILED].
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/k8s-inference/k3d_common.sh"
igw_env_load "$HERE" || exit 1

SVC=vllm-qwen3-svc
PORT=8000
MODEL="Qwen/Qwen3-0.6B"
BODY() { printf '{"model":"%s","messages":[{"role":"user","content":"%s"}]}' "$1" "$2"; }
rule_json() { rules_all | jq -c --arg n "llm_$SVC" '.lbAttr[]? | select(.serviceArguments.name|startswith($n))' | head -1; }

echo "=== 1. the Service was given the VIP ==="
if poll 90 bash -c "kubectl -n llm get svc $SVC -o json | jq -e '.status.loadBalancer.ingress[0]' >/dev/null"; then
  got=$(kubectl -n llm get svc "$SVC" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}{.status.loadBalancer.ingress[0].ip}')
  check "external address is llb-$NODE_IP" "$got" "llb-$NODE_IP"
else
  bad "external address assigned" "still pending after 90s"
fi

echo "=== 2. the rule carries the inference key and settings ==="
have_rule() { rules_all | jq -e --arg n "llm_$SVC" '.lbAttr[]? | select(.serviceArguments.name|startswith($n))' >/dev/null; }
if ! poll 60 have_rule; then
  bad "rule for $SVC present" "not found after 60s"
else
  ok "rule for $SVC present"
  RULE=$(rule_json)
  # 8 = CHWBL, 4 = fullproxy: both exist only on the inference gateway, so
  # their presence proves the flavor was detected and nothing was stripped.
  check "sel is chwbl(8)"        "$(jq -r '.serviceArguments.sel'  <<<"$RULE")" "8"
  check "mode is fullproxy(4)"   "$(jq -r '.serviceArguments.mode' <<<"$RULE")" "4"
  check "model_name"             "$(jq -r '.serviceArguments.model_name' <<<"$RULE")" "$MODEL"
  check "chwbl_prefix_hash_level" "$(jq -r '.serviceArguments.chwbl_prefix_hash_level' <<<"$RULE")" "2"
  check "sse_mode"               "$(jq -r '.serviceArguments.sse_mode' <<<"$RULE")" "true"
  # The proxy looks a pool up by host + path prefix + match mode; without them
  # the rule reads back fine and answers model_unavailable to everything.
  check "routing key host"       "$(jq -r '.serviceArguments.host' <<<"$RULE")" "$NODE_IP"
  check "routing key path"       "$(jq -r '.serviceArguments.path_prefix' <<<"$RULE")" "/"
  check "routing key match mode" "$(jq -r '.serviceArguments.path_match_mode' <<<"$RULE")" "prefix"

  echo "=== 3. endpoints are the pods (usepodnetwork) ==="
  EPS=$(jq -r '[.endpoints[]?.endpointIP] | sort | join(",")' <<<"$RULE")
  PODS=$(kubectl -n llm get pods -l app=vllm-qwen3 -o json | jq -r '[.items[].status.podIP] | sort | join(",")')
  check "rule endpoints == pod IPs" "$EPS" "$PODS"
fi

echo "=== 4. fullproxy bound a socket on the VIP ==="
if node_listening "$NODE_IP" "$PORT"; then ok "socket bound on $NODE_IP:$PORT"
else bad "socket bound on $NODE_IP:$PORT"; fi

echo "=== 5. a request naming the model is served by a pod ==="
POD_NAMES=$(kubectl -n llm get pods -l app=vllm-qwen3 -o jsonpath='{.items[*].metadata.name}')
RESP=$(client_curl -s -i --max-time 8 -X POST "http://$NODE_IP:$PORT/v1/chat/completions" \
         -H 'Content-Type: application/json' -d "$(BODY "$MODEL" ping)" | tr -d '\r')
code=$(awk 'NR==1{print $2}' <<<"$RESP")
served=$(grep -i '^x-served-by:' <<<"$RESP" | awk '{print $2}' | head -1)
check "HTTP 200 through the VIP" "$code" "200"
if grep -qw "${served:-__none__}" <<<"$POD_NAMES"; then ok "served by pod $served"
else bad "served by one of the pods" "X-Served-By='$served', pods='$POD_NAMES'"; fi

echo "=== 6. a model the rule does not carry is refused ==="
RESP=$(client_curl -s --max-time 8 -w '\n%{http_code}' -X POST "http://$NODE_IP:$PORT/v1/chat/completions" \
         -H 'Content-Type: application/json' -d "$(BODY not-this-one ping)")
check "unknown model returns 503" "$(tail -1 <<<"$RESP")" "503"
if grep -q model_unavailable <<<"$RESP"; then ok "body says model_unavailable"
else bad "body says model_unavailable" "$(head -1 <<<"$RESP")"; fi

echo "=== 7. CHWBL pins one prompt to one pod ==="
servers=""
for i in 1 2 3 4 5; do
  s=$(client_curl -s -i --max-time 8 -X POST "http://$NODE_IP:$PORT/v1/chat/completions" \
        -H 'Content-Type: application/json' -d "$(BODY "$MODEL" "same prefix, same pod")" \
      | tr -d '\r' | grep -i '^x-served-by:' | awk '{print $2}' | head -1)
  servers="$servers${s:+$s\n}"
done
distinct=$(printf "$servers" | sort -u | grep -c .)
first=$(printf "$servers" | sort -u | head -1)
if [ "$distinct" = 1 ] && grep -qw "$first" <<<"$POD_NAMES"; then
  ok "5/5 identical prompts served by $first"
else
  bad "identical prompts pin to one pod" "servers: $(printf "$servers" | sort | uniq -c | tr '\n' ' ')"
fi

echo "=== 8. SSE streaming survives the proxy ==="
SSE=$(client_curl -s -N --max-time 15 -X POST "http://$NODE_IP:$PORT/v1/chat/completions" \
        -H 'Content-Type: application/json' -H 'Accept: text/event-stream' \
        -d "$(printf '{"model":"%s","messages":[{"role":"user","content":"count"}],"stream":true}' "$MODEL")")
if grep -q '^data:' <<<"$SSE" && grep -q 'data: \[DONE\]' <<<"$SSE"; then
  ok "data: events and [DONE] received"
else
  bad "SSE stream" "$(head -c 120 <<<"$SSE")"
fi

echo "=== 9. kube-loxilb's verdicts land as events ==="
EV_OK=$(kubectl -n llm get events --field-selector involvedObject.name=$SVC -o json |
        jq -r '[.items[] | select(.reason=="InvalidInferenceConfig" or .reason=="InferenceGatewayRequired")] | length')
check "no warnings on the valid Service" "$EV_OK" "0"
if poll 30 bash -c "kubectl -n llm get events --field-selector involvedObject.name=vllm-qwen3-invalid -o json | jq -e '.items[] | select(.reason==\"InvalidInferenceConfig\")' >/dev/null"; then
  ok "InvalidInferenceConfig on the chwbl+onearm Service"
else
  bad "InvalidInferenceConfig on the chwbl+onearm Service" "no such event after 30s"
fi
INV_IP=$(kubectl -n llm get svc vllm-qwen3-invalid -o jsonpath='{.status.loadBalancer.ingress}')
check "refused Service got no address" "$INV_IP" ""
N_INVALID=$(rules_all | jq '[.lbAttr[]? | select(.serviceArguments.port==8001)] | length')
check "and no rule on its port" "$N_INVALID" "0"

echo "=== 10. reconcile: scale updates endpoints, delete removes the rule ==="
kubectl -n llm scale deploy/vllm-qwen3 --replicas=3 >/dev/null
kubectl -n llm rollout status deploy/vllm-qwen3 --timeout=120s >/dev/null
eps_count() { rules_all | jq --arg n "llm_$SVC" '[.lbAttr[]? | select(.serviceArguments.name|startswith($n)) | .endpoints[]] | length'; }
eps_is_3() { [ "$(eps_count)" = "3" ]; }
if poll 60 eps_is_3; then
  ok "scale 2->3 reflected in the rule endpoints"
else
  bad "scale 2->3 reflected" "endpoints: $(rule_json | jq -c '[.endpoints[]?.endpointIP]')"
fi
kubectl -n llm delete svc "$SVC" --wait=true >/dev/null
rule_gone() { [ "$(rules_all | jq --arg n "llm_$SVC" '[.lbAttr[]? | select(.serviceArguments.name|startswith($n))] | length')" = "0" ]; }
if poll 60 rule_gone; then
  ok "deleting the Service removed the rule"
else
  bad "deleting the Service removed the rule" "$(rule_json | jq -c '.serviceArguments | {name,port}')"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "SCENARIO-k3d-incluster-inference-svc [OK]"; exit 0
fi
echo "SCENARIO-k3d-incluster-inference-svc [FAILED] ($fails check(s))"; exit 1
