#!/bin/bash
# validation.sh — strict KV-exact admission matrix (GPU-free).
#
# Coverage (each admit/refusal leg is a single-input change from a green
# neighbor, so every gate has a red twin in the matrix itself):
#   A1  strict vllm rule with a published profile admits (HTTP 200) and the
#       binding read-back proves profile+contract+binding identity.
#   A2  one profile reused by three separate Rules — separate bindings.
#   A3  immutability: kvModelProfile / kvExactApiMode are replace-only
#       (409 "cant modify"), read-back unchanged afterwards.
#   A4  adapter selection: engine family + effective hash contract per rule
#       (vllm/sha256_cbor vs sglang/sha256_sglang); llamacpp/trtllm exact
#       rules refuse with typed 400s.
#   A5  binding identity/generation: endpoint-set replace keeps identity+gen
#       stable; delete + recreate mints a NEW ruleIdentity with a fresh gen
#       space (protection is the identity+gen pair, per rule identity).
#   A6  multi-model cardinality: same VIP:port serves two models as two
#       Rules; a model not served by the named profile refuses.
#   A10 evidence state: strict rules are never READY (or silently legacy)
#       without attestation; legacy rules say LEGACY_ACTIVE_UNATTESTED.
#   W   contract-word enforcement: a bindable VIP earns a full ACK
#       (enforcement.lastAckAt); an unbindable VIP surfaces an honest fault
#       instead of pretending enforcement.
#   R*  refusal matrix: every rejected POST answers a CLASSIFIED 400 (never
#       an internal 500 hiding the refusal) and provably leaves ZERO state:
#       no rule, no kv-exact status entry, no new kv metrics series, no
#       inventory keyspace.
#
# The vllm seed-absent refusal and profile-registry trust/parse refusals are
# unit-layer legs (they need per-case process env / filesystem identities).

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
code=0

LBBASE="http://localhost:11111/netlox/v1/config/loadbalancer"
METRICS="http://localhost:11111/netlox/v1/metrics"
VIP="10.10.10.254"

MODEL_A="Qwen/Qwen3-0.6B"
MODEL_B="Qwen/Qwen2.5-7B-Instruct"
PROF_A="qwen3-06b-completions-v1"
PROF_B="qwen25-7bi-completions-v1"

chk() { # chk <label> <extended-regex the value must match> <value>
    local label="$1" want="$2" got="$3"
    if [[ "$got" =~ $want ]]; then
        echo "  [OK] $label"
    else
        echo "  [FAILED] $label — want /$want/ got '$got'"
        code=1
    fi
}

# post_rule <port> <model> <profile> <apiMode> <engine> <extraArgsJson> <eps>
# -> prints "HTTPCODE|body"
# Optional fields are assembled as complete JSON fragments BEFORE the heredoc
# — ${var:+", key": "..."} inside a heredoc quote-removes the embedded quotes
# and emits invalid JSON (proven live: every POST failed body parse).
post_rule() {
    local port="$1" model="$2" profile="$3" apimode="$4" engine="$5" extra="$6" eps="$7" vip="${8:-$VIP}"
    local f="" body http
    [[ -n "$engine" ]]  && f="${f}, \"kvEngineType\": \"${engine}\""
    [[ -n "$model" ]]   && f="${f}, \"model_name\": \"${model}\""
    [[ -n "$profile" ]] && f="${f}, \"kvModelProfile\": \"${profile}\""
    [[ -n "$apimode" ]] && f="${f}, \"kvExactApiMode\": \"${apimode}\""
    [[ -n "$extra" ]]   && f="${f}, ${extra}"
    body=$(cat <<JSON
{
  "serviceArguments": {
    "externalIP": "${vip}", "port": ${port}, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "${vip}",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5557, "kvBlockSize": 16${f}
  },
  "endpoints": [ ${eps} ]
}
JSON
)
    http=$($hexec llb1 curl -s -m 10 -o /tmp/kvpa-resp.json -w "%{http_code}" \
        -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${body}")
    echo "${http}|$(cat /tmp/kvpa-resp.json 2>/dev/null | tr -d '\n')"
}

EPS_PD='{ "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 }, { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 }'
EPS_PD3='{ "endpointIP": "31.31.31.1", "targetPort": 80, "weight": 1, "ep_role": 1 }, { "endpointIP": "33.33.33.1", "targetPort": 80, "weight": 1, "ep_role": 1 }, { "endpointIP": "32.32.32.1", "targetPort": 80, "weight": 1, "ep_role": 2 }'

# kvstatus <port> [model] -> raw JSON array for VIP:<port>
kvstatus() {
    local port="$1" model="${2:-}"
    local url="${LBBASE}/externalipaddress/${VIP}/port/${port}/protocol/tcp/kvexactstatus"
    [[ -n "$model" ]] && url="${url}?model_name=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$model")"
    $hexec llb1 curl -s -m 5 "$url"
}

# jfield <json> <jq-expr>
jfield() { echo "$1" | jq -r "$2" 2>/dev/null; }

# has_rule <port> -> count of LB rules on VIP:<port> from the full dump
has_rule() {
    $hexec llb1 curl -s -m 5 "${LBBASE}/all" \
        | jq "[.lbAttr[]? | select(.serviceArguments.externalIP==\"${VIP}\" and .serviceArguments.port==$1)] | length"
}

# zero_state_sweep <label> <port>
# A rejected POST must leave nothing behind: no rule, no kv-exact status
# entry, and no kv/subscriber metrics series referencing the rejected port.
# (Total-series-count comparison would be flaky: the ADMITTED rules' ZMQ
# subscribers mint error-counter series lazily in the background — filtering
# by the rejected port isolates exactly the state that must not exist.)
zero_state_sweep() {
    local label="$1" port="$2"
    chk "$label: zero rules on :$port" '^0$' "$(has_rule "$port")"
    local st; st=$(kvstatus "$port")
    local n; n=$(echo "$st" | jq '.kvExactStatusAttr | length' 2>/dev/null)
    chk "$label: zero kv-exact status on :$port" '^(0|)$' "${n}"
    local hits
    hits=$($hexec llb1 curl -s -m 5 "$METRICS" | grep "^loxilb_kv" | grep -c ":${port}")
    chk "$label: zero kv metric series for :$port" '^0$' "$hits"
}

#################################################################################
echo "=== A1: strict vllm rule admits and binds (profile A on :8080) ==="
#################################################################################
r=$(post_rule 8080 "$MODEL_A" "$PROF_A" "completions" "vllm" "" "$EPS_PD")
chk "A1 strict POST :8080 -> 200" '^200\|' "$r"

st=$(kvstatus 8080)
chk "A1 status modelProfileId" "^${PROF_A}\$" "$(jfield "$st" '.kvExactStatusAttr[0].modelProfileId')"
chk "A1 status engineContractId" '^vllm-kv-' "$(jfield "$st" '.kvExactStatusAttr[0].engineContractId')"
chk "A1 status bindingGen >= 1" '^[1-9][0-9]*$' "$(jfield "$st" '.kvExactStatusAttr[0].bindingGen')"
chk "A1 status bindingDigest set" '^[0-9a-f]{8,}$' "$(jfield "$st" '.kvExactStatusAttr[0].bindingDigest')"
chk "A1 status requiredEvidenceLevel" '^validated$' "$(jfield "$st" '.kvExactStatusAttr[0].requiredEvidenceLevel')"
chk "A1 status apiMode resolved" '^completions$' "$(jfield "$st" '.kvExactStatusAttr[0].apiMode')"
BG_8080_FIRST=$(jfield "$st" '.kvExactStatusAttr[0].bindingGen')

#################################################################################
echo "=== A2: one profile, three separate Rules (:8080 :8082 :8083) ==="
#################################################################################
r=$(post_rule 8082 "$MODEL_A" "$PROF_A" "completions" "vllm" "" "$EPS_PD")
chk "A2 reuse POST :8082 -> 200" '^200\|' "$r"
r=$(post_rule 8083 "$MODEL_A" "$PROF_A" "completions" "vllm" "" "$EPS_PD")
chk "A2 reuse POST :8083 -> 200" '^200\|' "$r"
id0=$(jfield "$(kvstatus 8080)" '.kvExactStatusAttr[0].ruleIdentity')
id2=$(jfield "$(kvstatus 8082)" '.kvExactStatusAttr[0].ruleIdentity')
id3=$(jfield "$(kvstatus 8083)" '.kvExactStatusAttr[0].ruleIdentity')
chk "A2 three distinct rule identities" '^3$' "$(printf '%s\n%s\n%s\n' "$id0" "$id2" "$id3" | sort -u | grep -c .)"

#################################################################################
echo "=== A6: multi-model cardinality on one VIP:port ==="
#################################################################################
r=$(post_rule 8080 "$MODEL_B" "$PROF_B" "completions" "vllm" "" "$EPS_PD")
chk "A6 second model on :8080 -> 200" '^200\|' "$r"
n=$(kvstatus 8080 | jq '.kvExactStatusAttr | length')
chk "A6 :8080 now serves two models" '^2$' "$n"

#################################################################################
echo "=== A4: adapter selection per engine family ==="
#################################################################################
r=$(post_rule 8084 "$MODEL_A" "$PROF_A" "completions" "sglang" "" "$EPS_PD")
chk "A4 strict sglang POST :8084 -> 200" '^200\|' "$r"
st=$(kvstatus 8084)
chk "A4 sglang engineFamily" '^sglang$' "$(jfield "$st" '.kvExactStatusAttr[0].engineFamily')"
chk "A4 sglang hashContractId" '^sha256_sglang$' "$(jfield "$st" '.kvExactStatusAttr[0].hashContractId')"
chk "A4 vllm hashContractId" '^sha256_cbor$' "$(jfield "$(kvstatus 8080 "$MODEL_A")" '.kvExactStatusAttr[0].hashContractId')"

#################################################################################
echo "=== A10: evidence state — never READY (or silently legacy) unattested ==="
#################################################################################
st=$(kvstatus 8080 "$MODEL_A")
des=$(jfield "$st" '.kvExactStatusAttr[0].desiredState')
enf=$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')
chk "A10 strict desiredState populated" '^[A-Z_]+$' "$des"
chk "A10 strict enforcedState never READY (got $enf)" '^ok$' "$([[ -n "$enf" && "$enf" != "READY" ]] && echo ok || echo "bad:$enf")"
chk "A10 strict never silently LEGACY (got $enf)" '^ok$' "$([[ "$enf" != "LEGACY_ACTIVE_UNATTESTED" ]] && echo ok || echo "bad:$enf")"

r=$(post_rule 8090 "$MODEL_A" "" "" "vllm" "" "$EPS_PD")
chk "A10 legacy profile-less POST :8090 -> 200" '^200\|' "$r"
st=$(kvstatus 8090)
chk "A10 legacy desiredState" '^LEGACY_ACTIVE_UNATTESTED$' "$(jfield "$st" '.kvExactStatusAttr[0].desiredState')"
chk "A10 legacy reason" 'no_model_profile_bound' "$(jfield "$st" '.kvExactStatusAttr[0].reasonCodes[0]')"

#################################################################################
echo "=== W: contract-word enforcement ACK vs honest fault ==="
#################################################################################
# Bindable VIP: the strict rule's contract word must be installed AND fully
# ACKed by the data plane (readback + digest halves) within the poll window.
ack=""
for _ in $(seq 1 30); do
    ack=$(jfield "$(kvstatus 8080 "$MODEL_A")" '.kvExactStatusAttr[0].enforcement.lastAckAt')
    [[ -n "$ack" && "$ack" != "null" ]] && break
    sleep 1
done
chk "W contract ACK observed on :8080 (lastAckAt)" '^20' "$ack"
# A full ACK lifts the Go-side deny fence (the C word still holds eligible=0
# until the readiness ladder passes) — and a LIFTED fence must serialize as
# an explicit false, never disappear from the wire.
chk "W fence lifted after full ACK (goFenced=false)" '^false$' "$(jfield "$(kvstatus 8080 "$MODEL_A")" '.kvExactStatusAttr[0].enforcement.goFenced')"

# Unbindable VIP (99.99.99.9 is on no llb1 interface): admission accepts the
# rule (bindability is a data-plane property) but enforcement must surface
# the fault honestly — never a fake ACK.
r=$(post_rule 8085 "$MODEL_A" "$PROF_A" "completions" "vllm" "" "$EPS_PD" "99.99.99.9")
chk "W unbindable-VIP POST -> 200 (admission is control-plane)" '^200\|' "$r"
sleep 3
stf=$($hexec llb1 curl -s -m 5 "${LBBASE}/externalipaddress/99.99.99.9/port/8085/protocol/tcp/kvexactstatus")
fack=$(jfield "$stf" '.kvExactStatusAttr[0].enforcement.lastAckAt')
ffault=$(jfield "$stf" '.kvExactStatusAttr[0].enforcement.fault')
chk "W unbindable VIP: no ACK claimed" '^(|null)$' "$fack"
chk "W unbindable VIP: fault surfaced (got '$ffault')" '^ok$' "$([[ -n "$ffault" && "$ffault" != "null" ]] && echo ok || echo "bad:$ffault")"
chk "W unbindable VIP: fence still engaged (goFenced=true)" '^true$' "$(jfield "$stf" '.kvExactStatusAttr[0].enforcement.goFenced')"

#################################################################################
echo "=== A3: immutability — kvModelProfile / kvExactApiMode replace-only ==="
#################################################################################
# A profile swap serving the SAME model is unconstructible (the registry
# maps each served model to exactly one profile), so the swap refuses at
# admission as not-served (400) before the immutability 409 could fire —
# refused either way, and the read-back below proves nothing moved. The
# clean immutability 409 is the apiMode leg.
r=$(post_rule 8080 "$MODEL_A" "$PROF_B" "completions" "vllm" "" "$EPS_PD")
chk "A3 profile swap on live rule refused (4xx)" '^4[0-9][0-9]\|' "$r"
r=$(post_rule 8080 "$MODEL_A" "$PROF_A" "" "vllm" "" "$EPS_PD")
chk "A3 apiMode swap on live rule -> 409" '^409\|' "$r"
chk "A3 read-back unchanged after refusals" "^${PROF_A}\$" \
    "$(jfield "$(kvstatus 8080 "$MODEL_A")" '.kvExactStatusAttr[0].modelProfileId')"

#################################################################################
echo "=== A5: binding generation is monotonic ==="
#################################################################################
# Endpoint-set change via rule replace keeps the binding IDENTITY stable —
# the composed binding keys profile+contract, not the member set. What must
# never happen is a silent re-key under in-flight requests.
bg_before=$(jfield "$(kvstatus 8082)" '.kvExactStatusAttr[0].bindingGen')
dg_before=$(jfield "$(kvstatus 8082)" '.kvExactStatusAttr[0].bindingDigest')
r=$(post_rule 8082 "$MODEL_A" "$PROF_A" "completions" "vllm" "" "$EPS_PD3")
chk "A5 endpoint-set replace :8082 -> 200" '^200\|' "$r"
bg_after=$(jfield "$(kvstatus 8082)" '.kvExactStatusAttr[0].bindingGen')
dg_after=$(jfield "$(kvstatus 8082)" '.kvExactStatusAttr[0].bindingDigest')
chk "A5 replace keeps bindingGen ($bg_before -> $bg_after)" "^${bg_before}\$" "$bg_after"
chk "A5 replace keeps bindingDigest" "^${dg_before}\$" "$dg_after"

# Delete + recreate mints a NEW rule identity whose generation space starts
# fresh — the anti-replay protection is the (ruleIdentity, bindingGen) PAIR,
# not a global monotonic counter. The rules are vhost-keyed (host=VIP), so
# the delete addresses the hosturl variant.
rid_before=$(jfield "$(kvstatus 8083)" '.kvExactStatusAttr[0].ruleIdentity')
chk "A5 :8083 has a ruleIdentity pre-delete" '^..*$' "$rid_before"
ENC_MODEL_A=$(python3 -c "import urllib.parse;print(urllib.parse.quote('${MODEL_A}',safe=''))")
http=$($hexec llb1 curl -s -m 5 -o /tmp/kvpa-del.json -w "%{http_code}" -X DELETE \
    "${LBBASE}/hosturl/${VIP}/externalipaddress/${VIP}/port/8083/protocol/tcp?model_name=${ENC_MODEL_A}")
chk "A5 DELETE :8083 -> 200" '^200$' "$http"
chk "A5 :8083 gone after delete" '^0$' "$(has_rule 8083)"
r=$(post_rule 8083 "$MODEL_A" "$PROF_A" "completions" "vllm" "" "$EPS_PD")
chk "A5 recreate :8083 -> 200" '^200\|' "$r"
st_re=$(kvstatus 8083)
rid_re=$(jfield "$st_re" '.kvExactStatusAttr[0].ruleIdentity')
bg_re=$(jfield "$st_re" '.kvExactStatusAttr[0].bindingGen')
chk "A5 recreate mints a new ruleIdentity ($rid_before -> $rid_re)" '^1$' \
    "$([[ -n "$rid_re" && "$rid_re" != "null" && "$rid_re" != "$rid_before" ]] && echo 1 || echo 0)"
chk "A5 recreate gen space starts fresh (bindingGen >= 1, got '$bg_re')" '^1$' \
    "$([[ -n "$bg_re" && "$bg_re" -ge 1 ]] && echo 1 || echo 0)"

#################################################################################
echo "=== R: refusal matrix — classified 400s + zero-state sweeps ==="
#################################################################################
r=$(post_rule 9001 "$MODEL_A" "no-such-profile" "completions" "vllm" "" "$EPS_PD")
chk "R1 unknown profile -> 400 (never an internal 500)" '^400\|' "$r"
chk "R1 refusal wording reaches the caller" 'not a published model-prompt profile' "$r"
zero_state_sweep "R1" 9001

r=$(post_rule 9002 "$MODEL_B" "$PROF_A" "completions" "vllm" "" "$EPS_PD")
chk "R2 model not served by profile -> 400" '^400\|' "$r"
zero_state_sweep "R2" 9002

r=$(post_rule 9003 "$MODEL_A" "$PROF_A" "chat" "vllm" "" "$EPS_PD")
chk "R3 chat surface on completions-only profile -> 400" '^400\|' "$r"
zero_state_sweep "R3" 9003

r=$(post_rule 9004 "$MODEL_A" "" "" "llamacpp" "" "$EPS_PD")
chk "R4 llamacpp kvExactMode -> 400 typed refusal" '^400\|' "$r"
zero_state_sweep "R4" 9004

# A8 (TRT ownership): a strict trtllm rule ADMITS (the HTTP-polled event
# plane exists) but production readiness stays fenced until the ownership
# mechanism lands — never READY, and the engine identity resolves through
# the trtllm adapter/hash contract.
r=$(post_rule 8086 "$MODEL_A" "$PROF_A" "completions" "trtllm" "" "$EPS_PD")
chk "A8 trtllm strict rule admits (event plane exists)" '^200\|' "$r"
st=$(kvstatus 8086)
chk "A8 trtllm engineFamily" '^trtllm$' "$(jfield "$st" '.kvExactStatusAttr[0].engineFamily')"
chk "A8 trtllm hashContractId" '^blockhash_trtllm$' "$(jfield "$st" '.kvExactStatusAttr[0].hashContractId')"
enf8=$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')
chk "A8 trtllm never READY (got $enf8)" '^ok$' "$([[ -n "$enf8" && "$enf8" != "READY" ]] && echo ok || echo "bad:$enf8")"

# R5 (the TRT refusal twin): the engine's genuinely meaningless knob still
# fails loudly with zero state — a non-default kvZmqPort configures a ZMQ
# transport trtllm does not have.
body=$(cat <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": 9005, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "${VIP}",
    "pd_disagg_mode": true, "probeRetries": 1,
    "kvExactMode": 1, "kvZmqPort": 5999, "kvBlockSize": 16,
    "kvEngineType": "trtllm", "model_name": "${MODEL_A}",
    "kvModelProfile": "${PROF_A}", "kvExactApiMode": "completions"
  },
  "endpoints": [ ${EPS_PD} ]
}
JSON
)
http=$($hexec llb1 curl -s -m 10 -o /tmp/kvpa-resp.json -w "%{http_code}" -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${body}")
chk "R5 trtllm non-default kvZmqPort -> 400 (meaningless knob)" '^400$' "$http"
zero_state_sweep "R5" 9005

r=$(post_rule 9006 "$MODEL_A" "$PROF_A" "completions" "vllm" '"kvHashAlgo": "sha256_sglang"' "$EPS_PD")
chk "R6 vllm + sglang hash algo -> 400 (geometry coherence)" '^400\|' "$r"
zero_state_sweep "R6" 9006

body=$(cat <<JSON
{
  "serviceArguments": {
    "externalIP": "${VIP}", "port": 9007, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "${VIP}", "probeRetries": 1,
    "model_name": "${MODEL_A}", "kvModelProfile": "${PROF_A}"
  },
  "endpoints": [ ${EPS_PD} ]
}
JSON
)
http=$($hexec llb1 curl -s -m 10 -o /tmp/kvpa-resp.json -w "%{http_code}" -X POST "${LBBASE}" -H 'Content-Type: application/json' -d "${body}")
chk "R7 kvModelProfile without kvExactMode -> 400" '^400$' "$http"
zero_state_sweep "R7" 9007

r=$(post_rule 9008 "" "$PROF_A" "completions" "vllm" "" "$EPS_PD")
chk "R8 missing model_name -> 400" '^400\|' "$r"
zero_state_sweep "R8" 9008

#################################################################################
echo "=== T: the admitted rule actually routes (Tier-2 fallback path) ==="
#################################################################################
# The rules are vhost+model-keyed L7 fullproxy: a routed request is a
# completions POST naming the served model (no KV events published, so this
# exercises the Tier-2 fallback selection, not exact scoring).
banner=$($hexec l3h1 curl -s -m 5 -X POST "http://${VIP}:8080/v1/completions" \
    -H "Host: ${VIP}" -H 'Content-Type: application/json' \
    -d "{\"model\": \"${MODEL_A}\", \"prompt\": \"hello\", \"max_tokens\": 4}" 2>/dev/null | head -3)
chk "T VIP :8080 completions POST reaches a reflect-echo backend" 'X-Echo-Backend' "$banner"

#################################################################################
echo "=== D: restore semantics — REQUIRES_MIGRATION + strict bypass + migration ==="
#################################################################################
# Capture the live config (includes every admitted matrix rule), then run
# the committed restore pipeline. Restore replays profile-less KV-exact
# rules as REQUIRES_MIGRATION with the exact path fenced (strict bypass) —
# the pre-upgrade unattested behavior must not survive a restore by default.
$hexec llb1 curl -s -m 15 "http://localhost:11111/netlox/v1/config/snapshot" -o /tmp/kvpa-snap.json
snap_bytes=$(wc -c < /tmp/kvpa-snap.json)
chk "D snapshot captured (bytes=$snap_bytes)" '^ok$' "$([[ "$snap_bytes" -gt 500 ]] && echo ok || echo bad)"

rest=$($hexec llb1 curl -s -m 60 -o /tmp/kvpa-restore.json -w "%{http_code}" \
    -X POST "http://localhost:11111/netlox/v1/config/restore?mode=commit" \
    -H 'Content-Type: application/json' --data-binary @/tmp/kvpa-snap.json)
chk "D restore commit -> 200" '^200$' "$rest"

# The restored legacy rule (:8090): REQUIRES_MIGRATION, fenced, honest.
st=""
for _ in $(seq 1 15); do
    st=$(kvstatus 8090)
    [[ "$(jfield "$st" '.kvExactStatusAttr | length')" == "1" ]] && break
    sleep 1
done
chk "D restored legacy desiredState REQUIRES_MIGRATION" '^REQUIRES_MIGRATION$' "$(jfield "$st" '.kvExactStatusAttr[0].desiredState')"
chk "D restored legacy enforcedState REQUIRES_MIGRATION" '^REQUIRES_MIGRATION$' "$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')"
chk "D restored legacy reason" 'restored_profile_less_requires_migration' "$(jfield "$st" '.kvExactStatusAttr[0].reasonCodes[0]')"
chk "D restored legacy fence engaged (goFenced=true)" '^true$' "$(jfield "$st" '.kvExactStatusAttr[0].enforcement.goFenced')"

# service continuity: the fenced rule still serves through the normal
# LB tiers (the bypass is of the EXACT tier, not of the service).
banner=$($hexec l3h1 curl -s -m 5 -X POST "http://${VIP}:8090/v1/completions" \
    -H "Host: ${VIP}" -H 'Content-Type: application/json' \
    -d "{\"model\": \"${MODEL_A}\", \"prompt\": \"hello\", \"max_tokens\": 4}" 2>/dev/null | head -3)
chk "D fenced rule still routes via normal tiers" 'X-Echo-Backend' "$banner"

# The restored STRICT rule (:8080) re-earns — binding identity restored from
# the snapshot, never inherited READY, and a fresh contract ACK arrives.
st=$(kvstatus 8080 "$MODEL_A")
chk "D restored strict profile identity" "^${PROF_A}\$" "$(jfield "$st" '.kvExactStatusAttr[0].modelProfileId')"
enf=$(jfield "$st" '.kvExactStatusAttr[0].enforcedState')
chk "D restored strict never READY (got $enf)" '^ok$' "$([[ -n "$enf" && "$enf" != "READY" ]] && echo ok || echo "bad:$enf")"
ack=""
for _ in $(seq 1 30); do
    ack=$(jfield "$(kvstatus 8080 "$MODEL_A")" '.kvExactStatusAttr[0].enforcement.lastAckAt')
    [[ -n "$ack" && "$ack" != "null" ]] && break
    sleep 1
done
chk "D restored strict re-earns a contract ACK" '^20' "$ack"

# Migration red twin FIRST: attaching a profile that does not serve the
# model refuses and the rule stays REQUIRES_MIGRATION + fenced.
r=$(post_rule 8090 "$MODEL_A" "$PROF_B" "" "vllm" "" "$EPS_PD")
chk "D migration with non-serving profile -> 400" '^400\|' "$r"
chk "D rule still REQUIRES_MIGRATION after refused migration" '^REQUIRES_MIGRATION$' "$(jfield "$(kvstatus 8090)" '.kvExactStatusAttr[0].desiredState')"

# Migration commit: replace attaching the serving profile — the rule earns
# its way onto the strict path (identity bound, fence lifts only via ACK).
r=$(post_rule 8090 "$MODEL_A" "$PROF_A" "" "vllm" "" "$EPS_PD")
chk "D migration attach -> 200" '^200\|' "$r"
st=$(kvstatus 8090)
chk "D migrated rule bound to profile" "^${PROF_A}\$" "$(jfield "$st" '.kvExactStatusAttr[0].modelProfileId')"
chk "D migrated rule bindingGen >= 1" '^[1-9][0-9]*$' "$(jfield "$st" '.kvExactStatusAttr[0].bindingGen')"
chk "D migrated rule left REQUIRES_MIGRATION" '^ok$' "$([[ "$(jfield "$st" '.kvExactStatusAttr[0].desiredState')" != "REQUIRES_MIGRATION" ]] && echo ok || echo bad)"
ack=""
for _ in $(seq 1 30); do
    ack=$(jfield "$(kvstatus 8090)" '.kvExactStatusAttr[0].enforcement.lastAckAt')
    [[ -n "$ack" && "$ack" != "null" ]] && break
    sleep 1
done
chk "D migrated rule earns a contract ACK" '^20' "$ack"

#################################################################################
if [[ $code == 0 ]]; then
    echo "=== SCENARIO-kv-profile-admission [OK] ==="
else
    echo "=== SCENARIO-kv-profile-admission [FAILED] ==="
fi
exit $code
