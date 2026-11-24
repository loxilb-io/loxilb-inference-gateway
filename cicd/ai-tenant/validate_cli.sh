#!/bin/bash
# validate_cli.sh — CLI-driven validation for the tenant QoS band queue
# (cicd/ai-tenant), with loxicmd-inference-gateway as the subject-under-test
# and the REST API as the oracle: every mutation is issued through `loxicmd`
# inside the gateway container (tqllb), then read back through the REST API
# from tqh1 and cross-checked with `loxicmd get lb -o json` / `--bands`.
#
# This scenario runs the gateway WITHOUT --userservice (as ai-model-routing):
# the CLI needs no token and the REST oracle sends no Authorization header.
#
# The gateway advertises api_key_auth, epp and jwt_auth_profile in /version.
# Every band, objective and netidentity command therefore prints one line on
# stderr — "warning: gateway does not advertise <feature>; sending anyway, the
# gateway's answer decides" — and sends the request; the exit code is the
# gateway's answer. Each such call asserts the line is on stderr only, once,
# and that it moved no exit code.
#
# Checks:
#   C0 get lbversion: product and the features line against GET /version.
#   C1 Equivalence: the rules, the objective, the tenant rate limits and the
#      API keys config.sh creates with curl are created again through loxicmd;
#      the REST read-back after the CLI apply must equal the read-back after
#      the curl apply, field by field (fc_effective, counters and timestamps
#      left out). A difference is a CLI bug: it is reported, never adapted to.
#   C2 P10 via CLI: all nine band knobs on the knob port, read back via REST,
#      `get lb -o json`, `get lb -o wide` and `--bands`; a replace that omits
#      them keeps them; the reset values clear them and read back absent.
#   C3 S8 via CLI: the twelve refused combinations, by flags; every one
#      refused with the rule unchanged. The nine the gateway refuses relay
#      its 400 body verbatim under one exit code (6, CONTRACT_MISMATCH); the
#      three loxicmd refuses itself (a value out of its range, a malformed
#      triple: docs/COMMANDS.md keeps each value's own range on the CLI side)
#      exit 2 (INVALID_ARGUMENT) naming the flag, and send nothing.
#   C4 R1 under load: waiters in all three bands on the scheduling pool;
#      `get lb --bands` shows the populated table, equal to fc_effective from
#      REST; the table is kept in the evidence directory.
#   C5 netidentity: a CIDR binding for tqh1's network, get, delete, a second
#      delete answered 404; the REST list as the oracle at each step.
#
# Runs AFTER the scheduling cases of validation-sched.sh; folded into its exit
# code. Gated by bands_cli_preflight (CLI_TESTS=auto|required|skip) so an
# image predating loxicmd #83 skips cleanly instead of hard-failing. A failed
# check is recorded and the run continues, so one run reports every check;
# the exit code is 1 when any check failed.
#
# Exit codes: 0 every check passed; 1 a check failed (or CLI_TESTS=required
# and the preflight refused the CLI); 3 the preflight skipped the half
# (CLI_TESTS=auto on a loxicmd without the surface, or CLI_TESTS=skip): the
# caller reports SKIPPED with the preflight's reason, never PASS.
#
# Evidence: $CLI_OUT (default ./artifacts-cli): the commands issued, every
# read-back compared, the --bands table under load.

source ../common.sh
source ./lib/classload.sh

GW=tqllb
CLI_OUT=${CLI_OUT:-$(pwd)/artifacts-cli}
rm -rf "$CLI_OUT"; mkdir -p "$CLI_OUT"
T=$CLI_OUT/tmp; mkdir -p "$T"

echo ""
echo "========================================="
echo " CLI Validation (tenant QoS: priority bands)"
echo "========================================="

# ── Preflight: does the packaged loxicmd carry the band flags? ───────────────
if ! bands_cli_preflight $GW; then
  exit 3
fi

code=0
ok()  { echo "  $1 [OK]"; }
bad() { echo "  $1 [FAIL] — $2"; code=1; }
check_eq() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then ok "$label ($got)"; else bad "$label" "expected '$want', got '$got'"; fi
}
check_has() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == *"$want"* ]]; then ok "$label"; else bad "$label" "expected '$want' in: $(echo "$got" | tr '\n' ' ' | cut -c1-300)"; fi
}
# check_same <label> <a> <b>: two documents (JSON or text) equal; the
# difference is printed when they are not.
check_same() {
  local label="$1" a="$2" b="$3"
  if [[ "$a" == "$b" ]]; then ok "$label"; else
    bad "$label" "the two read-backs differ:"
    diff <(echo "$a" | jq . 2>/dev/null || echo "$a") <(echo "$b" | jq . 2>/dev/null || echo "$b") | sed 's/^/      /'
  fi
}

# cli <args...>: loxicmd inside the gateway container. stdout and stderr are
# kept apart ($T/stdout, $T/stderr; CLI_STDOUT, CLI_STDERR) and the exit code
# is CLI_RC (also returned). Every command is logged in commands.log.
cli() {
  $dexec $GW loxicmd "$@" > "$T/stdout" 2> "$T/stderr"
  CLI_RC=$?
  CLI_STDOUT=$(cat "$T/stdout"); CLI_STDERR=$(cat "$T/stderr")
  echo "loxicmd $* -> exit $CLI_RC" >> "$CLI_OUT/commands.log"
  return $CLI_RC
}
# warn_check <label> <feature|none>: the advisory line for a feature the
# gateway does not advertise is on stderr, exactly once, never on stdout;
# a command that uses no such feature prints none.
warn_check() {
  local label=$1 feat=$2 ne no
  ne=$(grep -c '^warning: gateway does not advertise' "$T/stderr")
  no=$(grep -c 'warning: gateway does not advertise' "$T/stdout")
  if [[ "$feat" == none ]]; then
    check_eq "$label: no advisory line (stderr/stdout)" "0/0" "$ne/$no"
  else
    check_eq "$label: one advisory line, on stderr only (stderr/stdout)" "1/0" "$ne/$no"
    check_has "$label: it names $feat and defers to the gateway" \
      "warning: gateway does not advertise $feat; sending anyway, the gateway's answer decides" "$CLI_STDERR"
  fi
}

# ── REST oracle ─────────────────────────────────────────────────────────────
rest() { $hexec tqh1 curl -s -m 8 "$API$1"; }
# rest_rule <port>: the rule's lbAttr entry, one line; empty when absent.
rest_rule() { rest /config/loadbalancer/all | jq -c ".lbAttr[] | select(.serviceArguments.port==$1)"; }
# rule_view: what C1 compares — the serviceArguments without the runtime
# view (fc_effective) and the id the gateway mints for each rule instance,
# and the endpoints by address, port and weight.
rule_view() { jq -S -c '{sa: (.serviceArguments | del(.fc_effective, .id)), eps: [(.endpoints // [])[] | {endpointIP, targetPort, weight}] | sort_by(.targetPort)}'; }
# knobs9 <serviceArguments>: the nine band knobs as read back, "-" when absent
knobs9() { jq -r '[.fc_wake_policy, .fc_band_weights, .fc_band_min_share_pct, .fc_critical_reserve_pct, .fc_band_wait_ms, .fc_band_queue_pct, .fc_shed_queue, .fc_tenant_wake, .fc_llmd_headers] | map(if . == null then "-" else tostring end) | join(" ")'; }
# band_view <serviceArguments>: the band part of fc_effective. A false, zero
# or empty top-level value is dropped on both sides: the CLI re-marshals the
# document through its own struct with omitempty, which is a serialization
# choice, not a reading of the gateway.
band_view() { jq -S -c '.fc_effective | {wake_policy, wake_policy_effective, weights_in_use, shed_queue, shed_queue_effective, tenant_wake, tenant_wake_effective, band_fallback_reason, llmd_headers, bands_configured, bands, source: ((.source // {}) | {wake_policy, band_weights, band_min_share_pct, critical_reserve_pct, band_wait_ms, band_queue_pct} | with_entries(select(.value != null)))} | with_entries(select(.value != null and .value != false and .value != 0 and .value != ""))'; }
# norm: a document with its empty values (null, "", [], false, 0) dropped at
# every level, for a list the CLI re-marshals through its own omitempty
# struct against the gateway's own serialization of the same list.
norm() { jq -S -c 'walk(if type == "object" then with_entries(select(.value != null and .value != "" and .value != [] and .value != false and .value != 0)) else . end)'; }
# rest_band_rows <port>: the three band rows as `get lb --bands` must print
# them, built from fc_effective (band inflight queued wait_ms queue_pct
# min_share_pct floor_units weight weight_pct source)
rest_band_rows() {
  tq_rule_get $1 | jq -r '.fc_effective as $e
    | ([$e.source.band_weights, $e.source.band_min_share_pct, $e.source.band_wait_ms, $e.source.band_queue_pct] | map(if . == null or . == "" then "-" else . end) | join("/")) as $src
    | ("critical", "standard", "sheddable") as $b | ($e.bands[$b] // {}) as $x
    | [$b, ($x.inflight // 0), ($x.queued // 0), ($x.wait_ms // 0), ($x.queue_pct // 0), ($x.min_share_pct // 0), ($x.floor_units // 0), ($x.weight // 0), ($x.weight_pct // 0), $src] | map(tostring) | join(" ")'
}
# bands_section <port>: the part of the last `get lb --bands` output that
# belongs to the rule on <port>: its heading line and its table. A heading is
# "<name> <ip>:<port>/<proto>  ..." (two spaces after the key).
bands_section() {
  awk -v key=" $VIP:$1/tcp  " '
    index($0, key) { p = 1; print; next }
    p && $0 ~ /^[^ ]+ [0-9.]+:[0-9]+\/[a-z]+  / { p = 0 }
    p { print }' "$T/stdout"
}
# cli_band_rows <port>: the three rows of that table, cells separated by one
# space (the table borders removed)
cli_band_rows() {
  bands_section $1 | grep -E '^\|? *(critical|standard|sheddable) ' | sed 's/|/ /g' | tr -s ' ' | sed 's/^ //; s/ $//'
}

# ── The scenario's rules, as loxicmd must spell them ────────────────────────
# Target ports: a range in --tcp (8080-8081) gives the one endpoint address
# both target ports, as the scenario's two endpoints do.
lb_base() { echo "$VIP --tcp=$1:$2 --mode=fullproxy --endpoints=$EP:1 --host=$VIP --path-prefix=/ --path-match-mode=prefix --model-name=$MODEL --sse-mode"; }
LB_SCHED_GATE="$(lb_base $PORT_SCHED 8080-8081) --inatimeout=60 --api-key-auth=required"
LB_SCHED="$LB_SCHED_GATE --fc-max-outstanding=$SCHED_MAX --fc-max-queue-depth=$SCHED_DEPTH --fc-max-queue-wait-ms=$SCHED_WAIT_MS"
LB_H2="$(lb_base $PORT_H2 9090-9091) --inatimeout=60 --api-key-auth=required --backend-protocol=http2 --fc-max-outstanding=2"
LB_IDLE="$(lb_base $PORT_IDLE 8080) --inatimeout=2 --fc-max-outstanding=1 --fc-max-queue-depth=4 --fc-max-queue-wait-ms=5000"
LB_KNOB="$(lb_base $PORT_KNOB 8080-8081) --inatimeout=60 --fc-max-outstanding=4 --fc-max-queue-depth=8 --fc-max-queue-wait-ms=5000"
# The full-reset flags: every band knob at the value that clears it.
BAND_RESET="--fc-wake-policy=inherit --fc-band-weights=0:0:0 --fc-band-min-share-pct=0:0:0 --fc-critical-reserve-pct=0 --fc-band-wait-ms=0:0:0 --fc-band-queue-pct=0:0:0 --fc-shed-queue=inherit --fc-tenant-wake=inherit --fc-llmd-headers=inherit"
# The same reset as the scenario's curl writes it, with every gate knob a
# case may have left on a rule (P8 and X8 leave fc_telemetry_stale_ms; the
# knob cases fc_ep_max_inflight, fc_mode, fc_adaptive, fc_expose_headers,
# fc_prefill_max_inflight), so the curl apply of C1 leaves the rule in
# config.sh's shape; 0 and inherit read back absent.
RESET_JSON=', "fc_wake_policy": "inherit", "fc_band_weights": "0:0:0", "fc_band_min_share_pct": "0:0:0", "fc_critical_reserve_pct": 0, "fc_band_wait_ms": "0:0:0", "fc_band_queue_pct": "0:0:0", "fc_shed_queue": "inherit", "fc_tenant_wake": "inherit", "fc_llmd_headers": "inherit", "fc_tenant_max_share_pct": 0, "fc_adaptive": "inherit", "fc_mode": "inherit", "fc_ep_max_inflight": 0, "fc_telemetry_stale_ms": 0, "fc_prefill_max_inflight": 0, "fc_decode_max_inflight": 0, "fc_expose_headers": "inherit"'
# lb_del <port>: the rule by its full L7 key (host, path, match mode, model)
lb_del() { cli delete lb $VIP --tcp=$1 --host=$VIP --path-prefix=/ --path-match-mode=prefix --model-name=$MODEL; }

# ── C0: what the gateway advertises ─────────────────────────────────────────
echo ""
echo "C0: loxicmd get lbversion against GET /version"
V=$(rest /version)
cli get lbversion; check_eq "C0 get lbversion (exit)" 0 "$CLI_RC"; warn_check "C0 get lbversion" none
echo "$CLI_STDOUT" | sed 's/^/      /'
check_has "C0 the product column" "$(echo "$V" | jq -r .product)" "$CLI_STDOUT"
check_has "C0 the features line equals /version" "features: $(echo "$V" | jq -r '.features | join(", ")')" "$CLI_STDOUT"
for f in api_key_auth epp jwt_auth_profile; do
  check_eq "C0 this gateway advertises $f" true \
    "$(echo "$V" | jq -r --arg f "$f" '.features | index($f) != null')"
done

# ── C1: equivalence with the scenario's curl configuration ──────────────────
echo ""
echo "C1: the rules, objective, tenant rate limits and API keys of config.sh, through loxicmd"
# c1_rule <port> <extra-json> <target ports> <cli flags>: the curl apply
# (config.sh's document, every band knob at its reset value), its read-back;
# the CLI delete and create; the read-back again; the two compared.
c1_rule() {
  local port=$1 extra=$2 tps=$3 flags=$4 r a b
  r=$(tq_api POST /config/loadbalancer "$(tq_rule_json $port "$extra$RESET_JSON" $tps)")
  case "$r" in 200*|409*exists*) ;; *) bad "C1 :$port the curl apply" "$r"; return ;; esac
  a=$(rest_rule $port | rule_view); echo "$a" > "$CLI_OUT/c1-$port-curl.json"
  lb_del $port; check_eq "C1 :$port loxicmd delete lb by the full L7 key (exit)" 0 "$CLI_RC"
  check_eq "C1 :$port the rule is gone after the CLI delete" "" "$(rest_rule $port)"
  cli create lb $flags; check_eq "C1 :$port loxicmd create lb (exit)" 0 "$CLI_RC"; warn_check "C1 :$port create lb" none
  b=$(rest_rule $port | rule_view); echo "$b" > "$CLI_OUT/c1-$port-cli.json"
  check_same "C1 :$port the read-back after the CLI apply equals the one after the curl apply" "$a" "$b"
}
c1_rule $PORT_SCHED "$SCHED_JSON" "8080 8081" "$LB_SCHED"
c1_rule $PORT_H2 "$H2_JSON" "9090 9091" "$LB_H2"
c1_rule $PORT_IDLE "$IDLE_JSON, \"inactiveTimeOut\": 2" "8080" "$LB_IDLE"
c1_rule $PORT_KNOB "$KNOB_JSON" "8080 8081" "$LB_KNOB"

echo "  -- the objective"
obj_rest() { rest /config/ai/objective | jq -S -c ".objectiveAttr[] | select(.name==\"$1\") | del(.updated_at)"; }
a=$(obj_rest tq-critical); echo "$a" > "$CLI_OUT/c1-objective-curl.json"
cli create objective tq-critical --priority=1; check_eq "C1 loxicmd create objective tq-critical --priority=1 (exit)" 0 "$CLI_RC"; warn_check "C1 create objective" objectives
b=$(obj_rest tq-critical); echo "$b" > "$CLI_OUT/c1-objective-cli.json"
check_same "C1 the objective reads back as the curl one" "$a" "$b"
cli get objective -o json; check_eq "C1 loxicmd get objective -o json (exit)" 0 "$CLI_RC"; warn_check "C1 get objective" objectives
check_same "C1 get objective -o json lists what REST lists" "$(rest /config/ai/objective | jq -c '[.objectiveAttr[] | del(.updated_at)]' | norm)" "$(echo "$CLI_STDOUT" | jq -c '[.objectiveAttr[] | del(.updated_at)]' 2>/dev/null | norm)"
cli get objective; check_has "C1 get objective names where the list came from ($(rest /config/ai/objective | jq -r .source))" "$(rest /config/ai/objective | jq -r .source)" "$CLI_STDOUT"

echo "  -- the tenant rate limits"
rl_rest() { rest /config/ai/tenant/ratelimit/$1 | jq -S -c 'del(.updated_at)'; }
for t in $TENANTS; do
  name=${t%%:*}; cls=${t##*:}; def=""; [ "$cls" == critical ] && def="--default-objective=tq-critical"
  a=$(rl_rest $name)
  cli set ratelimit --tenant-id=$name --priority-class=$cls $def; check_eq "C1 set ratelimit $name --priority-class=$cls $def (exit)" 0 "$CLI_RC"; warn_check "C1 set ratelimit $name" objectives
  check_same "C1 $name reads back as the curl one" "$a" "$(rl_rest $name)"
done
cli get ratelimit t-crit -o wide; check_has "C1 get ratelimit t-crit -o wide shows the class and the objective" "critical" "$CLI_STDOUT"; check_has "C1 ... and the default objective" "tq-critical" "$CLI_STDOUT"

echo "  -- the API keys (a CLI twin beside each curl key, then removed)"
key_view() { jq -S -c "[.[] | select(.name==\"$1\")] | first | del(.key_id, .name, .created_at, .updated_at, .last_used_at)"; }
key_id_of() { jq -r "[.[] | select(.name==\"$1\")] | first | .key_id // empty"; }
for t in $TENANTS; do
  name=${t%%:*}
  cli create apikey --tenant-id=$name --name=$name-cli --allowed-models=$MODEL --rps=10000 --burst=10000 --enabled=true -o json
  check_eq "C1 create apikey --tenant-id=$name (exit)" 0 "$CLI_RC"; warn_check "C1 create apikey $name" none
  L=$(rest "/config/ai/apikey?tenant_id=$name" | jq -c 'if type=="array" then . else (.apikeys // .items // .apiKeyAttr // []) end')
  check_same "C1 $name: the CLI key reads back as the curl key (key_id, name and timestamps apart)" "$(echo "$L" | key_view $name-band)" "$(echo "$L" | key_view $name-cli)"
  kid=$(echo "$L" | key_id_of $name-cli)
  if [[ -n "$kid" ]]; then
    cli delete apikey "$kid"; check_eq "C1 delete apikey $name-cli (exit)" 0 "$CLI_RC"
    check_eq "C1 $name-cli gone from the REST list" "" "$(rest "/config/ai/apikey?tenant_id=$name" | jq -c 'if type=="array" then . else (.apikeys // .items // .apiKeyAttr // []) end' | key_id_of $name-cli)"
  else
    bad "C1 $name-cli readable via REST" "no key named $name-cli in the list"
  fi
done

# ── C2: P10 through the CLI, on the knob port ───────────────────────────────
echo ""
echo "C2: every band knob on :$PORT_KNOB through loxicmd (P10)"
NINE="--fc-wake-policy=weighted --fc-band-weights=8:3:1 --fc-band-min-share-pct=0:25:0 --fc-critical-reserve-pct=10 --fc-band-wait-ms=0:5000:500 --fc-band-queue-pct=25:50:25 --fc-shed-queue=on --fc-tenant-wake=rr --fc-llmd-headers=on"
cli create lb $LB_KNOB $NINE; check_eq "C2 the nine knobs applied (exit)" 0 "$CLI_RC"; warn_check "C2 create lb with band knobs" bands
G=$(tq_rule_get $PORT_KNOB); echo "$G" > "$CLI_OUT/c2-declared.json"
check_eq "C2 REST reads back as declared" "weighted 8:3:1 0:25:0 10 0:5000:500 25:50:25 on rr on" "$(echo "$G" | knobs9)"
check_eq "C2 in force, from the rule" "weighted weighted none rule rule" \
  "$(tq_fce $PORT_KNOB .wake_policy) $(tq_fce $PORT_KNOB .wake_policy_effective) $(tq_fce $PORT_KNOB .band_fallback_reason) $(tq_fce $PORT_KNOB .source.wake_policy) $(tq_fce $PORT_KNOB .source.band_weights)"
check_eq "C2 the standard floor in units (25 % of 4, rounded up)" 1 "$(tq_fce $PORT_KNOB .bands.standard.floor_units)"
check_eq "C2 the reserve in force (10 % of 4), in units" "10 $(tq_fce $PORT_KNOB .bands.critical_reserve_units)" "$(tq_fce $PORT_KNOB .bands.critical_reserve_pct) $(tq_fce $PORT_KNOB .bands.critical_reserve_units)"
cli get lb -o json; check_eq "C2 get lb -o json (exit)" 0 "$CLI_RC"; warn_check "C2 get lb -o json" none
J=$(echo "$CLI_STDOUT" | jq -c ".lbAttr[] | select(.serviceArguments.port==$PORT_KNOB) | .serviceArguments" 2>/dev/null)
check_eq "C2 get lb -o json carries the nine knobs as REST does" "$(echo "$G" | knobs9)" "$(echo "$J" | knobs9)"
check_same "C2 get lb -o json carries fc_effective's band view as REST does" "$(echo "$G" | band_view)" "$(echo "$J" | band_view)"
cli get lb -o wide; check_eq "C2 get lb -o wide (exit)" 0 "$CLI_RC"
check_has "C2 get lb -o wide shows the wake policy on :$PORT_KNOB" "weighted" "$(echo "$CLI_STDOUT" | grep -E "[| ]$PORT_KNOB[| ]" | head -1)"
cli get lb --bands; check_eq "C2 get lb --bands (exit)" 0 "$CLI_RC"; warn_check "C2 get lb --bands" bands
bands_section $PORT_KNOB > "$CLI_OUT/c2-bands.txt"; sed 's/^/      /' "$CLI_OUT/c2-bands.txt"
H=$(head -1 "$CLI_OUT/c2-bands.txt")
check_has "C2 --bands heading: the wake policy" "wake policy: weighted" "$H"
check_has "C2 --bands heading: the shed queue and the tenant wake" "shed queue: on  tenant wake: rr" "$H"
check_has "C2 --bands heading: the reserve in percent and units" "critical reserve: $(tq_fce $PORT_KNOB .bands.critical_reserve_pct)% ($(tq_fce $PORT_KNOB .bands.critical_reserve_units) units)" "$H"
check_same "C2 --bands rows equal fc_effective (band inflight queued wait queue% share% floor weight weight% source)" "$(rest_band_rows $PORT_KNOB)" "$(cli_band_rows $PORT_KNOB)"
# A replace that names no band knob keeps them all (one gate field changed so
# the replace is not the identical document the gateway answers 409 to).
cli create lb $LB_KNOB --fc-ep-max-inflight=4; check_eq "C2 a replace that omits every band knob (exit)" 0 "$CLI_RC"; warn_check "C2 replace without band flags" none
check_eq "C2 keeps them all" "weighted 8:3:1 0:25:0 10 0:5000:500 25:50:25 on rr on" "$(tq_rule_get $PORT_KNOB | knobs9)"
cli create lb $LB_KNOB --fc-ep-max-inflight=0 $BAND_RESET; check_eq "C2 the reset values (exit)" 0 "$CLI_RC"; warn_check "C2 reset" bands
check_eq "C2 back to the defaults" "strict false off fifo none" \
  "$(tq_fce $PORT_KNOB .wake_policy_effective) $(tq_fce $PORT_KNOB .bands_configured) $(tq_fce $PORT_KNOB .shed_queue_effective) $(tq_fce $PORT_KNOB .tenant_wake_effective) $(tq_fce $PORT_KNOB .band_fallback_reason)"
check_eq "C2 the reset values read back absent" "- - - - - - - - -" "$(tq_rule_get $PORT_KNOB | knobs9)"
cli get lb --bands; bands_section $PORT_KNOB > "$CLI_OUT/c2-bands-reset.txt"
check_has "C2 --bands after the reset: the default policy" "wake policy: strict" "$(head -1 "$CLI_OUT/c2-bands-reset.txt")"
check_same "C2 --bands rows after the reset equal fc_effective" "$(rest_band_rows $PORT_KNOB)" "$(cli_band_rows $PORT_KNOB)"

# ── C3: S8 through the CLI — the twelve refused combinations ────────────────
echo ""
echo "C3: the twelve combinations the gateway refuses, by flags (S8)"
S8_RCS=""; S8_GW=""; S8_CLI=""
# s8_cli <label> <field named> <flags...>: refused (non-zero exit), the field
# named in the CLI's output, the rule unchanged; what the CLI printed is shown
# verbatim (a gateway 400 body is relayed as received).
s8_cli() {
  local label=$1 field=$2 before; shift 2
  before=$(tq_rule_get $PORT_KNOB | jq -S -c 'del(.fc_effective)')
  cli create lb $LB_KNOB "$@"
  echo "  C3 $label: loxicmd create lb ... $* -> exit $CLI_RC"
  # What the CLI printed: its warning and error lines in full (a gateway 400
  # body is relayed verbatim on the Error line); a usage text it appends to
  # a flag it could not parse is counted, not copied.
  grep -E '^(warning|Error):' "$T/stderr" | sed 's/^/      stderr: /'
  local rest; rest=$(grep -vcE '^(warning|Error):' "$T/stderr"); [ "$rest" -gt 0 ] && echo "      stderr: (+ $rest lines of usage text)"
  [ -s "$T/stdout" ] && sed 's/^/      stdout: /' "$T/stdout"
  S8_RCS="$S8_RCS $CLI_RC"
  # Who refused: the gateway (its 400 relayed, after the advisory line) or
  # the CLI itself (nothing sent: no advisory line either).
  if grep -q '^Error: server returned 400' "$T/stderr"; then
    S8_GW="$S8_GW $CLI_RC"
    check_eq "C3 $label: the gateway's 400 reached the CLI after the advisory line (advisory lines)" 1 "$(grep -c '^warning: gateway does not advertise bands' "$T/stderr")"
  else
    S8_CLI="$S8_CLI $CLI_RC"
    check_eq "C3 $label: refused by the CLI itself, nothing sent (advisory lines)" 0 "$(grep -c '^warning: gateway does not advertise' "$T/stderr")"
  fi
  if [[ $CLI_RC -ne 0 ]]; then ok "C3 $label: refused (exit $CLI_RC)"; else bad "C3 $label: refused" "exit 0"; fi
  case "$CLI_STDERR$CLI_STDOUT" in *"$field"*|*"${field//_/-}"*) ok "C3 $label: names $field";; *) bad "C3 $label: names $field" "neither $field nor --${field//_/-} in the output";; esac
  check_same "C3 $label: the rule unchanged" "$before" "$(tq_rule_get $PORT_KNOB | jq -S -c 'del(.fc_effective)')"
}
s8_cli "weighted with a zero weight" fc_band_weights --fc-wake-policy=weighted --fc-band-weights=8:0:1
s8_cli "weighted without weights" fc_band_weights --fc-wake-policy=weighted
s8_cli "weighted with weights declared 0:0:0" fc_band_weights --fc-wake-policy=weighted --fc-band-weights=0:0:0
s8_cli "weights summing past 64" fc_band_weights --fc-wake-policy=weighted --fc-band-weights=40:20:5
s8_cli "a weight past 62" fc_band_weights --fc-band-weights=63:1:0
s8_cli "a zero weight under strict" fc_band_weights --fc-wake-policy=strict --fc-band-weights=8:0:1
s8_cli "floors summing past 100" fc_band_min_share_pct --fc-band-min-share-pct=50:40:20
s8_cli "the reserve and the other two floors past 100" fc_critical_reserve_pct --fc-critical-reserve-pct=60 --fc-band-min-share-pct=0:50:0
s8_cli "the reserve and the other two floors past 100 (sheddable)" fc_critical_reserve_pct --fc-critical-reserve-pct=50 --fc-band-min-share-pct=0:30:30
s8_cli "queue shares past 100" fc_band_queue_pct --fc-band-queue-pct=50:40:20
s8_cli "a malformed triple" fc_band_wait_ms --fc-band-wait-ms=100:200
s8_cli "a wait past an hour" fc_band_wait_ms --fc-band-wait-ms=0:3600001:0
echo "  C3 exit codes:$S8_RCS (gateway 400s:$S8_GW; refused by the CLI:$S8_CLI)"
check_eq "C3 the gateway refused nine of the twelve" 9 "$(echo $S8_GW | wc -w | tr -d ' ')"
check_eq "C3 one exit code for every gateway 400: 6 (CONTRACT_MISMATCH)" "6" "$(echo $S8_GW | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')"
check_eq "C3 the CLI refused the other three itself" 3 "$(echo $S8_CLI | wc -w | tr -d ' ')"
check_eq "C3 one exit code for every CLI refusal: 2 (INVALID_ARGUMENT)" "2" "$(echo $S8_CLI | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')"
echo "  (and the cross-field refusal beside them)"
s8_cli "shed queue with no queue" fc_shed_queue --fc-max-queue-depth=0 --fc-shed-queue=on
check_eq "C3 the knob rule still reads back as the defaults" "- - - - - - - - -" "$(tq_rule_get $PORT_KNOB | knobs9)"

# ── C4: R1 under load — the populated --bands table ─────────────────────────
echo ""
echo "C4: waiters in all three bands on :$PORT_SCHED, read through get lb --bands (R1)"
C4D=$CLI_OUT/c4; mkdir -p "$C4D"
# A pool of two, a queue of eight, weighted 8:3:1 with a standard floor of
# 25 % (one unit of two) and the sheddable band allowed to wait.
cli create lb $LB_SCHED_GATE --fc-max-outstanding=2 --fc-max-queue-depth=8 --fc-max-queue-wait-ms=30000 \
  --fc-wake-policy=weighted --fc-band-weights=8:3:1 --fc-band-min-share-pct=0:25:0 --fc-critical-reserve-pct=0 \
  --fc-band-wait-ms=0:0:0 --fc-band-queue-pct=0:0:0 --fc-shed-queue=on --fc-tenant-wake=fifo --fc-llmd-headers=inherit
check_eq "C4 the pool shaped through the CLI (exit)" 0 "$CLI_RC"; warn_check "C4 shape" bands
check_eq "C4 the shape in force" "weighted 2 1 on" "$(tq_fce $PORT_SCHED .wake_policy_effective) $(tq_fce $PORT_SCHED .effective_max_outstanding) $(tq_fce $PORT_SCHED .bands.standard.floor_units) $(tq_fce $PORT_SCHED .shed_queue_effective)"
cl_one $PORT_SCHED t-crit c4r1 "$C4D"; cl_one $PORT_SCHED t-crit c4r2 "$C4D"
wait_receipts c4r1 1 >/dev/null; wait_receipts c4r2 1 >/dev/null
cl_one $PORT_SCHED t-crit c4c1 "$C4D"; sleep 0.2
cl_one $PORT_SCHED t-a c4s1 "$C4D"; sleep 0.2; cl_one $PORT_SCHED t-a c4s2 "$C4D"; sleep 0.2
cl_one $PORT_SCHED t-shed c4b1 "$C4D"; sleep 0.2; cl_one $PORT_SCHED t-shed c4b2 "$C4D"; sleep 0.8
check_eq "C4 two run, five wait" "2 5" "$(tq_fce $PORT_SCHED .inflight) $(tq_fce $PORT_SCHED .queued)"
check_eq "C4 a waiter in every band (critical standard sheddable)" "1 2 2" \
  "$(tq_fce $PORT_SCHED .bands.critical.queued) $(tq_fce $PORT_SCHED .bands.standard.queued) $(tq_fce $PORT_SCHED .bands.sheddable.queued)"
R1=$(rest_band_rows $PORT_SCHED)
cli get lb --bands; check_eq "C4 get lb --bands under load (exit)" 0 "$CLI_RC"; warn_check "C4 get lb --bands" bands
R2=$(rest_band_rows $PORT_SCHED)
bands_section $PORT_SCHED > "$CLI_OUT/c4-bands.txt"
echo "  the table, verbatim ($CLI_OUT/c4-bands.txt):"; sed 's/^/      /' "$CLI_OUT/c4-bands.txt"
tq_rule_get $PORT_SCHED | jq .fc_effective > "$CLI_OUT/c4-fc-effective.json"
check_same "C4 the state held still across the CLI read (REST before = REST after)" "$R1" "$R2"
check_same "C4 the --bands rows equal fc_effective (band inflight queued wait queue% share% floor weight weight% source)" "$R1" "$(cli_band_rows $PORT_SCHED)"
check_has "C4 the rows are populated: critical runs two and one waits" "critical 2 1 " "$(cli_band_rows $PORT_SCHED)"
check_has "C4 --bands heading: weighted, shed queue on" "wake policy: weighted  shed queue: on" "$(head -1 "$CLI_OUT/c4-bands.txt")"
# Release everyone, then the pool back to config.sh's shape through the CLI.
for i in $(seq 1 60); do cl_release_all; sleep 0.5; [ "$(tq_fce $PORT_SCHED .inflight) $(tq_fce $PORT_SCHED .queued)" == "0 0" ] && break; done
wait_done "$C4D" 'c4*' 7 20
check_eq "C4 every request was answered 200" "200 200 200 200 200 200 200" "$(cl_errs "$C4D" 'c4*')"
cli create lb $LB_SCHED $BAND_RESET; check_eq "C4 the pool back to its shape (exit)" 0 "$CLI_RC"
check_same "C4 the pool reads back as C1 left it" "$(cat "$CLI_OUT/c1-$PORT_SCHED-cli.json")" "$(rest_rule $PORT_SCHED | rule_view)"

# ── C5: netidentity — a CIDR binding for tqh1's network ─────────────────────
echo ""
echo "C5: loxicmd create/get/delete netidentity against GET /config/ai/netidentity"
ni_rest() { rest /config/ai/netidentity | jq -S -c "[.netIdentityAttr[] | select(.name==\"$1\")] | first // empty"; }
cli create netidentity tq-cli-net --tenant=t-a --cidr=10.71.10.0/24
check_eq "C5 create netidentity tq-cli-net --tenant=t-a --cidr=10.71.10.0/24 (exit)" 0 "$CLI_RC"; warn_check "C5 create netidentity" netidentity
echo "$CLI_STDOUT" | sed 's/^/      /'
N=$(ni_rest tq-cli-net); echo "$N" > "$CLI_OUT/c5-netidentity.json"
check_eq "C5 REST lists the binding with its tenant and CIDR" "t-a 10.71.10.0/24" "$(echo "$N" | jq -r '.tenant + " " + (.match.cidr | join(","))' 2>/dev/null)"
cli get netidentity -o json; check_eq "C5 get netidentity -o json (exit)" 0 "$CLI_RC"; warn_check "C5 get netidentity -o json" netidentity
check_same "C5 get netidentity -o json lists what REST lists" "$(rest /config/ai/netidentity | jq -c '.netIdentityAttr' | norm)" "$(echo "$CLI_STDOUT" | jq -c '.netIdentityAttr' 2>/dev/null | norm)"
cli get netidentity tq-cli-net; check_eq "C5 get netidentity tq-cli-net (exit)" 0 "$CLI_RC"
echo "$CLI_STDOUT" | sed 's/^/      /'
check_has "C5 the table names the binding" "tq-cli-net" "$CLI_STDOUT"; check_has "C5 ... its tenant" "t-a" "$CLI_STDOUT"; check_has "C5 ... its CIDR" "10.71.10.0/24" "$CLI_STDOUT"
cli delete netidentity tq-cli-net; check_eq "C5 delete netidentity (exit)" 0 "$CLI_RC"; warn_check "C5 delete netidentity" netidentity
check_eq "C5 gone from the REST list" "" "$(ni_rest tq-cli-net)"
cli delete netidentity tq-cli-net
sed 's/^/      stderr: /' "$T/stderr"
check_eq "C5 a second delete: 404 is exit 4 (PRECONDITION)" 4 "$CLI_RC"; warn_check "C5 second delete" netidentity
check_has "C5 ... and says 404" "404" "$CLI_STDERR"
check_eq "C5 still absent" "" "$(ni_rest tq-cli-net)"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
if [[ $code == 0 ]]; then
  echo "=== CLI Validation (tenant QoS: priority bands): all C0-C5 checks passed ==="
else
  echo "=== CLI Validation (tenant QoS: priority bands): FAILED (see [FAIL] lines above; evidence in $CLI_OUT) ==="
fi
exit $code
