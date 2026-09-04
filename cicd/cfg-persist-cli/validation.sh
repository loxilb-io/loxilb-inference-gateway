#!/bin/bash
# validation.sh — cfg-persist-cli: the CLI is the subject, REST and the
# host-mounted config volume are the oracles.
#
# Discipline (see cicd/common/persist_lib.sh):
#  * Every CLI claim is cross-checked against the same fact read another
#    way. "The CLI printed a checksum" proves nothing; "the checksum the
#    CLI printed is the checksum in the file on the host, and that file
#    hashes to it" does.
#  * Exit statuses are the point of half these cases, so the CLI is run
#    without any wrapper that could swallow one, and the status is asserted
#    before the output is read.
#  * Fine-grained decode and status-code matrices live in the CLI
#    repository's tests against a fake gateway. This suite covers only what
#    needs a real gateway.
source ../common.sh
source ../common/persist_lib.sh
echo SCENARIO-cfg-persist-cli

code=0
pass() { echo "  [OK] $1"; }
fail() { echo "  [FAILED] $1"; code=1; }

echo "  CLI under test: $(cat .cli-under-test 2>/dev/null || echo unknown)"

CLI_RC=0
CLI_OUT=""
CLI_ERR=""
cli() { # cli <label> <loxicmd args...>
    local label=$1; shift
    CLI_OUT="$PLIB_ARTIFACTS/cli-$label.out"
    CLI_ERR="$PLIB_ARTIFACTS/cli-$label.err"
    $dexec llb1 loxicmd "$@" > "$CLI_OUT" 2> "$CLI_ERR"
    CLI_RC=$?
    return 0
}

# fetch <container-path> <label> — bring a CLI-written file to the host so
# the suite can hash and parse it with tools the image need not carry.
fetch() {
    sudo docker cp "llb1:$1" "$PLIB_ARTIFACTS/$2" >/dev/null 2>&1
    sudo chmod 644 "$PLIB_ARTIFACTS/$2" >/dev/null 2>&1
}

lb_count() { plib_curl llb1 "$PLIB_API/config/loadbalancer/all" | jq '[.lbAttr[]?] | length'; }
ondisk_generation() { sudo jq -r '.generation // 0' < llb1_config/snapshot.json 2>/dev/null; }
ondisk_checksum() { sudo jq -r '.checksum // ""' < llb1_config/snapshot.json 2>/dev/null; }

# The auto-persist debounce is a legitimate concurrent writer: a leg that
# pins a generation has to let it drain first, or it pins one the gateway
# is about to advance.
drain_debounce() { sleep 6; }

#################################################################################
echo "=== persist: the CLI reports what was actually written ==="
#################################################################################
drain_debounce
cli persist create persist
if [[ $CLI_RC -eq 0 ]]; then
    pass "create persist exits 0 against a healthy gateway"
else
    fail "create persist exited $CLI_RC: $(cat "$CLI_ERR")"
fi
printed_path=$(grep -o '/[^ ]*snapshot\.json' "$PLIB_ARTIFACTS/cli-persist.out" | head -1)
printed_sum=$(grep -o 'sha256:[0-9a-f]\{64\}' "$PLIB_ARTIFACTS/cli-persist.out" | head -1)
printed_gen=$(sed -n 's/.*generation \([0-9]\{1,\}\).*/\1/p' "$PLIB_ARTIFACTS/cli-persist.out" | head -1)

if [[ "$printed_path" == *"snapshot.json" ]]; then
    pass "persist output names the persisted document ($printed_path)"
else
    fail "persist output names no path: $(cat "$PLIB_ARTIFACTS/cli-persist.out")"
fi
disk_sum=$(ondisk_checksum)
if [[ -n "$printed_sum" && "$printed_sum" == "$disk_sum" ]]; then
    pass "the checksum the CLI printed is the checksum in the file on the host"
else
    fail "CLI printed '$printed_sum', the file carries '$disk_sum'"
fi
disk_gen=$(ondisk_generation)
if [[ -n "$printed_gen" && "$printed_gen" == "$disk_gen" ]]; then
    pass "the lineage generation the CLI printed is the one in the file ($disk_gen)"
else
    fail "CLI printed generation '$printed_gen', the file carries '$disk_gen'"
fi
if grep -q "Not captured:" "$PLIB_ARTIFACTS/cli-persist.out"; then
    pass "persist output states what the document does NOT cover"
else
    fail "persist output makes no coverage-exclusion statement"
fi

#################################################################################
echo "=== persist: the json envelope is machine-readable and agrees with disk ==="
#################################################################################
drain_debounce
cli persist-json create persist -o json
if [[ $CLI_RC -eq 0 ]] && jq -e . "$PLIB_ARTIFACTS/cli-persist-json.out" >/dev/null 2>&1; then
    pass "create persist -o json exits 0 and emits parseable JSON"
else
    fail "json mode: rc=$CLI_RC body=$(cat "$PLIB_ARTIFACTS/cli-persist-json.out")"
fi
jresult=$(jq -r '.result // ""'   < "$PLIB_ARTIFACTS/cli-persist-json.out")
jreason=$(jq -r '.reason // ""'   < "$PLIB_ARTIFACTS/cli-persist-json.out")
jcontract=$(jq -r '.contract // ""' < "$PLIB_ARTIFACTS/cli-persist-json.out")
jsum=$(jq -r '.persist.checksum // ""' < "$PLIB_ARTIFACTS/cli-persist-json.out")
jgen=$(jq -r '.persist.generation // -1' < "$PLIB_ARTIFACTS/cli-persist-json.out")
jdom=$(jq -r '.persist.included_domains | length' < "$PLIB_ARTIFACTS/cli-persist-json.out" 2>/dev/null)
if [[ "$jresult" == "ok" && "$jreason" == "ok" ]]; then
    pass "envelope carries result=ok reason=ok"
else
    fail "envelope result='$jresult' reason='$jreason'"
fi
if [[ "$jcontract" == "durable" ]]; then
    pass "envelope reports the durable contract (this gateway does report identity)"
else
    fail "envelope contract='$jcontract', want durable — the CLI did not see the identity fields"
fi
if [[ "$jsum" == "$(ondisk_checksum)" && "$jgen" == "$(ondisk_generation)" ]]; then
    pass "envelope identity matches the document on disk (checksum + generation)"
else
    fail "envelope checksum/generation ($jsum/$jgen) != disk ($(ondisk_checksum)/$(ondisk_generation))"
fi
if [[ "$jdom" -gt 0 ]]; then
    pass "envelope declares the captured domains ($jdom)"
else
    fail "envelope declares no captured domains"
fi

#################################################################################
echo "=== persist: the lineage advances through the CLI ==="
#################################################################################
gen_before=$(ondisk_generation)
drain_debounce
cli persist-2 create persist
gen_after=$(ondisk_generation)
if [[ $CLI_RC -eq 0 && "$gen_after" -gt "$gen_before" ]]; then
    pass "a second CLI persist advanced the lineage ($gen_before -> $gen_after)"
else
    fail "lineage did not advance through the CLI ($gen_before -> $gen_after, rc=$CLI_RC)"
fi

#################################################################################
echo "=== strict mode is not vacuous against a gateway that does report ==="
#################################################################################
drain_debounce
cli persist-strict create persist --strict
if [[ $CLI_RC -eq 0 ]]; then
    pass "--strict accepts a gateway that reports the durable contract"
else
    fail "--strict rejected a durable-contract gateway: $(cat "$CLI_ERR")"
fi

#################################################################################
echo "=== get snapshot -f: verified, and stored 0600 ==="
#################################################################################
cli snap get snapshot -f /tmp/cli-snap.json
if [[ $CLI_RC -eq 0 ]]; then
    pass "get snapshot -f exits 0"
else
    fail "get snapshot -f exited $CLI_RC: $(cat "$CLI_ERR")"
fi
if grep -q "Checksum verified" "$PLIB_ARTIFACTS/cli-snap.out"; then
    pass "the CLI reports that it verified the document"
else
    fail "the CLI stored a document without claiming verification: $(cat "$PLIB_ARTIFACTS/cli-snap.out")"
fi
mode=$($dexec llb1 stat -c '%a' /tmp/cli-snap.json 2>/dev/null | tr -d '\r')
if [[ "$mode" == "600" ]]; then
    pass "the stored document is 0600 (it carries the whole configuration)"
else
    fail "stored mode is $mode, want 600"
fi
# Independent oracle: recompute the checksum the way the gateway defines it
# (canonical bytes with the checksum value emptied) and compare with what
# the document claims. This does not trust the CLI's own verification.
fetch /tmp/cli-snap.json cli-snap.json
claimed=$(jq -r '.checksum' < "$PLIB_ARTIFACTS/cli-snap.json")
computed="sha256:$(sed 's/"checksum":"sha256:[0-9a-f]*"/"checksum":""/' "$PLIB_ARTIFACTS/cli-snap.json" | tr -d '\n' | sha256sum | cut -d' ' -f1)"
if [[ -n "$claimed" && "$claimed" == "$computed" ]]; then
    pass "the stored document independently hashes to the checksum it claims"
else
    fail "stored document claims $claimed but hashes to $computed"
fi

#################################################################################
echo "=== a failed download leaves the previous good copy untouched ==="
#################################################################################
cli snap-keep get snapshot -f /tmp/cli-keep.json
before_hash=$($dexec llb1 sha256sum /tmp/cli-keep.json 2>/dev/null | cut -d' ' -f1)
if [[ $CLI_RC -eq 0 && -n "$before_hash" ]]; then
    pass "a good download is in place before the failure leg"
else
    fail "could not stage the good download (rc=$CLI_RC)"
fi

echo "  stopping the gateway process (the CLI must fail, not truncate)"
docker exec llb1 pkill -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
for _ in $(seq 1 15); do
    docker exec llb1 pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
    sleep 1
done
docker exec llb1 pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1

cli snap-down get snapshot -f /tmp/cli-keep.json -o json
if [[ $CLI_RC -ne 0 ]]; then
    pass "get snapshot against a dead gateway exits non-zero ($CLI_RC)"
else
    fail "get snapshot against a dead gateway exited 0"
fi
downreason=$(jq -r '.reason // ""' < "$PLIB_ARTIFACTS/cli-snap-down.out" 2>/dev/null)
if [[ "$downreason" == "request-failed" ]]; then
    pass "the failure carries the transport reason code"
else
    fail "reason='$downreason', want request-failed"
fi
after_hash=$($dexec llb1 sha256sum /tmp/cli-keep.json 2>/dev/null | cut -d' ' -f1)
if [[ -n "$after_hash" && "$after_hash" == "$before_hash" ]]; then
    pass "the previously downloaded snapshot is byte-identical after the failure"
else
    fail "a failed download damaged the previous copy ($before_hash -> $after_hash)"
fi
residue=$($dexec llb1 sh -c 'ls -1 /tmp | grep -c "^\.cli-keep.json.tmp-" || true' | tr -d '\r')
if [[ "$residue" == "0" ]]; then
    pass "no temporary file was left behind"
else
    fail "the failed download left $residue temporary file(s)"
fi

cli persist-down create persist
if [[ $CLI_RC -ne 0 ]]; then
    pass "create persist against a dead gateway exits non-zero ($CLI_RC)"
else
    fail "create persist against a dead gateway exited 0"
fi

echo "  restarting the gateway"
if restart_inplace_keep llb1; then
    pass "gateway restarted and replayed its snapshot"
else
    fail "gateway did not come back after the failure leg"
fi

#################################################################################
echo "=== restore: dry-run plans without mutating, commit round-trips ==="
#################################################################################
cli snap-base get snapshot -f /tmp/cli-base.json
lb_before=$(lb_count)
cli restore-dry create restore -f /tmp/cli-base.json
if [[ $CLI_RC -eq 0 ]]; then
    pass "dry-run restore exits 0"
else
    fail "dry-run restore exited $CLI_RC: $(cat "$CLI_ERR")"
fi
if grep -q "nothing was changed" "$PLIB_ARTIFACTS/cli-restore-dry.out" && \
   grep -q "^  Plan " "$PLIB_ARTIFACTS/cli-restore-dry.out"; then
    pass "dry-run output states the plan and that nothing changed"
else
    fail "dry-run output: $(cat "$PLIB_ARTIFACTS/cli-restore-dry.out")"
fi
if [[ "$(lb_count)" == "$lb_before" ]]; then
    pass "dry-run mutated nothing (load balancer count unchanged: $lb_before)"
else
    fail "dry-run changed the running configuration ($lb_before -> $(lb_count))"
fi

echo "  deleting the load balancer rule through REST, then restoring with the CLI"
plib_curl llb1 -o /dev/null -X DELETE \
    "$PLIB_API/config/loadbalancer/externalipaddress/20.20.20.1/port/2020/protocol/tcp"
if [[ "$(lb_count)" == "0" ]]; then
    pass "the rule is gone before the restore (count 0)"
else
    fail "the rule survived the delete; the restore leg would prove nothing"
fi

cli restore-commit create restore -f /tmp/cli-base.json --commit
if [[ $CLI_RC -eq 0 ]]; then
    pass "commit restore exits 0"
else
    fail "commit restore exited $CLI_RC: $(cat "$CLI_ERR")"
fi
if grep -q "Restore committed" "$PLIB_ARTIFACTS/cli-restore-commit.out" && \
   grep -q "Persisted: yes" "$PLIB_ARTIFACTS/cli-restore-commit.out"; then
    pass "commit output reports the restore AND its write-through"
else
    fail "commit output: $(cat "$PLIB_ARTIFACTS/cli-restore-commit.out")"
fi
if [[ "$(lb_count)" == "$lb_before" ]]; then
    pass "the restored configuration is back (count $lb_before)"
else
    fail "restore did not bring the rule back ($(lb_count) != $lb_before)"
fi

#################################################################################
echo "=== restore: a corrupt document is refused, loudly and without mutating ==="
#################################################################################
# Flip one character of the document's kind, leaving its checksum field
# intact - a corrupted transfer, not a re-signed document. The guard below
# is the important part: a substitution that matched nothing would hand the
# gateway a perfectly good document and the leg would "pass" having tested
# nothing at all.
$dexec llb1 sh -c "sed 's/\"kind\":\"loxilb-snapshot\"/\"kind\":\"loxilb-snapshoT\"/' /tmp/cli-base.json > /tmp/cli-corrupt.json"
if $dexec llb1 cmp -s /tmp/cli-base.json /tmp/cli-corrupt.json; then
    fail "the corruption fixture changed nothing; this leg would prove nothing"
else
    pass "the corruption fixture differs from the good document"
fi
lb_before=$(lb_count)
cli restore-corrupt create restore -f /tmp/cli-corrupt.json --commit -o json
if [[ $CLI_RC -ne 0 ]]; then
    pass "a corrupt document restore exits non-zero ($CLI_RC)"
else
    fail "a corrupt document restore exited 0"
fi
# The gateway answers a checksum mismatch with compatible=false, so the CLI
# reports the gateway's own signal rather than inventing a code of its own -
# and the message keeps the gateway's detail, which is what names the field
# that failed.
creason=$(jq -r '.reason // ""' < "$PLIB_ARTIFACTS/cli-restore-corrupt.out" 2>/dev/null)
if [[ "$creason" == "incompatible-snapshot" ]]; then
    pass "the refusal carries the reason the gateway's own answer implies ($creason)"
else
    fail "reason='$creason', want incompatible-snapshot"
fi
if grep -q "checksum mismatch" "$PLIB_ARTIFACTS/cli-restore-corrupt.out"; then
    pass "the refusal keeps the gateway's detail (which check failed)"
else
    fail "the refusal dropped the gateway's detail: $(cat "$PLIB_ARTIFACTS/cli-restore-corrupt.out")"
fi
if [[ "$(lb_count)" == "$lb_before" ]]; then
    pass "the refused restore mutated nothing (count $lb_before)"
else
    fail "a refused restore changed the configuration ($lb_before -> $(lb_count))"
fi

cli restore-absent create restore -f /tmp/no-such-document.json -o json
if [[ $CLI_RC -ne 0 && "$(jq -r '.reason // ""' < "$PLIB_ARTIFACTS/cli-restore-absent.out")" == "file-read-failed" ]]; then
    pass "a missing document fails locally with the file reason code"
else
    fail "missing document: rc=$CLI_RC body=$(cat "$PLIB_ARTIFACTS/cli-restore-absent.out")"
fi

#################################################################################
echo "=== save --api: the alias, and the combinations it refuses ==="
#################################################################################
drain_debounce
gen_before=$(ondisk_generation)
cli save-api save --api
gen_after=$(ondisk_generation)
if [[ $CLI_RC -eq 0 && "$gen_after" -gt "$gen_before" ]]; then
    pass "save --api persisted through the same call ($gen_before -> $gen_after)"
else
    fail "save --api: rc=$CLI_RC generation $gen_before -> $gen_after"
fi
if grep -q "Configuration persisted to" "$PLIB_ARTIFACTS/cli-save-api.out"; then
    pass "save --api reports the same result the canonical command does"
else
    fail "save --api output: $(cat "$PLIB_ARTIFACTS/cli-save-api.out")"
fi

gen_before=$(ondisk_generation)
cli save-api-all save --api --all
if [[ $CLI_RC -ne 0 ]]; then
    pass "save --api --all is refused ($CLI_RC)"
else
    fail "save --api --all exited 0 while writing none of the dumps --all names"
fi
if grep -q -- "--all" "$PLIB_ARTIFACTS/cli-save-api-all.err"; then
    pass "the refusal names the offending flag"
else
    fail "refusal message: $(cat "$PLIB_ARTIFACTS/cli-save-api-all.err")"
fi
if [[ "$(ondisk_generation)" == "$gen_before" ]]; then
    pass "the refused combination never reached the gateway (generation unchanged)"
else
    fail "a refused combination still persisted ($gen_before -> $(ondisk_generation))"
fi

cli save-api-cfgpath save --api --config-path /tmp/cli-dumps
if [[ $CLI_RC -ne 0 ]] && grep -q "does not change where the gateway" "$PLIB_ARTIFACTS/cli-save-api-cfgpath.err"; then
    pass "save --api --config-path is refused with the client/server split explained"
else
    fail "save --api --config-path: rc=$CLI_RC err=$(cat "$PLIB_ARTIFACTS/cli-save-api-cfgpath.err")"
fi

drain_debounce
gen_before=$(ondisk_generation)
cli save-api-ip save --api --ip --config-path /tmp/cli-dumps
if [[ $CLI_RC -eq 0 ]]; then
    pass "save --api --ip is accepted (interface config is outside the snapshot)"
else
    fail "save --api --ip exited $CLI_RC: $(cat "$CLI_ERR")"
fi
if grep -q "IP Configuration saved in" "$PLIB_ARTIFACTS/cli-save-api-ip.out" && \
   grep -q "Configuration persisted to" "$PLIB_ARTIFACTS/cli-save-api-ip.out"; then
    pass "save --api --ip did both halves: the local dump and the gateway persist"
else
    fail "save --api --ip output: $(cat "$PLIB_ARTIFACTS/cli-save-api-ip.out")"
fi

#################################################################################
echo "=== the document the CLI persisted is a document the gateway accepts ==="
#################################################################################
if ondisk_doc_valid llb1 cli-final; then
    pass "the on-disk document written through the CLI passes the restore pipeline"
else
    fail "the document the CLI persisted does not survive a dry-run restore"
fi

plib_collect_logs llb1
echo "cfg-persist-cli validation done (exit $code)"
exit $code
