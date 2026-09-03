#!/bin/bash
# persist_lib.sh — shared harness for the cfg-persist-* scenario suites.
#
# Source AFTER ../common.sh, from inside a suite directory whose gateway
# container is named by the first argument of each function (llb1 in every
# current suite). Design rules (do not regress):
#
#  * Canonical deep-diff oracle, not probe re-runs: every domain is dumped
#    via its GET API, jq-canonicalized (sorted keys) with volatile runtime
#    fields stripped by the EXPLICIT per-domain filters below — a new field
#    fails the diff by default instead of being silently ignored.
#  * No bare sleeps where a receipt is pollable: restarts poll the boot
#    replay receipt ("boot snapshot: snapshot.json applied" in
#    /tmp/loxilb.out) because boot restore RETRIES while late subsystems
#    come up and every failed attempt rolls config back to empty — probing
#    inside that window produces phantom verdicts.
#  * Never `docker restart` a gateway whose veths must survive: in-place
#    restart kills and relaunches the process inside the container
#    (SIGTERM → SIGKILL escalation, datapath scrub), the same trio the
#    auth-plane tiers use.
#  * Diff output and response bodies are written under $PLIB_ARTIFACTS so a
#    failure is diagnosable from the artifacts alone.

PLIB_API="http://localhost:11111/netlox/v1"
PLIB_ARTIFACTS="${PLIB_ARTIFACTS:-$(pwd)/artifacts}"
mkdir -p "$PLIB_ARTIFACTS"

# plib_curl <llb> <curl-args...> — curl from inside the gateway's netns.
plib_curl() {
    local llb=$1; shift
    $hexec "$llb" curl -s -m 15 "$@"
}

# plib_wait_api <llb> — poll the REST API until it answers.
plib_wait_api() {
    local llb=$1
    for _ in $(seq 1 60); do
        rc=$(plib_curl "$llb" -o /dev/null -w "%{http_code}" "$PLIB_API/version" 2>/dev/null)
        [[ "$rc" == "200" ]] && return 0
        sleep 1
    done
    echo "  FATAL: $llb REST API never became ready"
    return 1
}

# --- canonical dumps -------------------------------------------------------
#
# One jq filter per domain: '.' would silently tolerate new volatile fields,
# so each filter strips EXACTLY the known runtime fields and sorts unordered
# nested lists. Everything else participates in the diff.

plib_dump_domain() { # plib_dump_domain <llb> <domain> <outdir>
    local llb=$1 domain=$2 outdir=$3 url filter
    case "$domain" in
    endpoint)
        url="$PLIB_API/config/endpoint/all"
        filter='[.Attr[]? | del(.minDelay,.avgDelay,.maxDelay,.currState)] | sort' ;;
    loadbalancer)
        url="$PLIB_API/config/loadbalancer/all"
        filter='[.lbAttr[]? | .endpoints = ([.endpoints[]? | del(.state,.counters,.counter)] | sort)
                            | .secondaryIPs = (.secondaryIPs | if . == null then [] else sort end)
                            | .allowedSources = (.allowedSources | if . == null then [] else sort end)] | sort' ;;
    firewall)
        url="$PLIB_API/config/firewall/all"
        filter='[.fwAttr[]? | del(.opts.counter)] | sort' ;;
    policy)
        url="$PLIB_API/config/policy/all"
        filter='[.polAttr[]?] | sort' ;;
    mirror)
        url="$PLIB_API/config/mirror/all"
        filter='[.mirrAttr[]? | del(.sync)] | sort' ;;
    session)
        url="$PLIB_API/config/session/all"
        filter='[.sessionAttr[]?] | sort' ;;
    sessionulcl)
        url="$PLIB_API/config/sessionulcl/all"
        filter='[.ulclAttr[]?] | sort' ;;
    ipfilter)
        url="$PLIB_API/config/ipfilter/all"
        filter='[.ipfilterAttr[]? | del(.packets,.bytes)] | sort' ;;
    securityrate)
        # The flat REST view mixes config and live counters in one object;
        # strip the KNOWN counter keys explicitly -- a new (unclassified)
        # field then shows up in the diff by default and forces a decision.
        url="$PLIB_API/config/securityrate/all"
        filter='[.securityrateAttr[]? | del(.synPassed,.synBlocked,.synCookies,.connPassed,.connBlocked,.udpPassed,.udpBlocked,.uniqueIps)] | sort' ;;
    bfd)
        url="$PLIB_API/config/bfd/all"
        filter='[.Attr[]? | del(.state)] | sort' ;;
    bgpneigh)
        url="$PLIB_API/config/bgp/neigh/all"
        filter='[.bgpNeiAttr[]? | del(.state,.uptime)] | sort' ;;
    l7policy)
        url="$PLIB_API/config/l7policy"
        filter='[.l7policyAttr[]?] | sort' ;;
    cors)
        url="$PLIB_API/config/cors/all"
        filter='{cors: ((.corsAttr // []) | sort)}' ;;
    tracing)
        # connected is live exporter state, not desired config; header
        # values come back redacted (stable), names participate.
        url="$PLIB_API/config/trace/otlp"
        filter='del(.connected)' ;;
    cert)
        # The SNI store view: hostname + managed path are desired state;
        # refCount tracks live proxy attachment and churns with restarts.
        url="$PLIB_API/sni/certificates"
        filter='[.certificates[]? | del(.refCount)] | sort' ;;
    snapshotdoc)
        # The snapshot document itself: metadata that legitimately changes
        # per capture is stripped; the domains payload is the subject.
        url="$PLIB_API/config/snapshot"
        filter='del(.created_at,.checksum,.gateway_version,.hostname,.trigger)' ;;
    *)
        echo "  FATAL: plib_dump_domain: unknown domain $domain"; return 1 ;;
    esac
    local raw="$outdir/.raw-$domain.json"
    plib_curl "$llb" "$url" -o "$raw"
    if ! jq -S "$filter" < "$raw" > "$outdir/$domain.json" 2>"$outdir/.jqerr-$domain"; then
        echo "  FATAL: canonicalization failed for $domain (raw + jq error kept in $outdir)"
        return 1
    fi
    rm -f "$outdir/.jqerr-$domain"
}

PLIB_DOMAINS="endpoint loadbalancer firewall policy mirror session sessionulcl ipfilter securityrate bfd bgpneigh l7policy cors tracing cert snapshotdoc"

canonical_get_all() { # canonical_get_all <llb> <outdir>
    local llb=$1 outdir=$2 d
    mkdir -p "$outdir"
    for d in $PLIB_DOMAINS; do
        plib_dump_domain "$llb" "$d" "$outdir" || return 1
    done
}

deep_diff() { # deep_diff <beforedir> <afterdir> <label> — 0 iff identical
    local before=$1 after=$2 label=$3 d bad=0
    local ddir="$PLIB_ARTIFACTS/deep-diff-$label"
    mkdir -p "$ddir"
    for d in $PLIB_DOMAINS; do
        if ! diff -u "$before/$d.json" "$after/$d.json" > "$ddir/$d.diff" 2>&1; then
            echo "  deep-diff[$label]: domain $d DIFFERS (see $ddir/$d.diff)"
            bad=1
        else
            rm -f "$ddir/$d.diff"
        fi
    done
    return $bad
}

# --- persist / restore -----------------------------------------------------

persist_and_verify() { # persist_and_verify <llb> — asserts contract + file
    local llb=$1
    local resp="$PLIB_ARTIFACTS/persist-response.json"
    local rc
    rc=$(plib_curl "$llb" -o "$resp" -w "%{http_code}" -X POST "$PLIB_API/config/persist")
    if [[ "$rc" != "200" ]]; then
        echo "  persist: HTTP $rc (body kept in $resp)"; return 1
    fi
    local result path sum
    result=$(jq -r '.result' < "$resp")
    path=$(jq -r '.path' < "$resp")
    sum=$(jq -r '.checksum' < "$resp")
    [[ "$result" == "ok" ]] || { echo "  persist: result=$result"; return 1; }
    [[ "$path" == *snapshot.json ]] || { echo "  persist: unexpected path $path"; return 1; }
    [[ "$sum" == sha256:* ]] || { echo "  persist: malformed checksum $sum"; return 1; }
    # The persisted file must exist host-side (pick_config mount) and its
    # embedded checksum must match the response's. The gateway writes it
    # root-owned 0600, so read through sudo.
    local fsum
    fsum=$(sudo cat "${llb}_config/snapshot.json" 2>/dev/null | jq -r '.checksum')
    [[ "$fsum" == "$sum" ]] || { echo "  persist: file checksum $fsum != response $sum"; return 1; }
    return 0
}

restore_commit() { # restore_commit <llb> <docfile> [extra-query] — echoes http code, body in artifacts
    local llb=$1 doc=$2 q=$3
    plib_curl "$llb" -o "$PLIB_ARTIFACTS/restore-response.json" -w "%{http_code}" \
        -X POST "$PLIB_API/config/restore?mode=commit${q}" \
        -H 'Content-Type: application/json' --data-binary @"$doc"
}

# --- restarts --------------------------------------------------------------

wait_replay_receipt() { # wait_replay_receipt <llb>
    local llb=$1
    for _ in $(seq 1 30); do
        docker exec "$llb" grep -aq "boot snapshot: snapshot.json applied" /tmp/loxilb.out 2>/dev/null && return 0
        sleep 2
    done
    echo "  boot snapshot never settled; restore lines:"
    docker exec "$llb" grep -a "boot snapshot" /tmp/loxilb.out 2>/dev/null | tail -5
    return 1
}

plib_start_gw() { # plib_start_gw <llb> <flags...> — kill + scrub + relaunch
    local llb=$1; shift
    docker exec "$llb" pkill -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
    for _ in $(seq 1 15); do
        docker exec "$llb" pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
        sleep 1
    done
    if docker exec "$llb" pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
        echo "  (old gateway survived SIGTERM for 15s; escalating to SIGKILL)"
        docker exec "$llb" pkill -9 -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1
        for _ in $(seq 1 10); do
            docker exec "$llb" pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1 || break
            sleep 1
        done
    fi
    if docker exec "$llb" pgrep -f '/root/loxilb-io/loxilb/loxilb' >/dev/null 2>&1; then
        echo "  FATAL: the old gateway process would not die; refusing to run legs against it"
        return 1
    fi
    docker exec "$llb" ip link del llb0 >/dev/null 2>&1
    for ifc in $(docker exec "$llb" ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        [ "$ifc" = "lo" ] && continue
        docker exec "$llb" ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
        docker exec "$llb" tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
    done
    docker exec "$llb" umount /opt/loxilb/dp >/dev/null 2>&1
    docker exec -d "$llb" bash -c "ulimit -l unlimited; /root/loxilb-io/loxilb/loxilb $* > /tmp/loxilb.out 2> /tmp/loxilb.err"
    for _ in $(seq 1 40); do
        if docker exec "$llb" curl -sf -m 3 "$PLIB_API/version" >/dev/null 2>&1; then
            sleep 5; return 0
        fi
        sleep 2
    done
    echo "  gateway did not come back; stderr tail:"
    docker exec "$llb" tail -20 /tmp/loxilb.err
    return 1
}

restart_inplace_keep() { # restart_inplace_keep <llb> <flags...> — snapshot survives, replay polled
    local llb=$1; shift
    plib_start_gw "$llb" "$@" || return 1
    wait_replay_receipt "$llb"
}

restart_inplace_cold() { # restart_inplace_cold <llb> <flags...> — snapshot removed first
    local llb=$1; shift
    sudo rm -f "${llb}_config/snapshot.json"
    plib_start_gw "$llb" "$@"
}

# plib_collect_logs <llb> — always-callable evidence collection. Captured
# snapshot documents in the artifacts are SCRUBBED of the ipsec domain
# before they can leave the runner: snapshots embed tunnel PSKs and
# private-key PEM, and evidence uploads must never carry live secrets.
plib_collect_logs() {
    local llb=$1 f
    docker exec "$llb" tail -200 /tmp/loxilb.out > "$PLIB_ARTIFACTS/loxilb.out.tail" 2>/dev/null
    docker exec "$llb" tail -100 /tmp/loxilb.err > "$PLIB_ARTIFACTS/loxilb.err.tail" 2>/dev/null
    for f in "$PLIB_ARTIFACTS"/*.json; do
        [ -f "$f" ] || continue
        if sudo jq -e '.domains.ipsec?' "$f" >/dev/null 2>&1; then
            sudo jq '.domains.ipsec = {"scrubbed": true} | .checksum = "scrubbed"' "$f" > "$f.scrub" \
                && sudo mv "$f.scrub" "$f"
        fi
    done
}
