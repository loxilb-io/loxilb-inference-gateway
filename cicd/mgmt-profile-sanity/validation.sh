#!/bin/bash
# CICD validation: mgmt-profile-sanity — the profile legs.
#
# Every leg restarts the gateway under a different flag set, because the flag
# set is the thing under test. Leg map:
#
#   B0  legacy baseline: the management API answers on every NIC and on
#       loopback. This leg keeps the negative legs honest — it proves each
#       probe path genuinely reaches the API when the profile leaves the
#       door open, so a later "unreachable" verdict cannot be a broken probe.
#   A1  appliance-local: every NIC probe is refused, loopback still serves,
#       and the packaged CLI works over loopback. --host is left at its
#       default 0.0.0.0, so this leg exercises the coerce-to-loopback rule.
#   A2  appliance-local --tls: the TLS listener is coerced to loopback too.
#   A3  appliance-local --host <NIC address>: the gateway refuses to start —
#       an explicitly typed reachable address is never silently overridden.
#   R1  remote-tls without --tls: refuses to start.
#   R2  remote-tls --tls without an authentication service: refuses to start.
#       The mounted certificates exist, so the refusal must name the missing
#       authentication service — a cert complaint here would be a different
#       (and wrong) failure.
#   R3  remote-tls --tls --manualtoken: TLS answers on every NIC, an
#       unauthenticated read of a secured route draws 401, the token draws
#       200, and no plaintext listener exists anywhere — loopback included.
#
# Verdicts are fail-fast: the legs share the restart machinery, so a leg that
# cannot complete leaves every later verdict meaningless.
cd "$(dirname "$0")"
source ../common.sh
echo SCENARIO-mgmt-profile-sanity-validation

GW=/root/loxilb-io/loxilb/loxilb
NICS=(10.10.10.254 20.20.20.254 30.30.30.254)
CLIENTS=(c1 c2 c3)

die() {
  echo "  FAILED: $1"
  shift
  for line in "$@"; do echo "    $line"; done
  echo "  gateway stderr tail:"
  docker exec llb1 tail -20 /tmp/loxilb.err 2>/dev/null
  echo SCENARIO-mgmt-profile-sanity-validation [FAILED]
  exit 1
}

# probe_code <netns> <url> [curl args...] — prints the HTTP status, or 000
# when nothing answered. Probes run from the client/gateway net namespaces
# with the runner's own curl, so no verdict depends on container tooling.
probe_code() {
  local ns="$1" url="$2"
  shift 2
  $hexec "$ns" curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 -m 5 "$@" "$url" 2>/dev/null || true
}

# stop_gw kills the gateway and clears the datapath state that outlives it.
# A bare kill-and-start always fails on `llb_xh_init: Assertion 0 failed`:
# the persistent llb0 TAP, the XDP programs and clsact qdiscs on each
# interface, and the bpffs pins under /opt/loxilb/dp all survive the process.
# The TAP is what actually blocks the restart; the rest are cleared for the
# same reason. A refused-start leg still initializes the datapath before the
# listener plan is evaluated, so this runs before every start, not only
# after healthy ones.
stop_gw() {
  docker exec llb1 pkill -f "$GW" >/dev/null 2>&1
  for _ in $(seq 1 15); do
    docker exec llb1 pgrep -f "$GW" >/dev/null 2>&1 || break
    sleep 1
  done
  # A survivor keeps the port bind: the new gateway loses it and dies while
  # the old one answers, and every leg after that runs against the previous
  # flag set as a phantom product failure. Escalate, then refuse to go on.
  if docker exec llb1 pgrep -f "$GW" >/dev/null 2>&1; then
    echo "  (old gateway survived SIGTERM for 15s; escalating to SIGKILL)"
    docker exec llb1 pkill -9 -f "$GW" >/dev/null 2>&1
    for _ in $(seq 1 10); do
      docker exec llb1 pgrep -f "$GW" >/dev/null 2>&1 || break
      sleep 1
    done
  fi
  if docker exec llb1 pgrep -f "$GW" >/dev/null 2>&1; then
    die "the old gateway process would not die; refusing to run legs against it"
  fi
  # The captured output files carry the previous leg's messages; a refusal
  # assert must never be satisfied by a stale line, so start each leg blank.
  docker exec llb1 bash -c ': > /tmp/loxilb.out; : > /tmp/loxilb.err' >/dev/null 2>&1
  docker exec llb1 ip link del llb0 >/dev/null 2>&1
  for ifc in $(docker exec llb1 ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    [ "$ifc" = "lo" ] && continue
    docker exec llb1 ip link set dev "$ifc" xdpgeneric off >/dev/null 2>&1
    docker exec llb1 tc qdisc del dev "$ifc" clsact >/dev/null 2>&1
  done
  docker exec llb1 umount /opt/loxilb/dp >/dev/null 2>&1
}

# start_gw <flags...> — stderr is captured because a gateway started with
# `docker exec -d` and no redirection loses its refusal message entirely, and
# the refusal message is the assert of three legs. `docker exec` hands the
# process an 8192K memlock limit the eBPF maps do not fit in; lift it.
start_gw() {
  docker exec -d llb1 bash -c "ulimit -l unlimited; $GW $* > /tmp/loxilb.out 2> /tmp/loxilb.err"
}

# wait_api <netns> <url> [curl args...] — waits for a 200 on an auth-free
# route, then settles the boot config replay through the same base URL so no
# later mutation (the settle probe included) races the freeze window.
wait_api() {
  local ns="$1" url="$2"
  shift 2
  local i
  for i in $(seq 1 40); do
    [ "$(probe_code "$ns" "$url" "$@")" = "200" ] && break
    if [ "$i" -eq 40 ]; then
      die "gateway did not come back on $url"
    fi
    sleep 2
  done
  local base="${url%/netlox/v1/version}"
  for i in $(seq 1 40); do
    if ! $hexec "$ns" curl -s -m 3 "$@" -X POST "$base/netlox/v1/config/loadbalancer" -H 'Content-Type: application/json' -d '{}' 2>/dev/null | grep -q 'boot config replay settles'; then
      echo "  boot config settled (${i})"
      return 0
    fi
    sleep 2
  done
  die "boot config replay never settled on $base"
}

# expect_fatal <refusal text> <flags...> — a fail-closed start: the exact
# refusal must appear, the process must exit, and nothing may be listening.
# Matching the exact wording matters: a start that dies for any other reason
# is a different defect and must not count as this leg passing.
expect_fatal() {
  local needle="$1"
  shift
  stop_gw
  start_gw "$@"
  local i
  for i in $(seq 1 60); do
    docker exec llb1 grep -qF "$needle" /tmp/loxilb.err /tmp/loxilb.out 2>/dev/null && break
    if [ "$i" -eq 60 ]; then
      die "gateway did not refuse to start" "expected refusal: $needle" "flags: $*"
    fi
    sleep 1
  done
  for i in $(seq 1 30); do
    docker exec llb1 pgrep -f "$GW" >/dev/null 2>&1 || break
    if [ "$i" -eq 30 ]; then
      die "gateway logged the refusal but kept running" "refusal: $needle"
    fi
    sleep 1
  done
  local nic
  for nic in "${NICS[@]}"; do
    local got
    got=$(probe_code c1 "http://$nic:11111/netlox/v1/version")
    [ "$got" = "000" ] || die "a refused start left the API answering on $nic (HTTP $got)"
  done
  got=$(probe_code llb1 "http://127.0.0.1:11111/netlox/v1/version")
  [ "$got" = "000" ] || die "a refused start left the API answering on loopback (HTTP $got)"
}

# assert_nic_http <expected-code> — each NIC probed from its own client, so a
# verdict about an interface is a verdict about a packet that crossed it.
assert_nic_http() {
  local want="$1" i got
  for i in 0 1 2; do
    got=$(probe_code "${CLIENTS[$i]}" "http://${NICS[$i]}:11111/netlox/v1/version")
    [ "$got" = "$want" ] || die "plaintext ${NICS[$i]}:11111 from ${CLIENTS[$i]}: HTTP $got, wanted $want"
  done
}

assert_nic_https() {
  local want="$1" i got
  for i in 0 1 2; do
    got=$(probe_code "${CLIENTS[$i]}" "https://${NICS[$i]}:8091/netlox/v1/version" -k)
    [ "$got" = "$want" ] || die "TLS ${NICS[$i]}:8091 from ${CLIENTS[$i]}: HTTP $got, wanted $want"
  done
}

echo "B0: legacy baseline — every probe path must reach the API"
# Runs against the gateway config.sh spawned (default profile). If any of
# these probes cannot reach an open API, no negative leg below may claim its
# closed door means anything.
assert_nic_http 200
got=$(probe_code llb1 "http://127.0.0.1:11111/netlox/v1/version")
[ "$got" = "200" ] || die "legacy loopback :11111: HTTP $got, wanted 200"
echo "  [OK] legacy serves on all three NICs and loopback"

echo "A1: appliance-local — loopback only, NICs refused, CLI works"
stop_gw
start_gw -p --mgmt-profile appliance-local
wait_api llb1 "http://127.0.0.1:11111/netlox/v1/version"
assert_nic_http 000
got=$(probe_code llb1 "http://127.0.0.1:11111/netlox/v1/version")
[ "$got" = "200" ] || die "appliance-local loopback :11111: HTTP $got, wanted 200"
# The packaged CLI talks to 127.0.0.1:11111 by default — the operator's
# loopback session must keep working when the profile closes the NICs.
docker exec llb1 loxicmd get lb >/dev/null 2>&1 || die "loxicmd get lb failed over loopback under appliance-local"
echo "  [OK] appliance-local closed the NICs and kept loopback + CLI"

echo "A2: appliance-local --tls — the TLS listener is loopback-coerced too"
stop_gw
start_gw -p --mgmt-profile appliance-local --tls
wait_api llb1 "http://127.0.0.1:11111/netlox/v1/version"
got=$(probe_code llb1 "https://127.0.0.1:8091/netlox/v1/version" -k)
[ "$got" = "200" ] || die "appliance-local TLS loopback :8091: HTTP $got, wanted 200"
assert_nic_http 000
assert_nic_https 000
echo "  [OK] appliance-local coerced both listeners to loopback"

echo "A3: appliance-local with an explicit NIC address — refused start"
expect_fatal "mgmt-profile appliance-local requires a loopback --host" \
  -p --mgmt-profile appliance-local --host 10.10.10.254
echo "  [OK] an explicitly typed reachable address is fatal, not overridden"

echo "R1: remote-tls without --tls — refused start"
expect_fatal "mgmt-profile remote-tls requires --tls" \
  -p --mgmt-profile remote-tls
echo "  [OK] remote-tls never serves plaintext"

echo "R2: remote-tls with TLS but no authentication service — refused start"
expect_fatal "requires an authentication service" \
  -p --mgmt-profile remote-tls --tls
echo "  [OK] remote-tls refuses to authorize every caller"

echo "R3: remote-tls with TLS and manual-token auth — serves, enforces"
docker exec llb1 bash -c "mkdir -p /etc/loxilb && printf 'mgmt-profile-suite-token\n' > /etc/loxilb/manual_token" \
  || die "could not place the manual token file"
stop_gw
start_gw -p --mgmt-profile remote-tls --tls --manualtoken
wait_api c1 "https://10.10.10.254:8091/netlox/v1/version" -k
assert_nic_https 200
# /version is deliberately auth-free; the enforcement verdict needs a secured
# route. 401 without the token and 200 with it proves the authenticator is
# examining credentials, not merely configured.
got=$(probe_code c1 "https://10.10.10.254:8091/netlox/v1/config/loadbalancer/all" -k)
[ "$got" = "401" ] || die "unauthenticated secured read over TLS: HTTP $got, wanted 401"
got=$(probe_code c1 "https://10.10.10.254:8091/netlox/v1/config/loadbalancer/all" -k -H "Authorization: Bearer mgmt-profile-suite-token")
[ "$got" = "200" ] || die "token-bearing secured read over TLS: HTTP $got, wanted 200"
assert_nic_http 000
got=$(probe_code llb1 "http://127.0.0.1:11111/netlox/v1/version")
[ "$got" = "000" ] || die "remote-tls left a plaintext listener on loopback (HTTP $got)"
echo "  [OK] remote-tls serves TLS everywhere, enforces auth, and has no plaintext listener"

echo SCENARIO-mgmt-profile-sanity-validation [OK]
exit 0
