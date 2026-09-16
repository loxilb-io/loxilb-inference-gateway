#!/bin/bash
# validation.sh — P/D bounded-admission exit gate (GPU-free mock P/D bed).
#
# Covers the three per-EP admission counter families, which have no committed coverage
# anywhere else because arming them requires process env that cannot be toggled on a
# live gateway:
#
#   loxilb_pd_admission_shed_total            plain shed   (queueing OFF)
#   loxilb_pd_admission_queued_total          park         (queueing ON)
#   loxilb_pd_admission_overflow_shed_total   overflow shed(queueing ON)
#
# ── why this file reconfigures the bed halfway through ────────────────────────────────
#
# The three are MUTUALLY EXCLUSIVE inside one gateway process. From the all-capped branch
# in sockproxy_pd.c: at queue depth 0 the plain-shed site is the only reachable one; at
# depth > 0 it is unreachable and park/overflow are the only reachable ones. Both knobs
# are getenv-once at process start, so covering all three means TWO gateway lifecycles.
# Phase A runs at depth 0, then the bed is torn down and config.sh re-runs at depth 2.
#
# That exclusion is the attribution oracle, not an inconvenience: each phase asserts the
# OTHER phase's sites stayed at ZERO. Each family has exactly one writer site repo-wide
# (verified by grep over the C tree), so a per-family delta is honest here — unlike the
# multi-writer families in vllm-kvcache-routing-cpu — but "the counter moved" still would
# not say WHICH branch ran without the cross-phase flat asserts below.
#
# ── the two traps this stage encodes ──────────────────────────────────────────────────
#
# 1. THE THREE LOG LINES COLLIDE UNDER A LITERAL GREP. The overflow line contains the
#    substring "shed:" that the plain line is identified by, so `grep -cF "shed:"` counts
#    BOTH and a plain-shed assert would be satisfied by overflow sheds. The discriminators
#    used here are the counter-name suffixes, which do not nest: "(shed_total=" is unique
#    to plain (overflow writes ", overflow_shed_total="), "overflow_shed_total=" is unique
#    to overflow, "(queued_total=" is unique to park. The loose count is then asserted to
#    equal plain + overflow, so a discriminator that silently stopped discriminating
#    fails the stage instead of passing it.
#
# 2. A HANGING BACKEND GETS DEMOTED, AND THEN THE PREDICTION IS FOR THE WRONG POOL SIZE.
#    Control-plane health demotes an unresponsive backend after roughly 19s. Every shed and
#    overflow log line carries its own healthy_elig count, so this stage reads the pool size
#    OUT OF THE PRODUCT'S OWN LINE and asserts it is 3. A drive that silently ran against a
#    pool of 2 fails here rather than reporting an off-by-one as a product defect.
#
# Both arms use a settle window longer than one collector period: these families are POLLED
# (RunSockproxyMetrics sleeps PrometheusDefaultPeriod = 10s), not CGO-callback, so a short
# settle reads a live writer as dead — including the FLAT readings, whose whole value is
# that they had a real chance to move.
#
# Run: sudo ./config.sh && sudo ./validation.sh ; ./rmconfig.sh

source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"
VIP="10.10.10.254"
VPORT="8080"
METRICS="http://localhost:11111/netlox/v1/metrics"
DPLOG="/var/log/loxilbdp.log"

# The fault machinery lives in the sibling KV scenario; cross-scenario asset reuse is the
# established idiom here (sglang-loxilb-kvcache/config.sh does the same with the publisher).
FAULT_SWAP="${CFGDIR}/../vllm-kvcache-routing-cpu/pd-fault-swap.sh"
PREFILL_NS="l3ep1 l3ep3 l3ep5"

SKELETON_STRICT="${SKELETON_STRICT:-1}"
code=0

assert() {
    local name="$1" ok="$2"
    if [[ "$ok" == 1 ]]; then
        echo "  ${name} [OK]"
    elif [[ "$SKELETON_STRICT" == 1 ]]; then
        echo "  ${name} [FAILED]"
        code=1
    else
        echo "  ${name} [PENDING] (SKELETON_STRICT=0 dev dry-run — would have FAILED)"
    fi
}

llb_curl() { $hexec llb1 curl -s --max-time 10 --retry 2 "$@"; }

# metric_val <extended-regex> — sum the value column of all matching /metrics lines (0 if none).
metric_val() {
    local v
    v=$(llb_curl "${METRICS}" 2>/dev/null | grep -E "$1" | awk '{s+=$NF} END{printf "%d", s}')
    echo "${v:-0}"
}

adm_shed()     { metric_val "^loxilb_pd_admission_shed_total "; }
adm_queued()   { metric_val "^loxilb_pd_admission_queued_total "; }
adm_overflow() { metric_val "^loxilb_pd_admission_overflow_shed_total "; }

# dplog_count <FIXED-STRING> — count matching lines in the in-container datapath log.
# Returns -1 on an unreadable log rather than 0: collapsing "I could not measure" into
# "nothing happened" is how a vacuous flat assert passes.
dplog_count() {
    local out rc
    out=$(docker exec llb1 grep -cF "$1" "${DPLOG}" 2>/dev/null); rc=$?
    if [[ $rc -gt 1 ]]; then echo "-1"; else echo "${out:-0}"; fi
}

# count_lines <regex> <file> — matching lines, without the double-zero trap.
# 🚨 `grep -c` PRINTS "0" *and* EXITS 1 on zero matches, so the obvious
# `$(grep -c ... || echo 0)` appends a SECOND "0" and the caller captures "0\n0".
# That string compares unequal to everything (so an == assert fails safe and merely
# prints nonsense) but is a SYNTAX ERROR inside `[[ .. -gt .. ]]`, which is a gate
# failure rather than a gate result. Found by the cap=0 red twin, which is the only
# arm where these counts are legitimately zero.
count_lines() {
    local n
    n=$(grep -c "$1" "$2" 2>/dev/null)
    echo "${n:-0}"
}

# The three non-nesting discriminators (see trap 1 in the header).
L_SHED="(shed_total="
L_QUEUED="(queued_total="
L_OVERFLOW="overflow_shed_total="
L_LOOSE="shed_total="          # matches plain AND overflow — the self-verifying total

# healthy_elig as the PRODUCT reports it, counted over shed/overflow lines (see trap 2).
POOL3_SHED="shed: all 3 healthy prefill EPs"
POOL3_OVER="overflow shed: all 3 healthy prefill EPs"

SETTLE="${ADM_SETTLE:-14}"     # > one 10s collector period, with margin
HOLD_N=3                       # one in-flight request per prefill EP fills a cap=1 pool
PROBE_N=6                      # phase A sheds; phase B parks (3 EPs x depth 2 = 6 slots)

HOLDER_PIDS=""

# ── fixture assertions ────────────────────────────────────────────────────────────────
# Read the knobs off the RUNNING container, never off the builder's intent. config.sh
# could have been edited, re-run with a different ADM_*, or silently no-opped on an
# existing container — and every prediction below is arithmetic on these two numbers.
running_env() {
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' llb1 2>/dev/null \
        | grep -E "^$1=" | head -1 | cut -d= -f2-
}

assert_fixture() {
    local want_cap="$1" want_depth="$2" got_cap got_depth
    got_cap=$(running_env LLB_PD_MAX_INFLIGHT_PER_EP)
    got_depth=$(running_env LLB_PD_QUEUE_DEPTH_PER_EP)
    assert "fixture: running llb1 has cap=${want_cap} (got '${got_cap}')" \
        "$([[ "$got_cap" == "$want_cap" ]] && echo 1 || echo 0)"
    assert "fixture: running llb1 has queue_depth=${want_depth} (got '${got_depth}')" \
        "$([[ "$got_depth" == "$want_depth" ]] && echo 1 || echo 0)"
}

# ── holders ───────────────────────────────────────────────────────────────────────────
# The cap is a statement about requests that OVERLAP, so the drive needs genuine
# concurrency: each holder must still be in flight when the next one is selected. Against
# a hanging backend a holder sits in PD_PHASE_PREFILL_WAITING and keeps its active_conns
# increment, which is what fills the pool.
#
# The holders land on three DISTINCT prefill EPs by the mechanism under test rather than by
# luck: at cap=1 an EP with one in-flight request is at cap, so the selector EXCLUDES it and
# holder 2 cannot re-pick holder 1's EP. The stagger only keeps the selections ordered.
start_holders() {
    local i
    HOLDER_PIDS=""
    for i in $(seq 1 ${HOLD_N}); do
        ( $hexec l3h1 curl -s -o /dev/null --max-time 120 \
            -X POST "http://${VIP}:${VPORT}/v1/completions" \
            -H 'Content-Type: application/json' \
            -d "{\"model\":\"mock\",\"prompt\":\"holder-${i}\",\"max_tokens\":8}" \
            >/dev/null 2>&1 ) &
        HOLDER_PIDS="${HOLDER_PIDS} $!"
        sleep 0.4
    done
    sleep 2   # let the last holder reach the backend and bank its active_conns
}

stop_holders() {
    local pid
    for pid in ${HOLDER_PIDS}; do kill "${pid}" >/dev/null 2>&1 || true; done
    wait 2>/dev/null || true
    HOLDER_PIDS=""
}

faults_on()  { local ns; for ns in ${PREFILL_NS}; do sudo "${FAULT_SWAP}" "${ns}" hang >/dev/null || return 1; done; }
faults_off() { local ns; for ns in ${PREFILL_NS}; do sudo "${FAULT_SWAP}" "${ns}" off  >/dev/null || true; done; }

echo "#########################################"
echo "P/D bounded-admission gate"
echo "#########################################"

[[ -x "${FAULT_SWAP}" ]] || { echo "FATAL: fault machinery not found at ${FAULT_SWAP}"; exit 1; }

# ── why every arm releases the fault BEFORE it settles ────────────────────────────────
# Control-plane health demotes an unresponsive backend after roughly 19s, and a demoted EP
# leaves healthy_elig — which means the all-capped guard (healthy_elig > 0 && under_cap == 0)
# stops being true and the ENTIRE admission block becomes unreachable. Every counter then
# reads flat and the client hangs, which presents exactly like a dead feature.
#
# This was measured here, not assumed: a first cut of this stage held the fault across the
# 14s settle, and the requests issued after ~19s produced flat counters and an empty
# %{http_code} while the requests issued before it shed correctly with healthy_elig==3.
#
# So the settle — which only waits for the POLLED metrics pipeline (PrometheusDefaultPeriod
# = 10s), never for the product to decide anything — happens with the bed healthy. The
# admission verdict is taken at selection time and is already banked in the counter before
# the holders are released, so releasing early changes nothing except the exposure window.
arm_down() { stop_holders; faults_off; }

#################################################################################
# PHASE A — queueing OFF (depth 0): the plain shed site is the ONLY reachable one
#################################################################################
echo ""
echo "=== phase A (cap=1, queue_depth=0) — plain admission shed ==="

assert_fixture 1 0

# ── A-control: fill the pool EXACTLY, and no further ──────────────────────────────────
# Three overlapping requests against a 3-EP pool at cap=1 leave under_cap non-zero at the
# moment of EVERY selection — holder 3 still finds the third EP free — so nothing may shed.
# This control is one request away from the drive, which is what makes it strong: it rules
# out a cap that sheds merely because requests are concurrent, or because a backend hangs.
a_shed_b=$(adm_shed); a_qd_b=$(adm_queued); a_ov_b=$(adm_overflow)
a_shedlog_b=$(dplog_count "${L_SHED}")

faults_on || { echo "FATAL: could not put the prefill EPs behind hanging backends"; exit 1; }
start_holders
arm_down
sleep "${SETTLE}"

a_shed_c=$(adm_shed)
a_shedlog_c=$(dplog_count "${L_SHED}")
d_shed_ctl=$(( a_shed_c - a_shed_b ))
d_shedlog_ctl=$(( a_shedlog_c - a_shedlog_b ))

assert "A-control: ${HOLD_N} overlapping requests exactly fill the pool — shed FLAT (Δ${d_shed_ctl})" \
    "$([[ "$d_shed_ctl" == 0 ]] && echo 1 || echo 0)"
assert "A-control: no plain-shed log line was written (Δ${d_shedlog_ctl})" \
    "$([[ "$d_shedlog_ctl" == 0 ]] && echo 1 || echo 0)"
assert "A-control: the datapath log was readable (not a vacuous flat reading)" \
    "$([[ "$a_shedlog_c" -ge 0 ]] && echo 1 || echo 0)"

# ── A-drive: one more request than the pool can hold ──────────────────────────────────
# The holders stay in flight, so every one of the PROBE_N probes meets a fully capped pool.
a_shed_b2=$(adm_shed); a_qd_b2=$(adm_queued); a_ov_b2=$(adm_overflow)
a_shedlog_b2=$(dplog_count "${L_SHED}")
a_loose_b2=$(dplog_count "${L_LOOSE}")
a_ovlog_b2=$(dplog_count "${L_OVERFLOW}")
a_pool3_b2=$(dplog_count "${POOL3_SHED}")

probe_codes="${CFGDIR}/.adm-a-codes"
body_file="${CFGDIR}/.adm-a-body"
: > "${probe_codes}"; : > "${body_file}"

faults_on || { echo "FATAL: could not put the prefill EPs behind hanging backends"; exit 1; }
start_holders

# Probe 1 keeps its BODY as well as its code. The shed receipt leaves through the RESPONSE
# path and never traverses the metrics pipeline, so counter and receipt agreeing is two
# independent oracles rather than one read twice — but it must be one of the batch, not an
# extra serialized request afterwards: an earlier cut of this stage fired it separately and
# it landed past the health-demotion window described above, scoring a real shed as absent.
for i in $(seq 1 ${PROBE_N}); do
    if [[ "$i" == 1 ]]; then out="${body_file}"; else out=/dev/null; fi
    ( $hexec l3h1 curl -s -o "${out}" --max-time 20 -w '%{http_code}\n' \
        -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' \
        -d "{\"model\":\"mock\",\"prompt\":\"probe-a-${i}\",\"max_tokens\":8}" \
        >> "${probe_codes}" 2>/dev/null ) &
done
wait

arm_down
sleep "${SETTLE}"
body_429=$(cat "${body_file}" 2>/dev/null)

a_shed_d=$(adm_shed); a_qd_d=$(adm_queued); a_ov_d=$(adm_overflow)
a_shedlog_d=$(dplog_count "${L_SHED}")
a_loose_d=$(dplog_count "${L_LOOSE}")
a_ovlog_d=$(dplog_count "${L_OVERFLOW}")
a_pool3_d=$(dplog_count "${POOL3_SHED}")

d_shed=$(( a_shed_d - a_shed_b2 ))
d_qd=$(( a_qd_d - a_qd_b2 ))
d_ov=$(( a_ov_d - a_ov_b2 ))
d_shedlog=$(( a_shedlog_d - a_shedlog_b2 ))
d_loose=$(( a_loose_d - a_loose_b2 ))
d_ovlog=$(( a_ovlog_d - a_ovlog_b2 ))
d_pool3=$(( a_pool3_d - a_pool3_b2 ))

n_codes=$(count_lines . "${probe_codes}")
n_429=$(count_lines '^429$' "${probe_codes}")

# An empty %{http_code} is a failed curl SPAWN, not a gateway answer — a lost measurement
# must not be scored as a non-429.
assert "A-drive: all ${PROBE_N} probes produced a measurement (got ${n_codes})" \
    "$([[ "$n_codes" == "${PROBE_N}" ]] && echo 1 || echo 0)"
assert "A-drive: shed counter moved once per probe (Δ${d_shed}, want ${PROBE_N})" \
    "$([[ "$d_shed" == "${PROBE_N}" ]] && echo 1 || echo 0)"
assert "A-drive: Δcounter == Δplain-shed log lines (${d_shed} == ${d_shedlog})" \
    "$([[ "$d_shed" == "$d_shedlog" ]] && echo 1 || echo 0)"
assert "A-drive: ${PROBE_N} probes all received 429 (got ${n_429})" \
    "$([[ "$n_429" == "${PROBE_N}" ]] && echo 1 || echo 0)"
assert "A-drive: the shed receipt is pd_overloaded at in-flight capacity" \
    "$(echo "${body_429}" | grep -q 'pd_overloaded' && echo "${body_429}" | grep -q 'all prefill endpoints at in-flight capacity' && echo 1 || echo 0)"

# Drive shape read out of the product's own line: every shed must name a pool of THREE.
assert "A-drive: every shed line reports healthy_elig==3 (${d_pool3} of ${d_shedlog})" \
    "$([[ "$d_pool3" == "$d_shedlog" ]] && [[ "$d_shedlog" -gt 0 ]] && echo 1 || echo 0)"

# Attribution — the depth-0 branch ran, and the queueing branches did not. At depth 0 these
# are structurally unreachable, so a movement here means the fixture is not what it claims.
assert "A-attribution: park site silent at depth 0 (Δ${d_qd})" \
    "$([[ "$d_qd" == 0 ]] && echo 1 || echo 0)"
assert "A-attribution: overflow site silent at depth 0 (Δ${d_ov})" \
    "$([[ "$d_ov" == 0 ]] && echo 1 || echo 0)"
assert "A-attribution: no overflow log line at depth 0 (Δ${d_ovlog})" \
    "$([[ "$d_ovlog" == 0 ]] && echo 1 || echo 0)"
# Self-verifying discriminator: the loose count spans plain AND overflow, so if the plain
# pattern ever stopped discriminating this identity breaks instead of quietly passing.
assert "A-drive: loose shed_total count == plain + overflow (${d_loose} == ${d_shedlog} + ${d_ovlog})" \
    "$([[ "$d_loose" == "$(( d_shedlog + d_ovlog ))" ]] && echo 1 || echo 0)"

rm -f "${probe_codes}" "${body_file}" >/dev/null 2>&1 || true

#################################################################################
# RE-FIXTURE — the only way to change a getenv-once knob is a new process
#################################################################################
echo ""
echo "=== re-fixture: rebuilding the bed at queue_depth=2 ==="

pid_before=$(docker inspect -f '{{.State.Pid}}' llb1 2>/dev/null || echo "none")

"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true
ADM_CAP=1 ADM_QUEUE_DEPTH=2 "${CFGDIR}/config.sh" >/dev/null 2>&1 || {
    echo "FATAL: re-fixture config.sh failed at queue_depth=2"; exit 1; }

pid_after=$(docker inspect -f '{{.State.Pid}}' llb1 2>/dev/null || echo "none")

# A re-fixture that silently did not happen would leave phase B driving the phase A binary
# and reading its (unreachable) sites as a product defect. Prove the process really changed.
assert "re-fixture: llb1 is a NEW process (pid ${pid_before} -> ${pid_after})" \
    "$([[ "$pid_before" != "$pid_after" ]] && [[ "$pid_after" != "none" ]] && echo 1 || echo 0)"

#################################################################################
# PHASE B — queueing ON (depth 2): park and overflow are the ONLY reachable sites
#################################################################################
echo ""
echo "=== phase B (cap=1, queue_depth=2) — park and overflow shed ==="

assert_fixture 1 2

# ── B-control: fill the pool exactly — nothing may park ───────────────────────────────
b_qd_b=$(adm_queued); b_ov_b=$(adm_overflow); b_shed_b=$(adm_shed)
b_qdlog_b=$(dplog_count "${L_QUEUED}")

faults_on || { echo "FATAL: could not put the prefill EPs behind hanging backends"; exit 1; }
start_holders
arm_down
sleep "${SETTLE}"

d_qd_ctl=$(( $(adm_queued) - b_qd_b ))
d_qdlog_ctl=$(( $(dplog_count "${L_QUEUED}") - b_qdlog_b ))

assert "B-control: ${HOLD_N} overlapping requests fill the pool without parking (Δ${d_qd_ctl})" \
    "$([[ "$d_qd_ctl" == 0 ]] && echo 1 || echo 0)"
assert "B-control: no park log line was written (Δ${d_qdlog_ctl})" \
    "$([[ "$d_qdlog_ctl" == 0 ]] && echo 1 || echo 0)"

# ── B-drive: park to capacity, then one request past it — in ONE window ───────────────
# The park selector takes the eligible EP with the SHORTEST FIFO and admits only while that
# FIFO is strictly under the bound, so 3 EPs at depth 2 hold EXACTLY 6. Six is the whole
# point of depth 2 rather than depth 1: at depth 1 a drive that was off by one would still
# land in the branch it aimed for, and this assert could not tell the difference.
#
# 🚨 THE PARK AND THE OVERFLOW MUST SHARE ONE WINDOW, AND THE REASON IS NOT TIDINESS.
# A parked entry leaves the FIFO when its client DISCONNECTS, not when it is answered. An
# earlier cut of this stage parked six probes, let them time out, settled, and only then
# drove the overflow — by which time all six had disconnected, every FIFO was empty again,
# and the "overflow" request simply PARKED and hung. It scored Δoverflow 0 with an empty
# %{http_code}, which reads as a dead valve rather than as a harness that dismantled its own
# precondition. So the overflow probes are fired while the park probes are still connected.
#
# A parked client is SUSPENDED (fd held open, EPOLLIN-paused) and LLB_PD_MAX_PARK_SEC
# defaults to 0 (no reap), so a parked probe never answers. Its receipt is therefore curl's
# EXIT CODE 28 (operation timeout) — a positive statement that the request was HELD, which
# is exactly what distinguishes a park from a shed at the client. The overflow probes, by
# contrast, must answer 429 immediately; that difference in client-visible behaviour is the
# only thing separating the two branches from outside the process.
b_qd_b2=$(adm_queued); b_ov_b2=$(adm_overflow); b_shed_b2=$(adm_shed)
b_qdlog_b2=$(dplog_count "${L_QUEUED}")
b_ovlog_b2=$(dplog_count "${L_OVERFLOW}")
b_looselog_b2=$(dplog_count "${L_LOOSE}")
b_shedlog_b2=$(dplog_count "${L_SHED}")
b_pool3over_b2=$(dplog_count "${POOL3_OVER}")

park_rcs="${CFGDIR}/.adm-b-park-rcs"
: > "${park_rcs}"

faults_on || { echo "FATAL: could not put the prefill EPs behind hanging backends"; exit 1; }
start_holders

for i in $(seq 1 ${PROBE_N}); do
    ( $hexec l3h1 curl -s -o /dev/null --max-time 8 \
        -X POST "http://${VIP}:${VPORT}/v1/completions" \
        -H 'Content-Type: application/json' \
        -d "{\"model\":\"mock\",\"prompt\":\"probe-b-park-${i}\",\"max_tokens\":8}" \
        >/dev/null 2>&1; echo "$?" >> "${park_rcs}" ) &
done

# Let all six reach the park branch, then overflow while they are still holding their slots.
# This sleep is bounded well inside the park probes' 8s budget on purpose: it must land
# after the last park and before the first disconnect.
sleep 3

ov_body=$($hexec l3h1 curl -s --max-time 10 \
    -X POST "http://${VIP}:${VPORT}/v1/completions" \
    -H 'Content-Type: application/json' \
    -d '{"model":"mock","prompt":"probe-b-overflow","max_tokens":8}' 2>/dev/null)
ov_code=$($hexec l3h1 curl -s -o /dev/null --max-time 10 -w '%{http_code}' \
    -X POST "http://${VIP}:${VPORT}/v1/completions" \
    -H 'Content-Type: application/json' \
    -d '{"model":"mock","prompt":"probe-b-overflow2","max_tokens":8}' 2>/dev/null)

wait
arm_down
sleep "${SETTLE}"

d_qd=$(( $(adm_queued) - b_qd_b2 ))
d_ov=$(( $(adm_overflow) - b_ov_b2 ))
d_shed_b=$(( $(adm_shed) - b_shed_b2 ))
d_qdlog=$(( $(dplog_count "${L_QUEUED}") - b_qdlog_b2 ))
d_ovlog=$(( $(dplog_count "${L_OVERFLOW}") - b_ovlog_b2 ))
d_looselog=$(( $(dplog_count "${L_LOOSE}") - b_looselog_b2 ))
d_shedlog=$(( $(dplog_count "${L_SHED}") - b_shedlog_b2 ))
d_pool3over=$(( $(dplog_count "${POOL3_OVER}") - b_pool3over_b2 ))

n_parkrc=$(count_lines . "${park_rcs}")
n_held=$(count_lines '^28$' "${park_rcs}")

assert "B-drive: all ${PROBE_N} park probes produced a measurement (got ${n_parkrc})" \
    "$([[ "$n_parkrc" == "${PROBE_N}" ]] && echo 1 || echo 0)"
assert "B-drive: park counter moved by exactly the FIFO capacity (Δ${d_qd}, want ${PROBE_N})" \
    "$([[ "$d_qd" == "${PROBE_N}" ]] && echo 1 || echo 0)"
assert "B-drive: Δcounter == Δpark log lines (${d_qd} == ${d_qdlog})" \
    "$([[ "$d_qd" == "$d_qdlog" ]] && echo 1 || echo 0)"
assert "B-drive: every park probe was HELD, not answered (curl 28 x ${n_held})" \
    "$([[ "$n_held" == "${PROBE_N}" ]] && echo 1 || echo 0)"

# The exact split is what attributes the window: had the six park probes overflowed instead
# of parking, Δqueued would be short and Δoverflow long by the same amount. Asserting both
# numbers pins which branch each of the eight requests took.
assert "B-overflow: counter moved by exactly the two overflow requests (Δ${d_ov}, want 2)" \
    "$([[ "$d_ov" == 2 ]] && echo 1 || echo 0)"
assert "B-overflow: Δcounter == Δoverflow log lines (${d_ov} == ${d_ovlog})" \
    "$([[ "$d_ov" == "$d_ovlog" ]] && echo 1 || echo 0)"
assert "B-overflow: the client receipt is 429, not a hang (got ${ov_code})" \
    "$([[ "$ov_code" == "429" ]] && echo 1 || echo 0)"
assert "B-overflow: the overflow receipt is pd_overloaded" \
    "$(echo "${ov_body}" | grep -q 'pd_overloaded' && echo 1 || echo 0)"

# The headline attribution: at depth 2 the plain-shed site cannot be reached at all. This is
# what separates the two shed families — at the client they are byte-identical.
assert "B-attribution: plain-shed site unreachable at depth 2 (Δ${d_shed_b})" \
    "$([[ "$d_shed_b" == 0 ]] && echo 1 || echo 0)"
assert "B-attribution: no plain-shed log line at depth 2 (Δ${d_shedlog})" \
    "$([[ "$d_shedlog" == 0 ]] && echo 1 || echo 0)"
assert "B-overflow: every overflow line reports healthy_elig==3 (${d_pool3over} of ${d_ovlog})" \
    "$([[ "$d_pool3over" == "$d_ovlog" ]] && [[ "$d_ovlog" -gt 0 ]] && echo 1 || echo 0)"
# Self-verifying discriminator, same identity as phase A but with the plain side as the zero.
assert "B-drive: loose shed_total count == plain + overflow (${d_looselog} == ${d_shedlog} + ${d_ovlog})" \
    "$([[ "$d_looselog" == "$(( d_shedlog + d_ovlog ))" ]] && echo 1 || echo 0)"

stop_holders
faults_off
rm -f "${park_rcs}" >/dev/null 2>&1 || true

#################################################################################
# Teardown + sentinel
#################################################################################
echo ""
"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true

if [[ "$code" == 0 ]]; then
    echo "=== SCENARIO-vllm-pd-admission-cpu [OK] ==="
else
    echo "=== SCENARIO-vllm-pd-admission-cpu [FAILED] ==="
fi
exit "$code"
