#!/bin/bash
# lib.sh — simulator lifecycle shared by config.sh and validation.sh.
# Sourced, never executed. Requires ../common.sh already sourced ($hexec).

KVSGL_CFGDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KVSGL_KVHASH="${KVSGL_CFGDIR}/../common/kv_hash"
KVSGL_TOK="${KVSGL_KVHASH}/fixtures/tokenizers/Qwen__Qwen3-0.6B/tokenizer.json"

# sim_pids: /proc-scan for the simulators. External kill/pkill binaries are
# DISABLED stubs on the CI host — every signal must go through the shell
# BUILTIN kill against explicit pids, or the action silently no-ops (the
# kv-mixed-version suite learned this live).
kvsgl_sim_pids() {
    local d p
    for d in /proc/[0-9]*/cmdline; do
        if tr "\0" " " < "$d" 2>/dev/null | grep -q "sglang_attest_sim.py"; then
            p="${d#/proc/}"; echo "${p%/cmdline}"
        fi
    done
}

sims_stop() {
    local p
    for p in $(kvsgl_sim_pids); do kill -9 "$p" 2>/dev/null; done
    rm -f "${KVSGL_CFGDIR}/.sim-pids"
    sleep 1
}

# sims_start <fail-mode-or-empty> <dp-ranks> — one sim per EP netns.
sims_start() {
    local fail="$1" ranks="$2" ns failarg=""
    [[ -n "$fail" ]] && failarg="--fail $fail"
    rm -f "${KVSGL_CFGDIR}/.sim-pids"
    for ns in l3ep1 l3ep2; do
        nohup sudo ip netns exec "$ns" python3 "${KVSGL_KVHASH}/sglang_attest_sim.py" \
            --tokenizer "${KVSGL_TOK}" --model "Qwen/Qwen3-0.6B" \
            --http-port 80 --zmq-port 5557 --dp-ranks "$ranks" \
            --block-size 16 ${failarg} \
            > "/tmp/kvsgl-sim-${ns}.log" 2>&1 &
        echo $! >> "${KVSGL_CFGDIR}/.sim-pids"
    done
    # Readiness: /get_server_info answers in both netns.
    local tries
    for ns in l3ep1 l3ep2; do
        for tries in $(seq 1 20); do
            $hexec "$ns" curl -s -m 2 -o /dev/null http://127.0.0.1:80/get_server_info && break
            sleep 0.5
        done
    done
    sleep 1  # PUB slow-joiner margin beyond the sim's own guard
}
