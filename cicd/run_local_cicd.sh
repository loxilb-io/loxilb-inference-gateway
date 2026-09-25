#!/bin/bash
set -e

# CLI validation as a first-class pre-release gate.
#
# The inference-gateway loxicmd CLI is exercised two ways, both keyed off the
# CLI_TESTS knob consumed by cli_preflight() in common.sh:
#   1. Config path — ~18 proxy/mcp/vllm/mtls scenarios drive `loxicmd` as the
#      load-bearing config path in their config.sh (USE_CLI gate).
#   2. Dedicated CLI tests — the ai-apikey / ai-model-routing / ai-sse-quota
#      scenarios run validate_cli.sh (CLI mutation, REST oracle); each is folded
#      into that scenario's validation.sh exit code.
#
# Default CLI_TESTS=auto SKIPS the CLI when the image predates the packaging swap.
# For a release pre-flight we want the CLI actually validated, so default to
# 'required' here: a missing/broken AI-capable loxicmd hard-fails the suite
# instead of silently falling back to REST. Override for an old image with
#   CLI_TESTS=auto ./run_local_cicd.sh   (or CLI_TESTS=skip to skip CLI entirely)
export CLI_TESTS="${CLI_TESTS:-required}"

# Every scenario runs through the wrapper: cleanup always happens, the original
# failure survives it, and one broken scenario no longer hides every scenario
# after it. See cicd/scenario_runner.sh.
source "$(dirname "$0")/scenario_runner.sh"

# Cheap gates first — none of these needs a container.
scenario_preflight

run_scenario sconnect -- './config.sh' './validation.sh'

run_scenario tcplb -- './config.sh' './validation.sh'

run_scenario tcplbmark -- './config.sh' './validation.sh'

run_scenario tcplbdsr1 -- './config.sh' './validation.sh'

run_scenario tcplbdsr2 -- './config.sh' './validation.sh'

run_scenario tcplbl3dsr -- './config.sh' './validation.sh'

run_scenario tcplbhash -- './config.sh' './validation.sh'


run_scenario sctplb -- './config.sh' './validation.sh'

run_scenario sctponearm -- './config.sh' './validation.sh'

run_scenario sctplbdsr -- './config.sh' './validation.sh'

run_scenario tcplbmon -- './config.sh' './validation.sh'

run_scenario tcplbmon-epstat -- './config.sh' './validation.sh'
    
run_scenario udplbmon -- './config.sh' './validation.sh'
 
run_scenario sctplbmon -- './config.sh' './validation.sh'
  
run_scenario tcplbmon6 -- './config.sh' './validation.sh'

run_scenario tcplbepmod -- './config.sh' './validation.sh'

run_scenario lbtimeout -- './config.sh' './validation.sh'

run_scenario lb6timeout -- './config.sh' './validation.sh'

run_scenario tcpsctpperf -- './config.sh' './validation.sh 20  30'

run_scenario http2ep -- './config.sh' './validation.sh'

run_scenario e2ehttpsproxy -- './config.sh' './validation-http1.sh' './validation-http2.sh'

run_scenario e2ehttpsproxy-prefix -- './config.sh' './validation-http1.sh' './validation-http2.sh'

run_scenario e2ehttpsproxy-grpc -- './config.sh' './validation.sh'

run_scenario httpproxy -- './config.sh' './validation.sh' './validation-http2.sh'

run_scenario httpproxy-prefix -- './config.sh' './validation.sh' './validation-http2.sh'

run_scenario httpsproxy -- './config.sh' './validation.sh' './validation-http2.sh'

run_scenario httpsproxy-prefix -- './config.sh' './validation.sh' './validation-http2.sh'

# fullnat: eBPF L4 dp_ins_ppv2 GSO fix. EXPECT=fixed is the post-fix regression
# gate; the default EXPECT=bug asserts the historical #1044/#1089 bug REPRODUCES,
# which no longer happens now that the GSO fix has landed (so it would fail).
run_scenario tlsproxyprotov2 'tlsproxyprotov2 (fullnat)' -- './config.sh' 'EXPECT=fixed ./validation.sh'
# fullproxy: L7 userspace sockproxy PPv2 header emit (a separate testbed setup -
# plaintext proxy_protocol backends + a fullproxy LB rule).
run_scenario tlsproxyprotov2 'tlsproxyprotov2 (fullproxy)' -- 'PPV2MODE=fullproxy ./config.sh' 'PPV2MODE=fullproxy ./validation.sh'

run_scenario vllm-fullproxy -- './config.sh' './validation-level1.sh'

run_scenario vllm-httpproxy -- './config.sh' './validation-level1.sh'

run_scenario vllm-fullproxy-wrr -- './config.sh' './validation-level1.sh'

run_scenario vllm-httpproxy-wrr -- './config.sh' './validation-level1.sh'

run_scenario mcp-fullproxy -- './config.sh' './validation.sh'

run_scenario mcp-httpproxy -- './config.sh' './validation.sh'

run_scenario mcp-e2ehttps -- './config.sh' './validation.sh'

run_scenario httpsproxy-mtls -- './config.sh' './validation.sh'

run_scenario e2ehttpsproxy-mtls -- './config.sh' './validation.sh'

# ai-apikey / ai-model-routing / ai-sse-quota: their validation.sh runs the REST
# suite and then bash validate_cli.sh (CLI-driven, REST oracle). With the
# CLI_TESTS=required default above, the CLI half is enforced, not skipped.
run_scenario ai-apikey -- './config.sh' './validation.sh'

run_scenario ai-model-routing -- './config.sh' './validation.sh'

run_scenario ai-sse-quota -- './config.sh' './validation.sh'

# ai-ephealth: the lightweight endpoint-health path — one probe transition has
# to reach every pool that shares the failed backend, not just the first. The
# oracle is the datapath's per-pool receipt lines, not traffic: the full
# rule-sync fallback converges seconds later, so a broken health mechanism
# still passes every traffic assertion.
run_scenario ai-ephealth -- './config.sh' './validation.sh'

# ai-model-conflict: the effective-model contract on enforcing services —
# one body-first model resolution shared by authorization and routing, and a
# hard 400 when a request's body and X-Model header disagree.
run_scenario ai-model-conflict -- './config.sh' './validation.sh'

# ai-jwtauth: the bearer (JWT) admission arm against a real Keycloak realm —
# the token verdict ladder, apikey-or-jwt precedence, upstream header
# hygiene, and the fail-closed postures (HTTP/2, unreachable JWKS). Builds
# loxilb-aigw-keycloak:26.0-aigw on first use and reuses it afterwards
# (cicd/ai-jwtauth/keycloak/build.sh); config.sh also pulls postgres:18.6 for
# the key store the precedence legs need.
run_scenario ai-jwtauth -- './config.sh' './validation.sh'

# ai-authsep: the authentication-plane regression, container-only (no GPU) —
# the same four suites the auth-plane-sanity workflow runs. validation.sh is
# the four-cell {userservice x key store} matrix with role isolation, verified
# TLS and enforcement mechanics; tiers.sh sweeps management-auth mode x store
# state x key policy x streaming shape; backcompat.sh pins the upgrade
# contract for pre-policy rule bodies and exported backups. Needs minica on
# PATH (the TLS legs mint their own CA) and python3 (the counting backend);
# config.sh pulls postgres:18.6 for the two credential stores. See the
# suite's README for the reference green counts.
run_scenario ai-authsep -- './config.sh' './validation.sh' './tiers.sh' './backcompat.sh'

# audit-mgmt: the management-plane audit trail, container-only (no GPU) —
# the same suite the audit-sanity workflow runs. The gate fails closed with
# the state unchanged, actors are attributed or honestly auth=none, canary
# secrets reach no segment, a crash between intent and result is reported
# at the next boot, a full audit filesystem is visible on /metrics and in
# the log before the retroactive record, and the delegated originator is
# recorded and trusted only for accounts marked delegation_allowed. Needs
# jq on the host; config.sh pulls postgres:18.6 for the two stores. The
# coverage manifest next to it names which assertion proves which event
# type (cicd/audit-mgmt/gen-coverage-manifest.py --check).
run_scenario audit-mgmt -- './config.sh' './validation.sh'

# audit-data: the inference path's own trail, container-only (no GPU) — the
# data-stream half of the same workflow. A request's completion, its token
# settle and any refusal carry one correlation key and are joined by it; the
# tokens recorded are the tokens charged, including a body split across
# segments; every refusal names the identity its arm resolved, and no segment
# carries a raw credential. The saturation arms stall the writer on purpose,
# so the image MUST carry the audit_faults tag:
#
#   make HAVE_AUDIT_FAULTS=1 && make docker-cp HAVE_AUDIT_FAULTS=1 dock=<name>
#
# A bare docker-cp re-runs build without the tag and ships a writer that
# cannot be stalled; validation.sh reads the tag off --version and fails
# rather than skipping, so it will say so. Allow about 25 minutes: the stall
# costs a second a record, and its budget is spent before the backlog drains.
# Needs jq on the host; config.sh pulls postgres:18.6 for the key store.
run_scenario audit-data -- './config.sh' './validation.sh'

# AI QoS on the mock topology (no GPU): rule-attached ingress policing,
# full-proxy payload shaping, and egress-direction policing. The per-engine
# QoS acceptance (token quotas end-to-end against real inference engines)
# needs GPUs and runs on the testbed out of band; these three gate the
# datapath mechanics that do not.
run_scenario qos-rulepol -- './config.sh' './validation.sh'

run_scenario qos-fullproxy -- './config.sh' './validation.sh'

run_scenario qos-egrpol -- './config.sh' './validation.sh'

run_scenario vllm-pd-disagg -- './config.sh' './validation.sh'

run_scenario sglang-pd-disagg -- './config.sh' './validation.sh'

run_scenario trtllm-pd-disagg -- './config.sh' './validation.sh'

run_scenario llamacpp-lb -- './config.sh' './validation.sh'

run_scenario vllm-kvcache-routing-cpu -- './config.sh' './validation.sh'

# backward-compat: vllm-pd-disagg must still pass on a runner that has just run
# vllm-kvcache-routing-cpu. Both scenarios name their backends l3ep1/l3ep2, and
# pd-disagg's apt-install aborts if it execs into the alpine reflect-echo image
# the KV scenario leaves behind, so the clean handoff is a real claim worth
# scoring. It used to be scored as a nested re-run inside the KV scenario's own
# validation.sh, which put two scenarios' runtime inside ONE step's
# SCENARIO_TIMEOUT — a budget that could not be satisfied once either grew, and
# which killed the nested run mid-phase with no verdict in the log.
#
# Deliberately NO pre-clean here. The nested version tore the KV containers down
# itself, which masked the only interesting failure: the KV scenario's own
# rmconfig.sh is what has to leave the runner usable, and LEAK_STRICT fails the
# scenario if it does not.
run_scenario vllm-pd-disagg vllm-pd-disagg-after-kvcache -- './config.sh' './validation.sh'

run_scenario sglang-loxilb-kvcache -- './config.sh' './validation.sh'

run_scenario k8slbsim -- './config.sh' './validation.sh'

run_scenario onearml2 -- './config.sh' './validation.sh'

run_scenario tcptunlb -- './config.sh' './validation.sh'

run_scenario sctptunlb -- './config.sh' './validation.sh'

run_scenario wrrtcplb1 -- './config.sh' './validation.sh'

run_scenario wrrtcplb2 -- './config.sh' './validation.sh'

run_scenario nat64tcp -- './config.sh' './validation.sh'

run_scenario tcplbmaxep -- './config.sh' './validation.sh'

run_scenario ipmasquerade -- './config.sh' './validation.sh'

run_scenario tcplb-src -- './config.sh' './validation.sh'

run_scenario udplb-persist -- './config.sh' './validation.sh'

# One honest verdict for the whole run. Non-zero when anything failed.
scenario_summary
