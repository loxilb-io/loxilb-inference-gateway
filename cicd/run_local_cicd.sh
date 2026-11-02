#!/bin/bash
set -e

# CLI validation as a first-class pre-release gate.
#
# The inference-gateway loxicmd CLI is exercised two ways, both keyed off the
# CLI_TESTS knob consumed by cli_preflight() in common.sh:
#   1. Config path — ~18 proxy/mcp/vllm/mtls scenarios drive `loxicmd` as the
#      load-bearing config path in their config.sh (USE_CLI gate).
#   2. Dedicated CLI tests — the ai-apikey / ai-model-routing / ai-sse-quota /
#      ai-tenant / ai-jwtauth scenarios run validate_cli.sh (CLI mutation, REST
#      oracle); each is folded into that scenario's validation exit code. The
#      feature-specific halves have their own preflight (bands_cli_preflight,
#      jwtauth_cli_preflight) on the same CLI_TESTS knob.
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

# A scenario marked --needs sctp, ipv6 or minica is skipped, with the reason,
# on a bed that lacks it (see preflight-caps.sh): an IPv6-less kernel cannot
# run the NAT66 suites, and a missing libsctp fails the SCTP ones at load time.
# ONLY / SKIP select a subset; see scenario_runner.sh.

# The image under test, resolved the way common.sh resolves it, for the two
# scenarios that take it as a parameter instead (kv-mixed-version and
# cfg-persist-upgrade run an old and a new image side by side).
# kv-mixed-version's own fallback, kv-p6-ci, is a tag only its CI job builds.
if [[ -n ${LOXILB_DOCKER_IMAGE:-} ]]; then
  IMAGE_UNDER_TEST=$LOXILB_DOCKER_IMAGE
  [[ $IMAGE_UNDER_TEST != *"/"* && $IMAGE_UNDER_TEST != *":"* ]] &&
    IMAGE_UNDER_TEST="ghcr.io/loxilb-io/loxilb-inference-gateway:$IMAGE_UNDER_TEST"
elif [[ $(lsb_release -r 2>/dev/null | cut -f2) == *"24.04"* ]]; then
  IMAGE_UNDER_TEST="ghcr.io/loxilb-io/loxilb-inference-gateway:main-u24"
else
  IMAGE_UNDER_TEST="ghcr.io/loxilb-io/loxilb-inference-gateway:main"
fi

# Cheap gates first — none of these needs a container.
scenario_preflight

run_scenario sconnect -- './config.sh' './validation.sh'

run_scenario tcplb -- './config.sh' './validation.sh'

run_scenario tcplbmark -- './config.sh' './validation.sh'

run_scenario tcplbdsr1 -- './config.sh' './validation.sh'

run_scenario tcplbdsr2 -- './config.sh' './validation.sh'

run_scenario tcplbl3dsr -- './config.sh' './validation.sh'

run_scenario tcplbhash -- './config.sh' './validation.sh'


run_scenario --needs sctp sctplb -- './config.sh' './validation.sh'

run_scenario --needs sctp sctponearm -- './config.sh' './validation.sh'

run_scenario --needs sctp sctplbdsr -- './config.sh' './validation.sh'

run_scenario tcplbmon -- './config.sh' './validation.sh'

run_scenario tcplbmon-epstat -- './config.sh' './validation.sh'
    
run_scenario udplbmon -- './config.sh' './validation.sh'
 
run_scenario --needs sctp sctplbmon -- './config.sh' './validation.sh'
  
run_scenario --needs ipv6 tcplbmon6 -- './config.sh' './validation.sh'

run_scenario tcplbepmod -- './config.sh' './validation.sh'

run_scenario lbtimeout -- './config.sh' './validation.sh'

run_scenario --needs ipv6 lb6timeout -- './config.sh' './validation.sh'

run_scenario tcpsctpperf -- './config.sh' './validation.sh 20  30'

run_scenario --needs minica http2ep -- './config.sh' './validation.sh'

run_scenario --needs minica e2ehttpsproxy -- './config.sh' './validation-http1.sh' './validation-http2.sh'

run_scenario e2ehttpsproxy-prefix -- './config.sh' './validation-http1.sh' './validation-http2.sh'

run_scenario e2ehttpsproxy-betls -- './config.sh' './validation.sh'

run_scenario e2ehttpsproxy-grpc -- './config.sh' './validation.sh'

run_scenario httpproxy -- './config.sh' './validation.sh' './validation-http2.sh'

run_scenario httpproxy-prefix -- './config.sh' './validation.sh' './validation-http2.sh'

run_scenario --needs minica httpsproxy -- './config.sh' './validation.sh' './validation-http2.sh'

run_scenario --needs minica httpsproxy-prefix -- './config.sh' './validation.sh' './validation-http2.sh'

# fullnat: eBPF L4 dp_ins_ppv2 GSO fix. EXPECT=fixed is the post-fix regression
# gate; the default EXPECT=bug asserts the historical #1044/#1089 bug REPRODUCES,
# which no longer happens now that the GSO fix has landed (so it would fail).
run_scenario --needs minica tlsproxyprotov2 'tlsproxyprotov2 (fullnat)' -- './config.sh' 'EXPECT=fixed ./validation.sh'
# fullproxy: L7 userspace sockproxy PPv2 header emit (a separate testbed setup -
# plaintext proxy_protocol backends + a fullproxy LB rule).
run_scenario --needs minica tlsproxyprotov2 'tlsproxyprotov2 (fullproxy)' -- 'PPV2MODE=fullproxy ./config.sh' 'PPV2MODE=fullproxy ./validation.sh'

run_scenario --needs minica vllm-fullproxy -- './config.sh' './validation-level1.sh'

run_scenario --needs minica vllm-httpproxy -- './config.sh' './validation-level1.sh'

run_scenario --needs minica vllm-fullproxy-wrr -- './config.sh' './validation-level1.sh'

run_scenario --needs minica vllm-httpproxy-wrr -- './config.sh' './validation-level1.sh'

run_scenario --needs minica mcp-fullproxy -- './config.sh' './validation.sh'

run_scenario --needs minica mcp-httpproxy -- './config.sh' './validation.sh'

run_scenario --needs minica mcp-e2ehttps -- './config.sh' './validation.sh'

run_scenario --needs minica httpsproxy-mtls -- './config.sh' './validation.sh'

run_scenario --needs minica e2ehttpsproxy-mtls -- './config.sh' './validation.sh'

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
# the key store the precedence legs need. validation.sh ends with
# validate_cli.sh: a JWT auth profile created, read and deleted through
# loxicmd with the REST list as the oracle, enforced by CLI_TESTS=required.
run_scenario ai-jwtauth -- './config.sh' './validation.sh'

# ai-tenant: tenant QoS, the priority bands of the capacity gate — the
# scheduling, release-accounting, h2c-parity and knob cases of
# validation-sched.sh (REQUIRE_ALL=1: a declared case that is still pending
# fails the run, as the PR gate requires), then validate_cli.sh: the same
# configuration and the band knobs through loxicmd with REST as the oracle,
# the --bands table read under load, enforced by CLI_TESTS=required. Needs
# jq, curl and python3 on the host; config.sh pulls postgres:18.6 for the
# tenant and key store. Allow about an hour: the floor and adaptive-ceiling
# cases follow the engines' scraped queue depth.
run_scenario ai-tenant -- './config.sh' 'REQUIRE_ALL=1 ./validation-sched.sh'

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

# audit-sink: the trail leaving the gateway, container-only (no GPU), scored
# at a strict RFC 5425 receiver that stands in for the SIEM: a session only
# to a receiver the configured CA vouches for, nothing lost over a receiver
# outage with or without a gateway restart in it, order kept across a seal,
# a filtered sink's export sequence never used twice, and a segment pruned
# before a sink had it put on record first. The crash arms need the
# audit_faults tag in the image, built as for audit-data; validation.sh
# fails rather than skips without it. Allow about 15 minutes: it restarts
# the gateway a dozen times and waits on the 30-second prune pass. Needs jq,
# openssl and python3 on the host.
run_scenario audit-sink -- './config.sh' './validation.sh'

# AI QoS on the mock topology (no GPU): rule-attached ingress policing,
# full-proxy payload shaping, and egress-direction policing. The per-engine
# QoS acceptance (token quotas end-to-end against real inference engines)
# needs GPUs and runs on the testbed out of band; these three gate the
# datapath mechanics that do not.
run_scenario qos-rulepol -- './config.sh' './validation.sh'

run_scenario qos-fullproxy -- './config.sh' './validation.sh'

run_scenario qos-egrpol -- './config.sh' './validation.sh'

run_scenario --needs minica vllm-pd-disagg -- './config.sh' './validation.sh'

run_scenario --needs minica sglang-pd-disagg -- './config.sh' './validation.sh'

run_scenario --needs minica trtllm-pd-disagg -- './config.sh' './validation.sh'

run_scenario --needs minica llamacpp-lb -- './config.sh' './validation.sh'

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
run_scenario --needs minica vllm-pd-disagg vllm-pd-disagg-after-kvcache -- './config.sh' './validation.sh'

run_scenario sglang-loxilb-kvcache -- './config.sh' './validation.sh'

# AI-gateway admission, KV and P/D suites gated by ai-gateway-sanity, all
# GPU-free. ai-admission: the admission arms, killing root-owned holders from
# a non-root runner. lbreplace / tcplbconnlimit: rule replace in place and
# the per-rule connection limit.
run_scenario ai-admission -- './config.sh' './validation.sh'

run_scenario lbreplace -- './config.sh' './validation.sh'

run_scenario tcplbconnlimit -- './config.sh' './validation.sh'

# vllm-pd-admission-cpu: P/D bounded admission (shed, park, overflow) against
# hanging prefill stubs. vllm-pd-decode-pressure-cpu: the decode selector's
# KV-pressure term, read off each decode mock's own /metrics; its validation
# restarts the gateway between the weight-0 and weight-8 lifecycles. Both run
# as root, as their README and the CI job do.
run_scenario vllm-pd-admission-cpu -- 'sudo -E ./config.sh' 'sudo -E ./validation.sh'

run_scenario vllm-pd-decode-pressure-cpu -- 'sudo -E ./config.sh' 'sudo -E ./validation.sh'

# Strict KV profile admission (refusals, replace-only fields, binding
# identity) and the SGLang attestation rungs through the committed vLLM/SGLang
# simulator in cicd/common/kv_hash, whose self-test gates config.sh.
run_scenario kv-profile-admission -- './config.sh' './validation.sh'

run_scenario kv-sglang-attest -- './config.sh' './validation.sh'

# sockmap-fullproxy: API-key enforcement on a sockmap-accelerated full proxy,
# with the optional PostgreSQL key store. Needs an image built with
# -DHAVE_SOCKOPS, which the Dockerfile's default EXTRA_CFLAGS is.
run_scenario sockmap-fullproxy -- 'SOCKMAP_AI_KEY_STORE=1 ./config.sh' 'SOCKMAP_AI_KEY_STORE=1 ./validation_apikey_response.sh'

# Two gateways on one host, as the ha-two-node-nightly workflow runs them.
# kv-mixed-version pairs the image under test with an older release
# (KV_OLD_IMAGE, default v0.9.8.9-rc.1-u24, pulled on first use) and swaps the
# peer between cases; ai-qos-ha-sync checks QoS state sync across the pair.
run_scenario kv-mixed-version -- "LOXILB_DOCKER_IMAGE=$IMAGE_UNDER_TEST ./config.sh" "LOXILB_DOCKER_IMAGE=$IMAGE_UNDER_TEST ./validation.sh"

run_scenario ai-qos-ha-sync -- 'sudo -E ./config.sh' 'sudo -E ./validation.sh'

run_scenario k8slbsim -- './config.sh' './validation.sh'

run_scenario onearml2 -- './config.sh' './validation.sh'

run_scenario tcptunlb -- './config.sh' './validation.sh'

run_scenario --needs sctp sctptunlb -- './config.sh' './validation.sh'

run_scenario wrrtcplb1 -- './config.sh' './validation.sh'

run_scenario wrrtcplb2 -- './config.sh' './validation.sh'

run_scenario --needs ipv6 nat64tcp -- './config.sh' './validation.sh'

run_scenario tcplbmaxep -- './config.sh' './validation.sh'

run_scenario ipmasquerade -- './config.sh' './validation.sh'

run_scenario tcplb-src -- './config.sh' './validation.sh'

run_scenario udplb-persist -- './config.sh' './validation.sh'

# Single-node scenarios the other PR workflows gate (security, MCP,
# management profile, persistence, L7 proxy, L4, egress, scale, NAT66,
# IPsec), so a local pass covers what those jobs check.
run_scenario secfilter -- './config.sh' './validation.sh'

run_scenario security-kv-coexist -- './config.sh' './validation.sh' './validation-ddos.sh'

run_scenario mcp-direct-test -- './config.sh' './validation.sh'

run_scenario mcp-direct-test-https -- './config.sh' './validation.sh'

run_scenario mgmt-profile-sanity -- './config.sh' './validation.sh'

# Configuration persistence: export/import round trip, refusals, the restart
# matrix, the CLI path, a mutation soak, and an upgrade from an older release
# (UP_OLD_IMAGE, default v0.9.8.9-rc.1-u24) to the image under test.
run_scenario cfg-persist-roundtrip -- './config.sh' './validation.sh'

run_scenario cfg-persist-negative -- './config.sh' './validation.sh'

run_scenario cfg-persist-restartmatrix -- './config.sh' './validation.sh'

run_scenario cfg-persist-cli -- './config.sh' './validation.sh'

run_scenario cfg-persist-soak -- './config.sh' './validation.sh'

run_scenario cfg-persist-upgrade -- "UP_NEW_IMAGE=$IMAGE_UNDER_TEST ./config.sh" "UP_NEW_IMAGE=$IMAGE_UNDER_TEST ./validation.sh"

run_scenario --needs minica httpsep -- './config.sh' './validation.sh'

run_scenario --needs minica httpshostproxy -- './config.sh' './validation.sh'

run_scenario udplb -- './config.sh' './validation.sh'

run_scenario tcplblc -- './config.sh' './validation.sh'

run_scenario --needs sctp sctplblc -- './config.sh' './validation.sh'

run_scenario egresslb -- './config.sh' './validation.sh'

run_scenario tcpepscale -- './config.sh' './validation.sh'

run_scenario --needs ipv6 nat66tcp -- './config.sh' './validation.sh'

run_scenario --needs ipv6 nat66udp -- './config.sh' './validation.sh'

run_scenario ipsec1 -- './config.sh' './validation.sh'

run_scenario ipsec2 -- './config.sh' './validation.sh'

run_scenario ipsec3 -- './config.sh' './validation.sh'

run_scenario ipsec-e2e -- './config.sh' './validation.sh'

# One honest verdict for the whole run. Non-zero when anything failed.
scenario_summary
