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

cd sconnect/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplb/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbmark/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbdsr1/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbdsr2/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbl3dsr/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbhash/
./config.sh
./validation.sh
./rmconfig.sh
cd -


cd sctplb/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd sctponearm/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd sctplbdsr/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbmon/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbmon-epstat/
./config.sh
./validation.sh
./rmconfig.sh
cd -
    
cd udplbmon/
./config.sh
./validation.sh
./rmconfig.sh
cd -
 
cd sctplbmon/
./config.sh
./validation.sh
./rmconfig.sh
cd -
  
cd tcplbmon6/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbepmod/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd lbtimeout/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd lb6timeout/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcpsctpperf
./config.sh
./validation.sh 20  30
./rmconfig.sh
cd -

cd http2ep/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd e2ehttpsproxy/
./config.sh
./validation-http1.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd e2ehttpsproxy-prefix/
./config.sh
./validation-http1.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd e2ehttpsproxy-grpc/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd httpproxy/
./config.sh
./validation.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd httpproxy-prefix/
./config.sh
./validation.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd httpsproxy/
./config.sh
./validation.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd httpsproxy-prefix/
./config.sh
./validation.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd tlsproxyprotov2/
# fullnat: eBPF L4 dp_ins_ppv2 GSO fix. EXPECT=fixed is the post-fix regression
# gate; the default EXPECT=bug asserts the historical #1044/#1089 bug REPRODUCES,
# which no longer happens now that the GSO fix has landed (so it would fail).
./config.sh
EXPECT=fixed ./validation.sh
./rmconfig.sh
# fullproxy: L7 userspace sockproxy PPv2 header emit (a separate testbed setup -
# plaintext proxy_protocol backends + a fullproxy LB rule).
PPV2MODE=fullproxy ./config.sh
PPV2MODE=fullproxy ./validation.sh
./rmconfig.sh
cd -

cd vllm-fullproxy/
./config.sh
./validation-level1.sh
./rmconfig.sh
cd -

cd vllm-httpproxy/
./config.sh
./validation-level1.sh
./rmconfig.sh
cd -

cd vllm-fullproxy-wrr/
./config.sh
./validation-level1.sh
./rmconfig.sh
cd -

cd vllm-httpproxy-wrr/
./config.sh
./validation-level1.sh
./rmconfig.sh
cd -

cd mcp-fullproxy/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd mcp-httpproxy/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd mcp-e2ehttps/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd httpsproxy-mtls/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd e2ehttpsproxy-mtls/
./config.sh
./validation.sh
./rmconfig.sh
cd -

# ai-apikey / ai-model-routing / ai-sse-quota: their validation.sh runs the REST
# suite and then bash validate_cli.sh (CLI-driven, REST oracle). With the
# CLI_TESTS=required default above, the CLI half is enforced, not skipped.
cd ai-apikey/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd ai-model-routing/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd ai-sse-quota/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd vllm-pd-disagg/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd sglang-pd-disagg/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd trtllm-pd-disagg/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd vllm-kvcache-routing-cpu/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd sglang-loxilb-kvcache/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd k8slbsim/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd onearml2/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcptunlb/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd sctptunlb/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd wrrtcplb1/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd wrrtcplb2/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd nat64tcp/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd tcplbmaxep/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd ipmasquerade/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd httpsproxy/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd e2ehttpsproxy/
./config.sh
./validation-http1.sh
./validation-http2.sh
./rmconfig.sh
cd -

cd tcplb-src/
./config.sh
./validation.sh
./rmconfig.sh
cd -

cd udplb-persist/
./config.sh
./validation.sh
./rmconfig.sh