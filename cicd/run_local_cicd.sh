#!/bin/bash
set -e

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

cd sglang-loxilb-kvcache/
./config.sh
./validation.sh
./rmconfig.sh
cd -
