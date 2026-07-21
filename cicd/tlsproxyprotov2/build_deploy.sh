#!/bin/bash
# Build a complete loxilb-inference-gateway image from LOCAL source and point the
# tlsproxyprotov2 testbed at it.
#
# This intentionally does a full Dockerfile.u24 build rather than the upstream
# "swap the two eBPF .o files" fast path, because the PROXY-protocol-v2 work spans
# BOTH datapaths:
#   - eBPF L4 fullnat GSO fix   -> lives in the kernel .o (llb_ebpf_main.o)
#   - L7 fullproxy header emit  -> lives in the userspace sockproxy, i.e. the
#                                  loxilb Go binary + libloxilbdp, NOT the .o
# A .o-only swap would silently miss the L7 change, so we rebuild the whole image.
#
# Usage:   ./build_deploy.sh                       # fullnat testbed (default)
#          PPV2MODE=fullproxy ./build_deploy.sh    # fullproxy testbed
#          IMAGE=my/tag ./build_deploy.sh          # override the built image tag
# (docker group assumed; no leading sudo -- config.sh calls sudo internally.)
set -e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:ppv2test}"

echo "== [1/3] build full image $IMAGE from local source (go 1.25.x + eBPF) =="
docker build -f "$ROOT/Dockerfile.u24" -t "$IMAGE" "$ROOT"

echo "== [2/3] rebuild testbed (PPV2MODE=${PPV2MODE:-fullnat}) with $IMAGE =="
cd "$ROOT/cicd/tlsproxyprotov2"
./rmconfig.sh >/dev/null 2>&1 || true
LOXILB_IMAGE="$IMAGE" PPV2MODE="${PPV2MODE:-fullnat}" ./config.sh >config.run.log 2>&1
grep -q "Setup done" config.run.log && echo "   testbed up" || { echo "   CONFIG FAILED"; tail -5 config.run.log; exit 1; }

echo "== [3/3] done. validate: =="
echo "     fullnat   : EXPECT=fixed ./validation.sh"
echo "     fullproxy : PPV2MODE=fullproxy ./validation.sh"
