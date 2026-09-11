#!/bin/bash
#
# sockmap-fullproxy / build-measure-image.sh
#
# Builds a loxilb image suitable for CPU measurement.
#
# Why a separate image is needed
# ------------------------------
# sockproxy.c defines HAVE_PROXY_EXTRA_DEBUG itself at the top of the file, which makes
# proxy_sock_read() call log_debug() on every recv(). The userspace relay path calls
# recv() per byte and pays that cost; the kernel redirect (sockmap) path never calls
# recv() and does not. So a sockmap on/off CPU comparison also measures "debug logging
# versus none". An image with it removed at compile time via
# -DHAVE_PROXY_NO_EXTRA_DEBUG is the measurement baseline.
#
# Why it builds inside a container
# --------------------------------
# The runtime image is Ubuntu 22.04 (glibc 2.35) while the development host may be
# 24.04 (glibc 2.39). A host-built binary fails inside the image with
# `GLIBC_2.38 not found`. So the build runs in a builder container made from the
# runtime image plus a toolchain. (The image's /usr/local/go is a trimmed distribution
# without stdlib sources, so the host GOROOT is mounted and used instead.)
#
# Usage:
#   ./build-measure-image.sh                    # :sockmap-nodebug (logging removed)
#   ./build-measure-image.sh sockmap-dbgctl 1   # same tree, control image with logging
#
# Args: $1 = resulting tag (default sockmap-nodebug), $2 = 1 keeps logging (control)
set -e

TAG=${1:-sockmap-nodebug}
KEEP_DEBUG=${2:-0}
BASE=${BASE_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}
BUILDER_IMG=loxilb-inbuilder:22.04
BUILDER=llbbuilder
REPO=$(cd "$(dirname "$0")/../.." && pwd)

if [[ "$KEEP_DEBUG" == "1" ]]; then
  XCF="-DHAVE_SOCKOPS"
else
  XCF="-DHAVE_SOCKOPS -DHAVE_PROXY_NO_EXTRA_DEBUG"
fi

command -v go >/dev/null || { echo "ERROR: go not found on host (needed for the GOROOT mount)"; exit 1; }
HOST_GOROOT=$(go env GOROOT)
HOST_GOMODCACHE=$(go env GOMODCACHE)

# ---- 1) builder image (runtime image + toolchain), built once and reused
if ! sudo docker image inspect "$BUILDER_IMG" >/dev/null 2>&1; then
  echo "[build] creating builder image $BUILDER_IMG from $BASE"
  sudo docker rm -f "$BUILDER" >/dev/null 2>&1 || true
  sudo docker run -dt --name "$BUILDER" --entrypoint /bin/bash "$BASE" >/dev/null
  sudo docker exec "$BUILDER" bash -c '
    apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      gcc gcc-multilib make binutils clang llvm \
      libelf-dev zlib1g-dev libssl-dev libjson-c-dev libnghttp2-dev pkg-config >/dev/null 2>&1'
  sudo docker commit "$BUILDER" "$BUILDER_IMG" >/dev/null
  sudo docker rm -f "$BUILDER" >/dev/null
fi

# ---- 2) start the builder container with repo / GOROOT / go caches mounted
sudo docker rm -f "$BUILDER" >/dev/null 2>&1 || true
sudo docker run -dt --name "$BUILDER" \
  -v "$REPO":/src -w /src \
  -v "$HOST_GOROOT":/hostgo:ro \
  -v "$HOST_GOMODCACHE":/gomodcache \
  --entrypoint /bin/bash "$BUILDER_IMG" >/dev/null

# ---- 3) build subsys and the Go binary inside the container
echo "[build] compiling in-container with EXTRA_CFLAGS=\"$XCF\""
sudo docker exec "$BUILDER" bash -c "
  set -e
  export GOROOT=/hostgo PATH=/hostgo/bin:\$PATH GOMODCACHE=/gomodcache GOFLAGS=-mod=mod
  cd /src/loxilb-ebpf
  # A host-built libbpf.a references __isoc23_* symbols and will not link on 22.04,
  # so everything is rebuilt here.
  make clean >/tmp/clean.log 2>&1 || true
  make EXTRA_CFLAGS=\"$XCF\" >/tmp/build.log 2>&1 || { tail -30 /tmp/build.log; exit 1; }
  cd /src
  go build -o loxilb.measure -ldflags=\"-X 'github.com/loxilb-io/loxilb/common.BuildInfo=measure-$TAG'\"
"
n=$(strings "$REPO/loxilb-ebpf/common/sockproxy.o" | grep -c "SOCK_READ" || true)
echo "[build] sockproxy.o per-recv debug strings: $n (0 means logging removed)"

# ---- 4) swap only the binary and eBPF objects into the runtime image, then commit
C=llbmk
sudo docker rm -f $C >/dev/null 2>&1 || true
sudo docker run -u root --cap-add SYS_ADMIN --privileged -dt --entrypoint /bin/bash --name $C "$BASE" >/dev/null
sudo docker cp "$REPO/loxilb.measure" $C:/root/loxilb-io/loxilb/loxilb
for o in llb_ebpf_main.o llb_ebpf_emain.o llb_xdp_main.o llb_kern_sock.o \
         llb_kern_sockmap.o llb_kern_sockstream.o llb_kern_sockdirect.o; do
  sudo docker cp "$REPO/loxilb-ebpf/kernel/$o" $C:/opt/loxilb/$o
done
sudo docker cp "$REPO/loxilb-ebpf/kernel/loxilb_dp_debug" $C:/usr/local/sbin/ 2>/dev/null || true
# libbpf is linked statically (-l:libbpf.a), so the runtime .so is left alone.
sudo docker exec $C mkllb_bpffs >/dev/null 2>&1 || true
sudo docker commit $C ghcr.io/loxilb-io/loxilb-inference-gateway:"$TAG" >/dev/null
sudo docker rm -f $C >/dev/null
sudo docker rm -f "$BUILDER" >/dev/null

# Restore ownership of artifacts the container created as root.
sudo chown -R "$(id -u):$(id -g)" "$REPO/loxilb-ebpf" "$REPO/loxilb.measure"
rm -f "$REPO/loxilb.measure"

echo "[build] done: ghcr.io/loxilb-io/loxilb-inference-gateway:$TAG"
echo "        use: LOXILB_IMAGE=ghcr.io/loxilb-io/loxilb-inference-gateway:$TAG ./config.sh"
