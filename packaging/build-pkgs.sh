#!/usr/bin/env bash
#
# build-pkgs.sh — produce the loxilb-inference-gateway release packages
# (.deb, .rpm, binary tarball) from a staged artifact directory, or build
# the artifacts first via packaging/Dockerfile.build.
#
# Usage (from the repository root):
#   packaging/build-pkgs.sh --version v0.9.8.6-igw.1 --arch amd64 --from-docker
#   packaging/build-pkgs.sh --version v0.9.8.6-igw.1-rc.1 --arch arm64 \
#       --staging dist/stage-arm64 --formats deb,rpm,tarball --checksums
#
# Options:
#   --version <tag>    release tag (vX.Y.Z[.W]-igw.N[-rc.M]); default: git describe
#   --arch <arch>      amd64 | arm64 (default: host architecture)
#   --staging <dir>    directory with staged artifacts (loxilb, loxilb-mcp,
#                      lib/, ebpf/); default dist/stage-<arch>
#   --from-docker      build the staging directory via packaging/Dockerfile.build
#   --formats <list>   comma-separated: deb,rpm,tarball (default: all)
#   --out <dir>        output directory (default: dist)
#   --checksums        write SHA256SUMS over the produced artifacts in --out
#
# Version mapping (deb revision / rpm Release both handle the pre-release
# ordering via "~"):
#   v0.9.8.6-igw.1       -> version 0.9.8.6, release igw.1
#   v0.9.8.6-igw.1-rc.1  -> version 0.9.8.6, release igw.1~rc.1
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION_TAG=""
ARCH=""
STAGING=""
FROM_DOCKER=0
FORMATS="deb,rpm,tarball"
OUT="dist"
CHECKSUMS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION_TAG="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --staging) STAGING="$2"; shift 2 ;;
    --from-docker) FROM_DOCKER=1; shift ;;
    --formats) FORMATS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --checksums) CHECKSUMS=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$VERSION_TAG" ]; then
  VERSION_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev.0")
  echo ">> no --version given, using $VERSION_TAG"
fi
if [ -z "$ARCH" ]; then
  case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) ARCH=amd64 ;;
  esac
fi
[ -n "$STAGING" ] || STAGING="dist/stage-$ARCH"

# --- Version parsing -------------------------------------------------------
FULLVER=${VERSION_TAG#v}
PKG_VERSION=${FULLVER%%-*}
if [ "$FULLVER" = "$PKG_VERSION" ]; then
  PKG_RELEASE="1"
else
  PKG_RELEASE=${FULLVER#*-}
  PKG_RELEASE=${PKG_RELEASE//-/\~}
fi
echo ">> tag=$VERSION_TAG version=$PKG_VERSION release=$PKG_RELEASE arch=$ARCH"

# --- Stage artifacts -------------------------------------------------------
if [ "$FROM_DOCKER" = 1 ]; then
  echo ">> building artifacts via packaging/Dockerfile.build (arch=$ARCH)"
  build_args=()
  host_arch=$(uname -m | sed -e s/aarch64/arm64/ -e s/x86_64/amd64/)
  if [ "$ARCH" != "$host_arch" ]; then
    build_args+=(--platform "linux/$ARCH")
    [ "$ARCH" = "arm64" ] && build_args+=(--build-arg USE_DOCKER_BUILDX_ARM64=true)
  fi
  rm -rf "$STAGING"
  DOCKER_BUILDKIT=1 docker build -f packaging/Dockerfile.build \
    --target artifacts --output "type=local,dest=$STAGING" "${build_args[@]}" .
fi

for f in loxilb loxilb-mcp lib/libssl.so.3 lib/libcrypto.so.3; do
  [ -e "$STAGING/$f" ] || { echo "ERROR: missing staged artifact: $STAGING/$f" >&2; exit 1; }
done
ls "$STAGING"/ebpf/*.o >/dev/null 2>&1 || { echo "ERROR: no eBPF objects in $STAGING/ebpf/" >&2; exit 1; }

mkdir -p "$OUT"
export PKG_VERSION PKG_RELEASE PKG_ARCH="$ARCH"

# nfpm does not expand env vars in content src paths; give it a fixed path.
rm -f packaging/.staging
ln -s "$(cd "$STAGING" && pwd)" packaging/.staging

TARDIR=""
cleanup() {
  rm -f packaging/.staging
  if [ -n "$TARDIR" ]; then rm -rf "$TARDIR"; fi
}
trap cleanup EXIT

# --- Packages --------------------------------------------------------------
case ",$FORMATS," in *,deb,*)
  nfpm package -f packaging/nfpm.yaml -p deb --target "$OUT/"
  echo ">> deb written to $OUT/"
;; esac
case ",$FORMATS," in *,rpm,*)
  nfpm package -f packaging/nfpm.yaml -p rpm --target "$OUT/"
  echo ">> rpm written to $OUT/"
;; esac

# --- Tarball ---------------------------------------------------------------
case ",$FORMATS," in *,tarball,*)
  TARNAME="loxilb-inference-gateway_${FULLVER}_linux_${ARCH}"
  TARDIR=$(mktemp -d)
  mkdir -p "$TARDIR/$TARNAME"
  cp "$STAGING/loxilb" "$STAGING/loxilb-mcp" "$TARDIR/$TARNAME/"
  cp -r "$STAGING/lib" "$STAGING/ebpf" "$TARDIR/$TARNAME/"
  cp packaging/loxilb.service packaging/mkllb-bpffs.sh LICENSE NOTICE "$TARDIR/$TARNAME/"
  cat > "$TARDIR/$TARNAME/README.txt" <<'EOF'
loxilb-inference-gateway binary tarball
=======================================

Contents:
  loxilb          the load-balancer binary (needs the bundled lib/ at runtime)
  loxilb-mcp      standalone MCP bridge (static binary, no dependencies)
  lib/            bundled shared libraries (kTLS OpenSSL, libbpf)
  ebpf/           eBPF datapath objects, expected under /opt/loxilb
  loxilb.service  systemd unit (expects the .deb/.rpm file layout)
  mkllb-bpffs.sh  bpf filesystem mount helper

Quick start (run as root):
  install -d /opt/loxilb
  cp ebpf/*.o /opt/loxilb/
  ./mkllb-bpffs.sh
  LD_LIBRARY_PATH=$PWD/lib ./loxilb

For a managed install use the .deb/.rpm packages instead; see the project
README for the full quickstart and kernel baseline requirements.
EOF
  tar -C "$TARDIR" -czf "$OUT/$TARNAME.tar.gz" "$TARNAME"
  echo ">> tarball written to $OUT/$TARNAME.tar.gz"
;; esac

# --- Checksums -------------------------------------------------------------
if [ "$CHECKSUMS" = 1 ]; then
  if command -v sha256sum >/dev/null 2>&1; then SHATOOL="sha256sum"; else SHATOOL="shasum -a 256"; fi
  (
    cd "$OUT"
    files=$(find . -maxdepth 1 -type f ! -name 'SHA256SUMS' | sed 's|^\./||' | sort)
    [ -n "$files" ] && $SHATOOL $files > SHA256SUMS
  )
  echo ">> SHA256SUMS written"
fi

echo ">> done"
