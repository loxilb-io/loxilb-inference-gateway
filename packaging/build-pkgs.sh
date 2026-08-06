#!/usr/bin/env bash
#
# build-pkgs.sh — produce the loxilb-inference-gateway release packages
# (.deb, .rpm, binary tarball) from a staged artifact directory, or build
# the artifacts first via packaging/Dockerfile.build.
#
# Usage (from the repository root):
#   packaging/build-pkgs.sh --version v0.9.8.7 --arch amd64 --from-docker
#   packaging/build-pkgs.sh --version v0.9.8.7-rc.1 --arch arm64 \
#       --staging dist/stage-arm64 --formats deb,rpm,tarball --checksums
#
# Options:
#   --version <tag>    release tag (vX.Y.Z[.W][-rc.M]); default: git describe
#   --arch <arch>      amd64 | arm64 (default: host architecture)
#   --staging <dir>    directory with staged artifacts (loxilb,
#                      lib/, ebpf/); default dist/stage-<arch>
#   --from-docker      build the staging directory via packaging/Dockerfile.build
#   --formats <list>   comma-separated: deb,rpm,tarball (default: all)
#   --out <dir>        output directory (default: dist)
#   --checksums        write SHA256SUMS over the produced artifacts in --out
#
# The gateway follows loxilb-io/loxilb's tag scheme: vMAJOR.MINOR.PATCH with an
# optional fourth build component, plus an optional -rc.N prerelease suffix.
#
# Version mapping (deb revision / rpm Release both handle the pre-release
# ordering via "~", which sorts before everything including the empty string):
#   v0.9.8.7        -> version 0.9.8.7, release 1
#   v0.9.8.7-rc.1   -> version 0.9.8.7, release 1~rc.1   (upgrades to -1)
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
  # --match is load-bearing: loxilb-mcp is released from this same repo under
  # `mcp/vX.Y.Z` tags, and a bare `git describe --tags` will happily return one
  # of those, packaging the datapath under the MCP bridge's version.
  VERSION_TAG=$(git describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null || echo "v0.0.0")
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
# Reject anything that is not the documented scheme, so a stray tag cannot
# produce a package with a nonsense version. Nightly builds append a
# -nightly.<date> suffix, which is accepted as a prerelease like -rc.N.
if ! printf '%s' "$VERSION_TAG" | grep -Eq '^v[0-9]+(\.[0-9]+){2,3}(-[A-Za-z0-9.]+)?$'; then
  echo "ERROR: '$VERSION_TAG' is not a valid version tag." >&2
  echo "       expected vMAJOR.MINOR.PATCH[.BUILD][-rc.N]  (e.g. v0.9.8.7, v0.9.8.7-rc.1)" >&2
  exit 2
fi

FULLVER=${VERSION_TAG#v}
PKG_VERSION=${FULLVER%%-*}
if [ "$FULLVER" = "$PKG_VERSION" ]; then
  PKG_RELEASE="1"
else
  # Prerelease: hold the revision at 1 and hang the suffix off a "~", which
  # sorts before the bare revision. So 0.9.8.7-1~rc.1 upgrades cleanly to the
  # final 0.9.8.7-1, in both dpkg and rpm ordering.
  PKG_RELEASE="1~${FULLVER#*-}"
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
  # VERSION must be passed explicitly: .dockerignore strips .git, so the
  # Makefile's `git describe` cannot resolve the tag inside the builder and the
  # packaged binary would report "dev" while the package filename said 0.9.8.7.
  DOCKER_BUILDKIT=1 docker build -f packaging/Dockerfile.build \
    --build-arg VERSION="$VERSION_TAG" \
    --target artifacts --output "type=local,dest=$STAGING" "${build_args[@]}" .
fi

for f in loxilb lib/libssl.so.3 lib/libcrypto.so.3; do
  [ -e "$STAGING/$f" ] || { echo "ERROR: missing staged artifact: $STAGING/$f" >&2; exit 1; }
done
ls "$STAGING"/ebpf/*.o >/dev/null 2>&1 || { echo "ERROR: no eBPF objects in $STAGING/ebpf/" >&2; exit 1; }

mkdir -p "$OUT"
export PKG_VERSION PKG_RELEASE PKG_ARCH="$ARCH"

# nfpm does not expand env vars in content src paths; give it a fixed path.
rm -f packaging/.staging
ln -s "$(cd "$STAGING" && pwd)" packaging/.staging

# Monitoring stack payload: configuration content only (compose, scrape
# config, alert rules, dashboards, provisioning). Ships in the packages at
# /usr/share/loxilb/monitoring and, with --formats ...,monitoring, as an
# arch-independent tarball. CI lint tooling is not user-facing — excluded.
rm -rf packaging/.staging-monitoring
mkdir -p packaging/.staging-monitoring
tar -C deploy/monitoring --exclude=./ci --exclude='CLAUDE.md' --exclude='.gitignore' -cf - . \
  | tar -C packaging/.staging-monitoring -xf -

TARDIR=""
cleanup() {
  rm -f packaging/.staging
  rm -rf packaging/.staging-monitoring
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
  cp "$STAGING/loxilb" "$TARDIR/$TARNAME/"
  cp -r "$STAGING/lib" "$STAGING/ebpf" "$TARDIR/$TARNAME/"
  cp packaging/loxilb.service packaging/mkllb-bpffs.sh LICENSE NOTICE "$TARDIR/$TARNAME/"
  cat > "$TARDIR/$TARNAME/README.txt" <<'EOF'
loxilb-inference-gateway binary tarball
=======================================

Contents:
  loxilb          the load-balancer binary (needs the bundled lib/ at runtime)
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

# --- Monitoring tarball (arch-independent — build on one arch only) ---------
case ",$FORMATS," in *,monitoring,*)
  MONNAME="loxilb-inference-gateway-monitoring_${FULLVER}"
  MONDIR=$(mktemp -d)
  mkdir -p "$MONDIR/$MONNAME"
  cp -r packaging/.staging-monitoring/. "$MONDIR/$MONNAME/"
  tar -C "$MONDIR" -czf "$OUT/$MONNAME.tar.gz" "$MONNAME"
  rm -rf "$MONDIR"
  echo ">> monitoring tarball written to $OUT/$MONNAME.tar.gz"
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
