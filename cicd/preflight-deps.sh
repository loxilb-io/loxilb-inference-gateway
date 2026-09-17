#!/bin/bash
# Host dependency preflight for the CICD suite.
#
# Run this once per bed, before any scenario:
#
#   cd cicd && ./preflight-deps.sh            # the baseline every scenario needs
#   cd cicd && ./preflight-deps.sh base kv    # add the KV-cache publisher deps
#
# ── why this exists, and why it insists on WHERE ────────────────────────────
#
# Scenarios reach their mock backends through `hexec`, which is
# "sudo ip netns exec": that swaps the network namespace, keeps the host
# filesystem, and runs the process as ROOT. Three consequences drive every
# decision below.
#
#   1. A tool installed into a container with `dexec` ("docker exec") is not
#      on the host PATH, so it does nothing for a host-side assertion.
#   2. A python module installed with a plain `pip3 install --user` lands in
#      the CALLING user's site directory. Root does not read that directory,
#      so the module is invisible to the very process that imports it. A
#      scenario may bridge it deliberately by exporting PYTHONPATH into the
#      hexec'd command - the KV-cache scenarios do exactly that - but nothing
#      that does not bridge can rely on it.
#   3. Therefore a dependency is only "present" if the ROOT interpreter can
#      import it. That is what this script verifies, and it is the reason
#      every install below targets a root-visible location: apt's
#      dist-packages first, and `sudo python3 -m pip` as the fallback.
#
# Verifying in the caller's environment instead is not a smaller version of
# this check - it is a check that passes at the exact moment the bed is
# broken, which is worse than no check at all.
set -u

DEP_GROUPS="${*:-base}"
rc=0
installed_any=0

say()  { printf '  %s\n' "$*"; }
head2() { printf '\n%s\n' "$*"; }

# ── package tables ──────────────────────────────────────────────────────────
# Binaries the host needs on PATH.
BASE_BINS="jq curl"

# Python modules the host needs importable BY ROOT, as "module:aptpackage".
# An empty apt field means no distro package exists and pip is the only route.
BASE_PYS="h2:python3-h2"

# The KV-cache publisher and hash-parity deps. Heavy (transformers pulls a
# large dependency tree), so they are opt-in rather than part of the baseline.
# The KV scenarios also bridge their own user-site through PYTHONPATH, so they
# work without this group; installing it makes them work under root directly.
KV_PYS="zmq:python3-zmq msgpack:python3-msgpack cbor2:python3-cbor2 xxhash:python3-xxhash requests:python3-requests yaml:python3-yaml tokenizers: transformers:"

want_bins=""
want_pys=""
for g in $DEP_GROUPS; do
  case "$g" in
    base) want_bins="$want_bins $BASE_BINS"; want_pys="$want_pys $BASE_PYS" ;;
    kv)   want_pys="$want_pys $KV_PYS" ;;
    *)    echo "FATAL: unknown dependency group '$g' (known: base kv)"; exit 2 ;;
  esac
done

echo "==== cicd host dependency preflight (groups: $DEP_GROUPS) ===="

# ── binaries ────────────────────────────────────────────────────────────────
head2 "--- host binaries (must be on PATH)"
missing_bins=""
for b in $want_bins; do
  if command -v "$b" >/dev/null 2>&1; then
    say "[have]    $b"
  else
    missing_bins="$missing_bins $b"
    say "[missing] $b"
  fi
done
if [[ -n "$missing_bins" ]]; then
  say "installing:$missing_bins"
  # Output is discarded rather than shown: apt exits 0 after "Unable to locate
  # package", so its chatter is not evidence either way. The re-probe below is.
  sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get update -qq >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get install -y -qq $missing_bins >/dev/null 2>&1 || true
  for b in $missing_bins; do
    if command -v "$b" >/dev/null 2>&1; then say "[ok]      $b installed"; else say "[FAIL]    $b still absent"; rc=1; fi
  done
  installed_any=1
fi

# ── python modules, verified as ROOT ────────────────────────────────────────
#
# `sudo python3 -c "import X"` is the whole point: it is the interpreter that
# `hexec ... python3 script.py` will actually use. A bare `python3 -c` here
# would check the caller's environment, which is not the one that runs.
root_has() { sudo python3 -c "import $1" >/dev/null 2>&1; }

pip_bsp=""   # --break-system-packages exists only from pip 23.0.1 (PEP 668)
if sudo python3 -m pip install --help 2>/dev/null | grep -q -- '--break-system-packages'; then
  pip_bsp="--break-system-packages"
fi

head2 "--- python modules (must be importable by ROOT, the user hexec runs as)"
for entry in $want_pys; do
  mod="${entry%%:*}"
  apt_pkg="${entry#*:}"
  [[ "$apt_pkg" == "$entry" ]] && apt_pkg=""

  if root_has "$mod"; then
    say "[have]    $mod"
    continue
  fi

  say "[missing] $mod - installing"
  if [[ -n "$apt_pkg" ]]; then
    # dist-packages is on BOTH the caller's and root's sys.path, so the distro
    # package fixes every consumer at once. Preferred for that reason alone.
    sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y -qq "$apt_pkg" >/dev/null 2>&1 || true
  fi
  if ! root_has "$mod"; then
    # Fall back to pip as ROOT, so it lands in root's site-packages rather
    # than the caller's user-site. `python3 -m pip` rather than the pip3
    # wrapper, which is absent on bare-python3 hosts.
    # shellcheck disable=SC2086
    sudo python3 -m pip install --quiet $pip_bsp "$mod" >/dev/null 2>&1 || true
  fi
  installed_any=1

  if root_has "$mod"; then
    say "[ok]      $mod installed"
  else
    say "[FAIL]    $mod still not importable by root"
    rc=1
  fi
done

# ── final verdict, re-probed rather than remembered ─────────────────────────
#
# The verdict comes from probing again, never from whether the installers
# reported success: apt answers "Unable to locate package" and still exits 0,
# so an installer's exit status is not evidence that anything was installed.
head2 "--- verdict"
final_bad=""
for b in $want_bins; do
  command -v "$b" >/dev/null 2>&1 || final_bad="$final_bad bin:$b"
done
for entry in $want_pys; do
  mod="${entry%%:*}"
  root_has "$mod" || final_bad="$final_bad py:$mod"
done

if [[ -n "$final_bad" ]]; then
  say "[FAIL] still unsatisfied:$final_bad"
  say ""
  say "These are host dependencies. Python modules must be importable by ROOT,"
  say "because scenarios launch their mocks through 'sudo ip netns exec'. A"
  say "'pip3 install --user' as your own user will NOT satisfy them."
  exit 1
fi

if [[ $installed_any == 1 ]]; then
  say "[PASS] all dependencies present (some were installed just now)"
else
  say "[PASS] all dependencies already present"
fi
exit $rc
