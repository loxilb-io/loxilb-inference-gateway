#!/bin/bash
# config.sh — appliance-dispatch topology.
#
# The `loxicmd appliance` family never opens a gateway API connection, so this
# suite needs exactly one container: no client, no endpoint, no VIP. What it
# does need is the CLI talking to a backend at the REAL compiled-in path,
# /usr/libexec/loxilb-appliance/loxilb-appliance-backend.
#
# That path is the point. The CLI repository's own tests relocate the backend
# through `-ldflags -X ...pkg/backend.executablePath=`, so nothing there
# exercises the default the shipped binary actually carries -- a typo'd or
# moved libexec layout would pass every unit test and fail on the appliance.
# Here the binary is unmodified and the fixture is installed at the real path.

export LLB_HOST_PORTS=""
source ../common.sh

CFGDIR="$(cd "$(dirname "$0")" && pwd)"

"${CFGDIR}/rmconfig.sh" >/dev/null 2>&1 || true
sudo rm -rf "${CFGDIR}/artifacts" >/dev/null 2>&1 || true
mkdir -p "${CFGDIR}/artifacts"

echo "#########################################"
echo "Spawning llb1 (no client/endpoint: the appliance family needs no gateway API)"
echo "#########################################"
spawn_docker_host --dock-type loxilb --dock-name llb1

sleep 5

echo "#########################################"
echo "Selecting the CLI under test"
echo "#########################################"
if [[ -n "$LOXICMD_BIN" ]]; then
    [[ -x "$LOXICMD_BIN" ]] || { echo "FATAL: LOXICMD_BIN=$LOXICMD_BIN is not an executable"; exit 1; }
    sudo docker cp "$LOXICMD_BIN" llb1:/usr/local/sbin/loxicmd || { echo "FATAL: could not install the CLI under test"; exit 1; }
    $dexec llb1 chmod 0755 /usr/local/sbin/loxicmd
    echo "  CLI under test: $LOXICMD_BIN (copied into llb1, replacing the baked binary)"
    echo "$LOXICMD_BIN" > "${CFGDIR}/.cli-under-test"
else
    echo "  CLI under test: the loxicmd baked into the image"
    echo "image-baked" > "${CFGDIR}/.cli-under-test"
fi
$dexec llb1 loxicmd version >/dev/null || { echo "FATAL: the CLI does not run inside llb1"; exit 1; }

echo "#########################################"
echo "Installing the backend fixture at the real libexec path"
echo "#########################################"
$dexec llb1 mkdir -p /usr/libexec/loxilb-appliance /opt/appliance-fake/rec
sudo docker cp "${CFGDIR}/fake-backend.sh" llb1:/usr/libexec/loxilb-appliance/loxilb-appliance-backend
$dexec llb1 chmod 0755 /usr/libexec/loxilb-appliance/loxilb-appliance-backend
$dexec llb1 sh -c 'echo ok > /opt/appliance-fake/mode'

# Anti-vacuity gate. If the CLI cannot reach the fixture at the real path, every
# negative leg below would "pass" by failing for the wrong reason. Prove the
# happy path first or refuse to run at all.
if ! $dexec llb1 loxicmd appliance status >/dev/null 2>&1; then
    echo "FATAL: the CLI cannot reach the fixture at /usr/libexec/loxilb-appliance/loxilb-appliance-backend."
    echo "       Either the compiled-in backend path changed, or the fixture did not install."
    $dexec llb1 loxicmd appliance status || true
    exit 1
fi
echo "  the shipped binary reached the fixture at the real compiled-in path"

echo "appliance-dispatch config done"
