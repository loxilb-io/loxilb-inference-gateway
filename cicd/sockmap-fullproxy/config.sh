#!/bin/bash
#
# sockmap-fullproxy / config.sh
#
# Testbed layout:
#   l3h1 (client) -- llb1 (loxilb --sockmapsupport) -- l3ep1, l3ep2 (server)
#
# LB rules created:
#   R1: vip 10.10.10.254:2020 -> tcp/8080, sockMapAccel=true,  fullproxy
#   R2: vip 10.10.10.254:2021 -> tcp/8080, sockMapAccel=false, fullproxy (control)

source ../common.sh
source ./sockmap_common.sh

# Override the default loxilb image with the sockmap-test build.
# LOXILB_IMAGE selects a different tag. For CPU measurement use :sockmap-nodebug,
# built with -DHAVE_PROXY_NO_EXTRA_DEBUG, which drops the per-recv() logging.
lxdocker="${LOXILB_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}"

sockmap_init_artifacts

echo "#########################################"
echo "Spawning all hosts (sockmap-fullproxy)"
echo "#########################################"

# LOXILB_LOGLEVEL: the default image is a HAVE_PROXY_EXTRA_DEBUG build, so
# proxy_sock_read() calls log_debug() on every recv(). Only the userspace relay path
# pays that per-token formatting and file write; the kernel redirect path does not.
# Any CPU comparison (validation-cpu.sh / validation-sse-cpu.sh) must therefore run
# below debug to remove the bias. Raise it back to debug only for functional
# debugging.
LOXILB_LOGLEVEL=${LOXILB_LOGLEVEL:-info}
spawn_docker_host --dock-type loxilb --dock-name llb1 \
  --extra-args "--sockmapsupport --loglevel $LOXILB_LOGLEVEL"
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2

echo "#########################################"
echo "Connecting and configuring hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

config_docker_host --host1 l3h1  --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 llb1  --host2 l3h1  --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1  --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1  --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

sleep 5

if ! sockmap_ensure_bpftool llb1; then
  echo "ERROR: cannot proceed without bpftool in llb1"
  exit 1
fi

if ! sockmap_wait_api_ready llb1; then
  echo "ERROR: loxilb REST API never became ready"
  exit 1
fi

echo "#########################################"
echo "Booting-time sockmap asset check"
echo "#########################################"

if ! sockmap_assert_bpf_assets llb1; then
  echo "ERROR: sockmap BPF assets not attached after --sockmapsupport boot."
  echo "       Check that the loxilb image really contains the sockmap-phase1 build."
  exit 1
fi
echo "[sockmap] sockops prog + 3 maps detected in llb1."

echo "#########################################"
echo "Creating LB rules via REST API"
echo "#########################################"

# R1: sockmap enabled
if ! sockmap_create_lb_via_api llb1 \
        10.10.10.254 2020 8080 \
        "31.31.31.1,32.32.32.1" \
        true \
        "sockmap-on"; then
  exit 1
fi

# R2: sockmap disabled (control)
if ! sockmap_create_lb_via_api llb1 \
        10.10.10.254 2021 8080 \
        "31.31.31.1,32.32.32.1" \
        false \
        "sockmap-off"; then
  exit 1
fi

sleep 2

# Also record the portset state right after rule creation, for diagnostics.
{
  echo "## vip portset dump after rule create ##"
  vip_id=$(sockmap_map_id llb1 "$SOCKMAP_VIP_NAME")
  if [[ -n "$vip_id" ]]; then
    sudo docker exec -i llb1 bpftool map dump id "$vip_id" 2>&1
  fi
  echo
  echo "## ep portset dump after rule create ##"
  ep_id=$(sockmap_map_id llb1 "$SOCKMAP_EP_NAME")
  if [[ -n "$ep_id" ]]; then
    sudo docker exec -i llb1 bpftool map dump id "$ep_id" 2>&1
  fi
} > "$SOCKMAP_ARTIFACTS_DIR/post_create_portsets.txt"

echo
echo "#########################################"
echo "config.sh DONE"
echo "#########################################"
