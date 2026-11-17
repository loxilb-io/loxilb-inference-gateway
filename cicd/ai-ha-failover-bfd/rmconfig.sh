#!/bin/bash
# rmconfig.sh — ai-ha-failover-bfd teardown (idempotent).
#
# Removes what config.sh and validation.sh created: the containers, the two
# switch namespaces, every veth, the contents of /etc/shared/llb{1,2}, and the
# scenario's generated files. It does not remove images (see README: images
# are removed once, at the end of a campaign, and only those this scenario
# pulled or built) and it does not remove the /etc/shared/llb{1,2}
# directories themselves when they existed before the run.
source ../common.sh >/dev/null 2>&1
source ./lib.sh
CFGDIR="$HAFO_DIR"

if [ ! -f "${CFGDIR}/.owned" ]; then
  echo "ai-ha-failover-bfd rmconfig: nothing owned by this scenario on this host"
  exit 0
fi

# Monitors and backends are host processes inside a netns: match this
# scenario's own command lines.
for d in /proc/[0-9]*/cmdline; do
  if tr "\0" " " < "$d" 2>/dev/null | grep -q "hdr_echo.py ha-fo-\|hafo_backend.py ha-fo-\|ai-ha-failover-bfd/hafo_tools.py\|tcpdump -i docker0 -nn -tt -l udp port 3784"; then
    p="${d#/proc/}"; p="${p%/cmdline}"
    sudo kill -9 "$p" 2>/dev/null
  fi
done

for c in llb1 llb2 $CLIENT $BACKENDS; do
  docker rm -f -v "$c" >/dev/null 2>&1
  if [ -e "/var/run/netns/$c" ]; then
    sudo ip netns del "$c" >/dev/null 2>&1 || true
    sudo umount "/var/run/netns/$c" >/dev/null 2>&1 || true
    sudo rm -f "/var/run/netns/$c"
  fi
done
for ns in $SW_C $SW_B $MON; do
  [ -e "/var/run/netns/$ns" ] && sudo ip netns del "$ns" >/dev/null 2>&1
done
docker rm -f -v "$PG_NAME" "$KC_NAME" >/dev/null 2>&1

# The gateways write into the mounted /etc/shared/<node>; empty it, keep it.
for n in llb1 llb2; do
  [ -d "/etc/shared/$n" ] && sudo find "/etc/shared/$n" -mindepth 1 -delete 2>/dev/null
done

if [ -f "${CFGDIR}/.images-before" ]; then
  added=$(docker images --format '{{.Repository}}:{{.Tag}}' | LC_ALL=C sort | LC_ALL=C comm -13 "${CFGDIR}/.images-before" -)
  [ -n "$added" ] && { echo "images added since config.sh (kept; remove at campaign close):"; echo "$added" | sed 's/^/  /'; }
fi

rm -f "${CFGDIR}"/.keys "${CFGDIR}"/.fresh "${CFGDIR}"/.env "${CFGDIR}"/.cfg-list "${CFGDIR}"/.cfg-list.llb2 \
      "${CFGDIR}"/.llb1-bridge-ip "${CFGDIR}"/.llb2-bridge-ip "${CFGDIR}"/.llb1-cmdline "${CFGDIR}"/.llb2-cmdline \
      "${CFGDIR}"/.unhealthy "${CFGDIR}"/.burst-headers "${CFGDIR}"/.pg-ip "${CFGDIR}"/.startup-times "${CFGDIR}"/.images-before "${CFGDIR}"/.owned
sudo rm -rf "${CFGDIR}/llb1_config" "${CFGDIR}/llb2_config"
rm -f /tmp/hafo-nonce.* 2>/dev/null
echo "ai-ha-failover-bfd rmconfig done"
