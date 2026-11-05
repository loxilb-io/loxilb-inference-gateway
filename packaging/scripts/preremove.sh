#!/bin/sh
# preremove for loxilb-inference-gateway (.deb and .rpm).
# deb passes  $1=remove | upgrade
# rpm passes  $1=0 (erase) | 1 (upgrade)
# Stop the service only on true removal; upgrades must not leave it stopped
# behind the administrator's back.
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop loxilb.service || exit 1
            systemctl disable loxilb.service >/dev/null 2>&1 || true
        fi
        # The helper and its shared libraries still exist during preremove.
        # Retry cleanup if a previous stop left an offline ownership record.
        if [ -e /run/loxilb-datapath.json ]; then
            /usr/sbin/loxilb --detach-datapath=/run/loxilb-datapath.json || exit 1
        fi
        ;;
esac
true
