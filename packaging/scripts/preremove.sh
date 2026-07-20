#!/bin/sh
# preremove for loxilb-inference-gateway (.deb and .rpm).
# deb passes  $1=remove | upgrade
# rpm passes  $1=0 (erase) | 1 (upgrade)
# Stop the service only on true removal; upgrades must not leave it stopped
# behind the administrator's back.
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop loxilb.service >/dev/null 2>&1 || true
            systemctl disable loxilb.service >/dev/null 2>&1 || true
        fi
        ;;
esac
true
