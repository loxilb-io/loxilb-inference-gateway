#!/bin/sh
# postinstall for loxilb-inference-gateway (.deb and .rpm).
# deb passes  $1=configure  ($2 empty on fresh install, old version on upgrade)
# rpm passes  $1=1 (fresh install) | 2 (upgrade)
fresh=0
case "$1" in
    configure) [ -z "$2" ] && fresh=1 ;;
    1) fresh=1 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "$fresh" = 1 ]; then
        systemctl enable loxilb.service >/dev/null 2>&1 || true
        echo "loxilb-inference-gateway installed: service enabled but not started."
        echo "Start it with: systemctl start loxilb"
    fi
fi
true
