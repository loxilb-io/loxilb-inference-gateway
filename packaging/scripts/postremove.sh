#!/bin/sh
# postremove for loxilb-inference-gateway (.deb and .rpm).
# deb passes  $1=remove | purge | upgrade
# rpm passes  $1=0 (erase) | 1 (upgrade)
case "$1" in
    remove|purge|0)
        # Unmount the bpf filesystem the service mounted, if still present.
        umount /opt/loxilb/dp >/dev/null 2>&1 || true
        rmdir /opt/loxilb/dp >/dev/null 2>&1 || true
        # rpm does not own the intermediate directories; drop them if empty.
        rmdir /usr/lib/loxilb /opt/loxilb/cert /opt/loxilb >/dev/null 2>&1 || true
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
true
