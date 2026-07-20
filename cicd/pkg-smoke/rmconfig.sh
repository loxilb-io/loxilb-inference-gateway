#!/bin/bash
# pkg-smoke teardown: endpoints, netns topology, service, drill artifacts.

WORK=/tmp/pkg-smoke

for ep in ep1 ep2; do
    if [ -f "$WORK/$ep.pid" ]; then
        sudo kill "$(cat "$WORK/$ep.pid")" 2>/dev/null || true
    fi
done

for ns in pks-h1 pks-ep1 pks-ep2; do
    sudo ip netns del "$ns" 2>/dev/null || true
done
for hveth in pksh1 pksep1 pksep2; do
    sudo ip link del "$hveth" 2>/dev/null || true
done

sudo systemctl stop loxilb 2>/dev/null || true
sudo rm -f /etc/systemd/system/loxilb.service.d/pkg-smoke.conf
sudo rmdir /etc/systemd/system/loxilb.service.d 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true

# Remove the snapshot the drill persisted (keep /etc/loxilb itself)
sudo rm -f /etc/loxilb/snapshot.json
rm -rf "$WORK"

echo "pkg-smoke rmconfig done"
