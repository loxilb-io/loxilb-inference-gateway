#!/bin/sh
# Mount a fresh bpf filesystem at /opt/loxilb/dp for loxilb's pinned maps.
# Invoked by loxilb.service as ExecStartPre (runs as root, no sudo needed).
# Remounting on every start gives the datapath a clean slate; loxilb then
# reloads its eBPF programs and restores persisted configuration.
umount /opt/loxilb/dp 2>/dev/null || true
rm -rf /opt/loxilb/dp/bpf
mkdir -p /opt/loxilb/dp
exec mount -t bpf bpf /opt/loxilb/dp
