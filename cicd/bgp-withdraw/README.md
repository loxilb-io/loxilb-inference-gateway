# BGP withdrawal regression

Run on Linux with Docker and a locally built gateway image that contains
`loxicmd`, `gobgp` and `gobgpd`:

```sh
python3 cicd/bgp-withdraw/validate.py --image YOUR_IMAGE --output /tmp/bgp-withdraw-evidence
```

The script creates a unique internal network and two containers, including a
privileged gateway. The observer is passive by default; `--active-observer`
selects the separate active/active connection profile. It checks the independent peer RIB before and after actual
CLI deletion without `--bgp`. Cases include single/shared IPv4 and IPv6 VIPs,
SCTP secondary addresses, alternate IPv6 spellings, endpoint updates, rejection of BGP flag changes, last-member
detach, nonadvertising rules, and observer/speaker reconnection. The reconnect check requires
a live canary and confirms that previously deleted prefixes stay absent.

A delete passes only when the CLI succeeds, the rule disappears, the gateway
stays alive and the peer RIB has the expected state. An initial advertisement is
required for withdrawal cases. A process abort is a failure; later cases do not
run. Command output, RIB snapshots and container logs are retained under the
output directory. Cleanup verifies exact container IDs and the reproduction
label, then removes only those containers and the network it created.

For a separate control-plane diagnostic when native eBPF deletion fails:

```sh
python3 cicd/bgp-withdraw/validate.py --image YOUR_IMAGE --output /tmp/bgp-withdraw-control --proxy-only
```

This explicit mode uses the same gateway/CLI/BGP path with eBPF disabled. Its
results do not qualify the eBPF dataplane, SCTP traffic, physical HA, host reboot,
FIB/ECMP or multi-vendor interoperability. It never substitutes this mode after
a failure of the default run. A fresh standalone configuration is used; no HA
role or timer policy is changed.
