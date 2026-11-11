# BGP API intent recovery

Run on a Linux Docker test host with Go and a gateway image containing `gobgp`,
`gobgpd`, `curl`, `ip`, `tcpdump` and the native gateway:

```sh
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery-role --role-managed
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery-static --static-baseline
```

The default uses no gateway daemon YAML. It configures global state, a neighbor,
sets, definitions, an export assignment and a Full NAT TCP VIP through the API.
An independent passive GoBGP peer must reach Established and receive the VIP
with the configured AS path and MED 77. An external HTTP request must return a
unique token and appear in the separate backend's receipt log.

Checks cover completed-state and repeated SIGKILL recovery, acknowledged
neighbor/policy/set deletions racing persist and restart, full replacement
racing recovery/persist, durable container restart and a crash while saved BGP
boot recovery is pending. The pending case temporarily SIGSTOPs only the
test daemon, observes actual pending readiness, then SIGKILLs it. The role
profile checks suppression before the first MASTER request. The static profile
adopts YAML state and verifies that API deletions survive its later restarts.
`--expect-loss` requires the unfixed completed-state loss and is for a baseline
image. `--keep-on-failure` retains explicitly labeled isolated resources for
diagnosis; otherwise cleanup checks their exact IDs and labels.

The peer is a GoBGP RIB observer. The test explicitly installs the observed
next hop in the isolated client's FIB and adds the backend return route for
Full NAT. This verifies native TCP forwarding after BGP recovery; it does not
claim automatic BGP-to-kernel FIB integration, physical HA failover, reboot,
IPv6/SCTP traffic or interoperability with a different BGP implementation.
Commands, actual daemon/peer state, HTTP receipts and container logs are saved
in a unique directory under `--output`. Existing host routes and Docker
networks are checked before selecting an unused internal subnet.
