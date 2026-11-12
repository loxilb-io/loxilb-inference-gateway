# BGP API intent recovery

Run on a Linux Docker test host with Go and a gateway image containing `gobgp`,
`gobgpd`, `curl`, `ip`, `tcpdump` and the native gateway:

```sh
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery-role --role-managed
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery-static --static-baseline
python3 cicd/bgp-recovery/validate.py --image YOUR_IMAGE --output /tmp/bgp-recovery-yaml --yaml-preservation
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
All three profiles also persist a healthy out-of-band CLI neighbor change.
The YAML preservation profile uses a non-default hold timer, an unrelated LB
mutation and auto-persist, then adds a YAML-only peer after the first persist.
Daemon/container restarts must preserve that actual timer and the edited YAML
peer without applying the unadopted snapshot BGP group. It then explicitly adopts through the BGP API and
checks the dropped-attribute WARN/gauge and documented supported-projection
behavior through both restarts. The initial global POST has no harness retry;
the REST startup readiness wait handles that process startup window.
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

The BGP recovery workflow runs all four profiles on trusted repository PRs
matching the recovery paths and nightly. It reuses the reusable candidate-image
builder's Ubuntu 22.04 image artifact, verifies image ID and source revision,
and never selects a published `latest` image. Recovery runs even when a candidate
security scan fails; the security gate still fails independently. A cancelled
gateway job prevents recovery, and a missing candidate artifact fails the runtime
job with an explicit diagnostic. Like basic-sanity-ubuntu-24, it
uses the u22 datapath on the Ubuntu 24.04 runner to avoid the documented u24
image verifier E2BIG on hosted 6.x-azure kernels. The runtime job uses the standard
hosted Ubuntu Docker/privileged pattern and records elapsed seconds in its job
summary. Failure artifacts exclude the generated gateway config directory
(which can contain node keys). Fork and Dependabot refs do not receive the
repository-only build credentials or run this job.
