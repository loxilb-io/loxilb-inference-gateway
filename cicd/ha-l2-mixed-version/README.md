# L2 BFD mixed-version regression

This GPU-free scenario uses two on-prem IPv4 L4 nodes, one FullNAT/HASH VIP,
and three HTTP echo backends on one data segment. A separate link carries BFD
and peer sync. The AI-HA-Failover-BFD workflow runs it for relevant in-repository pull requests,
every night, and on demand. The [same-version suite](../ai-ha-failover-bfd/README.md)
runs alongside it and covers isolated election, process loss, and frontend
eligibility including both frontends down and same-name recreation.

- Start both nodes with the released image, persist a working rule on both,
  and back up each configuration directory before replacing either node.
- Replace the BACKUP with the candidate while checking the incumbent VIP and
  client HTTP continuously. The new node must recover the persisted rule and
  join as BACKUP with BFD UP.
- Stop the released MASTER for the planned takeover. The candidate must own
  the VIP and serve HTTP. Replace the stopped node and verify BACKUP recovery
  without another VIP transfer.
- Send SIGTERM to the candidate MASTER. Require withdrawal rank 1 on its BFD
  path, a clean process exit, and a serving peer. The companion same-version
  suite exercises normal BFD timeout and frontend-triggered withdrawal.
- Persist both candidate snapshots, stop both nodes, and verify loss of VIP
  service. Restore each pre-upgrade configuration backup into a fresh volume
  and start the released pair. Require a sole VIP owner, successful snapshot
  recovery, and stable HTTP. The released baseline accepts schema 1.12.
  Candidates using schema 1.13 or later require the pre-upgrade backup for
  this rollback.

The frontend option stays unset during mixed operation. The test uses a TCP
VIP with HTTP probes and retains image IDs, binary checksums, snapshots'
checksums, client samples, node logs, and the BFD capture. Existing client
connections and customer mTLS are outside this fixture's coverage.

## Versions and local execution

The default in [old-image.txt](old-image.txt) is the multi-platform digest
for the official `v0.9.9.1-u24` image. Set the workflow input `oldImage` or
repository variable `HA_L2_OLD_IMAGE` to test another official image digest.
Keep a pre-B1 baseline when testing interoperability with the legacy election.
The runner refuses equal old and new image IDs or gateway binary checksums.

Run on a disposable Linux Docker test host with passwordless sudo for the
BFD capture. The fixture creates its own containers, networks, and volumes.
The candidate image must already contain the build under test.

```bash
docker pull "$(cat cicd/ha-l2-mixed-version/old-image.txt)"
bash cicd/common/reflect-echo/docker-build.sh
LOXILB_DOCKER_IMAGE=local-gateway:under-test \
  python3 cicd/ha-l2-mixed-version/validation.py --out "$(mktemp -d)"
```
