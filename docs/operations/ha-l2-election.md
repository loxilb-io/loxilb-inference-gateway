# Two-node L2 HA election

This election applies to an on-premises IPv4 L2 pair started with `--ka` in
the default HA instance. It uses the existing LoxiLB BFD packets and does not
require a feature option. BGP deployments and other BFD sessions continue
to use their existing role policy.

The startup allowance for an isolated node is **95 seconds**, from the existing
90-second XSync hello wait plus the 5-second cool-off. There is no additional
HA timer. A BFD peer heard during that wait still takes part in the election.
If XSync settles early, BFD uses its normal detection interval to distinguish
ordinary startup negotiation from a missing peer. Runtime peer loss continues
to use BFD detection. A genuine partition can temporarily leave both nodes
active. When communication resumes, the two active ranks order the tie.

A returning node starts as a candidate and stays BACKUP when it hears an active
peer. Automatic L2 VIP advertisement begins only after an election outcome.
The HA role endpoint can read the selected role. Requests to change the
elected role use the existing error response. Readiness retains its
configuration-recovery meaning. The log and `loxilb_ha_election_events_total`
record transition reasons. The lone-start log records the 95-second allowance.

## Clean shutdown and frontend failure

On SIGTERM or SIGINT, a node in a managed pair stops advertising its IPv4 service
VIPs and attempts to remove them. It publishes withdrawal rank 1 on the
existing BFD session before the remaining shutdown stages. A peer that misses
the signal can still take over on the normal BFD timeout. A SIGKILL leaves any
kernel state to the existing recovery path.

On both upgraded L4 nodes, pass `--ha-frontend-interface=<ifname>` to make that
local interface part of the election. Leave it unset during the mixed-version
upgrade. Supply the interface to the L4 process itself (for example through
`loxilb.extraArgs` in the L4 gateway's Helm values). The option requires an
on-prem IPv4 default L2 HA pair started with `--ka`. The process refuses to
start if the interface is missing or is the actual kernel egress to the BFD
peer. It starts ineligible if the frontend is down or the VIPs do not resolve
to unique directly connected IPv4 prefixes on that interface.

The node withdraws after 300 ms of observed frontend loss. Link deletion and
rename invalidate the previous interface identity. Same-name replacement must
match the customer prefixes and pass five continuous seconds of Up before
the node returns as a candidate. Recovery does not preempt a healthy MASTER.
The kernel address prefix is used during recovery so loss of a connected
route cannot select a different customer interface.

VIP removal is attempted up to three times within 300 ms. If it fails, the
node still sends withdrawal rank 1. This can leave a temporary duplicate VIP.
The periodic sweep retries removing the local addresses. This node remains
ineligible until the sweep confirms removal. The same removal budget is used
at clean shutdown, followed by the existing shutdown cleanup.

## Startup and recovery timing

Budget gateway initialization, the **95 s start gate**, and VIP
installation for an isolated node. MASTER with the VIP completes the
election. Saved full-proxy rules then need listener preparation on the
existing 10 s rule ticker and may need the default 3 s quota warm-up
before HTTP 200. The original llbigw-2 samples took 113.536 s for a
restart and 132.122 s for cold start, including harness and sampling time.

## Election events

`loxilb_ha_election_events_total{reason="..."}` is a counter. Each time
series appears when its reason is used. The reason values are fixed.

| Reason | Decision |
|---|---|
| `active_alone` | XSync startup wait timed out with no usable BFD peer. |
| `active_without_bfd` | XSync reached the peer, but BFD was never heard before initial detection closed. |
| `peer_timeout` | An observed BFD peer stopped responding. |
| `preferred_rank`, `peer_preferred` | The local or remote rank won. |
| `equal_rank` | Equal ranks select BACKUP. |
| `legacy_peer` | The peer uses the legacy discriminator range. |
| `peer_withdrawn` | The peer has a withdrawn rank. |
| `waiting_for_peer` | No settled peer decision yet. |
| `ineligible`, `invalid_local_rank`, `shutdown_withdrawal` | The local node cannot be selected by that election decision. |
| `frontend_down` | The configured frontend is down or its identity and VIP prefixes cannot be confirmed. |
| `vip_withdrawal_failed` | The removal attempt left local VIP addresses unconfirmed. |
| `external_role_refused` | A role write conflicts with the current BFD election. |

If BFD alone is cut at startup, XSync can be ready on both nodes and both
can become active. On reconnect the higher-IP active rank keeps the VIP
and the lower-IP node becomes BACKUP.

## Upgrade

1. Verify one MASTER, one BACKUP, BFD UP, and customer traffic. Record the
   current VIP owner and back up each node's configuration directory.
   Upgrade the BACKUP first. Confirm that it rejoins as
   BACKUP and the legacy MASTER still owns the VIP.
2. Stop the legacy MASTER. Confirm that the updated peer takes over and the
   VIP serves customer traffic. Start the other node on the updated version
   and confirm that it rejoins as BACKUP. Expect one planned handover.

Legacy nodes start with large IPv4-derived discriminators and can take the role
from an upgraded node when they rejoin. Use mixed versions for the upgrade
window. An older implementation can also change its discriminator on timeout.
Do not rely on a mixed pair to converge across repeated partitions.

## Rollback

While the original MASTER is still serving in step 1, restore the BACKUP's
pre-upgrade configuration and start it with the previous build. After step 2,
use a maintenance window. Stop the updated pair, verify VIP withdrawal,
restore each node's pre-upgrade configuration, and start both legacy nodes.
Resume traffic after one legacy MASTER owns the VIP and the customer probe
succeeds.

The previous release can reject snapshots written with a newer schema.
Retain the pre-upgrade backups until the rollback window closes. See
[configuration recovery](configuration-recovery.md#image-changes-and-rollback)
for the separate stores to include in the backup.
