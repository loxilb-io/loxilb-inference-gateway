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

## Upgrade

1. Verify one MASTER, one BACKUP, BFD UP, and customer traffic. Record the
   current VIP owner. Upgrade the BACKUP first. Confirm that it rejoins as
   BACKUP and the legacy MASTER still owns the VIP.
2. Stop the legacy MASTER. Confirm that the updated peer takes over and the
   VIP serves customer traffic. Start the other node on the updated version
   and confirm that it rejoins as BACKUP. Expect one planned handover.

Legacy nodes start with large IPv4-derived discriminators and can take the role
from an upgraded node when they rejoin. Use mixed versions for the upgrade
window. An older implementation can also change its discriminator on timeout.
Do not rely on a mixed pair to converge across repeated partitions.

## Rollback

While the original MASTER is still serving in step 1, replace only the updated
BACKUP with the previous build. After step 2, use a maintenance window. Stop the
updated pair, verify VIP withdrawal, and then start both legacy nodes. Resume
traffic after one legacy MASTER owns the VIP and the customer probe succeeds.
