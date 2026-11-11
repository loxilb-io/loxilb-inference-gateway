# HA and BGP startup

The BGP daemon and its configuration start independently of the HA initial
hello wait. A healthy peer should not impose a 90-second speaker startup delay.
BGP configuration readiness and HA role readiness are separate conditions.
Application VIP advertisements wait until CI initialization (including legacy
BFD replay) and boot configuration replay have both settled. This prevents LB
rules replayed first from escaping before saved BFD enables the role barrier.
The next five-second BGP maintenance tick replays deferred rules. This boot-only
gate does not wait for the HA hello timeout or arm sticky role management for
CT-only, egress or otherwise role-unmanaged deployments.

The role barrier is enabled by actual role management: configured --ka/BFD,
or a valid cistate control request (including an unchanged NOT_DEFINED request).
This signal is sticky for the process. CT-sync peer registration, --cluster,
egress-only VXLAN endpoints and kube-loxilb without setRoles do not enable it.
These role-unmanaged deployments retain advertisements in NOT_DEFINED, including
active-active/ECMP-style use. BGP peer-only mode retains its speaker behavior;
LB datapath services are unavailable in that mode.

With role management active, new/replayed LB advertisements require MASTER or
BACKUP. The same check applies to AddBGPRule, daemon reconnection and pending
snapshot-group recovery. A pending BGP group separately blocks advertisement.
Before an external controller has sent its first role request, the process has
no controller-management signal; a CT peer alone deliberately does not supply it.
This change does not introduce a universal withdrawal policy for previously
advertised routes when an operator changes a role to STOP/FAULT/NOT_DEFINED.

MASTER advertises with the existing high preference/MED values. BACKUP keeps
its existing lower-priority advertisements. A wait timeout does not select a
role or independently authorize advertisements. The existing BFD policy still
releases its start gate after the hello wait (ready or timeout) and the existing
cool-off; changing that failure policy is outside this fix. Cancellation leaves
the gate closed. The default hello wait remains 90 seconds.

CT map notifications received before the local root zone and rule table are
published are ignored. This prevents an early callback from dereferencing uninitialized
state, including notifications observed from another instance on the same host.

Initial sync requests wait for receiver readiness and queued peer registration.
Standalone zero-peer initialization remains valid. A dedicated worker handles
hello, connect and get requests; these operations do not run on the datapath
GC/stats ticker. Healthy accepted peers are probed every 30 seconds. Failed peers
use individual exponential retry delays from 2 to 30 seconds. Network calls do
not hold the membership mutex; a concurrent operation skips a busy per-peer
transport and retains its retry state instead of blocking on it.

Hello readiness matches each configured peer's transport source IP. Legacy
net/rpc CONNECT and gRPC contexts bind the source identity without changing the
hello wire format. Self IDs alone are not identities and may be equal on
separate peers. A failure, add or remove invalidates only the affected peer's
hello. Direct peer addresses must match the transport source; NAT/alias identity
mapping is not introduced here. Simultaneous full-map requests still coalesce.


Normal process cancellation sends SIGTERM to gobgpd so it can close its BGP
sessions gracefully. WaitDelay bounds a non-cooperative daemon to 5 seconds
before SIGKILL, and shutdown waits for this supervisor within a 6-second stage.
An external SIGKILL remains a crash and cannot send a graceful notification.

Logs separate `BGP stage=daemon-start`, `BGP stage=config-ready`,
`HA stage=ct-request`, `HA stage=xsync-hello` and `HA stage=ka-gate`.
The hello wait reports `result=ready`, `timeout` or `cancelled`, with elapsed
time. `ct_complete=unverified` is deliberate: an accepted asynchronous request
and a reverse hello are not a completion acknowledgement for the entire
conntrack transfer. They must not be presented as full HA state replication.

The boot status and `loxilb_boot_bgp_pending` metric continue to describe
snapshot BGP recovery, not HA election or complete CT transfer. Verify routes
in an independent peer RIB and traffic at the backend when testing recovery.
A RIB observation does not establish kernel FIB programming or interoperability
with other BGP implementations.

## BGP configuration after a daemon crash

The gateway retains completed BGP intent, including global settings, neighbors,
defined sets, policy definitions and operator policy assignments. A successful
BGP API mutation updates this intent before returning, including deletions in
the auto-persist quiet period. The supervisor schedules the existing BGP group
coordinator before launching a replacement gobgpd; it does not wait for an
unconfigured replacement to acquire an ASN by itself. The retry applies only
the BGP group and verifies the daemon's actual configuration. New VIP
advertisements wait for the complete group and the existing HA role barriers.
Recovery rebuilds VIP references from current LB rules.

BGP API writes, interactive replacements and the retry are serialized. While
the group is pending, ordinary BGP writes return 409; a full committed snapshot
restore can replace that target. Cancelled workers cannot subsequently apply
their old target. Healthy persist/capture reads live operator configuration, including changes
made with the GoBGP CLI, and refreshes retained intent. During pending recovery,
a disconnected speaker, a failed read or a session change, it uses the last
complete intent rather than recording an empty or partially configured speaker. Process/container
restart survival continues to require a successful explicit, automatic or
restore write-through persist to `snapshot.json`; disabling auto-persist retains
the existing explicit-persist requirement. There is no second intent file.

Without a static GoBGP file, API/snapshot intent owns the speaker. When a
static file exists, YAML owns it until an explicit adoption: a successful BGP
REST mutation, or a committed interactive restore/import selecting a BGP domain.
An unrelated mutation, auto-persist, live capture and an unmarked boot snapshot
do not adopt YAML. Before adoption, replacement daemons reload the static file.
The snapshot BGP group is excluded entirely at boot and after daemon crashes,
even when its supported fields differ from YAML. A pending unadopted boot BGP
group is cancelled without apply, wipe or rollback; its recovery gates are
released while the existing HA/boot barriers still apply. Capture and retention
continue to observe healthy live state.

When upgrading a mixed YAML+API installation with an unmarked snapshot, YAML
owns the entire BGP group until an explicit BGP REST change or committed
interactive BGP restore/import adopts it. Snapshot-only peers from that old
snapshot are not overlaid onto YAML automatically. Returning an already
adopted installation to YAML ownership is currently unsupported: no REST flow
clears adoption, and hand-editing the checksummed snapshot marker is not a
supported ownership transition.

Adoption is recorded in the optional `bgp_api_adopted` field of `snapshot.json`
(schema 1.13); an absent field means false. Later persists carry it forward.
There is no second intent file. Once adopted, replacement daemons start without
the static file and replay the current API/snapshot intent, including deletions.
Editing old YAML no longer overrides that state. Adoption retains only fields
represented in the snapshot model; additional neighbor timers, authentication,
AFI/SAFI and other YAML-only settings are not preserved after adoption. Keep
YAML ownership when those settings are required. Generated gateway export
policies remain speaker-owned.

A recovery preparation failure keeps advertisements blocked and logs its reason
at error level. The supervisor retries preparation with a cancellable 2-to-30
second backoff. `loxilb_bgp_daemon_config_pending` is 1 while this gate is closed,
even before a pending snapshot group exists; readiness also reports it. A
successful committed restore/import selecting BGP cancels obsolete preparation
and completes this gate even when no pending group was created. The existing
HA role and boot gates still apply.

During initial speaker startup, BGP REST mutations wait for transport readiness
with bounded backoff for up to 30 seconds before taking the recovery operation
lock. An unconfigured but reachable speaker is ready for the first global POST.
No GoBGP mutex is held while waiting. Once transport readiness has been reached
in this process, later crash-window REST calls fail fast. Advertisement and
withdrawal RPCs always fail fast; the explicit connection probe and recovery
worker retain their own retry. A reachable but unresponsive daemon still has
bounded RPC deadlines. Each session owns one cancellable watch stream.

When explicitly adopting a static-file installation, live GoBGP peer
configuration is inspected before the mutation/replacement. API-only
installations skip this inspection and leave its WARN/gauge unchanged. Non-default timers, unsupported AFI/SAFI configuration,
graceful restart and exposed authentication presence that the snapshot model
cannot retain produce a WARN with peer IP and attribute names only. Secret
values are never logged. Adoption is not blocked. The scalar
`loxilb_bgp_adoption_dropped_attributes` counts detected peer/attribute categories
at the last successful adoption in this process; -1 means inspection failed,
0 means none detected. It resets on process restart, so 0 does not establish
that an earlier adoption preserved all attributes. Inspection failure logs a
fixed warning without raw peer/RPC payloads.

Schema 1.13 snapshots are rejected by older binaries as a newer minor version.
As with the 1.11 -> 1.12 boundary, additive fields do not permit an older build
to silently drop unsupported state; retain a compatible pre-upgrade snapshot
for a planned downgrade.

See `cicd/bgp-recovery/README.md` for the independent peer and traffic regression.
