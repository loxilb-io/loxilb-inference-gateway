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
