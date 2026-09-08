# cfg-persist-restartmatrix

One mid-size fixture (two LB rules, a firewall rule, a session, a managed
certificate), three restart classes, one oracle. Every class ends with the
canonical deep-compare against the pre-restart dump plus a live traffic
probe through the restored VIP — configuration that comes back
half-applied, reinvented from defaults, or only good enough for the path
traffic happens to take fails the diff.

## Classes

- **(a) In-place restart**: the gateway process is killed and relaunched;
  the container, its netns and its veths survive. Boot replays
  `snapshot.json`; the boot surface must report the replay at the exact
  lineage generation the persist recorded.
- **(b) Container recreate** (`docker stop` / `docker start`): the network
  namespace and every veth in it die, the host-mounted config volume does
  not. The suite re-registers the `/var/run/netns` handle (the old bind
  mount points at the dead namespace — every `hexec` would silently run
  there), rebuilds and re-addresses both veth pairs, then relaunches the
  gateway. The document *and* the managed certificate material must be
  found on the volume exactly as the previous container left them. This
  is the class a container image upgrade or node reboot lands in.
- **(c) Cold config**: `snapshot.json` (and any legacy `*.txt`) removed
  before the boot — the mis-mounted or wiped volume case. The gateway
  must come up genuinely empty and *say so*: `snapshot_found=false`,
  `succeeded=false`, no `last_restore`, not degraded, READY. A node that
  reports a recovery it never performed is how a configuration is lost
  for good. The leg then proves the empty dump DIFFERS from the baseline
  (so the deep-compare oracle cannot be passing on stale data), recovers
  through the operator path (REST commit restore of the last good
  document), and shows the recovered configuration surviving the next
  boot on its own via the restore's write-through.
## Red twin

`PLIB_RED_MUTATE=a|b|c` arms ONE deliberate break — the firewall rule
dropped after the baseline capture (mode (a)'s deep-compare), the managed
cert material removed before the recreate (mode (b)'s volume assert), or
`snapshot.json` left in place for the cold boot (mode (c)'s empty-boot
classification). `PLIB_RED_MUTATE=1` arms all three, which is a fine
smoke test but not a proof of each class: mode (b)'s break wedges the
node, so the later modes then fail on the cascade instead of on their own
oracle. Prove a class with its own letter; run a red whenever the suite
changes.


## Traps

- After `docker start` the `/var/run/netns/<name>` bind mount still points
  at the STOPPED container's namespace. Re-register it from the new PID
  before any `hexec`, or every probe silently runs in a dead namespace.
- The veth pairs die with the old namespace: `disconnect_docker_hosts`
  both ends before reconnecting, and re-address BOTH sides — the client
  and endpoint hosts lost their addresses with the deleted links.
- `plib_start_gw` truncates `/tmp/loxilb.out` on every launch, which is
  what keeps `wait_replay_receipt` from matching a previous boot's
  receipt inside a container that survived the restart.
- The cold class has no replay receipt to poll: the readiness surface's
  boot-gate reason is the receipt (`wait_boot_settled`).
- The gateway writes `snapshot.json` root-owned 0600 — host-side reads go
  through sudo.
- The baseline drains the auto-persist debounce before pinning the
  lineage generation. A debounce still pending from the fixture build
  writes snapshot.json again a few seconds later, and the boot then
  replays a generation the leg never recorded — a race, not a defect, and
  it only shows up on some runs.
