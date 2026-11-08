# BFD session lifecycle

A session keeps one ticker worker across interval/multiplier updates. Updating
an existing session preserves the initial HA synchronization gate. The BFD
interval defaults, detection policy, initial HA wait and MASTER/BACKUP election
policy are unchanged.

Deleting a session requests stop and waits for its ticker and accepted
receive-side callbacks to finish. A successful deletion sends the final
AdminDown packet for a started session, closes its UDP connection and removes
its configuration. Re-adding the same remote address then creates a new session.

A notifier callback has no cancellation contract. If it does not return within
the one-second session join wait, deletion returns an error and retains the
stopping configuration. Updates to that stopping session are refused; retry
deletion after the callback can finish. A changed configuration also has a
bounded one-second wait for an in-progress callback. An unchanged configuration
is idempotent. Final UDP writes retain their 500 ms deadline; configuration
serialization and other API work can add to total request time.

The session table remains available to readers while a callback or join is
pending. A timeout must not be interpreted as a successful deletion or as proof
that the peer has received AdminDown. Physical failover, host reboot and dataplane
traffic qualification remain separate checks.

## Operator notes

A stop timeout is reported at Warn with the remote address. The retained entry
has `stopping=true`: its accepted ticker/callback work has not yet joined, and
its UDP socket remains open until a subsequent delete completes. It is not a
successful deletion. Re-adding that remote is refused while the entry is
stopping. After the slow notifier can return, repeat the delete to finish
joining, send the final AdminDown where applicable, close the socket and remove
the entry. Re-add only after that delete succeeds.

## Known limits

Receive-side processing still runs through a single listener goroutine. A slow
external notifier for one session therefore delays receive handling for all
sessions. This is unchanged from the previous behavior, which held `BFDMtx`
across the state machine and notifier. Per-session receive dispatch or notifier
isolation remains follow-up work.
