# AI API-key store

The AI Gateway keeps its data-plane API keys and per-tenant quotas in
PostgreSQL, in a schema of its own under a role of its own. This is the
operator procedure for provisioning it, pointing the gateway at it, and
diagnosing it when the gateway says it cannot reach it.

## What lives where

| Party | Schema | Role | Tables |
|---|---|---|---|
| loxilb-oam | `public` | OAM's own role | OAM's users, tokens, and the rest |
| Gateway data plane | `aigw` | `aigwuser` | `api_keys`, `tenant_rate_limits`, `tenant_model_rate_limits` |
| Gateway management plane | `aigw_mgmt` | `aigw_mgmt_user` | `users`, `token` |

One PostgreSQL server, one database, three tenants inside it that cannot read
each other. The gateway's data-plane role holds the credentials that admit
traffic at the VIP; the management role holds the credentials that administer
the gateway. Keeping them apart at the database is why a compromise of one
does not hand over the other.

## Provisioning

`scripts/aigw-db-bootstrap.sql` creates the roles, the schemas and the grants.
It needs privileges the gateway's own role does not have, so it runs as the
database owner — once, at deployment, not by the gateway.

Two invocation paths, same file.

**An existing database** — the common case, where OAM is already deployed and
its PostgreSQL volume exists:

```bash
export AIGW_DB_PASSWORD='...'        # data-plane role
export AIGW_MGMT_DB_PASSWORD='...'   # management-plane role
psql -v ON_ERROR_STOP=1 -U <owner> -d <database> \
     -f scripts/aigw-db-bootstrap.sql
```

**A fresh deployment** — mount the file into the initdb hook, which the OAM
compose already does for its own schema:

```yaml
volumes:
  - ./aigw-db-bootstrap.sql:/docker-entrypoint-initdb.d/10-aigw-bootstrap.sql
```

The passwords reach it through the container's environment either way. The
script never takes a password as a literal, and refuses — with a non-zero exit
— when one is missing or empty, rather than creating a login role that anyone
can use.

It is idempotent: re-running is safe, and re-running with new passwords is how
you rotate them.

### Verifying a bootstrap

```sql
SELECT nspname, pg_get_userbyid(nspowner) AS owner FROM pg_namespace
 WHERE nspname IN ('aigw', 'aigw_mgmt');

SELECT has_schema_privilege('aigwuser', 'aigw', 'CREATE')      AS dp_own,
       has_schema_privilege('aigwuser', 'aigw_mgmt', 'USAGE')  AS dp_reaches_mgmt,
       has_schema_privilege('aigw_mgmt_user', 'aigw', 'USAGE') AS mgmt_reaches_dp,
       has_schema_privilege('aigwuser', 'public', 'CREATE')    AS dp_creates_public;
```

`aigw` owned by `aigwuser`, `aigw_mgmt` by `aigw_mgmt_user`; `dp_own` true and
the other three false.

`has_schema_privilege('aigwuser','public','USAGE')` reads **true** and that is
expected. `USAGE` on `public` is held by the `PUBLIC` pseudo-role, so it cannot
be revoked from one role without revoking it from every role on the server. It
confers nothing over the tables in the schema — connect as `aigwuser` and
`SELECT` from any OAM table to confirm it is denied.

## Pointing the gateway at it

```
--aikey-db-host=postgres.internal
--aikey-db-port=5432                 # default
--aikey-db-user=aigwuser
--aikey-db-name=loxilb
--aikey-db-password-file=/etc/loxilb/aigw_db_password
```

There is no `--aikeyservice` switch. The store is configured when
`--aikey-db-host` is set; whether keys are *enforced* is a per-service policy
you set through the API, so it changes without a restart.

The password comes from the file named above, or from `AIGW_DB_PASSWORD` in the
environment when no file is named. Never from a command-line argument — that
would be readable in `/proc/*/cmdline` by every local process. If a file is
named and cannot be read, the gateway reports that rather than quietly falling
back to the environment.

### TLS

```
--aikey-db-ssl
--aikey-db-ssl-ca-cert-file=/etc/loxilb/pg-ca.crt
--aikey-db-ssl-client-cert-file=/etc/loxilb/pg-client.crt
--aikey-db-ssl-client-key-file=/etc/loxilb/pg-client.key
```

This selects `sslmode=verify-full` with a client keypair: mutual TLS with full
chain and hostname verification, TLS 1.2 or better, and no plaintext fallback —
a server that refuses TLS gets an error, never a downgraded connection carrying
the password. The server certificate's SAN must cover the address in
`--aikey-db-host`, since that is the name verification is performed against.

### Upgrading from the `--userservice` store

Before this store existed, API keys lived in the same MySQL database as the
management users, and `--userservice` was what made key checking happen at all.
It no longer is: the two planes share nothing, and key checking now depends on
this store alone.

**A gateway upgraded with `--userservice` still set but no `--aikey-db-host`
has no key store.** A rule with `api_key_auth: "required"` answers 503
`policy_store_unavailable`, and a rule that declares nothing admits requests
without a key. The keys are not read from the old database any more — the tables
are not even created there. The gateway says so once, on the first such request:

```
[AIGateway] No API-key store configured (--aikey-db-host unset): services with api_key_auth=required are refusing requests with 503
```

Provision this store and point `--aikey-db-*` at it. The existing keys can be
carried over either way:

- **Keep the credentials working.** Copy the rows. The column that decides
  authentication is `key_hash`, and it means the same thing in both schemas, so
  a dump of the old `api_keys`, `tenant_rate_limits` and
  `tenant_model_rate_limits` loads into `aigw.*` and every key a tenant already
  holds keeps working. Watch the type differences: the timestamps are
  `TIMESTAMPTZ` here and MySQL's `DATETIME(3)` is a naive wall clock, so give
  the loaded values an explicit UTC offset rather than letting the server guess
  one; `enabled` is a real `BOOLEAN`, not `TINYINT(1)`; the integer columns are
  `NOT NULL`, so a NULL in the dump has to become a `0`; and `key_hash` is
  `UNIQUE`, so a duplicate in the old table — which MySQL permitted — has to be
  resolved before the load rather than discovered by it.
- **Re-issue instead.** Create fresh keys through `POST /config/ai/apikey` and
  hand them out. The old key material cannot be recovered from either database
  — only its hash was ever stored — so this is a re-issue, not a rotation the
  tenant can be shielded from.

## Rotation

1. `ALTER ROLE aigwuser PASSWORD '<new>'` — or re-run the bootstrap script with
   the new value in the environment.
2. Update the gateway's password file.
3. Restart the gateway.

Keys already in cache keep validating across the restart window, so this is not
immediately traffic-affecting — but treat it as a maintenance action, because a
gateway that restarts with a stale password comes up unable to reach the store.

## Time budgets and the write-outcome contract

Every statement the gateway runs against the key store, and against the
management credential store, carries a context deadline. A PostgreSQL that
stalls while keeping its TCP connections open (a hung or overloaded server, a
stalled volume, a path that black-holes packets, a paused container) answers
a statement with no deadline never: before these budgets a management write
committed after its client had given up, `/status/ready` hung, and a
cache-miss key lookup parked the proxy worker thread that asked. The budgets
are environment variables in milliseconds; keep each well below the client
timeout in front of the gateway so the gateway answers first.

| Variable | Default | Bounds |
|---|---|---|
| `LLB_AI_STORE_OP_TIMEOUT_MS` | 3000 | One management operation (a configuration read or write, retries included, plus the snapshot refresh a write performs before it returns). Also sent to the server as the session `statement_timeout`. |
| `LLB_AI_STORE_PING_TIMEOUT_MS` | 1000 | The readiness ping behind `/status/ready` and the housekeeping ping. |
| `LLB_AI_STORE_REFRESH_TIMEOUT_MS` | 3000 | One read of the objective/class/limit snapshot; clamped to half of `LLB_AI_OBJECTIVE_REFRESH_SEC`. |
| `LLB_AI_KEY_LOOKUP_TIMEOUT_MS` | 300 | One data-path store round trip: the key lookup on a cache miss and the quota-row reads behind a request. This is the longest a proxy worker is ever parked by the store. |

Idle pooled connections are dropped after 60 s, so a connection that idled
through a stall is not handed to a later statement indefinitely.

**What a write answers during a stall.** A deadline bounds the wait; it cannot
retract a statement that already reached the server. The API therefore
distinguishes two failures, and clients must treat them differently:

- **503 `ai_key_store_unavailable`** (management-plane wording: *Credential
  store unavailable*): the statement was never handed to the store. Nothing
  was written; retrying is safe.
- **504 `ai_key_store_outcome_unknown`** (management-plane result
  `store_outcome_unknown`): the statement was sent and the store did not
  answer within the budget. The server may still apply it when it resumes.
  **Read the resource back before retrying.** A blind retry of a
  non-idempotent write, such as creating a generated API key, can create a
  second row.

Reads never answer 504: a read whose budget expires is a 503.

**Reconciling after a 504.** Every write answered 504 leaves two traces: the
audit result record of the request, with `outcome.reason` set to
`store_outcome_unknown` and, for an API-key create, the tenant and the
`client_op_id` in its detail; and one step of
`loxilb_ai_store_write_outcome_unknown_total{plane}` (`aikey` for this store,
`mgmt` for the management credential store). Read the resource back once the
store answers: a limit or objective is present or absent; a key created
without a `client_op_id` shows in `GET /config/ai/apikey?tenant_id=…` by its
`name`, and if its secret was lost it is deleted and created again.

**Retrying a create safely.** A generated key's secret is minted by the
gateway and delivered once, so a create is not idempotent by itself: an
answer lost to a stall may have left an enabled key whose secret nobody
holds, and a blind retry makes a second one. Send `client_op_id` in the body
(or the `Idempotency-Key` header; at most 128 printable non-space ASCII
characters, unique per tenant, a UUID the client minted for this create) and
a retry converges on one row per `(tenant_id, client_op_id)`:

- no such row: the key is created and the id recorded (it shows as
  `client_op_id` on the key's summary);
- the row exists and the key has never authenticated: this is the retry of a
  lost answer. The secret is minted again and the row's hash rotated to it,
  so the earlier secret, held by nobody, stops authenticating on every
  gateway (the rotation is an invalidation like a revoke). The answer carries
  the **same `key_id`**, the new `raw_key`, and `reused: true`. The row's
  other fields are the first request's and are not rewritten;
- the row exists and the key has authenticated: **409
  `api_key_already_delivered`**, naming the `key_id`. The secret in use is
  not rotated out from under its holder and no second secret is minted for
  the same operation. Delete and recreate the key to issue a new one.

The first authentication of such a key is recorded by the data path, off the
proxy worker, with one statement per key lifetime; a key created without an
id costs nothing extra. Two retries carrying the same id serialise on the
row. An imported key (`api_key` in the body) takes the same path: a retry
with the same id and the same material is a no-op that answers `reused:
true`.

**Multi-statement writes are one transaction.** A key create with class
fields, a PATCH naming several fields, a tenant limit with model quotas, and
a user limit with model quotas each run as one transaction: applied whole or
not at all, and a 504 means the whole body may land. Before this a stall
between two statements left the row half-written with the caller told only
about the statement that failed.

**Readiness.** `/status/ready` probes each store under the ping budget and
answers 503 within it when a store stalls; `GET /config/ai/objective` keeps
answering from the applied snapshot with `store_reachable=false` once a
refresh has failed. `/version` answering says nothing about the store.

**Data path.** A request whose key is cached is validated without touching
the store. A cache miss during a stall is refused with 503
`policy_store_unavailable` and `Retry-After`: inside the lookup budget for the
first few misses, and immediately once the store-health circuit below has
opened. The answer is the same one a cold outage gives.

### Data-path isolation

The lookup budget bounds one round trip. On its own it still costs every cache
miss one full wait while the store stalls, on every proxy worker that asks.
Two guards sit in front of the data-path reads (the key lookup on a cache miss,
the quota-row reads behind a request); the management plane, the readiness
ping and the snapshot refresher do not consult them.

| Variable | Default | Meaning |
|---|---|---|
| `LLB_AI_KEY_LOOKUP_MAX_INFLIGHT` | 2 | Data-path round trips allowed on the store at once. A worker that finds no slot waits for one only until its lookup budget expires, so wait plus statement never exceed one budget. Deployments that raise `LLB_PROXY_WORKERS` well above the default and see high key churn may want this raised with it. |
| `LLB_AI_KEY_LOOKUP_CIRCUIT_FAILURES` | 3 | Consecutive store failures that open the circuit. 0 disables it. |
| `LLB_AI_KEY_LOOKUP_CIRCUIT_COOLDOWN_MS` | 5000 | How long the circuit stays open before one probe read is let through. |
| `LLB_AI_KEY_NEGATIVE_CACHE_MS` | 2000 | How long a key hash the store answered "no such key" for is refused without asking again. 0 disables it. |
| `LLB_AI_KEY_NEGATIVE_CACHE_CAP` | 4096 | Entries the negative cache holds; the oldest goes first. |

**The circuit.** It is closed while the store answers. A failure is a round
trip the store did not answer: the budget expired or the connection failed. A
row, and the store's "no such row", are answers and reset the count. So is an
error the server itself returned, such as a permission or schema error: the
store was reached and replied at once, no worker was parked, and the request
is refused on its own arm, but the count does not move, so the next read
after the cause is fixed is served without waiting out a cool-down. A store
that is not connected yet fails fast without a round trip; it shows as
zero-duration `unavailable` samples and does not move the circuit, so a
reconnect is used as soon as it lands. After `LLB_AI_KEY_LOOKUP_CIRCUIT_FAILURES` failures in a
row the circuit opens: every data-path miss is refused at once without
contacting the store, and every quota read answers from the last value the
store confirmed to this process (or from the last-known-good file), refusing
only a tenant, user or key the store never described. After the cool-down the
circuit is half-open: exactly one miss is let through as a probe, every other
miss is still refused; the probe's success closes the circuit, its failure
opens it again for a fresh cool-down. A refused in-flight slot is contention,
not a failure, and never opens the circuit. A statement that completes after
the circuit changed state is counted in the metrics and moves nothing.

**Two independent signals.** `store_reachable` (on `GET /config/ai/objective`
and `/diagnostics`) is the snapshot refresher's view: a 3 s-budget read every
refresh interval. `loxilb_ai_key_store_circuit_open` is the data path's view:
300 ms-budget reads driven by cache misses. They can disagree, and both are
right about what they measure. In particular the circuit **stays open after
the store recovers until a cache miss arrives to run the half-open probe**: a
gauge that reads 1 on a gateway with no miss traffic is not an outage. It
drops within one cool-down of recovery only while misses keep arriving.

**Key limits during an outage.** A key's rate limit and token quota come from
its row. Both the by-hash validation and the by-ID read keep the last view the
store confirmed, so a key this process has validated keeps its limits enforced
through an outage even after the cached entry aged out. A key the process has
never seen described (validated on a peer, or evicted by the cache cap) is
refused with 503 `policy_store_unavailable` rather than admitted on zero
limits.

**Negative cache.** A hash the store said does not exist is refused for
`LLB_AI_KEY_NEGATIVE_CACHE_MS` without another round trip. Creating that key
here, or a peer's invalidation for its hash, clears the entry at once; a key
created on a peer whose hash was probed here just before can therefore be
refused 401 for up to the TTL. That is the accepted trade for not spending a
slot and a budget per unknown key under a flood.

**Metrics.** `loxilb_ai_key_store_lookup_seconds{result}` is the time a worker
spent on one data-path round trip, by how it ended (`miss_found`,
`miss_invalid`, `timeout`, `refused_circuit`, `refused_inflight`,
`unavailable`, the last covering a connection that failed, a server-side error
and a store not yet connected; cache hits are not round trips and are not
counted);
`loxilb_ai_key_store_circuit_open` and `loxilb_ai_key_store_lookup_inflight`
are the two gauges. Samples piling up at the 0.3 s bucket edge are the stall
signature; `refused_circuit` rising with `circuit_open` at 1 is the guard
doing its job. On the management side,
`loxilb_ai_store_write_outcome_unknown_total{plane}` counts the writes
answered 504 (see "Reconciling after a 504" above); it is the one counter of
this family that names work an operator owes.

## Troubleshooting

**`key store preflight failed: schema "aigw" does not exist`**
The bootstrap script has not run against this database. Run it as the owner.
A common cause is mounting it into `docker-entrypoint-initdb.d` on a volume
that already existed — initdb hooks run only on a virgin volume, so use the
`psql -f` path against an existing database.

**`key store preflight failed: schema "aigw" is not accessible to role "…"`**
The gateway is connecting as a role the bootstrap did not grant. Check
`--aikey-db-user` against the role you provisioned; the message names the role
it actually authenticated as.

**`no store password (set AIGW_DB_PASSWORD or --aikey-db-password-file)`**
Neither source supplied one. The gateway will not attempt a passwordless
connection.

**Connection failures with TLS on.** Verify the server certificate's SAN covers
the `--aikey-db-host` value, and that the CA file holds the issuer of the
*server's* certificate. A CA file that parses but contains no certificate is
reported by name rather than surfacing as a verification error.

**The gateway started but reports the store as unavailable.** It starts
degraded rather than refusing to boot: cached keys keep validating and the
reconnect path retries. Look for the `[AIKey]` line naming the redacted DSN it
tried — the password is never in that line.
