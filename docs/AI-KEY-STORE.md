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
has no key store, and admits requests without a key.** The keys are not read
from the old database any more — the tables are not even created there. Nothing
in the traffic distinguishes this from working correctly, because the requests
that used to be allowed are still allowed; it is the ones that used to be
rejected that changed. The gateway says so once at startup of the first such
request:

```
[AIGateway] No API-key store configured (--aikey-db-host unset): requests are admitted without a key
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
