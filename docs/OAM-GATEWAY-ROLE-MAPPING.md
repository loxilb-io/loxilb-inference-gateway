# OAM → gateway role mapping

```
schema_version: 1
status: stable
```

`schema_version` is here so a consumer can vendor this statement and detect a
change rather than re-reading prose. It changes only if the mapping below
changes.

## The mapping

| OAM / UI role | Gateway role | Authority on the gateway management API |
|---|---|---|
| `admin` | `admin` | Full: every method on every route. |
| `operator` | `viewer` | **Read-only.** `GET` succeeds; every mutating method is refused with 403. |
| `viewer` | `viewer` | Read-only, identically to the above. |

## This is the answer, not an interim one

The gateway's role set is **closed at `{admin, viewer}`** and will not gain an
`operator` role. That is a decision, not a gap waiting to be filled, so a
client should map `operator → viewer` permanently rather than designing around
a third role arriving later.

The closed set is stated in three places that cannot disagree — the authorizer
(`pkg/authz`), the user-creation and update validation, and a `CHECK`
constraint on the role column. An account created with `operator` is refused at
creation, at storage, and at decision time. Sending `operator` to the gateway
therefore does not produce a degraded principal; it produces a rejected one.

## What an `operator` can and cannot do

An OAM `operator` mapped to gateway `viewer` may read configuration, status,
diagnostics and metrics. It may **not** create, modify or delete load-balancer
rules, endpoints, API keys, firewall rules or any other configuration, and it
may not perform maintenance transitions.

A UI that offers an `operator` a mutating control is offering an action the
server will refuse with 403. Hide such controls for this mapping rather than
letting the request fail — the refusal is correct, but the affordance was wrong.

The one exception to "read-only means GET": `POST /auth/logout` is permitted
for `viewer`, because ending your own session is not a configuration change.

## `/metrics` and this mapping

`GET /metrics` is not always subject to this mapping. Whether it requires a
credential at all is a deployment property, decided by `--metrics-auth`:

| `--metrics-auth` | Behaviour |
|---|---|
| `auto` (default) | A credential is required only under `--mgmt-profile remote-tls`. |
| `require` | A credential is always required. |
| `disable` | Never required. **Refused under `remote-tls`** — the process will not start. |

When a credential *is* required, `/metrics` is a `GET`, so both `admin` and
`viewer` are authorized; the mapping above applies unchanged. When it is not
required, the route is anonymous and no role is involved.

## What this does not unblock

Authenticating `/metrics` proves *who* is scraping. It does not partition
*what* they receive: there is no server-side label filtering, so an authorized
caller receives every series, including per-tenant labels for every tenant.

A **globally scoped, admin-only** metric view can therefore mount once
authentication is enforced. **Tenant-scoped** metric detail cannot, and must not
be approximated by filtering rows in the client — the data has already crossed
the boundary by then, and hiding it in a UI is a display choice, not a security
control.

See issue #142 for the scoped-projection design, which is deliberately deferred.
