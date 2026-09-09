# Management API exposure

Two options decide who can reach the management API and what they can read
without a credential: `--mgmt-profile` chooses the listener, and
`--metrics-auth` decides whether `GET /metrics` is part of the authenticated
surface.

## Listener profiles

| `--mgmt-profile` | Listeners | Refuses to start unless |
|---|---|---|
| `legacy` (default) | Plaintext on `--host` (any address), plus TLS when `--tls` is set | — nothing; the historical behaviour, unchanged |
| `appliance-local` | Plaintext on loopback only; TLS also loopback-only when enabled | `--host` (and `--tls-host`) are loopback. A reachable address is refused, never silently rewritten — except the flag default `0.0.0.0`, which cannot be told apart from an explicit one and is coerced to `127.0.0.1` |
| `remote-tls` | TLS only; the plaintext listener does not exist | `--tls` is set, the certificate and key are readable, **and** an authentication service is enabled (`--userservice`, `--oauth2` or `--manualtoken`) |

Every one of those refusals is fatal before any socket binds. A profile whose
security precondition does not hold is not started in a degraded mode.

## `GET /metrics`

The Prometheus route is declared without a security requirement, because a
scraper does not send a bearer token and on a loopback or trusted-network
deployment it should not have to. That default is wrong for exactly one
profile, and `--metrics-auth` is how it is corrected.

| `--metrics-auth` | `legacy` | `appliance-local` | `remote-tls` |
|---|---|---|---|
| `auto` (default) | anonymous | anonymous | **authenticated** |
| `require` | authenticated | authenticated | authenticated |
| `disable` | anonymous | anonymous | **refused at startup** |

### Why `remote-tls` is different

`remote-tls` will not start without TLS and without an authentication service.
An operator selects it to say: this management API is reachable from other
machines, and nothing on it is anonymous. `/metrics` contradicted that. The
exposition carries per-tenant labels — the tenant roster, per-tenant quota
limits, per-tenant consumption — along with client source addresses and
firewall CIDRs, all readable by anyone who could reach the port.

`--metrics-auth=disable` is refused under this profile rather than honoured,
because both alternatives are worse: silently overriding it would break a
scrape job the operator would then have to debug, and honouring it would ship
the exposure the profile exists to prevent.

### Migrating a scraper

Under `auto`, only `remote-tls` deployments change. A scrape job that starts
returning **401** is reaching a gateway that expects a credential — configure
the job with a bearer token rather than reaching for `--metrics-auth=disable`:

```yaml
scrape_configs:
  - job_name: loxilb
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/loxilb-token
    static_configs:
      - targets: ['gateway.example:8091']
```

`/metrics` is a `GET`, so both the `admin` and `viewer` roles are authorized
(see [OAM-GATEWAY-ROLE-MAPPING.md](OAM-GATEWAY-ROLE-MAPPING.md)). Use a
`viewer` credential for scraping; nothing about a scrape needs write authority.

### What authentication here does not do

It proves *who* is scraping. It does not partition *what* they receive — there
is no server-side label filtering, so any authorized caller gets every series
for every tenant. Tenant-scoped metric detail remains unavailable, and
filtering rows in a client is not a substitute: the data has already crossed
the boundary.

## Two 503s that are not the same

`GET /metrics` answers `503` in two unrelated cases, and they are worth telling
apart when debugging:

- **Metrics collection is disabled** (`--prometheus` not set, or switched off
  through `POST /config/metrics`). The body is plain text. This is answered
  *before* any credential check, deliberately: whether the subsystem is on is
  the same answer for every caller and discloses no metric values, so making an
  operator authenticate to be told it is off helps nobody.
- **The credential store could not answer.** The body is the JSON error
  envelope every other route uses. The request is refused because the gateway
  cannot decide, not because the caller is wrong — a client that retries is
  behaving correctly.
