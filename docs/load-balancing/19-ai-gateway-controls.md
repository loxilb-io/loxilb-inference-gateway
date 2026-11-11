# AI Gateway Controls — API Keys, Rate Limiting, Model Routing, SSE Quotas

> **Audience:** operators exposing OpenAI-compatible LLM endpoints to multiple teams, tenants,
> or customers, who need authentication, quota, and per-model traffic policy **at the gateway**
> instead of inside every serving engine.
> **Scope:** API-key management and enforcement, per-tenant rate limiting, model-name routing,
> and SSE stream quotas.
>
> **For exact rule fields, treat the matching `cicd/ai-*/config.sh` and `validation.sh` as the
> source of truth** — they are the gated, working configurations and track the current build.

---

## 1. The control surfaces at a glance

| Control | What it does | Config surface | CICD scenario |
|---|---|---|---|
| **API keys** | Issue/revoke `lxb_…` keys; clients authenticate with `X-Api-Key`; per-key model allow-list + rate/burst/token limits | `POST/GET/PATCH/DELETE /netlox/v1/config/ai/apikey` (`PATCH` is defined in `api/swagger-extras.yml`, not the main spec) | [`cicd/ai-apikey`](../../cicd/ai-apikey) |
| **Tenant rate limits** | Aggregate RPS / tokens-per-minute ceiling across all keys of a tenant | `POST/GET /netlox/v1/config/ai/tenant/ratelimit` | [`cicd/ai-apikey`](../../cicd/ai-apikey) |
| **Model-name routing** | Route by the request's model (`X-Model` header or JSON body `model`) to different endpoint pools | `model_name` + `path_prefix` + `path_match_mode` on the LB rule | [`cicd/ai-model-routing`](../../cicd/ai-model-routing) |
| **SSE stream quotas** | Keep streams alive past idle timeouts, cap runaway streams, backend keepalive | `sse_mode`, `max_stream_duration_sec`, `backend_keepalive_interval_sec` on the LB rule | [`cicd/ai-sse-quota`](../../cicd/ai-sse-quota) |

All of these run on **fullproxy** rules (`mode: 4`). Model routing and SSE quotas are pure
rule fields with no extra infrastructure; API keys and tenant limits additionally need the
user-service database (§2.1).

---

## 2. API-key management & enforcement

### 2.1 Prerequisites

API keys are persisted in the gateway's user-service database. Start loxilb with:

```bash
loxilb --userservice \
  --mgmt-db-host <postgres-ip> --mgmt-db-user aigw_mgmt_user --mgmt-db-name loxilb \
  --mgmt-db-password-file /etc/loxilb/mgmt_db_password \
  --aikey-db-host <postgres-ip> --aikey-db-user aigwuser --aikey-db-name loxilb \
  --aikey-db-password-file /etc/loxilb/aikey_password
```

backed by a PostgreSQL instance. Administrative calls authenticate with an
opaque session token, which the store holds only as a SHA-256 hash:

```bash
# one-time: create an admin user, then log in for a Bearer token
curl -s -X POST http://127.0.0.1:11111/netlox/v1/auth/users -d '{...}'
TOKEN=$(curl -s -X POST http://127.0.0.1:11111/netlox/v1/auth/login \
  -d '{"username":"...","password":"..."}' | jq -r .token)
```

### 2.2 Turning on data-plane enforcement

Enforcement (key validation + rate limiting) engages on any fullproxy rule with
`sse_mode: true`:

```json
{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "mode": 4, "sse_mode": true, "inactiveTimeOut": 60, "host": "10.10.10.254"
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]
}
```

The credential policy is read **once per listener** (address, port and
protocol), before a request is matched to a rule by host, path or model. Every
rule that shares a listener therefore has to declare the same `api_key_auth`
and, for the JWT modes, the same `jwt_auth_profile`: a create or replace that
disagrees with the rules already on the listener is refused with `400` (an
unset policy and an explicit `disabled` are different values), and a
configuration restored from a snapshot is kept whole with the disagreement
logged. Without that refusal a `jwt` rule installed after a rule without a
policy would be served unauthenticated.

### 2.3 Key lifecycle (admin, Bearer-authenticated)

**Create** — returns the raw key exactly once:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/ai/apikey \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "tenant_id": "team-a", "name": "prod-key",
  "allowed_models": ["llama-70b", "mistral-7b"],
  "rate_limit_rps": 50, "burst_size": 100, "tokens_per_min": 100000,
  "enabled": true }'
# → 201 { "key_id": "…", "raw_key": "lxb_…", … }   raw_key is shown only here
```

**List / get / update / delete:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:11111/netlox/v1/config/ai/apikey?tenant_id=team-a"      # list
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/apikey/<key_id>               # get (never returns key material)
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/apikey/<key_id> \
  -d '{"allowed_models":["llama-70b"]}'                                     # update
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/apikey/<key_id>               # → 204
```

### 2.4 Client-side usage & enforcement results

Clients send the key (and optionally the model) as headers to the VIP:

```bash
curl -s http://10.10.10.254:2020/v1/chat/completions \
  -H 'X-Api-Key: lxb_…' -H 'X-Model: llama-70b' -d '{...}'
```

| Condition | Response |
|---|---|
| Valid key, allowed model, within limits | `200` (proxied) |
| Missing/unknown key | `401` `invalid_api_key` |
| Model not in the key's `allowed_models` | `403` `model_not_allowed` |
| Per-key or per-tenant rate/token limit exceeded | `429` |
| JSON body above the inspect cap whose top-level `model` is not within the first 64 KiB of the body | `413` `request_too_large_for_admission` |
| Chunked (or length-less) body larger than the gateway's 1 MiB request buffer | `413` `request_body_too_large` |

Enforcement runs before the first byte reaches a backend for every request
shape, including bodies the gateway streams instead of buffering (any non-JSON
body above 64 KiB, or a JSON body above 768 KiB). For a streamed JSON body the
model is resolved from the first 64 KiB, so put `model` early in the object;
the token reservation for such a request is sized from its `Content-Length`.
A chunked request body is never streamed and must fit the request buffer;
declare `Content-Length` for large uploads.

Backend connectivity failures surface through the same VIP and are easy to mistake for
quota errors: `502 backend_unreachable` / `503 no_healthy_backend` come from the proxy's
connect-failover path, not from key enforcement — see the
[troubleshooting guide](06-troubleshooting.md) §5.

Every answer the gateway writes itself — status, `error` code, the stage that decided, whether it
is safe to retry and when — is listed in one table in the
[client refusal contract](27-ai-gateway-client-refusal-contract.md).

### 2.5 A backend's `X-Api-Key` and `X-Auth-*` response headers

On a service that declares `api_key_auth`, `X-Api-Key` is the gateway's credential header.
The caller's is consumed or removed on the way in; a backend's is removed on the way out, so
a backend cannot hand a key to a client under the gateway's header name.

| Service | A backend's `X-Api-Key` response header | A backend's `X-Auth-*` response headers |
|---|---|---|
| HTTP/1.1, `api_key_auth` declared (`required`, `disabled`, `jwt`, `apikey-or-jwt`), response relayed by the gateway | **removed** | passed through |
| HTTP/1.1, no `api_key_auth` declaration | passed through | passed through |
| HTTP/2, `api_key_auth` declared | **removed** (from the response head, interim or final; not from trailers) | passed through |
| HTTP/2, no `api_key_auth` declaration | passed through | passed through |
| Any service whose response direction is carried in the kernel (`sockMapMode` `response` or `both`) | passed through | passed through |

Limits:

- On HTTP/1.1 the header is removed from the response head only, and only when the head
  arrives whole in one read from the backend. A head split across two reads is passed as it
  is; so is the final head when an interim response (`100`, `103`) and the final one arrive
  in the same read.
- A rule accelerated with `sockMapMode` `response` or `both` does not see its responses, so
  nothing is removed there.
- A response body is never edited, and neither are HTTP/2 trailers.
- The gateway does not remove `X-Auth-*` from responses on any service: a backend that must
  not expose identity headers should not send them.

## 3. Per-tenant rate limiting

Tenant-level ceilings apply across **all** keys of a tenant, on top of per-key limits:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/ai/tenant/ratelimit \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id": "team-a", "rps": 100, "tokens_per_min": 500000}'

curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:11111/netlox/v1/config/ai/tenant/ratelimit/team-a       # read back
```

Both layers return `429` on breach; per-key limits trip first if they are tighter.

### Burst

`tokens_per_min` is a refill *rate*, not a hard per-minute cap. The tenant spends from a
bucket that refills continuously at that rate, so recovery from a breach is gradual rather
than a cliff at the top of the minute. `burst_pct` sets how large that bucket is, as a
percentage of `tokens_per_min` — that is, how much of a minute's budget a fully idle tenant
may spend at once:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/ai/tenant/ratelimit \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id": "team-a", "rps": 100, "tokens_per_min": 500000, "burst_pct": 50}'
```

Omit it (or send `0`) to use the server default of `100` — one whole minute's budget, which
is how tenants behave with no override. Lower it to smooth a tenant that would otherwise
drain its budget in one burst and starve itself for the rest of the minute; raise it for
tenants with long idle gaps and large single requests. Accepted range is `1`–`1000`, and
values outside it are clamped rather than rejected. The server-wide default can be changed
with the `LLB_AI_QUOTA_BURST_PCT` environment variable.

Note that a single request larger than the bucket can never be admitted — the pre-admission
check refuses it outright rather than letting it queue — so `burst_pct` must leave room for
the largest prompt-plus-`max_tokens` a tenant legitimately sends.

### Requests without `max_tokens`: the default reservation

Before a request is sent to a backend the gateway reserves its worst case against every
token quota it counts on (tenant, tenant and model, user, user and model, key, and the
service's shared bucket): the prompt estimate plus the completion ceiling the request
declares in `max_tokens` or `max_completion_tokens`. The reservation is released when the
response is settled and replaced by what was really used.

A request that declares no ceiling — the field is absent, `-1` or any negative number, `0`,
a string, a float, an object or an array — reserves its prompt estimate alone. That makes
leaving the field out the cheaper choice at admission: the same request with a ceiling can
be refused before dispatch, and without one it cannot, so a tenant's `tokens_per_min`
bounds only its prompts until the usage is counted afterwards.

The default reservation closes most of that gap. It is off unless set, per service:

```bash
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"serviceArguments": {"externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
        "mode": 4, "sse_mode": true, "host": "10.10.10.254",
        "ai_default_reservation": "on", "ai_default_max_tokens": 1024},
       "endpoints": [{"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1}]}'
```

| Field | Values | Meaning |
|---|---|---|
| `ai_default_reservation` | `on`, `off`, `inherit` | `on`: a request without a ceiling also reserves the default. `inherit` or omitted: the process default, `LLB_AI_DEFAULT_RESERVATION` (`on`/`off`), else off |
| `ai_default_max_tokens` | `0`–`100000000` | the default in tokens. `0` or omitted: `LLB_AI_DEFAULT_MAX_TOKENS`, else the built-in `512` |

How it behaves:

- **It never refuses a request.** The default is reserved beside the prompt estimate, and
  each quota bucket cuts it to what it can hold: to the bucket's capacity less the prompt
  estimate, and to what earlier reservations have left, down to nothing. Only the prompt
  estimate — and a ceiling the request declares — can be refused, exactly as before.
- **A request admitted with less than the default is counted**, per service and by
  reason, in `loxilb_ai_reservation_clamped_total{service, reason}` and on the rule's
  `GET` (`fc_effective.reservation_clamped_burst` and `reservation_clamped_budget`):
  - `burst`: the default beside the prompt estimate is more than a quota bucket can ever
    hold, so the request is clamped even on an idle bucket. This does not pass by itself.
    Lower `ai_default_max_tokens`, or raise the tenant's `tokens_per_min` or its burst.
    Alert on this one.
  - `budget`: the bucket's budget was already taken by other reservations or by spend.
    It passes as the minute refills; a count that keeps rising means the budgets are
    tight for the traffic.

  A request both apply to is counted as `burst`.
- **It sizes the reservation only.** Nothing is written into the request, a declared
  ceiling is never replaced, and the response is charged for its real usage as before.
- **It narrows the gap, it does not close it.** When a bucket is nearly empty the default
  is cut to nothing and that request is prompt-only again; if its response then overruns
  the budget, the tenant's next requests are refused `token_quota_exceeded` until the
  bucket refills.
- The built-in `512` is an estimate of a typical completion, not a measured one. Set
  `ai_default_max_tokens` to what your clients' completions look like.

**What is reserved right now.** The rule's `GET` also shows the reservations that
admitted requests hold and have not settled, read from the quota store itself
(`fc_effective.reservation_held_claims` and the list
`reservation_held` with each bucket's `kind`, `bucket` and `tokens`). Read it to see
which tenants hold budget on a service at this moment, or to check that a request
that ended — completed, refused, cancelled, timed out in the queue — gave its claim
back: its buckets must read what they read before it.

- A request holds its claim on every quota bucket that applies to it (the tenant's,
  the tenant's for the model, the user's, the key's, the service's shared keyless one),
  and `reservation_held_claims` counts those claims: one per request and bucket, so one
  in-flight request on three buckets reads 3. It is zero exactly when nothing is held;
  it is a count of claims, not of tokens (each bucket's tokens are in the list).
- A tenant's bucket belongs to the tenant, not to a service: every service the tenant
  has used shows it, with the same number.
- A reservation belongs to the minute it was made in (`reservation_epoch`) and is
  dropped when the minute turns, whether or not its request has ended. Compare two
  readings only inside one minute.
- The list holds at most 64 buckets, largest first; `reservation_held_truncated` says
  when there are more. This is a management read-back only. It is not exported to
  Prometheus, because it is per tenant.

**Per rule.** Where several rules share one listener (VIP and port) and are told apart
by host, path or model, each has its own default reservation: the gateway takes the
value from the rule the request routes to, by the same host, path and model lookup that
selects the pool. Two rules on one listener may therefore declare different values, and
`fc_effective.default_reservation` / `default_max_tokens` on a rule are what applies to
that rule's requests (`source` reads `rule`, `env` or `default`). One exception: a
request an L7 policy forwards to another pool reserves by the rule its host, path and
model select, not by the pool the policy picked.

Both fields follow the replace rules of the
`fc_*` fields: omitted on a replace keeps the stored value, `inherit` and `0` return to the
process default, `null` is refused, and a replace that changes nothing else applies in
place, to requests admitted from then on. A streamed request body whose `max_tokens` the
gateway has not read by the time it admits the request is treated as declaring none.

### Request priority: objectives and classes

A request has a priority, an integer, and a class that is its sign: `critical` (positive),
`standard` (zero, and every request while nothing below is configured) or `sheddable`
(negative). Three things decide it, all stored in the AI key store, so every gateway that
shares the store applies a change within one refresh interval
(`LLB_AI_OBJECTIVE_REFRESH_SEC`, default 10 s) and the one that took the write at once.
The class is the request's priority band at the capacity gate: it decides the wake order,
the floors and the shed there ([AI admission flow control](23-ai-admission-flow-control.md#which-waiter-a-freed-unit-wakes)).
With a rule's `fc_llmd_headers` on, the objective forwarded to the backend is that class,
not the client's header.

**Objectives** are named priorities:

```bash
curl -sk -X POST https://<LB>:11111/netlox/v1/config/ai/objective -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"realtime-chat","priority":10}'
curl -sk -X POST https://<LB>:11111/netlox/v1/config/ai/objective -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"batch","priority":-5,"services":["20.20.20.1:8080"]}'
curl -sk https://<LB>:11111/netlox/v1/config/ai/objective -H "Authorization: Bearer $TOKEN"
curl -sk -X DELETE https://<LB>:11111/netlox/v1/config/ai/objective/batch -H "Authorization: Bearer $TOKEN"
```

| Field | Values | Meaning |
|---|---|---|
| `name` | 1–63 of letters, digits, `-`, `_`, `.` | what a request's header names; compared exactly, case included |
| `priority` | int32 | positive `critical`, negative `sheddable`, zero `standard` |
| `services` | `["VIP:port", …]`, at most 256 | the services the objective applies to; empty or omitted = all |

**Class fields** on a tenant (`POST /config/ai/tenant/ratelimit`) and on an API key (create,
and `PATCH /config/ai/apikey/{key_id}`):

| Field | Meaning |
|---|---|
| `priority_class` | the highest class a request may have (`standard`, `critical`, `sheddable`); on a tenant, unset = `standard`; on a key, unset = the tenant's |
| `default_objective` | the objective a request gets when it names none, or one it may not use |
| `allowed_objectives` | the objectives a request may raise itself to by header, and the body tiers it may raise itself to (`tier:priority`, `tier:fast`, `tier:flex`); at most 64; empty = no raise can be asked for. A hint at or below what the request gets without one needs no entry |

A key can only narrow its tenant: its cap only lowers, its list counts only for names the
tenant's list holds. A JWT auth profile and a network-identity binding carry
`priority_class` alone, as one more cap (a binding's default is `standard`: say `critical`
on a binding that should not cap). The result is the lowest of what the request asks for
and every cap that applies: a hint can lower a request, never raise it. **A tenant that sets no
`priority_class` is held at `standard`**: a request is `critical` only when its tenant was
granted `critical`, and then only if no key, profile or binding lowers it. The order is the
tenant's cap, then the key's or the JWT profile's, then the binding's, then the hint; each
can only lower what the one before it allows.

**`priority_class` is a cap, not a default.** To run a tenant's un-hinted requests above
`standard`, set its `default_objective` to an objective with a positive priority;
`priority_class` only bounds what its requests may be raised to.

**How a request asks.** Two channels, under the same rule:

- The header `x-llm-d-inference-objective: <name>` (the older `x-gateway-inference-objective`
  is read too; when both are present the new name wins). The name must be an objective that
  applies to the service.
- The body's top-level `service_tier`: `priority` and `fast` ask for `critical` (priority 1),
  `flex` for `sheddable` (priority -1). Other values (`auto`, `default`, …) are no hint. The
  header, when it is there, decides; a refused header is not rescued by the body.

**`allowed_objectives` governs raises only.** A hint whose priority is at or below what the
request gets without one (its default objective, held under its caps; `standard`, priority 0,
when it has none) asks for less and is always applied, on strict and non-strict rules alike,
listed or not: an OpenAI SDK client's `service_tier: flex` runs `sheddable` with no grant. A
hint above that needs its name (`tier:priority`, `tier:fast`, `tier:flex` for the body) in
`allowed_objectives`. The comparison is by priority, not class: on a key whose default is
`batch` (priority -5), `flex` (-1) is a raise within `sheddable` and needs `tier:flex`.

A request that asks for what it may not use is admitted on its default objective, with
`objective_denied` on its records, or refused 403 `objective_not_allowed` on a rule with
`ai_objective_strict: true`, whichever channel it asked by. An objective name of 64 bytes or
more is such a request, never a 400 or a 5xx.

**The client can see it on the response.** On a rule with `fc_expose_headers` on, the response
to a request that was admitted on its default *because the objective it asked for was denied*
carries `X-Loxilb-Admission-Objective-Requested` beside `X-Loxilb-Admission-Objective` (the
objective applied, absent when the default is none) and `X-Loxilb-Admission-Class`:

```
X-Loxilb-Admission-Objective: batch
X-Loxilb-Admission-Class: sheddable
X-Loxilb-Admission-Objective-Requested: realtime-chat
```

- The value is what the request asked for: the header's objective name as it was sent, or
  `tier:<value>` when the body's `service_tier` was the hint. A name of 64 bytes or more reads
  `(oversize)`; a name with a space or a control character in it is not written.
- **The header is absent on every other response**: the request named no objective, or the one
  it named was applied. So "asked and was defaulted" and "asked nothing" are no longer the same
  response. It is also absent when the class stage did not run (no identity that resolves a
  tenant), on rules without `fc_expose_headers`, and, on HTTP/1.1, on a response whose head the
  backend sent in more than one piece, like the other two class headers.
- A header of that name sent by a backend is removed wherever the gateway writes the class
  headers. On a strict rule the request is refused instead (403, stage `objective`), and a
  refusal does not carry it.

A `service_tier` the gateway read is the gateway's: it is overwritten with `null`, in place and
at the same length, before the body is forwarded, whether or not it was allowed and whichever
hint decided. With the key more than once at the top level, the last one is the one read (as
the engines' JSON parsers read it) and every one is nulled. Key and value are read decoded,
as an engine's parser reads them: `"service\u005ftier"` is the key and `"priorit\u0079"` is
`priority`, read and nulled like the literal spelling, so no spelling of the hint the gateway
did not read reaches the engine. An escape that is not JSON (a bad `\u`, a lone surrogate)
spells nothing and is not a hint; the body is not JSON then and the engine refuses it.

A client-supplied engine priority does not leave the gateway either. vLLM orders admitted
requests by its own priority (the `X-Vllm-Priority` header first, then the body's top-level
`priority`; lower runs earlier) and SGLang by the body field, so a client could outrank the
band from inside the engine. Where the class stage runs, the header is stripped on HTTP/1.1
and HTTP/2, and a top-level body `priority` is renamed in place, at the same length, to
`_gw_prio`, a key no engine reads (read decoded, like `service_tier`: `"priority"` is
renamed too). It is renamed, not set to 0: 0 is vLLM's default but a mid rank on SGLang,
where an absent priority ranks lowest, so every engine sees exactly what it sees for a request
that never carried the field, and an engine that refuses unknown fields (TensorRT-LLM) refused
`priority` already. The name is the gateway's signature: an operator who sees `_gw_prio` in an
engine's request log is looking at a client's `priority` the gateway renamed on the way through,
never at a field a client wrote. A nested `priority` (inside `messages` or a tool's arguments) is no engine
field and is left as sent. The gateway logs one info line per service, at most every 10 s,
naming the source (`X-Vllm-Priority header`, `body priority`), so the clients that send one
are seen. Rules without an AI gateway are unchanged. Mapping a class to an engine priority is
not done: the engine orders admitted requests as if none had asked.

The records: a completion, and a refusal made after the class stage ran (an objective
refusal, a rate limit, a quota, a capacity refusal), carry `priority_class`, `priority`,
`objective` (the hint that was applied: a name, `tier:<value>`, or none), `objective_denied`
and `hint_not_applied`. `hint_not_applied` means "no body hint was read": the body was not whole
in the buffer, or there was none (a bodyless request reads the same way). A refusal made
before the stage ran (a bad credential) has none of these fields. An objective refusal is
stage `objective`, reason `authz`.

The class fields and the limits of a tenant are separate writes. A POST of limits leaves the
class as it is. A class field that is omitted is left as stored, an empty value (`""`, `[]`)
clears it. A body that names a class field and no limit writes the class alone:

```bash
curl -sk -X POST https://<LB>:11111/netlox/v1/config/ai/tenant/ratelimit -H "Authorization: Bearer $TOKEN" \
  -d '{"tenant_id":"acme","priority_class":"standard","default_objective":"batch","allowed_objectives":["batch","realtime-chat"]}'
```

On a rule, `ai_objective_strict: true` refuses a request that names an objective it may not
use (unknown, not for this service, or a raise it was not granted) with 403
`objective_not_allowed`; by default such a request falls to its default objective, and its
response says so with `X-Loxilb-Admission-Objective-Requested` when the rule exposes the
admission headers (above). A lowering hint is never refused.

**When the key store is away.** Every write above answers 503 (`ai_key_store_unavailable`,
or `ai_key_store_unconfigured` with no store) and changes nothing. A write the store was
handed and did not answer within its budget is 504 (`ai_key_store_outcome_unknown`): it may
still land, so read the resource back before retrying; an API-key create sent with a
`client_op_id` can be retried blindly and converges on one key (see
[AI-KEY-STORE.md](../AI-KEY-STORE.md), "Retrying a create safely"). A running gateway keeps
applying what it last read. A gateway that starts while the store does not answer serves
the last-known-good file `aigw-lkg.json` under `--config-path` (written, mode 0600, after
every read whose content changed) until the store answers. `fc_effective.config_source` on
any AI-gateway rule says which: `store`, `lkg` or `none`; while it is `lkg`,
`loxilb_ai_class_config_lkg_intervals_total` counts one per refresh interval.
`GET /config/ai/objective` answers 200 meanwhile with the objectives the gateway applies,
`source` (`store` for the last read of this process, `lkg` for the file) and
`source_timestamp` (when the store answered with them); it answers 503 only when the store
does not answer and nothing was applied yet.

Both the objective list and `fc_effective` also carry `store_reachable` and
`store_last_read`, whatever `source` / `config_source` say: `store_reachable: false` while
the store does not answer (a configuration read earlier still reads `source: store`), and
`store_last_read`, the time a read of the store last answered. After a restart from the
file it is the read that last changed the file, which is written only on a change: the
store may have answered later with nothing new, so read it as "at least this recent". An outage is visible in the API without
reading the gateway's logs. Without a key store, `fc_effective` carries neither.

**A restart while the key store is away.** The file carries the objectives, the class fields
of tenants and keys, and every tenant, tenant-and-model and default limit row, as the store
last had them. API keys are never cached on disk, so it does not carry them:

- A request that presents an API key is refused with 503 `policy_store_unavailable`. It is
  not admitted on a guess and it is not treated as keyless.
- Requests that need no key are served: a tenant named by a network-identity binding, and
  keyless services. Their objectives, classes and limits come from the file; a tenant the
  file holds no limit row for had none in the store, and is served without one.
- What this gateway confirmed from the store itself, before an outage that starts later,
  wins over the file. Once the store has answered, the file's limit rows are not used again
  by that process.
- The gateway keeps running. When the store answers again the gateway reads it within 20 s,
  `config_source` returns to `store`, and keys validate again.

So "no admission failure caused by the database" holds for requests that need no key; a
keyed request fails closed until the store is back.

---

## 4. Model-name routing

Route requests to different endpoint pools based on the model they ask for — the gateway reads
the `X-Model` header or the JSON body's `model` field. One rule per model on the same VIP/port
family; an empty `model_name` is the wildcard catch-all.

```bash
# llama-70b pool
curl -s -X POST http://127.0.0.1:11111/netlox/v1/config/loadbalancer -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "path_prefix": "/", "path_match_mode": "prefix",
    "model_name": "llama-70b", "inactiveTimeOut": 30 },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]}'

# mistral-7b pool → port 2021 with "model_name": "mistral-7b"
# catch-all      → port 2022 with "model_name": ""
```

Five fields are required per model-routing rule: `mode: 4`, `host`, `path_prefix`,
`path_match_mode`, `model_name`. No database or user-service is needed.

Combined with per-key `allowed_models` (§2), this gives tenant-scoped model access **and**
model-scoped backend pools from one gateway.

---

## 5. SSE stream quotas

LLM responses stream over SSE and can outlive any sane idle timeout — or run away entirely.
Three rule fields govern streaming behavior:

```json
{
  "serviceArguments": {
    "externalIP": "10.10.10.254", "port": 2020, "protocol": "tcp",
    "sel": 0, "mode": 4, "host": "10.10.10.254",
    "path_prefix": "/", "path_match_mode": "prefix", "model_name": "sse-test",
    "sse_mode": true,
    "max_stream_duration_sec": 120,
    "backend_keepalive_interval_sec": 30,
    "inactiveTimeOut": 60
  },
  "endpoints": [ { "endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1 } ]
}
```

| Field | Meaning |
|---|---|
| `sse_mode: true` | Detect SSE responses; suppress `inactiveTimeOut` while a stream is active; recognize the `data: [DONE]` terminator |
| `max_stream_duration_sec` | Hard wall-clock cap per stream — terminates runaway streams |
| `backend_keepalive_interval_sec` | TCP keepalive interval toward the backend during long streams |

This is a **stream-duration** quota; token-count budgets are enforced per key/tenant via
`tokens_per_min` (§2–§3).

### A request sent while a streamed answer is running (HTTP/1.1)

On HTTP/1.1 a connection carries one exchange at a time. While the gateway relays a
streamed answer the client must not send anything on that connection. If it does, the
gateway closes the connection: the bytes are not relayed, and the stream in progress ends
as one its client left. The request being answered was checked and charged as a whole;
bytes behind it belong to no checked request and would otherwise reach the backend without
a credential check, a model allowlist, a rate limit or a charge.

A streamed answer has ended when its framing ends (the last chunk, or `Content-Length`
bytes), with or without a `data: [DONE]` event; the next request on the connection is then
admitted as any request. A client should wait for the answer to end, open a second
connection, or use HTTP/2, where each request is its own stream.

`loxilb_ai_stream_early_bytes_closed_total{service}` counts one per closed connection
(absent until the first); at `--loglevel debug` the data-plane log has one
`[STREAM_INTRUSION]` line for each.

---

## 6. Try it

```bash
cd cicd/ai-model-routing   # no DB needed — model routing only
./config.sh && ./validation.sh && ./rmconfig.sh

cd ../ai-sse-quota         # SSE quota behaviors incl. the 10s runaway-cap probe
./config.sh && ./validation.sh && ./rmconfig.sh

cd ../ai-apikey            # full key lifecycle + 401/403/429 enforcement (brings up PostgreSQL)
./config.sh && ./validation.sh && ./rmconfig.sh
```

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `POST /config/ai/apikey` fails with `503 ai_key_store_unconfigured` | loxilb started without `--aikey-db-host` | Restart with the `--aikey-db-*` family and a reachable PostgreSQL provisioned by `scripts/aigw-db-bootstrap.sql` |
| `POST /config/ai/apikey` fails with `401` | loxilb started with `--userservice` and no credential was presented | Authenticate first; see the bootstrap note above |
| Mutating calls return `503` + `Retry-After: 5` right after a gateway restart | Boot-config gate: writes are held until the boot snapshot replay settles | Expected — retry after the `Retry-After` interval; not an outage |
| Keys accepted but not enforced at the VIP | Rule lacks `sse_mode: true` / not `mode: 4` | Enforcement runs in the fullproxy AI path only |
| Rule refused with `400`: `api_key_auth, jwt_auth_profile: the rule with ... is already on this address, port and protocol with a different value` | Another rule on the same listener (VIP, port, protocol) declares a different credential policy | Declare the same `api_key_auth` and `jwt_auth_profile` on every rule of the listener; unset and explicit `disabled` differ |
| Requests hit the wrong model pool | Field casing | `model_name`, `path_prefix`, `path_match_mode` are snake_case — a mis-cased field is silently dropped |
| Streams cut at ~`inactiveTimeOut` | `sse_mode` not set | Set `sse_mode: true` on streaming rules |
| Long streams die at exactly N seconds | `max_stream_duration_sec` cap | Raise the cap; it is the intended runaway guard |
| One `[HTTP/2] client connection ended: reason=…` line per HTTP/2 client connection in the data-plane log | The end line: one line each time an HTTP/2 client connection ends, so its volume follows the HTTP/2 connection rate, not the request rate. `info` for `reason=client_eof`, `reason=idle_timeout`, and `reason=backend_leg_ended` with `open_streams=0`; `warn` for every other end (requests lost, an error, or a gateway decision such as `header_deadline`) | Expected. Filter on `client connection ended` and the `reason=` field; alert on the `warn` lines only. At `--loglevel warn` the ordinary ends are not written |
