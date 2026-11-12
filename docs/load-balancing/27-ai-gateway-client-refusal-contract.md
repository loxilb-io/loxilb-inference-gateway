# AI gateway: the client refusal contract

An AI-gateway service can answer a request itself instead of relaying a backend's answer: the credential was
wrong, a limit was reached, the pool had no room, nothing serves the model, the request could not be admitted as
framed. This page is the one table of those answers, written for the author of a client (an SDK, an agent
runtime, a broker in front of the gateway) who has to decide, without parsing prose, **whether to retry, when, and
whether the request reached a model**.

The per-feature pages stay the reference for how each control is configured:
[AI gateway controls](19-ai-gateway-controls.md) (keys, rate limits, objectives, model routing) and
[AI admission flow control](23-ai-admission-flow-control.md) (the capacity gate and its queue).

## How to read a refusal

1. **`error` is the code.** Every gateway-written JSON answer has a string-typed `error` field holding a stable
   code (`{"error":"admission_capacity", …}`). An OpenAI-compatible backend's own error is an object
   (`{"error":{"message":…}}`). The code, not the status and not the message text, says what happened: `429` is
   used by five different stages, `503` by four.
2. **The stage says what kind of refusal it is.** Each code belongs to one stage of the gateway's decision
   (`auth`, `conflict`, `ratelimit`, `reserve`, `objective`, `capacity`, `route`, `framing`, `security`); the same
   name is the `stage` of the refusal's audit record, and the refusal carries it in the
   `X-Loxilb-Refusal-Stage` response header ([below](#the-two-headers-on-a-gateway-written-answer)). The tables
   are grouped by stage.
3. **`Retry-After` (seconds) is authoritative** when present. A `retry_after` body field carries the same number
   where the table lists it; `jitter_hint_ms` is milliseconds to spread retries by; `queued_ms` is the time the
   request already spent waiting, not an estimate of anything.
4. **Every refusal on this page is decided before any byte of the request is sent to a backend** (the Dispatch
   column says `none`). The answers that are not refusals — outages and endings after dispatch — are in their own
   section, and none of them is safe to retry blindly.

### The rule for a client that backs off on congestion

Only the **capacity stage** is congestion: `admission_capacity`, `admission_tenant_share`, `admission_shed`,
`admission_no_capacity`, `gateway_draining`, and the queue endings `admission_queue_timeout`,
`admission_ttl_expired`, `admission_drained`. Retry those after `Retry-After`, with jitter, a bounded number of
times. **Nothing else is congestion**: a rate-limit or quota `429` is the caller's own budget, an `auth` or
`objective` refusal will not change by waiting, a `policy_store_unavailable` `503` is the gateway's outage, a
`route` or `framing` refusal needs a different request or an operator. A response whose `error` is not a string
code from this page was not written by the gateway's refusal path: treat it as the backend's answer, or as
unknown, and do not feed it to the congestion back-off.

The same rule read from the header, without the code table: **`X-Loxilb-Refusal-Stage: capacity` or `queue` is
congestion; any other value is not; no such header means the gateway did not refuse the request before dispatch**
— it is a backend's answer, an outage, or one of the few refusals listed as unmarked below.

### The two headers on a gateway-written answer

Since the release that follows v0.9.9.1 (the `[Unreleased]` entries of the changelog). An earlier gateway sends
neither; the `error` code and the tables below classify its refusals.

| Header | Meaning | Present |
|---|---|---|
| `X-Loxilb-Refusal-Stage: <stage>` | the gateway refused this request **before any byte of it reached a backend**. The value is the Stage column of the refusal's row — the `stage` of its `sec.ai.deny` record — or `queue` for a request that ended while it waited for capacity (the rows written by the queue reaper; their audit record is at stage `capacity`) | on every refusal on this page, except the ones listed under "Unmarked" |
| `X-Request-Id: <id>` | on an answer the gateway wrote: **the ID of that request**, the one the client sent or the one the gateway minted for it | on a gateway-written answer whenever the request has an ID of its own at that moment; on refusals and on outages alike |

On HTTP/2 the two are the fields `x-loxilb-refusal-stage` and `x-request-id` of the response HEADERS.

**The two are independent.** The stage alone means "refused before dispatch". An answer with `X-Request-Id` and no
stage says nothing about dispatch: it is an outage, or the one refusal the gateway writes after request bytes
reached a backend (a JSON framing error found in a body that was being streamed to the backend; its audit record
is at `framing`).

**A `5xx` with a stage is a refusal, not an outage.** `policy_store_unavailable` and `netid_unavailable` are `503`
with stage `auth` or `ratelimit`: the gateway refused before dispatch, and it is not congestion.

**When `X-Request-Id` is absent from a gateway-written answer:**

- the request had no ID yet: it could not be parsed, or (HTTP/2) it was refused while its headers were still
  being read — three early HTTP/2 refusals carry the stage alone;
- the answer was written after the request had been handed to a backend connection (HTTP/1.1): the `502` for an
  endpoint that refused the connection on a plain rule, and the `502` for a backend that closed without
  answering. The gateway keeps the ID for the audit records, not for the answer; the `503 no_healthy_backend`
  written while the request is still being placed does carry it;
- the ID cannot be one header value (a control byte, a blank at either end): it is left out, never rewritten;
- the queue endings' plain form (below, under the capacity stage);
- the answers listed under "Unmarked" and everything else the prefill/decode path writes (its leg-failure and
  timeout answers), the reaper's Endpoint-Picker timeout, the in-stream events, and an L7-policy redirect.

The echo is the request's own ID, never the previous request's on a keep-alive connection. The gateway's read
path assumes a client does not send request N+1 before N is answered; a client that pipelines can find N+1's ID
on a `502` written for N when the backend fails before answering.

**Unmarked: refusals with neither header.** The refusals written by the prefill/decode code itself — the six
`pd_*` codes and the P/D `invalid_json_body` of the framing stage — carry no stage and no request ID; classify
them by `error`. `pd_overloaded` and `pd_admission_park_timeout` are written elsewhere and carry both (stage
`capacity` and `queue`).

**One stage header without a deny record.** A listener kept open after its last rule was deleted answers
`503 no_route` with `X-Loxilb-Refusal-Stage: route`, like every other `no_route`, but the gateway records it as
an outage completion, not as a `sec.ai.deny` at `route`. It is the only answer whose stage header has no deny
record of that stage behind it.

**A backend cannot send the stage.** `X-Loxilb-Refusal-*` fields in a backend's response are removed from every
relayed response head, on every service, whatever `fc_expose_headers` says. Two residuals: on HTTP/1.1 only a
head that arrives in one read is cleaned (a head split across reads passes as sent; an interim `1xx` and the
final head arriving in one read: the `1xx` is cleaned, the final head is not), and HTTP/2 trailers are not a head
and pass. Backends are operator-controlled; the residual closes with the HTTP/1.1 response-head assembly work.

## Columns

| Column | Meaning |
|---|---|
| Status, `error` | the HTTP status and the code in the JSON body |
| Stage | the gateway stage that decided; also `data.stage` of the audit record, and the value of `X-Loxilb-Refusal-Stage` (`queue` instead of `capacity` on the queue reaper's rows) |
| Written by | the part of the gateway that writes the answer: the policy gate, the capacity gate, the queue reaper, the router, the request framer, the content scanner, the prefill/decode (P/D) path |
| Dispatch | whether any request byte reached a backend: `none`, `sent`, or `unknown` |
| Retry-safe | `yes` = the identical request may be sent again after `Retry-After`; `no` = it will be refused again until something else changes; `cond.` = see the note in the row |
| `Retry-After` | present or not, and its value (always seconds) |
| Body | the fields beside `error` |
| Headers | gateway headers beside `Content-Type: application/json` and the two headers above (`X-Loxilb-Refusal-Stage`, `X-Request-Id`), which every row carries unless "Unmarked" lists it; `none` means none beside those |
| Connection | what happens to an HTTP/1.1 connection (an HTTP/2 refusal always ends only its stream) |
| H1 / H2 | differences between HTTP/1.1 and HTTP/2 |
| Audit | the record on the audit trail: every refusal is stream `data`, class `security`, event `sec.ai.deny`, with `data.stage` = the Stage column and `data.decision` = the `error` code unless the row says otherwise; `outcome.reason` is given in the row |
| Reproduced by | the `cicd/` scenario that produces the answer today (`ai-admission` rows by letter) |

The "Written by" names map to these writer functions in the data path (`loxilb-ebpf/common/`):

| Written by | HTTP/1.1 writer | HTTP/2 writer |
|---|---|---|
| policy gate | `ai_gw_admit` decides; `sp_h1_send_admit_deny` writes | `proxy_h2_send_ai_deny` |
| capacity gate | `sp_fc_h1_refuse` → `sp_h1_send_capacity_deny` | `sp_fc_h2_shed` → `proxy_h2_send_capacity_deny` |
| queue reaper | `sp_reap_finish` / `sp_fc_shed_answer_kept` → `sp_reap_fc_format`; the plain form from `pd_reap_respond` | — |
| router | `proxy_setup_ep__` → `sp_send_local_refusal` | `h2_send_local_refusal` |
| request framer | `sp_h1_send_framing_deny`, `sp_h1_json_refuse`, `sp_h1_stream_model_unresolvable`, `sp_mcp_h1_refuse` | `h2_send_local_refusal`, `h2_send_mcp_frame` |
| L7 policy | the L7 policy reject action | `proxy_h2_send_l7_synthetic` |
| content scanner | the LlamaFirewall block in the request path | — |
| P/D path | `pd_check_request_body`, `pd_prepare_failed`, `pd_sg_oversize_reject` (via `sp_pd_send_refusal`); `pd_overloaded` is written by `proxy_setup_ep__` | — |

"Admission triple" below means `X-Loxilb-Admission-Inflight`, `X-Loxilb-Admission-Queued`,
`X-Loxilb-Admission-Limit`. "Class pair" means `X-Loxilb-Admission-Class` and `X-Loxilb-Admission-Band-Wait-Ms`,
sent when the request's class was resolved before the refusal. "llm-d reason" means
`x-llm-d-request-dropped-reason`, sent only on a rule with `fc_llmd_headers` on.

## Refusals

### Stage `auth` — the credential, the model it may use, the store that knows

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `401` | `invalid_api_key` | auth | policy gate | none | no (a different key) | absent | `message` | none | closed | same body | reason `auth` | `ai-apikey`, `ai-authsep`, `ai-jwtauth` |
| `401` | `missing_token` | auth | policy gate | none | no (send a bearer token) | absent | `message` | none | closed | same | reason `auth` | `ai-jwtauth` |
| `401` | `invalid_token` | auth | policy gate | none | no (a valid token); deliberately coarse — signature, issuer, audience and format failures all read `invalid_token` | absent | `message` | none | closed | same | reason `auth` | `ai-jwtauth` |
| `401` | `token_expired` | auth | policy gate | none | cond. — after re-authenticating | absent | `message` | none | closed | same | reason `auth` | `ai-jwtauth` |
| `401` | `internal_error` | auth | policy gate | none | cond. — the validator failed and the gate refused rather than admit; not a statement about the credential | absent | `message` | none | closed | same | reason `auth` | none |
| `403` | `model_not_allowed` | auth | policy gate | none | no (a model the key, token or network identity may use) | absent | `message` | none | closed | same | reason `authz`; the record names the tenant | `ai-apikey`, `ai-authsep`, `ai-jwtauth`, `audit-data` |
| `403` | `network_tenant_mismatch` | auth | policy gate | none | no (the credential is valid but not from this network) | absent | `message` | none | closed | same | reason `authz` | none |
| `503` | `policy_store_unavailable` | auth | policy gate | none | yes, after `Retry-After`; the gateway cannot check credentials right now — not congestion | `5` | `message` | none | closed | same | reason `admission` | `ai-authsep`, `ai-jwtauth` |
| `503` | `netid_unavailable` | auth | policy gate | none | yes, after `Retry-After`; a network-identity binding could not be resolved on a rule that fails closed — not congestion | `5` | `message` | none | closed | same | reason `admission` | none |

### Stages `conflict` and `objective`

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `400` | `model_conflict` | conflict | policy gate | none | no (the JSON `model` and `X-Model` must agree, or send one) | absent | `message` | none | closed | same | reason `admission`; names the tenant and key | `ai-model-conflict` |
| `403` | `objective_not_allowed` | objective | policy gate | none | no (name an objective the identity may use, or none); only on a rule with `ai_objective_strict` | absent | `message` | none | closed | same | reason `authz` | none |

On a rule without `ai_objective_strict`, an objective the identity may not use is not refused: the request is
admitted under the default objective and only the audit record says the hint was denied.

### Stages `ratelimit` and `reserve` — the caller's own budget

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `429` | `rate_limit_exceeded` | ratelimit | policy gate | none | yes, after `Retry-After` — the key's (or the service's shared) request rate; not congestion | present | `retry_after` | none | closed | on HTTP/1.1 the header is written even when the value is `0`; on HTTP/2 only when it is above `0` | reason `ratelimit` | `ai-apikey`, `ai-authsep`, `ai-jwtauth` |
| `429` | `user_rate_limit_exceeded` | ratelimit | policy gate | none | yes, after `Retry-After` — the user's request rate | present | `retry_after` | none | closed | as above | reason `ratelimit` | `ai-jwtauth` |
| `429` | `tenant_quota_exceeded` | ratelimit | policy gate | none | yes, after `Retry-After` — the tenant's request rate | present | `retry_after` | none | closed | as above | reason `ratelimit` | `ai-apikey`, `ai-authsep`, `ai-jwtauth` |
| `429` | `token_quota_exceeded` | ratelimit | policy gate | none | cond. — a token budget is already spent; it refills over the minute | `60` | `retry_after` | none | closed | as above | reason `quota` | `ai-jwtauth`, `audit-data` |
| `503` | `policy_store_unavailable` | ratelimit | policy gate | none | yes, after `Retry-After`; the limits could not be read — not congestion | `5` | `retry_after` | none | closed | as above | reason `ratelimit` | none that names the stage |
| `429` | `token_quota_would_exceed` | reserve | policy gate | none | cond. — this request's own size (prompt estimate plus `max_tokens`) does not fit what is left of the token budget; a smaller request may pass at once | present | `retry_after` | none | closed | as above | reason `quota` | `ai-apikey`, `ai-jwtauth` |

`policy_store_unavailable` is written by two stages with two body shapes (`message` at `auth`, `retry_after` at
`ratelimit`). The code and the status are the same; so is what a client should do.

### Stage `capacity` — congestion

The only stage a congestion back-off should act on. Described in full in
[doc 23, "What the client sees"](23-ai-admission-flow-control.md#what-the-client-sees).

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `429` | `admission_capacity` | capacity | capacity gate | none | yes | `1`; the mean queue wait (`1`–`30`) when the queue was full | `retry_after`, `jitter_hint_ms` | admission triple, class pair, llm-d reason | kept open when the request body was fully buffered, else closed | HTTP/2 body always says `"retry_after":1` | reason `admission` | `ai-admission` B, N, Q, G, KA, K; E (HTTP/2) |
| `429` | `admission_tenant_share` | capacity | capacity gate | none | yes | as `admission_capacity` | `retry_after`, `jitter_hint_ms` | as above; the triple is the pool's counts, not the tenant's | as `admission_capacity` | as above | reason `admission` | `ai-admission` TS, TW |
| `429` | `admission_shed` | capacity | capacity gate; queue reaper for an evicted waiter | none | yes | as `admission_capacity` | `retry_after`, `jitter_hint_ms`; `queued_ms` for an evicted waiter | as above | as `admission_capacity`; an evicted waiter keeps its connection unless the once-a-second pass writes its answer | HTTP/2 streams are never evicted (they do not queue) | reason `admission` | `ai-tenant`, `mcp`, `vllm-pd-admission-cpu` |
| `503` | `admission_no_capacity` | capacity | capacity gate | none | yes | `1` | `message`, `retry_after` | as above | closed | same body (HTTP/2 gained `retry_after` with the two headers; before that it had `message` only) | reason `admission` | none |
| `503` | `gateway_draining` | capacity | capacity gate | none | yes — on another gateway node if there is one | `5` | `message`, `retry_after` | as above | closed | same body (HTTP/2 gained `retry_after` with the two headers; before that it had `message` only) | reason `admission` | `ai-admission` M |
| `504` | `admission_queue_timeout` | capacity | queue reaper | none | yes | the mean queue wait (`1`–`30`) | `queued_ms`, `retry_after` | as above | closed | HTTP/1.1 only | reason `admission` | `ai-admission` T |
| `429` | `admission_ttl_expired` | capacity | queue reaper | none | yes — the request's own `x-llm-d-inference-ttl` ended the wait | as above | `retry_after`, `jitter_hint_ms`, `queued_ms` | as above | closed | HTTP/1.1 only | reason `admission` | `ai-tenant` |
| `503` | `admission_drained` | capacity | queue reaper | none | yes | `5` | `queued_ms`, `retry_after` | as above | closed | HTTP/1.1 only | reason `admission` | `ai-admission` DL, M |
| `429` | `pd_overloaded` | capacity | P/D path | none | yes | `1` | `detail` | **none** (no admission triple) | closed; the response has no `Content-Length` | HTTP/1.1 only | reason `admission` | `vllm-pd-admission-cpu` |
| `504` | `pd_admission_park_timeout` | capacity | queue reaper (P/D park) | none | yes | **absent** | none | none | closed; no `Content-Length` | HTTP/1.1 only | reason `admission` | none |

The queue endings have a second, plain form. When the worker that owns the connection cannot write the answer, the
gateway ends the connection from another thread with a minimal text: the same status, `error` and `Retry-After`
(`1`, or `5` for `admission_drained`), `X-Loxilb-Refusal-Stage: queue`, `Content-Length`, `Connection: close`, and
**no `X-Request-Id`, no admission headers, no `queued_ms`**; a TLS client gets a clean close with no body at all. It is rare and counted. A client that keys on
status, `error` and `Retry-After` reads both forms the same way.

### Stage `route` — nothing serves the request as addressed

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `503` | `model_unavailable` | route | router | none | no, until an operator adds a pool for the model | absent | HTTP/1.1: `model`, `detail`; HTTP/2: `message` | none | closed; no `Content-Length` on HTTP/1.1 | field names differ as shown | reason `admission` | `ai-model-routing`, `ai-model-conflict`, `ai-jwtauth` |
| `503` | `no_route` | route | router | none | no (no rule matches the path, or no model to route by) | absent | `detail` (`model` too when the request had no `Host`) | none | closed; no `Content-Length` | HTTP/1.1 only | reason `admission` | `ai-json-parser`, `security-kv-coexist` |
| `503` | `no_rules` | route | router | none | no, until an operator adds a rule | absent | `detail` | none | closed; no `Content-Length` | HTTP/1.1 only | reason `admission` | none |
| configured | none — a `text/plain` body the operator configured | route | L7 policy | none | no | absent | plain text | none | closed | same status | reason `admission`, decision `l7_policy_reject` | — |

These `503`s are not congestion: waiting does not create a pool or a rule.

### Stage `framing` — the request cannot be admitted as sent

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `400` | `duplicate_model_field`, `duplicate_user_field` | framing | policy gate / request framer | none | no (one top-level `model`, one `user`) | absent | `message` | none | closed | same | reason `admission` | `ai-json-parser` |
| `400` | `invalid_model_field`, `invalid_json_body`, `duplicate_content_type` | framing | request framer | none | no | absent | `message` | none | closed | same | reason `admission` | `ai-json-parser` |
| `400` | `invalid_json_framing` | framing | request framer | none | no | absent | `message` | none | closed | HTTP/1.1 only | reason `admission` | none |
| `400` | `model_required_early` | framing | request framer | none | no (put `model` within the first 64 KiB of a streamed body); written on a service that does not enforce credentials | absent | `detail` | none | closed | HTTP/1.1 only | reason `admission` | none |
| `400` | `bad_request` | framing | request framer | none | no (unparseable or ambiguously framed request) | absent | `message` | none | closed; no `Content-Length` | HTTP/1.1 only | reason `admission` | — |
| `400` | `invalid_cache_salt` | framing | router | none | no (`cache_salt` must be a non-empty string of at most 63 bytes) | absent | HTTP/1.1 `detail`; HTTP/2 `message` | none | closed; no `Content-Length` on HTTP/1.1 | field names differ | reason `admission` | none |
| `413` | `request_too_large_for_admission` | framing | request framer | none | no (put `model` within the first 64 KiB); the credential is checked first, so an unauthenticated caller gets `401` | absent | `message` | none | closed | HTTP/1.1 only | reason `admission` | `ai-apikey` |
| `413` | `request_body_too_large` | framing | request framer | none | no (a chunked or length-less body must fit the 1 MiB request buffer; send `Content-Length`) | absent | `message` | none | closed | HTTP/1.1 only | reason `admission` | none |
| `400`, `405`, `413` | a JSON-RPC error object (MCP services) | framing | request framer | none | no | absent | JSON-RPC `error` object, not a string code | `Allow: POST` on `405` | closed | HTTP/2 also has `mcp_routing_operand_too_large`, `mcp_headers_too_large`, `mcp_body_too_large` (`413`, string code) | reason `admission`, decision `mcp_invalid_request`, `mcp_method_not_allowed` or `mcp_request_too_large` | `mcp`, `mcp-stateless` |
| `400` | `pd_pipelining_unsupported` | framing | P/D path | none | no (one P/D request at a time on a connection) | absent | `detail`, `max_body_bytes` | none | closed | HTTP/1.1 only | reason `admission` | none |
| `415` | `pd_body_unsupported_media` | framing | P/D path | none | no (`application/json`) | absent | `detail`, `max_body_bytes` | none | closed | HTTP/1.1 only | reason `admission` | — |
| `413` | `pd_body_too_large`, `pd_body_unbufferable` | framing | P/D path | none | no (a complete `Content-Length` body within `max_body_bytes`) | absent | `detail`, `max_body_bytes` | none | closed | HTTP/1.1 only | reason `admission` | `sglang-pd-disagg` |
| `400` | `invalid_json_body` (P/D rule) | framing | P/D path | none | no (the body must be a JSON object) | absent | `detail`, `max_body_bytes` | none | closed | HTTP/1.1 only | reason `admission` | — |
| `500` | `pd_prepare_failed` | framing | P/D path | none | cond. — the gateway could not prepare the request for prefill/decode; nothing was sent | absent | `detail` | none | closed | HTTP/1.1 only | reason `admission` | none |
| `503` | `pd_sg_oversize_unroutable` | framing | P/D path | none | no (the body exceeds what a prefill/decode rule can inspect) | absent | `detail` | none | closed; no `Content-Length` | HTTP/1.1 only | reason `admission` | `sglang-pd-disagg` |

The six `pd_*` codes and the P/D `invalid_json_body` in this table are written by the prefill/decode code
itself (`pd_check_request_body`, `pd_prepare_failed`, `pd_sg_oversize_reject`). These are the refusals that carry
neither `X-Loxilb-Refusal-Stage` nor `X-Request-Id` ("Unmarked", above); the two P/D codes of the capacity stage
(`pd_overloaded`, `pd_admission_park_timeout`) are written elsewhere and carry both.

### Stage `security` — a content scanner blocked the request

| Status | `error` | Stage | Written by | Dispatch | Retry-safe | `Retry-After` | Body | Headers | Connection | H1 / H2 | Audit | Reproduced by |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `403` | the sentence `Request blocked by LlamaFirewall` — not a code | security | content scanner | none | no | absent | `reason` | `X-LlamaFirewall-Decision: BLOCK` | closed; no `Content-Length` | HTTP/1.1 only | reason `admission`, decision `llamafirewall_block` | none |

Match this one on the status and the `X-LlamaFirewall-Decision` header, not on the `error` text.

## Answers that are not refusals

These are written by the gateway too, but they are recorded as the request's **completion**
(`data.ai.complete`, with the status written), not as a `sec.ai.deny`, and they have no stage: none carries
`X-Loxilb-Refusal-Stage`, with the one exception named in the `no_route` row below. None of them is a congestion
signal.

### Outages before dispatch

No request byte reached a backend, because none could take it. These answers carry `X-Request-Id` while the
request still has its ID (the rules above), on HTTP/1.1 and HTTP/2, and no stage.

| Status | `error` | When | Dispatch | Retry-safe |
|---|---|---|---|---|
| `503` | `no_healthy_backend` | every endpoint of the pool (or of the route's subset) is down or circuit-broken | none | cond. — safe to send again, but only an endpoint coming back changes the answer; no `Retry-After` |
| `503` | `service_unavailable` | every endpoint refused the connection | none | as above |
| `502` (HTTP/1.1), `503` (HTTP/2) | `backend_unreachable` | the chosen endpoint, and every failover candidate, did not accept the connection | none | as above |
| `503` | `no_route` with a `detail` naming a listener "kept open after its last rule was deleted" | the rule was deleted; see [doc 26](26-endpoint-picker-epp.md). **Carries `X-Loxilb-Refusal-Stage: route`** although it is recorded as an outage completion: the one stage header with no deny record | none | no, until a rule takes the address |
| `503` | `epp_unavailable` | the rule's Endpoint Picker did not decide in time | none | cond. |
| `429` | `epp_evicted` | the Endpoint Picker shed the request | none | cond. — the picker's decision, not the capacity gate's; no `Retry-After` |
| the picker's | the picker's own immediate response, with the picker's headers and the gateway's `X-Request-Id` (a picker that sets `X-Request-Id` itself leaves two) | an Endpoint Picker answered instead of choosing an endpoint | none | as the picker says |
| `503` | `mcp_backend_unavailable` | no MCP backend could take the stream | none | cond. |
| `503` | `pd_pool_unavailable` with `detail` `no healthy prefill or decode endpoint` or `no healthy decode endpoint accepted the request` | a P/D rule has no usable pair | none | cond. |

### Endings after dispatch

A backend received the request, or may have. **Never retry these as if nothing happened**: the model may have run,
tokens may have been spent, a stream may have been partly delivered.

| Status | `error` | When | Dispatch | Retry-safe |
|---|---|---|---|---|
| in-stream SSE event | `client_stalled` | the client stopped reading a streamed answer | sent | no |
| in-stream SSE event | `max_stream_duration_exceeded` | the stream reached the rule's duration cap | sent | no |
| `504` | `pd_prefill_timeout`, `pd_decode_timeout`, `pd_idle_timeout` | a prefill/decode leg did not answer in time | sent | no |
| `502` | `pd_decode_stream_timeout` | the decode stream went silent | sent | no |
| `502` | `pd_decode_backend_died` | the decode backend closed before any response byte | sent | no |
| `502` | `pd_sg_prefill_failed` | the prefill leg failed before decode produced output | sent | no |
| `4xx` | `prefill_rejected` (with the engine's `status`) | the prefill engine refused the request and its reply was cut at the gateway's buffer cap | sent | no |
| `503` | `pd_pool_unavailable` with any other `detail` (`decode endpoint unreachable`, `prefill backend connection dropped`, `decode response processing failed`, …) | a P/D leg was lost mid-request | sent or unknown | no |
| none — the connection or stream ends | none | the backend died under a relayed answer (audit reason `backend_conn`), or the listener was closed (`gateway_shutdown`) | sent | no |

An in-stream event is a `data: {"error":"…"}` SSE event written into an answer that has already started with
`200`; the status cannot change any more. A client that reads SSE must check each event for a string `error`.

## Request ID

- A client's `X-Request-Id` is adopted as the request's ID on HTTP/1.1 and HTTP/2. **At most 255 bytes are
  kept**: the first 255 bytes are the request's ID everywhere — in the audit records, in the value sent to the
  backend, and in the echo. A client that sends a longer ID gets its first 255 bytes back.
  A request without one is given 32 hexadecimal characters before the gateway decides anything about it.
- The ID is forwarded to the backend, and it is the `request_id` of every audit record of the request: its
  refusal (`sec.ai.deny`), its completion (`data.ai.complete`) and its token settlement. A client that supplies
  its own ID can therefore find the record of any answer on this page without help from the gateway.
- A gateway-written answer carries the ID back as `X-Request-Id`
  ([the rules, and when it is absent](#the-two-headers-on-a-gateway-written-answer)). A client that did not
  supply an ID learns the minted one from the refusal and can find the `sec.ai.deny` record by it.
- A relayed backend response keeps whatever `X-Request-Id` the backend sent; that echo is the backend's.
- **The request ID as a routing key.** On HTTP/2 the request ID never influences which endpoint serves a
  request. On HTTP/1.1 it does in two cases, because the gateway also reads `X-Request-Id` as a conversation ID:
  - on a prefill/decode (`pd_disagg`) rule, a client-supplied ID is the session key and takes precedence over the
    JSON `user` field, so a client that sends a new ID with every request gets no `user` stickiness;
  - on a rule whose `sel` is CHWBL (`8`), GPU-aware (`9`) or WRR-hash (`10`), a request with no extractable prompt prefix
    (no body, or a body the prefix reader cannot use) is placed by a hash of the ID.

  On a round-robin (`sel` `0`) or weighted (`2`) rule that is not prefill/decode it has no effect. A deployment that
  needs the request ID to be correlation-only should use such a rule, or send `X-Conversation-ID` deliberately
  for stickiness and treat `X-Request-Id` as described here.

## Admission metadata on responses

The admission triple appears on capacity refusals always, and on admitted responses when the rule has
`fc_expose_headers` on ([doc 23](23-ai-admission-flow-control.md#the-same-headers-on-admitted-responses)).

- **Scope**: the model pool the request was routed to. Not the gateway, not the tenant, not the user.
- **When measured**: as the response head goes out (the request itself counted on an admitted response); as the
  refusal is written on a refusal.
- **`-Limit`**: the service ceiling in force — the adaptive one while the pool adapts. `0` means the pool has no
  ceiling. On a refusal by a per-endpoint ceiling it is that ceiling.
- **`-Queued`** is the pool's waiting requests. It is **never a position in the queue** and says nothing about
  how long this client would wait.
- **Absent means unknown, never zero.** The headers are absent on requests the gate does not count
  (non-inference paths such as `GET /v1/models`, a pool in `off` mode), on rules without `fc_expose_headers`, and,
  on HTTP/1.1, on an admitted response whose head the backend sent in more than one piece.
- The class pair and `X-Loxilb-Admission-Objective` are present only when the request's class was resolved, which
  needs an identity that resolves a tenant. Their absence is not an error.

## What a backend's response can and cannot look like

A relayed backend response keeps its status, headers and body. Three things follow for a client that separates
gateway answers from backend answers:

- A backend's own `429` or `503` is relayed as it is. With `fc_expose_headers` on it **also carries the admission
  triple**, because the request was admitted and the triple is put on every admitted response head. The triple on
  a `429` is therefore not proof that the gateway refused; the string-typed `error` code is.
- With `fc_expose_headers` on, `X-Loxilb-Admission-*` headers sent by a backend are replaced by the gateway's.
  This happens only on the paths that add the gateway's values: not on rules with `fc_expose_headers` off, not on
  requests the gate does not count, and not on an HTTP/1.1 response head split across reads — there a backend's
  headers of those names pass through. Backends are operator-controlled; a backend that must not be able to say
  anything under these names should not send them.
- A backend's `X-Loxilb-Refusal-*` fields are removed from every relayed response head, with or without
  `fc_expose_headers` (the residuals are [above](#the-two-headers-on-a-gateway-written-answer)). A backend's
  `429` therefore never reads as a gateway capacity refusal: it has no stage, and its `error` is an object.
- A backend's `X-Api-Key` is removed on services that declare `api_key_auth`
  ([doc 19 §2.5](19-ai-gateway-controls.md#25-a-backends-x-api-key-and-x-auth--response-headers)).

## HTTP/1.1 and HTTP/2 at a glance

| | HTTP/1.1 | HTTP/2 |
|---|---|---|
| A refusal ends | the connection (`Connection: close`), except a capacity `429` on a fully buffered request, which keeps it | the stream only; the connection stays |
| Waiting in the capacity queue | yes, when the rule has a queue | never — a stream over a ceiling is refused at once |
| Queue endings (`admission_queue_timeout`, `admission_ttl_expired`, `admission_drained`, an evicted `admission_shed`) | yes | never |
| Capacity `429` body `retry_after` | the live value | always `1` |
| Capacity `503` body | `message`, `retry_after` | the same (before the release that added the two headers: `message` only) |
| `Retry-After` on a rate-limit refusal with value `0` | written | omitted |
| Detail field on route and framing answers | `detail` | `message` |
| `Content-Length` | on gate and capacity answers; missing on several route, framing and P/D answers | always (as `content-length`) |
| Admission triple on admitted responses | when the head arrives whole | always |
| Request ID as a routing key | on P/D and hash-selected rules (above) | never |
| `X-Loxilb-Refusal-Stage` | a header line after the status line | the field `x-loxilb-refusal-stage`, after the existing fields |
| `X-Request-Id` on a gateway-written answer | the connection's current request | the stream's own request; absent on three refusals written while the stream's headers are read |
| A refusal by the queue reaper from another thread | the plain form: stage `queue`, no request ID | — |

Only the status, the `error` code, the `Retry-After` header and the value of `X-Loxilb-Refusal-Stage` are the same
on both.
