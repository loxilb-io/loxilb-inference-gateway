# ai-admission — the capacity admission gate

A gateway booted with the capacity gate enforcing (service ceiling 8,
endpoint ceiling 5), six AI-gateway services over one backend process
whose receipts, peak-concurrency counters and arrival order say what
actually executed, and drivers that push each service past its ceilings
over HTTP/1.1, HTTP/2 and TLS, into and out of the bounded queue, through
a rule delete and a maintenance drain. The last arm reboots the gateway in
observe mode and drives the same load again.

The mode and the ceilings come from the process environment
(`LLB_FC_MODE`, `LLB_FC_MAX_OUTSTANDING`, `LLB_FC_EP_MAX_INFLIGHT`); the
queue is configured per rule (`fc_max_queue_depth`, `fc_max_queue_wait_ms`)
and read back through `fc_effective`.

## Topology

```
l3h1 (10.10.10.1) ---- llb1 (VIP 10.10.10.254) ---- l3ep1 (31.31.31.1)

:2021  HTTP/1.1   -> l3ep1:8080, :8081   mock_backend.py (one process, both ports)
:2022  HTTP/2     -> l3ep1:8090, :8091   h2c_backend.py x2
:2023  TLS        -> l3ep1:8080, :8081   with max_stream_duration_sec = 3
:2024  HTTP/1.1   -> l3ep1:8080          one endpoint, so its ceiling (5) binds
:2025  HTTP/1.1   -> l3ep1:8080, :8081   fc_max_queue_depth 4, fc_max_queue_wait_ms 30000
:2026  HTTP/1.1   -> l3ep1:8080          fc_max_queue_depth 65536: the memory warning at apply
:2028  HTTP/1.1   -> l3ep1:8080, :8081   fc_max_outstanding 4 (under the env's 8), fc_telemetry_stale_ms 45000
:2029  HTTP/1.1   -> l3ep1:8080, :8081   fc_max_outstanding 2, fc_max_queue_depth 4: raised at runtime
:2033  HTTP/1.1   -> l3ep1:8080, :8081   API keys required, fc_max_outstanding 4, fc_tenant_max_share_pct 50
:2034  HTTP/1.1   -> l3ep1:8080, :8081   API keys required, fc_max_outstanding 2, fc_tenant_max_share_pct 50, a queue
:2035  HTTP/1.1   -> l3ep1:8080, :8081   fc_max_outstanding 4, fc_expose_headers on
:2036  HTTP/2     -> l3ep1:8090, :8091   fc_max_outstanding 4, fc_expose_headers on
:2037  HTTP/1.1   -> l3ep1:8099          nothing listens there: the outage a failed connect is answered with (row OS)
:2038  HTTP/1.1   -> l3ep1:8080, :8081   keyed, admission headers on, not strict: created and deleted by row OBJ
:2039  HTTP/1.1   -> l3ep1:8080, :8081   the same with ai_objective_strict (row OBJ)
:2040  HTTP/2     -> l3ep1:8090, :8091   the :2038 rule on HTTP/2 (row OBJ)
pg-ai-admission (docker bridge)          PostgreSQL: the API-key store the two keyed pools resolve tenants from
```

The gateway runs with `--audit-dir --audit-required`, so every refusal the
gate makes must also be a `sec.ai.deny` record with stage `capacity`.

Rows RI, OS, NEG and F2 check the client refusal contract
(`docs/load-balancing/27-ai-gateway-client-refusal-contract.md`) on the wire:
`X-Loxilb-Refusal-Stage` and `X-Request-Id` on the answers the gateway
writes, and their absence from what a backend sent. Their expected values
are written in `validation.sh` before the run; RI and part of OS read the
answers the rows above them already collected.

## Rows

| Row | Drive | What must hold |
|---|---|---|
| P | scrape | mode 2, ceilings 8 / 5 exported, gauge 0, no anomaly |
| A | 4 sequential requests | 4 x 200, 4 receipts, admitted +4, gauge back to 0 |
| B | 12 held requests | exactly 8 receipts, 4 x 429 with `X-Loxilb-Admission-Inflight/-Queued/-Limit`, `Retry-After`, `jitter_hint_ms`; gauge 8 while held; 8 x 200 after release; capacity_shed +4; `requests_total{outcome="denied",status="429"}` +4 and `{outcome="completed",status="429"}` +0, 4xx class +4, 2xx class +8 |
| N | 12 held requests on the one-endpoint pool | exactly 5 receipts, 7 x 429 carrying `X-Loxilb-Admission-Limit: 5`, endpoint gauge 5, 5 x 200 after release |
| C | 64 simultaneous 2 s requests | peak concurrency at the backend == 8, each endpoint <= 5, receipts == admitted |
| D | 5 requests on one keep-alive socket | one connection, 5 receipts, gauge back to 0 |
| E | 12 HTTP/2 streams on one connection, 3 cancelled | gauge 8 (streams, not connections), 4 refused on their own stream with the headers, gauge 5 after the cancels, 5 x 200, 8 receipts |
| F | 4 executing clients reset | 4 receipts, gauge back to 0 with the backend still holding |
| G | second request on a kept connection while the pool is full | 429 on the same socket, 0 receipts |
| I | `GET /v1/models` while the pool is full | 200, reached the backend, counted as `bypass_non_inference` |
| K | the trail | 4 `sec.ai.deny` records for B's 429s: stage capacity, status 429, reason admission, decision admission_capacity, service, model |
| L | TLS listener | the ninth request reads a 429 through TLS (curl exit 0); an SSE stream past the cap reads the reaper's error event through TLS, chunk-framed like the stream it ends, and the gateway log shows the socket's owner worker wrote it |
| J | scrape | no anomaly, no no_healthy_capacity, every pool exported (16) |
| Q | 8 held on the queue pool (depth 4, wait 30 s), 4 more sent 300 ms apart, then 2 more | queued gauge 4, `role="queue"` limit 4, 0 receipts for the waiters, queued +4; the 2 extra get 429 with `X-Loxilb-Admission-Queued: 4` and `admission_capacity`, queue_full +2; one held request released ⇒ the 4 waiters reach the backend in arrival order (`__order`), 4 × 200, wait histogram count +4, admitted +12, gauges back to 0; `requests_total{outcome="denied",status="429"}` +2 and `{outcome="completed",status="429"}` +0, 4xx class +2 |
| T | the wait shortened to 4000 ms by a replace POST and read back, 8 held, 2 waiters past the window | both 504 `admission_queue_timeout` with `queued_ms` ≥ 4000 and `Retry-After`, queue_timeout +2, queued gauge 0, 0 receipts then or later, the 30 s wait restored and read back; `requests_total{outcome="denied",status="504"}` +2 and `{outcome="completed",status="504"}` +0, 5xx class +2 |
| X | 8 held, 2 waiters reset their connections after 3 s | cancelled +2, queued gauge 0, 0 receipts then or later, gauge back to 0 |
| W | the `:2026` rule with depth 65536 | the gateway log (read through the `loxilb*.log` glob, asserted non-empty) carries the memory warning naming that rule and both guards; no warning for the `:2025` rule; the pool is gated with queue limit 65536 |
| R | GET and a replace POST on the `:2025` rule | `fc_max_queue_depth`/`fc_max_queue_wait_ms` read back; `fc_effective` reports mode, ceiling, depth, wait, `queue_memory_bound_mib` = depth, live `queued`; a replace POST with depth 2 is read back, held by the data plane and exported, then restored; a depth without a wait window is refused 400; a replace carrying only a depth is accepted and keeps the stored wait, one carrying only a zero wait is refused 400 with the stored rule untouched (the pair is judged on the merged rule) |
| S | GET on `:2028`, 6 held, replace POSTs | the declared fields read back; `fc_effective` holds the rule's ceiling 4 (source `rule`), the env's endpoint ceiling and mode (source `env`), no queue (source `default`) and the rule's telemetry window; an undeclared `fc_mode` is not read back; 4 reach the backend, 2 get 429; an explicit `0` returns the ceiling to the env's 8 (source `env`), then restored; replaces with a ceiling over 100000, an unknown mode, a window over an hour or a `null` ceiling are refused and the stored rule is untouched |
| O | `:2028` replaced with `fc_mode: off`, 6 held, then `inherit` | mode `off` with source `rule`; all 6 reach the backend, none refused; `inherit` returns the mode to the env's `enforce` and is not read back |
| U | 6 held on `:2029` (ceiling 2, depth 4), the ceiling replaced with 6 | 2 reach the backend, 4 wait; once the data plane holds 6, all 4 waiters reach the backend within 1500 ms (the once-a-second pass alone would take three seconds or more), the queue empties, 6 × 200, none drained with 503 and the gateway logs an in-place update (a replace that changes only the gate never re-creates the entry); restored |
| UE | on `:2029` the gate replaced in place with endpoint ceiling 1, window 3 s; 2 held (one per endpoint), 1 more sent | the waiter parks behind the endpoint ceiling while the service has units, so the once-a-second pass wakes it every second and it goes back; it is still ended at its first window: 504 `admission_queue_timeout` within 5000 ms, never reaching a backend; both holders 200; restored, the endpoint ceiling read back from the environment |
| KA | pool full, one connection sends a buffered request, then another on the same socket after the pool empties | 429 with `Connection: keep-alive`, socket open; the second request on the SAME socket is 200; receipts 0 then 1 |
| DL | 8 held on `:2025`, 2 waiting, the rule is deleted by its full key (host, path prefix, match mode, model name) and the GET no longer lists it | both 503 `admission_drained`, 0 receipts then or later, 2 `sec.ai.deny` records with decision `admission_drained`; the rule re-created reports enforce with nothing in flight |
| M | 8 held on `:2025`, 2 waiting, `PUT /maintenance {enabled:true}` | GET maintenance says `refusing_new_inference: true` and `in_flight_requests: 8`; the 2 waiters get 503 `admission_drained` (drained +2); a new request gets 503 `gateway_draining` with `Connection: close` and `Retry-After: 5` and 0 receipts (draining +1); the 8 executing finish 200; `enabled:false` ⇒ `refusing_new_inference: false` and the next request is admitted |
| TS | three keys issued through `/config/ai/apikey`, one tenant each; tenant A holds 2 on `:2033` (ceiling 4, share 50 %), sends a third; tenant B holds 2 | A's third is 429 `admission_tenant_share` and never reaches a backend while B's two are admitted; `fc_effective` reports 2 tenants active and the share from the rule; `tenant_share` decisions +1; the 4 held answer 200 and no tenant holds anything after |
| TW | on `:2034` (ceiling 2, a unit and two queue places a tenant) A holds 1, 2 wait, a fourth is sent; then B, then C | A's fourth is 429 `admission_tenant_share` (its queue share); B is admitted past A's waiters; with the ceiling full C waits behind A's two, and the unit B frees goes to C, not to A's over-share head waiter; A's own unit goes to A's head waiter, then A's second; the 5 admitted answer 200, the queue empties, no tenant holds anything; `queued` decisions on `:2034` moved by exactly 3 (A's two and C: B was never parked) |
| XH | two held on `:2035` (ceiling 4, headers on); a plain request, a streamed one, one whose backend answers with its own `X-Loxilb-Admission-Inflight: 999`; the same request on `:2021` (environment: off); then the rule replaced with `fc_expose_headers` `off` while the two are held | the plain and streamed heads carry inflight 3, queued 0, limit 4; the stream is still `text/event-stream` with every event and `[DONE]` last; the backend's field is replaced (one line each, the gateway's values); `:2021` adds none; GET reads `on`, in force from the rule; `"yes"` is refused naming the field; after the replace GET reads `off` and the next response carries none, and the two held (not drained by the in-place change) answer 200 |
| XH2 | three HTTP/2 streams on `:2036` (ceiling 4, headers on), each held 2 s at the backend | all three admitted; every response's HEADERS carry the three fields with queued 0 and limit 4, inflight between 1 and 3 (read as each head goes out, while the stream holds its unit), the first head counting all three; nothing held after |
| RI | the heads rows B, TS, T, DL, M, L, KA, G and E kept; one more kept connection whose second request carries no ID | every refusal shape — 429 `admission_capacity` (plain, TLS, kept connection, HTTP/2 stream), 429 `admission_tenant_share`, 504 `admission_queue_timeout`, 503 `admission_drained` (rule delete and maintenance), 503 `gateway_draining` — carries `X-Loxilb-Refusal-Stage` (`capacity`; `queue` for the three queue endings) and `X-Request-Id` equal to the ID the client sent, and the `sec.ai.deny` record found by that ID is at stage `capacity`; a request sent without an ID (M's new request) is answered with a minted one that the trail has; on ONE connection whose first request was served and second refused, the refusal names the second request's ID (and has its deny record; the first has none), and when the second request carries no ID the refusal names a minted ID that is not the first's |
| OS | on `:2035`: the next backend answer forced to a 429 `{"error":{…}}` with its own `Retry-After: 7` (`/admin/answer-429-object`), then a 200 that carries `X-Loxilb-Refusal-Stage: capacity` and `X-Loxilb-Admission-Inflight: 999` of the backend's own (`/admin/echo-spoof-headers`), then both at once; the same spoof on `:2021` (admission headers off); a request on `:2037`, whose only endpoint refuses the connection; a request the backend resets after taking it; a request on `:2037` with that endpoint marked down through the API | the backend's 429 is relayed with the admission triple (1, 0, 4), its object body and its `Retry-After`, **no** `X-Loxilb-Refusal-*`, 1 receipt, no deny record; the spoofed stage is removed on both pools (and the admission values are the gateway's on `:2035`); the refused connect is a 502 `backend_unreachable` with no stage, no deny record and **no** `X-Request-Id` (it is written from the connect event: a documented residual); the reset after dispatch is a 502 with no stage and no `X-Request-Id`; the pool with no healthy endpoint is a 503 `no_healthy_backend` with no stage, no deny record and the request's own `X-Request-Id` |
| OBJ | objectives `obj-gold` (priority 1) and `obj-base` (0); tenant `obj-may` (may name `obj-gold`) and `obj-maynot` (may not), default `obj-base`, a key each; rules `:2038` (not strict), `:2039` (strict), `:2040` (HTTP/2, not strict), all with `fc_expose_headers` on. On `:2038`: `obj-gold` asked by each tenant; no objective; an unknown name; the deprecated header name; a 70-byte name; a body `service_tier: priority`; a backend that sends its own `X-Loxilb-Admission-Objective-Requested`. On `:2039` and `:2040`: `obj-gold` asked by each tenant | allowed: 200 with `X-Loxilb-Admission-Objective: obj-gold`, class `critical`, **no** `-Objective-Requested`. Denied on `:2038`: 200, `-Objective: obj-base`, class `standard`, `-Objective-Requested: obj-gold` once, 1 receipt, no stage header, no deny record; `no-such-objective`, `(oversize)` and `tier:priority` reported the same way; the backend's own line never reaches the client, denied or not. Denied on `:2039`: 403 `objective_not_allowed`, stage `objective`, the request's `X-Request-Id`, a deny record at that stage, 0 receipts, no `-Objective-Requested`. `:2040`: the same two headers on an HTTP/2 response head. The row deletes its rules and objectives |
| NEG | on the keyed `:2033`: no key; a key that may not use the model; a key limited to 1 request/s, four requests; a never-seen key after the store container is stopped | 401 `invalid_api_key` and 403 `model_not_allowed` at stage `auth`, 429 `rate_limit_exceeded` at stage `ratelimit` with `Retry-After`, 503 `policy_store_unavailable` at stage `auth` with `Retry-After: 5`: each with that stage in `X-Loxilb-Refusal-Stage` (never `capacity` or `queue`), the request's `X-Request-Id`, a deny record at that stage under that ID, and 0 receipts; the store is started again (empty) for row H. **NEG is terminal for the policy store**: the new store has no tables until the gateway next starts, so no row after NEG may write to it (objectives, tenant limits, keys). `validation.sh` enforces it: `store_guard` in the helpers that write (`mk_key`, `neg_key`, `obj_api`) reports such a write on stderr where it happens and as a `[FAIL] STORE` line at the end. A row that needs the store goes before NEG |
| F2 | the repository's Endpoint Picker fixture (`pkg/epp/epptest/fake.go`; no rule of this scenario runs a picker) | it sets no `X-Request-Id` on its answers, so an immediate answer cannot carry two; if it ever does, this row fails and the one-header assertion belongs in `cicd/k3d-incluster-inference-epp` |
| H | reboot in observe mode, 12 held | 12 receipts, gauge 12, nothing refused, observe_would_shed 6 (4 over the service ceiling, 1 over each endpoint's), admitted 12; after the reboot the `:2028` rule's ceiling and telemetry window still resolve to the rule's values (source `rule`) while its mode follows the new environment (`observe`, source `env`) |

## Files

- `config.sh` / `validation.sh` / `rmconfig.sh` — the scenario
- `gw.sh` — the gateway boot, rules and observe-mode restart, shared by config and validation
- `mock_backend.py` — HTTP/1.1 backend: receipts, hold/release, delay, peak concurrency across both ports; `/admin/answer-429-object` and `/admin/echo-spoof-headers` shape the next answer (rows OS)
- `h2c_backend.py` — the h2c echo backend the HTTP/2 legs of `ai-jwtauth` use (receipts, per-request delay)
- `h2_admit.py` — HTTP/2 driver: k streams on one connection, refusals reported per stream, RST_STREAM on live streams
- `h1_client.py` — the HTTP/1.1 shapes curl cannot drive: clients that vanish while executing, a second request on a kept connection (with or without an ID of its own)
