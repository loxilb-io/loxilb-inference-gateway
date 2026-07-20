# AI-Gateway L7 Proxy & HA (vLLM)

> The LLM-aware L7 fullproxy and its HA state synchronization.
> Covers vLLM fullproxy load balancing, Prefill/Decode (P/D) disaggregation routing, conversation
> stickiness, cache-aware routing, the circuit breaker, and sockproxy HA state sync over xSync gRPC.
>
> This path runs in the same userspace sockproxy as the L7 content-routing features but on the AI
> route (`has_l7_policy==0`) — the two are kept byte-for-byte independent.
>
> **For exact CLI flags / rule fields per feature, treat the matching `cicd/<scenario>/config.sh` as
> the source of truth** — they are the gated, working configurations and track the current build.

---

## 1. What the AI L7 proxy does

The sockproxy terminates the client connection, inspects the OpenAI-style JSON body, selects a vLLM
worker (or a prefill+decode pair), optionally rewrites the body, and proxies the response stream
(SSE) back untouched.

```
Client  ──►  VIP (e.g. 10.10.10.254:2020)  ──►  [LoxiLB sockproxy]  ──►  vLLM worker(s)
   {model, messages, stream, ...}                 routing + body rewrite      :8000
```

Two deployment shapes:

- **Fullproxy :** every endpoint handles a full request. Health failover, HTTP error
  pass-through, concurrency, and resilience are the GA-hardened behaviors.
- **Prefill/Decode disaggregation:** the request is split into a short *prefill* leg
  and a streaming *decode* leg routed to different workers, with KV-cache state handed between them.

---

## 2. Prefill/Decode (P/D) disaggregation

### 2.1 Routing tiers (in priority order)

| Tier | Name | Trigger | Mechanism |
|---|---|---|---|
| 0 | Conversation stickiness | `user_id` JSON field or `X-Conversation-Id` header | Pin the same `(prefill_ep, decode_ep)` pair for `pdSessionTTLSec` |
| 1 | Cache-aware trie | `pd_cache_aware_mode=true` | Hash(system-prompt) → radix-trie leaf → endpoint with cache affinity (CHWBL) |
| 1.5 | KV-exact (ZMQ) | `kvExactMode` + KV-event inventory | Engine-exact routing from the engines' KV-cache event streams — see [KV-cache-aware routing](08-kv-cache-aware-routing.md) |
| 2 | Min-load + RR | default | Least-loaded prefill EP; round-robin tiebreak; decode EP from the decode pool |

### 2.2 Body rewriting (what LoxiLB changes)

**Prefill leg** — force a one-token prefill, no streaming:

```jsonc
// client sends:        {"max_tokens": 512, "stream": true, ...}
// prefill leg becomes: {"max_tokens": 1,   "stream": false, ...}
```

LoxiLB auto-injects an `X-Request-Id` that encodes both EP addresses and the NIXL transfer port, e.g.
`___prefill_addr_31.31.31.1:9001___decode_addr_32.32.32.1:9002___<uuid>___`.

**Decode leg** — restore the original request and inject the KV handoff:

```jsonc
// {"max_tokens": 512, "stream": true, "kv_transfer_params": {"remote_block_ids": [...], ...}}
```

The `remote_block_ids` come from the prefill response; LoxiLB relays them so the decode worker pulls
the KV state from the prefill worker. The decode SSE stream — including the terminal `data: [DONE]` —
is proxied **as-is** (never strip or double-count `[DONE]`).

### 2.3 Circuit breaker

Per-endpoint, local-only (`CLOSED → OPEN → HALF_OPEN`): 5 consecutive failures open the breaker;
after a ~30s open window it probes `HALF_OPEN`. While open, traffic diverts to healthy siblings. **Not
synced across HA nodes** — re-validated locally per request (network paths are asymmetric).

---

## 3. HA / state sync

LoxiLB synchronizes sockproxy state between cluster nodes so AI sessions survive failover. This extends
the existing xSync gRPC service (`pkg/loxinet/xsync.proto`).

### 3.1 What syncs (and what doesn't)

| State | Sync mode | On failover |
|---|---|---|
| P/D session mappings (`conv_id → prefill_ep, decode_ep`) | Incremental push (≤256/batch or 100ms) + bulk pull on promotion | Re-validated locally; unhealthy EP → fall through to normal selection |
| Conversation mappings (`conv_id → ep`) | Same as above | Same health-gate |
| Rate-limiter buckets | Active-Passive: 200ms snapshot · Active-Active: 100–200ms gossip delta | Soft over-limit window ≈ `limit × 200ms × N_nodes` |
| **Circuit breaker** | **never** | Re-validated locally |
| **Endpoint health/`inv` flags** | **never** | Re-validated locally |

The **receiver is health-gated**: a node will not install a remote binding that points at an endpoint
it sees as unhealthy locally (rejected → `loxilb_sockproxy_sync_health_reject_total`).

### 3.2 Active-Active conflict resolution

First-writer-wins by `created_ts` (smaller wins; tie → local kept). Both nodes converge within ~2
RTTs. Metric: `loxilb_sockproxy_sync_conflict_total{outcome=local_kept|remote_won|tie_local_kept}`.

### 3.3 The restore-rate goal

The HA goal is **`restore_rate ≥ 0.90`**: after a master fails over, ≥90% of prior
sessions resume on the *same* `(prefill_ep, decode_ep)` pair. Measured by the HA stage of the
P/D CICD scenario (`run-pd-cicd.sh --phase=L`).

### 3.4 Wiring history (important for anyone reading old logs)

The coordinator wiring took three steps — know which build you're on:

- **Initial delivery:** shipped the coordinator, the xSync proto extension, the C event bridge, and
  the HA CICD harness.
- **Startup wiring:** wired `mh.sockproxySync` into loxinet startup and spawned per-peer consumer
  goroutines. A post-merge wiring probe found a gap: consumers were spawned only at boot (`Start()`),
  *before* keepalived elected a master — so the role-gated peer list was empty and **no consumers ran
  on the elected master**. Symptom: `restore_rate = 0/100`.
- **Promotion fix (current):** `OnStateChange` now calls `spawnConsumersForKnownPeers` on
  MASTER promotion. Expect a `[SOCKPROXY_SYNC] consumerLoop start peer=` log line within ~10s of
  the MASTER transition.

### 3.5 Rolling-upgrade safety

A new node calling RPC on an old peer gets `codes.Unimplemented`; it clears that peer's
capability bit, logs once at WARN, and continues in local-only sockproxy mode (CT sync keeps working).
The cluster does **not** split. Test: `TestSockproxySyncRollingUpgrade`.

### 3.6 Deferred

- **Failover warmup** (KV inventory + vLLM metrics snapshot at promotion) is **deferred**:
  it can't be measured on a single-host docker testbed because both loxilb containers share
  `/sys/fs/bpf`, so both HA arms read the same eBPF maps. Needs a 2-host (2-VM) testbed.

---

## 4. Configuration

The LB rule carries the AI knobs (health probe, P/D mode, endpoint roles, NIXL ports, hashing mode,
circuit-breaker thresholds, cache-aware mode). **Use the working scenario configs as templates:**

| Want | Reference config |
|---|---|
| Fullproxy GA (failover/errors/concurrency/resilience) | `cicd/vllm-fullproxy/config.sh` |
| Fullproxy + WRR | `cicd/vllm-fullproxy-wrr/config.sh` |
| HTTP (non-TLS) proxy | `cicd/vllm-httpproxy/config.sh` |
| P/D disaggregation (2P+2D) | `cicd/vllm-pd-disagg/config.sh` |

Two essentials that are easy to miss:

1. **Always set a health probe** — `--probe=tcp --probetimeout=5 --proberetries=3`. Without it,
   endpoint death is never detected (this was a real bug). Effective down-detection ≈ 4–6s.
2. **VIP must be local** to the loxilb node (fullproxy binds it).

REST CRUD works the same as any LB rule — see [REST reference](05-rest-api-reference.md). Inspect a
live rule:

```bash
curl -s http://10.10.10.254:11111/netlox/v1/config/loadbalancer/all | jq '.[] | select(.serviceArguments.port==2022)'
```

> **WRR caveat:** per-endpoint weight is ignored when P/D disaggregation mode is on (endpoint roles,
> not weights, drive prefill/decode selection).

---

## 5. CICD validation

| Suite | Coverage |
|---|---|
| `cicd/vllm-fullproxy/` (+ `validation-{failover,errorhandling,concurrency,resilience}.sh`) | health-probe failover, 4xx/5xx pass-through, malformed JSON, CHWBL stickiness under parallel load, Unicode/SSE `[DONE]`, X-Forwarded-For |
| `cicd/vllm-pd-disagg/` (`run-pd-cicd.sh --phase=…`) | stages A–K + L, ~57 checks: body rewriting, multi-EP routing, X-Request-Id, failover, concurrency, REST CRUD, SSE, Prometheus, circuit breaker, conversation stickiness, cache-aware trie |
| `cicd/vllm-pd-disagg/` HA stage (`--phase=L`) | 2-loxilb HA: `restore_rate ≥ 0.90` over 100 multi-turn sessions with `docker stop llb1` mid-stream |

**Run examples** (Linux + Docker testbed):
```bash
# Fullproxy
cd cicd/vllm-fullproxy && bash config.sh && bash validation-all.sh ; ./rmconfig.sh

# P/D, specific phases
cd cicd/vllm-pd-disagg && bash config.sh && ./run-pd-cicd.sh --phase=I --bail-on-fail ; ./rmconfig.sh

# HA (Phase L) — needs the 2-loxilb topology
cd cicd/vllm-pd-disagg && PHASE_L_HA=1 bash config.sh && ./run-pd-cicd.sh --phase=L ; ./rmconfig.sh
```

> **Testbed image freshness:** the registry image can predate your code. After `config.sh`, either
> rebuild (`make docker-u24`) or `docker cp ./loxilb {llb1,llb2}:/root/loxilb-io/loxilb/loxilb` so the
> harness tests *your* binary, not a stale one. Confirm with `strings ./loxilb | grep -c SOCKPROXY_SYNC`.

---

## 6. Troubleshooting (AI-Gateway)

| Symptom | Cause | Fix |
|---|---|---|
| Endpoint death never detected | No `--probe` on the rule | Add `--probe=tcp --probetimeout=5 --proberetries=3` |
| SSE stream cuts off / client hangs | `[DONE]` stripped or double-counted (pre-67 bug) | Use a post-67 build; `validation-resilience.sh` R4a asserts `data: [DONE]` |
| Failover test: `restore_rate = 0/100` | Pre-70.2 consumer-respawn gap, OR single-host `/sys/fs/bpf` map stomping, OR stale binary | Use a post-70.2 build on a 2-host testbed; `docker cp` your binary |
| `restore_rate` low but non-zero | Health gate rejecting (target EP unhealthy on new master) | Check `loxilb_sockproxy_sync_health_reject_total`; verify EPs reachable from the backup |
| Sessions never replicate to backup | Consumers not spawned on master | Grep for `consumerLoop start peer=`; if absent, you're pre-70.2 |
| Cluster split after upgrade | (Should not happen) | Rolling-upgrade degrades gracefully — check the WARN-once `Unimplemented` log |
| `Killed node …` in logs | Normal end-of-test cleanup | Not an OOM |

Diagnostic checklist for `restore_rate`:
```bash
# 1. consumers running on master?
docker exec llb1 grep -c 'consumerLoop start peer=' /var/log/loxilb/loxilb-stdout.log   # expect ≥1
# 2. binary has code?
strings ./loxilb | grep -c SOCKPROXY_SYNC                                                # expect ≥10
# 3. health-gate rejections?
curl -s http://llb1:11111/metrics | grep loxilb_sockproxy_sync_health_reject_total       # expect low
# 4. EPs reachable from the new master?
docker exec llb2 curl -s http://31.31.31.1:8000/v1/models                                # expect 200
```

---

## 7. Developer pointers

| Area | Location |
|---|---|
| Sockproxy L7 / P/D (C) | `loxilb-ebpf/common/sockproxy_ep.c`, `sockproxy_pd.c`, `sockproxy_http.c` (circuit breaker), `sockproxy.h` (`pd_session_mapping_t`, `conversation_mapping_t`, `proxy_epval_t`, `pd_trie`) |
| HA coordinator (Go) | `pkg/loxinet/sockproxy_sync.go` (drain/batch/push), `xsync.proto` (RPCs + messages) |
| Startup wiring | `pkg/loxinet/loxinet.go` (`NewSockproxySync`, `peersFn`, `Start`), `cluster.go` (`OnStateChange`) |
| Tests | `pkg/loxinet/sockproxy_sync_test.go`; probe `scripts/probe-sockproxy-sync-wiring.sh` |

**Invariants to preserve when extending sync:**

1. **rwlock hierarchy:** `pd_session_lock` (Pri-4) before `pd_trie_lock` (Pri-5).
2. **emit-after-unlock:** release the C mutation lock *before* the CGO emit callback.
3. **health-gated receiver:** never override a locally-healthy EP with a remote-unhealthy one.
4. **per-peer capability mask:** degrade gracefully on gRPC `Unimplemented` (rolling-upgrade safe).
5. **`proxy_fd_ent` is not synced** — anything that must survive failover goes into the wire format
   (`proxy_sync_event_t` / `pd_session_mapping_t` / `conversation_mapping_t`) or must be stateless
   (e.g. cookie-encoded session persistence rather than in-memory state).

To add a new synced state type, follow the proto → C emit → C apply (health-gated) → Go coordinator →
Go RPC → tests + metrics path in [Developer guide §AI/HA recipes](07-developer-guide.md#aiha-extension-recipes).

---

## 8. Shipped vs deferred summary

| Item | Status |
|---|---|
| Fullproxy GA (67) | ✅ Shipped 2026-05-20 |
| P/D harness A–K (68) | ✅ Shipped 2026-05-21 |
| P/D live QA (69) | ✅ Shipped 2026-05-25 (52 PASS / 0 FAIL) |
| xSync proto + coordinator (70-A) | ✅ Shipped |
| Rate-limiter sync (70-B) | ✅ Shipped |
| Phase L HA harness (70-L) | ✅ Shipped |
| Startup wiring (70.1) | ✅ Shipped (exposed consumer gap) |
| Consumer respawn on promotion (70.2) | ✅ Shipped (closes the gap) |
| Failover warmup — KV/metrics snapshot | ⏸ Deferred (needs 2-host testbed) |
| Tier 1.5 ZMQ KV-exact routing | ⏸ Deferred (needs GPU testbed) |
