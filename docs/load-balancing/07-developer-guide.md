# Developer Guide — Extending L4 / L7 / TLS / AI Load Balancing

> For control-plane (Go) and data-plane (C/eBPF + sockproxy) developers.
> Code map, build & test workflow, and concrete extension recipes for each feature area.
>
> Use **Serena (gopls-backed) or codegraph** for navigation — see the repo `CLAUDE.md`. The file:line
> pointers here are entry points, not exhaustive.

---

## 1. Architecture in one picture

```
                REST (api/)                       Control plane (pkg/loxinet/)            Data plane
  client ──► swagger handlers ──► models ──► rule engine (rules.go) ──► CGO ──► eBPF (L4)  +  sockproxy (L7, C)
            loadbalancer.go      common/    AddLbRule / LB2DP        dpebpf_   kernel/      loxilb-ebpf/common/
            l7policy.go          common.go  reconcile / drain        linux.go               sockproxy_*.c
            cert.go                         GetLBRuleBy*                                     (userspace fullproxy)
```

- **L4 features (72–74)** live in the Go control plane + the eBPF L4 dataplane. No sockproxy.
- **L7 + TLS + AI features (75–77, 67–70)** live in the Go control plane (config/REST) + the
  **userspace sockproxy** (C, in `loxilb-ebpf/common/`). The sockproxy engages only for fullproxy
  rules (`mode=4`).

---

## 2. Code map

### Go control plane (`pkg/loxinet/`)
| File | Responsibility |
|---|---|
| `rules.go` | LB rule engine: `AddLbRule`, `reconcileLBEndpointsAtomic`, `applyAdminStateUpDrain`, `GetLBRuleByOpaqueID`, `GetLBRuleByServArgs`, `LB2DP`; health probes incl. `tlsHelloProbe`, `httpsContentProbe` |
| `qospol.go` | policer; `PolAssociateLbRule` |
| `dpebpf_linux.go` | CGO bridge: `DpProxyAttachL7Policy`/`DpProxyDetachL7Policy`, TLS scalar threading (`alpnToBackendCap`, `tlsVersionsToRange`) |
| `sockproxy_sync.go` | HA coordinator: drain/batch/push of sockproxy state |
| `loxinet.go`, `cluster.go` | Coordinator wiring (`NewSockproxySync`, `peersFn`, `Start`, `OnStateChange`) |
| `xsync.proto` | gRPC sync service + messages |

### REST (`api/`)
| File | Responsibility |
|---|---|
| `swagger.yml` | OpenAPI source of truth (regenerate with `build_api.sh`) |
| `restapi/handler/loadbalancer.go` | GET-all/by-key/by-id/status/stats, `serializeLBRule`, `deriveOperatingStatus` |
| `restapi/handler/loadbalancer_octavia_patch.go` | `PATCH` merge-patch |
| `restapi/handler/l7policy.go` | L7 policy CRUD + validation |
| `restapi/handler/cert.go` | certId registry CRUD |
| `restapi/handler/*_test.go` | handler unit tests |

### C data plane (`loxilb-ebpf/common/`)
| File | Responsibility |
|---|---|
| `sockproxy_l7policy.{c,h}` | L7 IR, `l7_policy_evaluate`, `l7_route_dispatch`, HSTS synth |
| `sockproxy_ep.c` | H1 dispatch seam; conversation cleanup |
| `sockproxy_http.c` | H1 parse/inject; circuit breaker |
| `sockproxy_h2.c` | H2 dispatch + nghttp2 emitters (`proxy_h2_send_l7_synthetic`, `proxy_h2_inject_resp_headers`, `proxy_h2_build_l7_req_headers`) |
| `sockproxy_ssl.{c,h}` | ALPN, version/cipher pinning, certId registry |
| `sockproxy_mtls.c` | client-cert verify, CRL, SAN/CN matching, backend cert resolution |
| `sockproxy_pd.c` | P/D session mapping, cache-aware trie |
| `sockproxy.h` | `proxy_arg`, `proxy_fd_ent`, `proxy_epval_t`, P/D & conversation structs |

---

## 3. Build & test workflow

C/eBPF/CGO **cannot build on macOS** — these packages build against the eBPF dataplane, so run the
build and tests on a Linux testbed.

```bash
# Full build (Go + eBPF + CGO) on the testbed
make clean && make

# Go unit tests (scoped)
go test ./pkg/loxinet/... -run 'TLSHello|ProbeVerify|Octavia'
go test ./api/restapi/handler/... -run 'Cert|L7|Patch|Stats'

# C unit tests
make test_pd

# End-to-end scenarios — run under cicd/ on a Linux + Docker host
#   (config.sh → validation.sh → rmconfig.sh)

# Docker image (for HA/multi-node scenarios)
make docker-u24
```

**Regenerate REST artifacts after a `swagger.yml` change:**
```bash
cd api && ./build_api.sh   # regenerates operations/ + models/ + embedded_spec.go
```
Commit the regenerated `embedded_spec.go` and `models/` at merge so the tree stays self-consistent
(hygiene; left it as a known non-blocking warning).

**Lint:** `golangci-lint run --enable-all` (or `make lint`).

---

## 4. Cross-cutting invariants (do not break these)

1. **L7 gating.** Every new sockproxy data-plane seam must be gated like
   `if (node && node->has_l7_policy) { ... }`. The AI/vLLM path (`has_l7_policy==0`) and plain L4 must
   stay byte-for-byte unchanged. This is the entire basis of the 66–70 no-regression guarantee.
2. **H1/H2 parity.** The policy engine runs at two seams (`sockproxy_ep.c` for H1, `sockproxy_h2.c`
   for H2). Any new match field, action, or header behavior must be implemented/verified on **both**,
   and every CICD assert runs on `--http1.1` and `--http2-prior-knowledge`.
3. **No raw bytes on H2.** All H2 output goes through nghttp2 (`proxy_h2_*`). Raw `HTTP/1.1\r\n`
   corrupts the connection.
4. **`proxy_arg` budget.** `sizeof(struct proxy_arg) <= 4096` is a link-time `_Static_assert`. Prefer
   short certId references over inline path buffers (reclaimed 768 bytes that way).
5. **`proxy_fd_ent` is not HA-synced.** State that must survive failover goes into the xSync wire
   format, or must be stateless (the cookie design). Don't put failover-critical bindings on
   `proxy_fd_ent`.
6. **HA lock & emit discipline.** rwlock hierarchy `pd_session_lock` (Pri-4) before `pd_trie_lock`
   (Pri-5); release the C mutation lock **before** the CGO emit callback; the receiver is
   health-gated.
7. **Additive API.** New L4/L7 data-model fields are optional/default-off; pointer types distinguish
   absent from explicit-false.

---

## 5. Extension recipes

### L4 extension recipes

**Add a mutable `serviceArguments` field:**
1. Field on `LbServiceArg` (`common/common.go`) with `omitempty`.
2. Add to `serviceArguments` in `api/swagger.yml`; regenerate (`build_api.sh`).
3. Add to the mutable list in `loadbalancer_octavia_patch.go` (presence-detection pattern).
4. Assign in `rules.go:AddLbRule` (new-rule path + presence-aware carry on the existing path).
5. Emit it in `serializeLBRule`.
6. Tests in `loadbalancer_octavia_patch_test.go`.

**Add an immutable field:** same as above but add to the immutable-reject block (returns `400`).

**Add an endpoint field:** field on `LbEndPointArg` + swagger `endpoints` items + thread through
`ruleLBEp` and the reconcile path + serializer + tests.

**Add a statistic:** field on `LoadbalanceStats` (swagger) + the stats struct + populate from the
conntrack walk in `rules.go` + emit in `ConfigGetLoadbalancerStats`.

### L7 extension recipes

**Add a match field:**
1. Add the enumerator to `l7_field_t` (`sockproxy_l7policy.h`).
2. Implement operand resolution in `l7_resolve_operand` (`sockproxy_l7policy.c`).
3. Reuse or add an op in `l7_op_matches`.
4. REST model (`common/common.go` + `swagger.yml`) + validation in `l7policy.go`.
5. Regenerate swagger; test on H1 **and** H2.

**Add an action:**
1. Add the variant to `l7_action_t` (`sockproxy_l7policy.h`).
2. Implement the executor; integrate in `l7_route_dispatch`.
3. If it emits a response, use `proxy_h2_send_l7_synthetic` on H2 (nghttp2), the CRLF-safe splice on H1.
4. REST model + validation + regen + dual-protocol test.

> Keep nghttp2 out of `sockproxy_l7policy.c` — declare the emitter in the header, define it in
> `sockproxy_h2.c`.

### TLS extension recipes

- **New cipher option:** `tls_ciphers` is already an opaque pass-through to
  `SSL_CTX_set_cipher_list`/`set_ciphersuites` — no code change; add a CICD assert.
- **Per-pool backend SSL_CTX cache:** build a cache keyed by `(pool_id, certId)` at route-attach time;
  thread per-pool certId refs from the pool config into `l7_route_t`/`proxy_arg`.
- **Hot listener TLS update:** re-apply `proxy_apply_tls_version_cipher` on rule update (already done at
  attach); test a live `PUT` of `tls_versions`.

### AI/HA extension recipes

To add a new synced state type, follow the full chain:
1. **Proto:** message + (if needed) RPC in `xsync.proto`.
2. **C emit:** call the emit helper *after unlock* in the relevant `sockproxy_*.c`.
3. **C apply:** new `proxy_sync_apply_*` handler with a **health gate**.
4. **Go coordinator:** new apply branch + conflict resolution (`created_ts` first-writer-wins) in
   `sockproxy_sync.go`.
5. **Go RPC:** server + client handlers; respect the per-peer capability mask (graceful
   `Unimplemented`).
6. **Tests + metrics:** unit tests (`sockproxy_sync_test.go`) + Prometheus counters (overflow,
   conflict, restore, health-reject).

Validate wiring end-to-end with `scripts/probe-sockproxy-sync-wiring.sh` (expect
`consumerLoop start peer=` within ~10s of MASTER promotion).

---

## 6. Test & scenario coverage

The **L4/L7 lifecycle, data-model, content-routing, and TLS** behaviors (feature areas 72–77) are
covered by unit tests in `api/restapi/handler/` — run them on a Linux testbed with:

```bash
go test ./api/restapi/handler/...
```

The **runnable end-to-end scenarios** in this repo live under `cicd/` and drive real proxy/AI paths
on a Linux + Docker host (each scenario is `config.sh` → `validation.sh` → `rmconfig.sh`). The AI /
proxy scenarios include:

| Scenario | Feature area |
|---|---|
| `vllm-fullproxy` (+ `-wrr`) | AI fullproxy (67) |
| `vllm-httpproxy` (+ `-wrr`) | AI HTTP proxy |
| `vllm-pd-disagg` | AI P/D + HA (68–70) |
| `vllm-kvcache-routing-cpu` | AI KV-cache routing |
| `mcp-fullproxy`, `mcp-httpproxy` | MCP proxy |

---

## 7. Where the history lives

Decision logs, research, verification reports, and per-plan summaries for every feature are in
. When a behavior here surprises you, the `*-DISCUSSION-LOG.md`,
`*-LEARNINGS.md`, and `*-VERIFICATION.md` files usually explain *why*. This guide is the production
contract; those are the provenance.
