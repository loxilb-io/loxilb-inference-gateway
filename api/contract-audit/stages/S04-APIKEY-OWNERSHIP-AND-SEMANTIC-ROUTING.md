# S04 API-key ownership and semantic-routing qualification

Run date: 2026-09-09 KST. Result: PASS for the scoped credential-namespace,
MCP create/observe, and mock semantic-routing slice. The result is awaiting
explicit approval; it does not authorize a later stage.

## Contract decision

`api_key_auth` alone owns the Gateway data-plane credential namespace:

| API state | Admission | Backend `X-Api-Key` |
|---|---|---|
| omitted | No Gateway API-key decision | Preserved byte-for-byte for a backend-owned contract |
| `disabled` | No Gateway API-key decision | Stripped because the Gateway namespace was explicitly declared |
| `required` | Gateway policy decision is mandatory | Stripped after capture; a denial never reaches the backend |

This rule is independent of `sse_mode`, `pd_disagg_mode`, and
`pd_cache_aware_mode`. Those flags may activate AI accounting, streaming, or
routing behavior, but they do not claim ownership of `X-Api-Key`.

## Implementation

- `pkg/loxinet/rules.go` now has one explicit namespace predicate. The API wire
  value remains `0` for omission, `1` for `required`, and `2` for explicitly
  `disabled`; the derived `ai_gw_mode` remains an accounting/routing marker.
- `loxilb-ebpf/common/sockproxy_ai_security.[ch]` provides the shared policy-only
  header-ownership predicate. HTTP/1.1 and HTTP/2 call the same predicate.
- `loxilb-ebpf/common/sockproxy_http.c` no longer strips a backend credential
  merely because SSE or P/D is enabled.
- `loxilb-ebpf/common/sockproxy_h2.c` no longer allocates or applies the API-key
  header filter from `ai_gw_mode`; only a declared API-key policy triggers it.
- Unit and runtime tests cover the 12 policy/feature shapes formed by three
  policy states and plain, SSE, P/D, or combined SSE+P/D service modes. The live
  HTTP/2 oracle specifically proves the formerly failing omitted+SSE case.
- MCP `lb_create` now exposes typed AI routing, P/D, KV, endpoint-role, and
  credential-policy arguments. `lb_list` reports the corresponding routing and
  ownership fields. The existing `service_extra` escape hatch remains for
  fields that are not yet typed and rejects conflicts with typed arguments.

## Authoritative environment and artifact identity

All verdict-bearing builds and runtime tests ran on an isolated Ubuntu 24.04
Linux 6.8 controller. The repository `make docker` workflow built the runtime
image. A Dockerfile `test-build` image provided the unit rail.

- Executable-source base: Gateway `bddade8387267129f64e2168d1f874586112644e`
  plus the S04 patch; eBPF PR head
  `19632172e300294d0805aec19f68c7115f6f8342` plus the S04 patch.
- The later Gateway PR head `98a131c3935dbca937e30d2b0c874536907590ff`
  changes only audit-document evidence paths and the ledger's evidence strings.
  It was fast-forwarded before delivery; executable inputs are unchanged.
- Isolated source tree: `/tmp/loxilb-s04.nyKFXY`.
- Evidence directory:
  `/root/loxilb-ai-multitier-evidence/s04-apikey-ownership-20260909`.
- Runtime image: `loxilb-inference-gateway:ai-multitier-s04-u24`, image ID
  `sha256:4fb712deb51ab84f465f5d8a68dc7d4dee6e3aedfce6a15a5902f23f19c8eb19`.
- Unit image: `loxilb-inference-gateway:ai-multitier-s04-unit-u24`, image ID
  `sha256:049d5823d5706a7105052d521bec2f0f63b66c17f9c73898cab3f4cecc8b3bae`.
- Gateway binary SHA-256:
  `206a198a66d9cfb5183a5a50fb427f798eeae315bdef39262723a86006772a15`; see
  `image-identity.log` for the final binary and four socket-object checksums.

## Verification results

| Rail | Result | Evidence |
|---|---|---|
| Source-order and ownership invariant | PASS | `check_security_order.py`; H1/H2 use the policy predicate and no longer use `ai_gw_mode` for credential filtering |
| Linux unit rail | PASS | `unit-tests.log`: `pkg/loxinet`, all MCP packages, and `test_aisec` |
| HTTP/1 credential semantics | PASS | `h1-validation.log`: required and disabled strip; omitted+SSE preserves; denied requests have zero backend delivery |
| HTTP/1 cross-product | PASS | `h1-tiers.log`: 12 policy/feature rules and the broader Tiers A-E suite, 171 passed and zero failed |
| HTTP/2 backend oracle | PASS | `h2-runtime.log`: 15/15; omitted+SSE preserves, disabled+SSE strips, required/store-unavailable fails closed with zero backend delta |
| Multi-tier and two-tier semantic routing | PASS | `semantic-validation.log`: 36/36 on one live Gateway, with a vLLM P/D rule and an SGLang single-pool rule |
| MCP typed create/observe | PASS | `mcp-validation.log`: typed AI creation, observation of `host` and `api_key_auth`, full-key deletion, and the existing traffic/guardrail/RCA checks |
| Script and diff checks | PASS | `bash -n`, ShellCheck error level, Python invariant check, parent and submodule `git diff --check` |

The semantic-routing rail uses contract-faithful mock KV publishers and HTTP
backends. It proves service isolation, engine-specific hashes, P/D role
partitioning, Tier-1.5 hits, Tier-2 fallback, reconnect/gap handling, cold seeding,
and engine immutability in the built Gateway. It is not a real-model latency,
quality, GPU, NIXL, or engine-version qualification.

## Defect classification and retained false-green history

### Implementation defects closed

- HTTP/1 and HTTP/2 incorrectly treated derived `ai_gw_mode` as ownership of
  `X-Api-Key`. An omitted policy therefore stripped a backend-owned credential
  on SSE and P/D services. Both protocol paths now use only the declared policy.
- MCP could create advanced AI rules only through untyped `service_extra`, and
  its observation output omitted the fields needed to verify P/D, KV, endpoint
  role, and API-key ownership. Typed creation and observation are now covered.

### Harness or environment defects corrected

- Initial remote unit attempts lacked the recursive libbpf checkout or network
  access for Go dependencies. The final unit image includes the recursive
  submodule and used the controller's available build network.
- The normal `make docker` attempt encountered container DNS timeouts while
  resolving GoBGP. The successful build used the same repository workflow with
  Docker host networking; the failed logs remain as `make-docker*.log`.
- The first semantic run changed `kvEngineType` to vLLM while retaining three
  SGLang ranks. Generic rank validation correctly rejected that request before
  the intended immutability branch. L5 now uses rank 1 and reaches the exact
  engine-immutability conflict; the failed run is retained as
  `semantic-validation-run1.log`.
- One HTTP/2 invocation omitted the unit image's `-u24` tag. It did not reach a
  product assertion and is retained as an invocation error.
- The controller has no host Go toolchain. MCP validation now accepts an
  explicitly prebuilt bridge; the bridge was built from the tested source in
  the final unit image.
- The first MCP extension mixed a typed full-proxy rule with the historical raw
  TCP traffic/delete check, omitting the full host rule key during deletion.
  The final harness keeps the existing L4 traffic round trip and separately
  creates, observes, and deletes the AI rule by its complete host-aware key.

## Coverage-ledger impact

The `api_key_auth` evidence now includes the S04 12-shape truth table, live H1
and H2 backend-header oracles, and MCP create/observe coverage. Its states remain
VERIFIED for admission/defaults/propagation, PARTIAL for behavior/failure, and
GAP for restore. Therefore the complete ledger count remains:

| State | Dimensions |
|---|---:|
| VERIFIED | 11 |
| PARTIAL | 12 |
| GAP | 727 |
| NOT_APPLICABLE | 0 |

The count is evidence accounting, not a product-readiness percentage.

## Explicit limits and later work

- HTTP/2 with a configured policy store still needs valid, missing, invalid,
  expired, model-denied, and RPS-limited live cells. HTTP/2 structured error-body,
  `Retry-After`, and token reservation/settlement parity also remain open.
- Restore/replay, HA propagation, and concurrent policy-transition semantics are
  not qualified by S04.
- The cross-product's P/D admission rows are recorded against mock backends;
  the engine matrix owns detailed P/D mechanics. Real registered model tuples
  remain a later, separately approved GPU qualification.
- No registered GPU model profile or service was changed. No production
  deployment was performed.

## Cleanup

All S04 namespaces, PostgreSQL test containers, publishers, backends, MCP
processes, and disposable topology containers were removed. The final active
inventory contains only the four pre-existing monitoring containers. No model
cache, registered model profile, persistent volume, or pre-existing container
was removed. The controller had 3.8 GiB free after runtime testing; one
superseded untagged S04 image created by this run was removed to recover space.
