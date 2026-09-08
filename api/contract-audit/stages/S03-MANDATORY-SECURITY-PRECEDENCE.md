# S03 mandatory API-key security precedence

Run dates: 2026-09-08 through 2026-09-09 KST. Result: PASS for the scoped
API-key admission precedence slice. The user approved the result and authorized
S04 on 2026-09-09.

## Scope and result

S03 verifies and repairs the rule that a declared mandatory data-plane
credential must be evaluated before any AI routing decision. The representative
control is `api_key_auth=required`. The implementation now applies that control
to both HTTP/1.1 and HTTP/2, stores HTTP/2 credentials per stream, fails closed
when the policy store cannot answer, and prevents the gateway credential from
reaching the selected backend.

The investigation found an implementation defect, not merely missing test
coverage. HTTP/1.1 passed through the `llhttp` message-complete security gate,
but HTTP/2 bypassed `llhttp` and entered L7/model/CHWBL/fallback endpoint
selection without capturing or validating `X-Api-Key`. The pre-fix source gate
in `/root/loxilb-ai-multitier-evidence/s03-h2-security-red-02.log` failed on
that exact absence.

## Implementation

- `loxilb-ebpf/common/sockproxy_ai_security.[ch]` provides protocol-neutral
  API-key and request-rate admission, bounded credential capture and HTTP/2
  backend-header filtering.
- `loxilb-ebpf/common/sockproxy_h2.[ch]` captures `X-Api-Key` in per-stream
  state, performs mandatory admission before every selector visible in the
  HTTP/2 dispatch path, returns a stream-local denial and strips the credential
  after optional L7 header mutation but before backend submission. Denial logs
  record only credential presence, never credential bytes.
- `loxilb-ebpf/common/Makefile` and `common.mk` compile and link the helper in
  both standalone and production builds. The missing `common.mk` integration
  was exposed by the first full Docker link and corrected before qualification.
- `loxilb-ebpf/common/test_ai_security.c` covers policy states, unknown wire
  values, 401/403/429/503 mapping, 255/256-byte boundaries and header removal.
- `cicd/ai-multitier-security/` adds the source-order gate and a live TLS/HTTP2
  backend-delivery oracle. The probes are built in the verified unit image when
  the controller has no Go toolchain.
- `cicd/ai-multitier-contract/run-unit.sh` and
  `.github/workflows/auth-plane-sanity.yml` make the security tests, existing
  omission/replace/wire tests and source-order invariant normal CI gates.

## Authoritative environment and identity

All verdict-bearing builds and tests ran on `ssh kv-loxilb-ctl`. Local activity
was limited to editing, formatting and static review. No GPU model endpoint was
contacted during this security slice.

- Base Gateway revision: `f8e6ace22f0f2262d56829e781a83e4b7075fef7`
  plus the archived working-tree patch.
- Remote source tree: `/root/loxilb-ai-multitier-evidence/s03-build-source-01`.
- Unit image:
  `loxilb-inference-gateway:ai-multitier-f8e6ace2-s03r2-unit-u24`, image ID
  `sha256:45597b6d7c83ea8d4a866b3914ef8fd3090d78b963ee2ae49118cdaa3d7dbec2`.
- Runtime image:
  `loxilb-inference-gateway:ai-multitier-f8e6ace2-s03r2-u24`, image ID
  `sha256:b5faa2c9174d5355e793b27be2c0177942e351fa34200aeaa55ef0dc41179021`.
- Gateway binary SHA-256 in both images:
  `f9fb83961cf39b91881eb0278f724c88097afa3c6f7c17c6ac8311bc5e2d90a0`.
- Build method: repository `make docker` on Ubuntu 24.04, with the Dockerfile's
  `test-build` target for the unit rail and the normal runtime target for live
  data-plane tests.
- Identity and source checksums:
  `/root/loxilb-ai-multitier-evidence/s03r2-integrity-01`.

## Evidence and diagnosis

| Evidence | Result | Classification |
|---|---|---|
| `s03-h2-security-red-01.log` | The S02 container did not contain an expanded submodule source tree | HARNESS/SETUP; not product evidence |
| `s03-h2-security-red-02.log` | Pre-fix HTTP/2 source had no per-stream API-key capture | IMPLEMENTATION defect |
| `s03-test-image-build-02.log` | Full link failed with three missing `ai_security_*` symbols | IMPLEMENTATION/BUILD-INTEGRATION defect; `common.mk` omitted the new object |
| `s03-test-image-build-03.log` and `s03-runtime-image-build-01.log` | Corrected unit and runtime Docker images built successfully | GREEN |
| `s03r2-test-image-build-02.log` and `s03r2-runtime-image-build-01.log` | Final credential-safe R2 unit and runtime images built successfully | GREEN |
| `s03r2-regression-unit-01` | Ten gates passed: models, handler, KV admission, security precedence, PD cache/adjacent, KV data plane, Swagger, inventory and harness | GREEN |
| `s03r2-h2-runtime-green-02.log` | 11/11 live TLS/HTTP2 and credential-log-safety checks passed | GREEN |
| `s03-authsep-validation-01.log` | Existing HTTP/1 auth-plane suite passed 96/96 | GREEN/no regression |

The 96-case HTTP/1 suite ran on the pre-R2 S03 package. R2 changed only the
HTTP/2 denial log payload, removing credential bytes; the final R2 package was
then rebuilt and requalified with all ten unit gates and the 11-case HTTP/2
runtime/log-safety gate. The 96-case result is therefore retained as HTTP/1
regression evidence, not represented as a second full run on R2.

Four intermediate HTTP/2 runtime attempts are retained to prevent false-green
history. `green-01` supplied no argument to strict-mode `common.sh`; `green-02`
assumed a host Go toolchain; `green-03` incorrectly expected keyless 401 when
the policy store was unconfigured; and `green-04` reused a stale backend
listener after incomplete cleanup. All four are HARNESS defects. An initial
standalone log-safety probe was also rejected because `tee` masked its failed
presence assertion; the assertion now runs inside the final harness. The first
R2 test-build command omitted the `-unit` tag component; the canonical rebuild
is `s03r2-test-image-build-02.log`. The final harness uses an offline Docker
build helper, process/PID cleanup, the canonical REST deletion paths, a fresh
backend port and a backend request counter.

The final HTTP/2 control returned HTTP/2 200, incremented the backend counter by
exactly one and showed `api_key=false` upstream. Both required-policy requests
returned HTTP/2 503 with the policy store intentionally unconfigured, and the
backend counter remained unchanged. Known test credential bytes had zero log
matches while two presence-only denial records made the check non-vacuous. The
503 is the established contract: with no policy store the gateway cannot make
a credential verdict, including for an absent credential. In the
configured-store HTTP/1 matrix, keyless, unknown and expired keys returned 401,
model denial returned 403, RPS exhaustion returned 429, store outage returned
503, and denied requests did not reach the backend.

## Coverage ledger impact

`api_key_auth` admission, default/update semantics and propagation move to
VERIFIED. Behavior and failure move to PARTIAL because important HTTP/2 and
tier-combination runtime cells remain open. Restore remains GAP. The complete
750-dimension ledger is now:

| State | Dimensions |
|---|---:|
| VERIFIED | 11 |
| PARTIAL | 12 |
| GAP | 727 |
| NOT_APPLICABLE | 0 |

This count is coverage accounting, not a product-wide readiness percentage.

## Explicit remaining security work

S03 does not claim complete security parity or multi-tier qualification:

- Live HTTP/2 with a configured store still needs valid, missing, invalid,
  expired, model-denied and RPS-limited cells, including backend delta checks.
- Credential ownership has an unresolved cross-field contract. Swagger says an
  omitted `api_key_auth` leaves a backend-owned `X-Api-Key` untouched and says
  authentication is independent of `sse_mode` and `pd_disagg_mode`. The current
  HTTP/1 and HTTP/2 filters instead remove the header whenever the derived
  `ai_gw_mode` is active, including omitted-policy SSE or P/D services. S03's
  required-policy assertions remain valid, but S04 must choose one ownership
  rule, align implementation and Swagger, and add the omitted/disabled/required
  cross-product tests before claiming general header behavior.
- HTTP/2 denials currently use a headers-only synthetic response. Structured
  error bodies and `Retry-After` parity with HTTP/1 require a contract and tests.
- HTTP/2 does not yet have the HTTP/1 token reservation/settlement path. This is
  a capacity-policy implementation GAP and must be closed before protocol parity
  is claimed.
- SEC-05 still requires mandatory rejection combined with actual Tier 0, Tier 1,
  Tier 1.5, Tier 2 and applicable CHWBL/fallback hits. These cases must later be
  repeated on the three registered representative model tuples where applicable.
- Other mandatory controls identified by the Swagger audit, including frontend
  client-certificate enforcement, backend certificate verification and AI
  inspection fail-closed behavior, remain separate security slices.
- Restore/replay and concurrent policy transition semantics were not run in S03.

## Testbed cleanup

The HTTP/2 topology, the auth-plane topology, both disposable PostgreSQL
containers, test namespaces and temporary probe binaries were removed. The
final active-container inventory matches the pre-run inventory: only the four
pre-existing `loxilb-mon-p6` monitoring containers remain active. Before
removing superseded S03 images, root free space was 9.3 GiB. The exact old S03
unit/runtime tags were then removed, leaving the final R2 images and 9.8 GiB
free; those old images require a rebuild to recover. No model cache, GPU service,
persistent volume, build cache or pre-existing container was removed. Cleanup
evidence is in `s03r2-disk-cleanup-01`.

No production deployment was performed. Git commit, push and pull-request
delivery are repository workflow records and do not change the runtime evidence
above.
