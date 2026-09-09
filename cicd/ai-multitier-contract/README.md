# Multi-tier argument regression

This suite is being implemented on `codex/ai-multitier-cicd`. A passing image
build is a prerequisite, not evidence of routing correctness.

## Build and test convention

Run on the Linux testbed controller using the repository's `make docker`
target. On Ubuntu 24.04 it selects `Dockerfile.u24` and appends `-u24` to
`TAG`. Use a campaign-specific `IMAGE`/`TAG` and resolve the resulting image
ID before deploying any scenario. The Dockerfile builds the Gateway, eBPF
objects, vendored libbpf and tokenizers in one environment, with HTTP trace,
L4 trace and mTLS enabled.

The final runtime image removes the source and build tools. Unit tests
therefore need a retained pre-cleanup build stage; running `go test` in the
runtime image is not a valid unit gate. Never overlay a host-built binary
onto a different Ubuntu runtime: the existing private QoS harness documents
a glibc 2.39/2.35 mismatch from that approach.

On the Ubuntu 24.04 controller, from an isolated source directory:

```bash
make docker IMAGE=loxilb-inference-gateway TAG=ai-multitier-REV-unit \
  VERSION=dev-REV DOCKER_BUILD_FLAGS='--network host --target test-build'
bash cicd/ai-multitier-contract/run-unit.sh \
  loxilb-inference-gateway:ai-multitier-REV-unit-u24 /absolute/new-run-directory
make docker IMAGE=loxilb-inference-gateway TAG=ai-multitier-REV \
  VERSION=dev-REV DOCKER_BUILD_FLAGS='--network host'
```

Replace `REV` with the source revision; include a dirty-source identifier
when appropriate and archive the diff. `run-unit.sh` does not deploy a
Gateway. It runs Go and C tests without host networking or privileged mode,
records every gate's exit code and leaves failed logs for triage. A nonzero
exit is not automatically classified as an implementation defect. Inspect
the assertion, compiler output and prerequisites first. For before-fix
proof, `TEST_SOURCE_DIR` may inject only the two new regression test files
into an old test-build image; their checksums are recorded explicitly.
The `api-handler` gate separately proves that typed rule-argument refusals
become HTTP 400 without adding broad message-text matches that could disclose
unclassified internal errors.

After packaging, exercise the actual runtime image's HTTP admission:

```bash
bash cicd/ai-multitier-contract/run-admission.sh \
  loxilb-inference-gateway:ai-multitier-REV-u24 /absolute/new-http-run
```

This uses `--proxyonlymode`, a private `--network none` namespace, no host
mounts, and NET_ADMIN without privileged mode. Its 51 cases include 19
positive controls and 32 rejections across numeric/role bounds, reserved mode,
engine/rank scope, fixed C-string byte limits and embedded NUL. A negative case
requires HTTP 400/422,
the relevant reason and unchanged full rule readback (top-level rule order
is normalized because GET enumerates a Go map; no fields are discarded).
The suite removes its own container after
saving logs. This proves REST admission only, not eBPF forwarding or live
GPU/model qualification.

TTL controls cover omitted/zero declarations, positive overrides and the int32
maximum; negative and overflow inputs must be rejected. Readback may omit zero
but must preserve positive values. It reports the declaration, not an effective
TTL status field (none is added by this change).

Test the harness oracle independently before trusting its product verdicts:

```bash
python3 -B -m unittest discover -s cicd/ai-multitier-contract -p 'test_*.py' -v
```

These controls require wrong error reasons, mutation despite rejection,
missing installation, wrong listeners/endpoints and server errors to fail.
They prove the oracle, not Gateway behavior. HTTP artifacts record the
harness hashes and the runtime binary hash so the packaged binary can be
compared with `run-unit.sh`'s prerequisite manifest.

The selected KV unit gate is intentionally not the full `pkg/loxinet` gate.
The existing `TestMain(t *testing.T)` invokes `loxiNetInit()` and mounts
bpffs; it cannot run in the unprivileged unit container. Preserve such an
attempt as a failed environment prerequisite, not a passing full-package
run. Qualify that integration test separately with its required network
and mount isolation. Likewise, preserve existing `t.Skip` results when
reporting broader handler test runs.

## Initial regressions

| Argument | Invalid input | Required behavior | Why it matters |
| --- | --- | --- | --- |
| `pd_balance_abs_threshold` | 256 | reject above uint8 range | formerly became 0, then default 3 |
| `kvBlockSize` | 4294967296 | reject above uint32 range | formerly became 0, altering hash geometry |
| `kvWarmupSec` | 4294967296 | reject above uint32 range | formerly became 0, bypassing configured warmup |
| `ep_role` | -1, 3 | accept only 0/1/2 | invalid roles have no valid P/D interpretation |
| `nixl_port` | -1, 65536 | accept only 0..65535 | narrowing changed the configured port |
| `kvExactMode` | 2 on vLLM/SGLang | reject reserved mode before dependencies | valid dependencies previously admitted a mode with no subscriber |
| `kvDpRankCount` | 2/8 on non-SGLang engines | reject unsupported fan-out | default/vLLM previously accepted SGLang-only rank topology |
| `host`, `path_prefix` | more than 255 UTF-8 bytes or embedded NUL | reject before rule mutation | each data-plane field is 256 bytes including its terminator |
| `session_header_name`, `model_name` | more than 127 UTF-8 bytes or embedded NUL | reject before rule mutation | each data-plane field is 128 bytes including its terminator |

The fixed-string limits are encoded as `x-loxilb-max-utf8-bytes` because
Swagger 2.0 `maxLength` counts Unicode code points rather than encoded bytes.
The server remains the security boundary; UI clients may use the extension for
early validation but must not substitute character count for UTF-8 byte count.
The encoded `host|path_prefix|model_name` routing key is separately limited to
511 bytes including its conditional separators, preventing silent truncation in
the 512-byte sockproxy lookup buffer.

Representable numeric controls test transport bounds; they do not qualify
an arbitrary block size against a real engine. Actual `kvBlockSize` must
still match the model/engine geometry.

The larger argument campaign remains open: CHWBL five-field wiring and
behavior, omitted versus explicit zero/defaults, real engine/rank event
behavior, Tier 0/1/1.5/2 interactions, three-model qualification, failure,
restore and HA tests. These initial gates must not be reported as complete
multi-tier or production readiness coverage.

Existing deployment adapters use different image variables:

| Adapter | Image input |
| --- | --- |
| testbed-recovery vLLM deployment | `LOXILB_IMAGE` |
| private-gpu-sglang / private-gpu-trtllm | `GATEWAY_IMAGE` |
| private-gpu-qos | `GW_IMG` |

Inspect the exact script before execution. Historical defaults reference
older engines and profile-less rules; copying an old invocation does not
establish that it targets the current model/profile contract.

## Evidence requirements

Record source and submodule revisions, dirty diff, build command and exit
status, image ID, runtime binary checksum, engine/model/profile identities,
request/response and routing receipts. Record a failure's observed boundary
before assigning its cause: setup/build failures alone do not prove an
implementation defect. Reserved-mode admission, CHWBL argument forwarding,
numeric narrowing and omitted-versus-zero semantics require dedicated
regressions and before/after proof.

The representative model set is Qwen2.5-7B-Instruct, Llama-3.1-8B-Instruct and
EXAONE-3.5-7.8B-Instruct. Resolve their registered profile IDs and pinned
artifacts from the target controller for each run. Registration alone is not
proof that an engine currently serves that model or that every API surface
is supported.

Keep run artifacts outside the Docker build context. Preserve active
testbed images, all three model caches and baseline recovery data when
handling disk pressure.

## Frozen source and inventory gates

### Original embedded Swagger contract

The pinned go-swagger 0.30.3 generator loses zero-valued minima in its original
document representation. `api/build_api.sh` now runs the source-preserving
`api/cmd/sync-swagger` postprocessor; direct generator invocations must also run
it. This replaces only the original SwaggerJSON expression. It does not modify
FlatSwaggerJSON, generated model validators or the `/meta` projection.

```bash
go test ./api/cmd/sync-swagger
go run ./api/cmd/sync-swagger -check
python3 -B -m unittest discover -s cicd/ai-multitier-contract -p test_swagger_generation.py -v
```

`run-swagger-contract.sh` is the isolated S01 rail: it takes a pinned existing
test-build image, frozen source, pre-fix embedded file and a new absolute evidence
directory. It performs real pinned-generator RED/repair checks plus independent
semantic and harness-negative controls without deploying a Gateway. Its before
and raw-generator gates intentionally return 1; they must carry the expected
drift reason, and the semantic oracle must additionally prove identified missing
zero minima and unchanged nonempty flattened content. See `api/contract-audit/stages/`.

The general unit runner includes the Swagger gate for current full source images.
Baseline test overlays explicitly report all omitted gates as NOT_RUN; they are
not full-source or S01 qualification. Argument-inventory drift remains a separate
gate and must be reconciled rather than hidden by this fix.

### Source transfer

Never start `make docker` while the source transfer is still running. Export a
fixed worktree snapshot, transfer its complete bundle, verify `SHA256SUMS`, and
extract into a new controller directory before building:

```bash
bash cicd/ai-multitier-contract/export-source.sh /absolute/new-source-bundle
```

The archive includes current tracked source, initialized submodules and
non-ignored new files. It excludes ignored private evidence. Submodule
untracked files must be reviewed and staged first. Do not edit the extracted
build source while either image stage is running. Compiler/toolchain layers
precede source COPY and VERSION so later source revisions do not reinstall
the toolchain merely because the release identifier changes.

`argument-inventory.json` captures 125 schema entries, including container
nodes, from `LoadbalanceEntry` and the extras spec's KV-inventory queries.
It preserves defaults (including zero/false), constraints, descriptions,
required flags and both source checksums. This is not 125 proven AI arguments
and does not inventory every unrelated API or process environment variable.

```bash
go test ./cicd/ai-multitier-contract/inventory
go run ./cicd/ai-multitier-contract/inventory \
  -check cicd/ai-multitier-contract/argument-inventory.json
python3 -B cicd/ai-multitier-contract/coverage.py \
  cicd/ai-multitier-contract/argument-inventory.json \
  cicd/ai-multitier-contract/coverage-ledger.json --release
```

The inventory check fails on drift. Review changes and affected tests before
regenerating with `-output`; do not regenerate merely to silence RED. The
ledger requires every entry exactly once and separately tracks admission,
defaults, propagation, behavior, failure and restore. GAP means not assessed
or not proved; it does not mean the product has no existing test. PARTIAL
never counts as complete. The release option deliberately remains nonzero
while any GAP/PARTIAL remains. Ledger integrity alone cannot certify runtime
readiness; evidence references still require review.

## Rank argument usage

For SGLang only, `kvDpRankCount=N` declares contiguous KV-event publisher ports
`kvZmqPort` through `kvZmqPort+N-1`, with inventory union per endpoint. Use 1..8
and match actual serving rank count and publisher configuration. Omitted/zero
internal values resolve to one rank; non-SGLang engines accept only this
single-rank/default declaration. For example, base 65528 and count 8 reach
65535; base 65529 and count 8 must be rejected before subscription. A plain-LB
readback control proves declaration handling, not live multi-rank inventory.

## Tier-0 TTL argument usage

Omitted/`pd_session_ttl_sec=0` selects the Gateway default of 300 seconds in both
lookup and periodic eviction. A positive value overrides it for the service.
There is no no-expiry mode. This Tier-0 P/D affinity policy applies independently
of `pd_cache_aware_mode`, and does not control engine KV retention, transfer
timeouts, or active requests. Lookup/store refresh the sliding idle timestamp;
expiry occurs when idle time exceeds the effective TTL. The 4096-entry LRU bound
and endpoint-health checks remain in force. The C tests use a controlled clock
for exact boundary checks without sleeping, alongside refresh and capacity tests.
HTTP readback alone cannot prove TTL
expiration behavior. Source-level C/ASan proof and packaged-image/GPU proof
must be reported separately for the exact image under test.
