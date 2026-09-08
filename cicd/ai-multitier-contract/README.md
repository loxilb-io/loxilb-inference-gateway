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

After packaging, exercise the actual runtime image's HTTP admission:

```bash
bash cicd/ai-multitier-contract/run-admission.sh \
  loxilb-inference-gateway:ai-multitier-REV-u24 /absolute/new-http-run
```

This uses `--proxyonlymode`, a private `--network none` namespace, no host
mounts, and NET_ADMIN without privileged mode. It creates one positive
control, then tests seven numeric/role rejections and two reserved-mode
rejections. A negative case requires HTTP 400/422, the relevant reason and
unchanged full rule readback. The suite removes its own container after
saving logs. This proves REST admission only, not eBPF forwarding or live
GPU/model qualification.

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

Representable numeric controls test transport bounds; they do not qualify
an arbitrary block size against a real engine. Actual `kvBlockSize` must
still match the model/engine geometry.

The larger argument campaign remains open: CHWBL five-field wiring and
behavior, omitted versus explicit zero/defaults, engine-specific rank
scope, Tier 0/1/1.5/2 interactions, three-model qualification, failure,
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
