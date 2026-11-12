# Build and run from source

This repository builds differently from upstream loxilb in three ways: the
[`loxilb-ebpf`](../loxilb-ebpf) dataplane is a **git submodule** (clone with
`--recurse-submodules`), missing swagger API models are regenerated via Docker,
and the repo ships extra Dockerfiles for the optional AI components.

## Prerequisites

Linux only (macOS cannot build the eBPF/CGO parts). Use the Go compiler pinned in
[`build/go-dependencies.json`](../build/go-dependencies.json), Docker with access
for the invoking user, and the eBPF toolchain:

```bash
sudo apt-get install -y clang llvm libelf-dev gcc-multilib libpcap-dev \
  linux-tools-$(uname -r) elfutils dwarves git libbsd-dev bridge-utils unzip \
  build-essential bison flex iproute2 libjson-c-dev libnghttp2-dev
```

The KV-cache router links against the prebuilt
[daulet/tokenizers](https://github.com/daulet/tokenizers) static library:

```bash
arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/)
wget -q https://github.com/daulet/tokenizers/releases/download/v1.27.0/libtokenizers.linux-${arch}.tar.gz
sudo tar -xzf libtokenizers.linux-${arch}.tar.gz -C /usr/local/lib/
```

## Build the gateway binary

```bash
git clone --recurse-submodules https://github.com/loxilb-io/loxilb-inference-gateway.git
cd loxilb-inference-gateway
make build          # eBPF dataplane (submodule) + swagger models (first run, via Docker) + Go control plane
```

`make build` runs three stages: `subsys` (compiles `loxilb-ebpf`), `api-models` (regenerates
`api/models`/`api/restapi` from `api/swagger.yml` with dockerized go-swagger 0.30.3 — only
when missing), then `go build` → the `./loxilb` binary.

### Full inference-gateway feature build

> ℹ️ The root Go module deliberately keeps the upstream module path
> (`github.com/loxilb-io/loxilb`) so upstream merges stay clean — it is **not**
> `go install`-able from this repo's URL. Build the gateway with `make` or the
> Dockerfiles below. The [`mcp/`](../mcp/) module uses this repo's path and *is*
> go-installable (see [`mcp/README.md`](../mcp/README.md)).

A plain `make build` produces a working gateway, but several inference-gateway features are
compiled **out**. The official Ubuntu 24.04 image ([`Dockerfile.u24`](../Dockerfile.u24)) builds
with:

```bash
make HAVE_HTTP_TRACE=1 HAVE_L4_TRACE=1 HAVE_MTLS=1 EXTRA_CFLAGS="-DHAVE_L4_TRACE"
```

| Flag | Enables | Default |
|---|---|---|
| `HAVE_MTLS=1` | Frontend/backend mTLS — Go tag `mtls` + `-DHAVE_MTLS=1` | **on** (`HAVE_MTLS ?= 1`); opt out with `make HAVE_MTLS=` |
| `HAVE_HTTP_TRACE=1` | HTTP/HTTPS request tracing (`lxb_ring` transport in the C data path) | off |
| `HAVE_L4_TRACE=1` **and** `EXTRA_CFLAGS="-DHAVE_L4_TRACE"` | L4 flow tracing and span assembly — Go tag `l4trace` | off |
| `HAVE_DOCA=1` | BlueField DPU offload — Go tag `doca` (see also `make dpu`) | off |
| `HAVE_DP_DPU_SLIM=1` | DPU slim `dp_proxy_tacts` layout | off |
| `HAVE_PII_DETECTION=1` | PII detection — Go tag `piidetection` (experimental; not compiled into packaged releases) | off |

Two things that are easy to get wrong:

- **L4 tracing needs both halves.** `HAVE_L4_TRACE=1` sets the Go build tag; `EXTRA_CFLAGS="-DHAVE_L4_TRACE"` turns it on in the C data path. Setting only one yields a half-enabled build.
- **Always set feature flags on the top-level `make`.** `HAVE_MTLS` is deliberately exported to the `loxilb-ebpf` sub-make because it changes the `dp_proxy_tacts` layout shared by the cgo Go binary and `libloxilbdp.a`. Building the submodule separately with different flags gives a silent ABI mismatch that no `_Static_assert` can catch.

To confirm what actually got compiled in, `make` echoes the resulting Go build tags on the
last line of the build:

```
Built with tags: -tags l4trace,mtls
```

A plain `make build` prints `Built with tags: -tags mtls` — mTLS only.

Run it directly on the host:

```bash
sudo loxilb-ebpf/utils/mkllb_bpffs.sh   # mount the bpf filesystem (once per boot)
sudo ./loxilb                           # REST API on :11111
```

## Optional AI components

These are developer build targets only — they are experimental and are not
part of the packaged releases (no published image or package ships them; the
gateway leaves them dormant unless explicitly configured).

```bash
make ai-controller            # → loxilb-ai-controller (TTFT/weight advisory controller; pure Go)
make kv-agent HAVE_DOCA=0     # → loxilb-kv-agent (KV-cache offload agent; HAVE_DOCA=1 on BlueField)
```

## Docker images

| Target / file | Produces |
|---|---|
| `make docker` | Gateway image — auto-picks `Dockerfile.u20` / `Dockerfile.u24` / default [`Dockerfile`](../Dockerfile) (Ubuntu 22.04) by host OS |
| `make docker-u24` | Ubuntu 24.04 image via [`Dockerfile.u24`](../Dockerfile.u24) |
| `make docker-arm64` · `docker-arm64-u24` | ARM64 images (docker buildx) |
| [`Dockerfile.aictrl`](../Dockerfile.aictrl) | `loxilb-ai-controller` image |
| [`Dockerfile.kv-agent`](../Dockerfile.kv-agent) | `loxilb-kv-agent` image |

Image name/tag come from `IMAGE?=ghcr.io/loxilb-io/loxilb-inference-gateway` and
`TAG?=latest` in the [`Makefile`](../Makefile); the u20/u24 variants append `-u20`/`-u24`
to the tag (`make docker` picks the suffix from the host OS):

```bash
make docker IMAGE=myrepo/loxilb-inference-gateway TAG=dev
```

Fast iteration without a full image rebuild — run the published image and overlay a freshly
built binary into it:

```bash
make docker-rp      # docker-run + build + docker cp ./loxilb, then docker-commit back to
                    # $(IMAGE):$(TAG) — the scratch container is stopped and removed
```

## Dependency updates and candidate security checks

[`build/go-dependencies.json`](../build/go-dependencies.json) owns the compiler,
x/net, gRPC, GoBGP and Go scanner/plugin pins. Dockerfile literals are generated
mirrors so the existing small fixture build contexts and offline reflect-echo
build remain usable. Change the manifest, then run this single update command:

```bash
python3 scripts/update-go-pins.py --write
python3 scripts/update-go-pins.py --check --verify-vendor
```

The updater uses Go tooling to refresh the root and reflect-echo modules,
regenerates vendor, and updates all managed Dockerfiles. `--x-net`, `--grpc` and
`--go-version` can set those manifest values in the same `--write` invocation.
An update that needs a newer minimum Go version also needs a compatible compiler
pin. On failure, inspect the working diff; the checker must pass before committing.
New independently pinned recipes/modules must join the managed inventory.
Dockerfiles that explicitly COPY/ADD the shared reflect-echo module or vendor
from the repository also join it, even when they contain no direct module pin.
The JSON parser mock and edge-cloud backend use this shared input; their compiler
mirrors follow the same manifest. `--list-shared-vendor-builds` provides the
profile/Dockerfile inventory used by CI so these consumers cannot be omitted.

Pull requests changing build/dependency inputs run the candidate-image workflow
through Trivy-Image. It builds the actual default/u24 Dockerfiles, the five
gRPC/reflect-echo fixture images, both shared-vendor consumers (JSON parser mock
and edge-cloud backend), and the legacy GoBGP recipe's Go payload.
It inspects every Go binary discovered by Trivy,
checks its embedded compiler/module versions, and runs binary govulncheck. Manual
Govulncheck dispatch can run the same reusable workflow. Scheduled/release Trivy
scans of published tags remain separate; a published tag is not evidence for a
changed Dockerfile candidate.

For an already-built local gateway image:

```bash
go install "golang.org/x/vuln/cmd/govulncheck@$(python3 scripts/update-go-pins.py --print-govulncheck-version)"
python3 scripts/scan-go-image-binaries.py --image YOUR_LOCAL_IMAGE --output /tmp/candidate-go-report
```

Use the repository's pinned Trivy installer in CI. The scanner requires a new
output directory and never starts the image container. It records the immutable
image ID, build metadata, binary hashes and reports; only its exact temporary
inspection container is removed. Fixture images use the corresponding `--profile`
(`reflect-echo`, `grpc-client`, `grpc-server`, `http-client` or `http-server`);
`json-parser-mock` and `edge-cloud-backend` check the shared-vendor consumers;
`gobgp-legacy` checks the legacy GoBGP pair. This does not qualify the full legacy
Ubuntu image or its native/runtime behavior. Both GoBGP recipe profiles now use
v3.35.0, which removes the fixable advisories present in the previous v3.29.0
legacy payload.

The source govulncheck gate blocks reachable findings with a fix. The binary gate
blocks vulnerable symbols present in a binary when a fix exists, including
symbols in GoBGP/CLI dependencies; binary analysis does not provide source call
stacks. No-fix and module-only findings remain visible. Trivy retains the existing
fixable-CRITICAL gate and reports other severities. Missing binaries, stale pins,
unreadable metadata and scanner failures fail the candidate check.

The u24 build and runtime stages upgrade installed Ubuntu packages before
installing their dependencies. This picks up the apt/libapt fix for
CVE-2026-109518 (2.8.4ubuntu0.1 or newer). Rebuild images to apply repository
security updates; existing containers are not modified by a source change.

## Regenerate API models

Run generation in a clean working copy because it refreshes generated API files:

```bash
CGO_ENABLED=0 go generate ./api/restapi
go run ./api/cmd/sync-model-validators -check
go test ./api/models -run '^TestEndPointHostStateTupleValidation$' -count=1
```

Both `go generate` and `api/build_api.sh` use the pinned Swagger generator and the
same post-generation hooks. Endpoint tuple validation lives in the non-generated
`api/models/end_point_host_state_validation.go`. The model hook calls it before
generated field checks, including for nil payloads, and preserves those generated
checks. Do not restore manual validation edits inside generated model files.

## Tests

The self-contained AI scenarios under [`cicd/`](../cicd/) are the
integration layer — CI runs them in
[`ai-gateway-sanity.yml`](../.github/workflows/ai-gateway-sanity.yml).

**For maintainers:** this fork tracks upstream `loxilb` / `loxilb-ebpf` with merge-based
sync (never rebase) in submodule lockstep — eBPF first, then the gateway pin bump. New
AI code lives in new files so untouched upstream files merge cleanly.
