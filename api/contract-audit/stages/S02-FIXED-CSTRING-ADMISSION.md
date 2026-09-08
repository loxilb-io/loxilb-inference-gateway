# S02 fixed-string admission and Go-to-C safety

Date: 2026-09-08. Result: PASS for the scoped admission and conversion contract.
The stage is complete and waits for explicit approval before any later stage.

## Scope and result

S02 closes AI-01 for the four `LoadbalanceEntry.serviceArguments` values copied
into fixed C arrays: `host`, `path_prefix`, `session_header_name` and
`model_name`. It also closes silent truncation of the conditional sockproxy
endpoint key derived from `host`, `path_prefix` and `model_name`.

The server now rejects invalid UTF-8, embedded NUL, individual encoded-byte
overflow and composite-key overflow before rule lookup or mutation. The
Go-to-C bridge repeats the check and copies bytes directly into zeroed C arrays
without allocating a temporary C string or copying `len+1` bytes blindly.
Operator argument failures are marked with a typed `RuleArgumentError` and map
to HTTP 400; unclassified errors still retain the fail-closed HTTP 500 path.

| Value | Individual maximum | C capacity | Additional relationship |
|---|---:|---:|---|
| `host` | 255 UTF-8 bytes | 256 bytes | endpoint key maximum 511 bytes |
| `path_prefix` | 255 UTF-8 bytes | 256 bytes | endpoint key maximum 511 bytes |
| `session_header_name` | 127 UTF-8 bytes | 128 bytes | none |
| `model_name` | 127 UTF-8 bytes | 128 bytes | endpoint key maximum 511 bytes |

The endpoint key forms are `host`, `host|path`, `host||model` and
`host|path|model`; literal separators count toward the 511-byte maximum.
Swagger exposes each individual limit as `x-loxilb-max-utf8-bytes` rather than
`maxLength`, because Swagger 2.0 counts characters rather than encoded bytes.
The cross-field rule is published as `LB-ENDPOINT-HASH-KEY-BYTES` under the
versioned `x-loxilb-contract-relations` metadata.

## Implementation

- `pkg/loxinet/rules.go`: pre-mutation validation, UTF-8/NUL/byte bounds,
  composite-key bound and typed argument refusal.
- `pkg/loxinet/dpebpf_linux.go`: repeated boundary validation and bounded direct
  copy into the actual C arrays.
- `common/rule_admission.go` and `api/restapi/handler/common.go`: structured
  HTTP 400 classification without broad error-text matching.
- `api/swagger.yml`, generated model/embedded spec and argument inventory:
  individual limits, relationship semantics and generated-contract parity.
- Go tests: admission order, exact/overflow ASCII and multibyte boundaries,
  invalid UTF-8, NUL, C ABI sizes, direct bridge bypass and structured REST
  mapping.
- HTTP harness: exact boundaries, overflow/NUL/multibyte/composite failures,
  relevant error text and unchanged normalized full-rule readback.

## Authoritative environment and source identity

All build and verdict-bearing tests ran on the dedicated Ubuntu controller. Local activity
was limited to editing, formatting and static review. No local macOS result is
used as product evidence.

- Base Gateway revision: `f8e6ace22f0f2262d56829e781a83e4b7075fef7`
  plus the archived working-tree patch.
- Final frozen source:
  `runtime-evidence:s02-final-source-02`.
- Final test image:
  `loxilb-inference-gateway:ai-multitier-f8e6ace2-s02r2-unit-u24`, image ID
  `sha256:9d84aa916f98cb7369fb425dcf08c77429868b94ead8819741ff55d8281bab40`.
- Final runtime image:
  `loxilb-inference-gateway:ai-multitier-f8e6ace2-s02r2-u24`, image ID
  `sha256:37e1fdaf2107430b4e03401075b07b3785000c0a72eb199f6749a3d52cc67c84`.
- Gateway binary SHA-256 in both rails:
  `a2d87c555a97d5b3292fe3db39d43608730d527a7b26bb0533d98989390b5162`.
- Build method: repository `make docker` on Ubuntu 24.04, with
  `--network host --target test-build` for unit evidence and `--network host`
  for the runtime package.

## Evidence and failure classification

### Before-fix product RED

`runtime-evidence:s02-fixed-cstrings-before-unit-03`
injects a black-box test that uses no new implementation symbols into image
`sha256:023c34613f795ee5c9117a12f7fc75d9c47fa53e36f0f97c2b92a2b9026255e3`.
All nine invalid cases reached the later `endpoints-range` check instead of a
pre-mutation argument refusal. Other baseline gates passed. Classification:
IMPLEMENTATION defect.

An earlier overlay at
`runtime-evidence:s02-fixed-cstrings-before-unit-02` failed to
compile because it referenced helper symbols absent from the old image.
It is retained and classified as TEST-OVERLAY/HARNESS incompatibility, not as
product proof. The independent black-box rerun above removes that ambiguity.

### Intermediate packaged-runtime RED

`runtime-evidence:s02-final-http-01` used the first fixed
runtime image. Internal validation rejected every unsafe value and preserved
rule state, but REST returned HTTP 500 because the generic classifier did not
recognize the new messages. Classification: IMPLEMENTATION defect in REST
error mapping. This produced the typed `RuleArgumentError` correction and the
dedicated `api-handler` unit gate.

### Final GREEN

`runtime-evidence:s02-final-unit-02` records exit 0 for all
nine gates: `api-models`, `api-handler`, `kv-admission`, `pd-cache`,
`pd-adjacent`, `kv-dataplane`, `swagger-contract`, `inventory` and `harness`.

The packaged runtime was then tested three times:

| Evidence directory | Passed | HTTP result distribution | Exit |
|---|---:|---|---:|
| `s02-final-http-02a` | 51/51 | 200 x 19, 422 x 8, 400 x 24 | 0 |
| `s02-final-http-02b` | 51/51 | 200 x 19, 422 x 8, 400 x 24 | 0 |
| `s02-final-http-02c` | 51/51 | 200 x 19, 422 x 8, 400 x 24 | 0 |

Every fixed-string rejection includes the relevant field/relation reason and
preserves the complete normalized rule set. Evidence checksum verification,
matching runtime binary manifests, no residual campaign container, unchanged
running-container inventory and the unchanged `loxilb-mon-p6` image ID are in
`runtime-evidence:s02-final-integrity-01`.

## Testbed cleanup

The controller initially had 7.6 GiB free. The approved exact-image cleanup in
`s02-disk-cleanup-01` raised this to 21 GiB without changing any container.
After R2 qualification, the two superseded R1 tags were removed under
`s02-disk-cleanup-02`; final free space was 16 GiB. Removed images require a
rebuild to recover, while their build/test evidence and hashes remain. R2,
the corrected-TTL baseline and the active `mon-p6` image remain present. No
model cache, volume, source tree or running service was removed.

## Explicit limits and remaining work

S02 does not qualify live sockproxy host/path/model matching, session-key
extraction, routing distribution, any GPU engine/model tuple, restore/boot
replay, replacement of a legacy oversized declaration or deletion of such a
legacy rule. The Go-to-C propagation dimension is therefore PARTIAL and the
behavior/default/restore dimensions remain open in the coverage ledger.

The downstream key still uses literal `|` separators. S02 prevents truncation
but does not ratify escaping or collision semantics for user values containing
`|`. Restore must gain whole-snapshot preflight before destructive replacement,
and legacy oversized rules may require a versioned recovery/delete mechanism;
neither lifecycle change is silently included here.

No production deployment, GPU workload or claim about the three representative
models is made by this stage.
