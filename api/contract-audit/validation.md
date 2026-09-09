# Static validation evidence

Date: 2026-09-08. Historical audit checkpoint: NOT CLOSED. No runtime qualification.

The user later authorized staged implementation. S01 follows up UI-02; consult
`stages/README.md` for its separately pinned results. The hashes, failures and
reproduction expectations below describe the original audit snapshot, not the
subsequent implementation tree. `embedded-parity.txt` remains the original RED.

## Source identity

Gateway HEAD `f8e6ace22f0f2262d56829e781a83e4b7075fef7` plus pre-existing
campaign WIP and this audit. These hashes identify the final specification
snapshot, not an immutable build or a committed source tree:

| Artifact | SHA-256 |
|---|---|
| `api/swagger.yml` | `ca3f404f3cef6edb53714f1e48844f76938ade806f38f5fc7d9e671efe1a96d7` |
| `api/swagger-extras.yml` | `69a99863139aaf4a50a8ac01f068e95cb55b7cbaa9cb6720ef85a5d7c1bc1514` |
| `api/restapi/embedded_spec.go` | `53e8bf014deb836afb1e62d86918a232fdd3577b54450862259e473d8b6db8eb` |

## Results

| Check | Result | Boundary |
|---|---|---|
| Duplicate-safe YAML inventory and reference resolution | PASS | 209 main + 8 extras operation declarations; 170 named definitions; 221 parameters; 1298 property nodes; 1318 response declarations. Three OPA operations overlap. |
| Relationship grammar, field pointers, IDs and evidence presence | PASS | 12 initial AI rules; does not prove their runtime enforcement or complete relationship coverage. |
| OpenAPI 2.0 validation, both specs | PASS WITH WARNINGS | go-swagger v0.36.5 validator. Main has three unused definitions: HealthCheckResponse, K8sConntrackEntry and MetricEntity. |
| Pinned server/model generation | PASS | Generator built from cached go-swagger v0.30.3 module with local Go 1.23.1 and offline dependencies. No product build. |
| Generated model syntax comparison before synchronization | PASS | All 166 generated model files match the pre-synchronization WIP model syntax after removing comments. This does not compare against clean HEAD or prove validator correctness. |
| Embedded SwaggerJSON versus original YAML | FAIL, OPEN | 29 zero-minimum constraints are missing. See embedded-parity.txt. Not waived. |
| Whitespace/diff check | PASS | Does not prove schema semantics or runtime correctness. |
| Application unit/CICD/GPU/SSH/build/deployment tests | NOT RUN | Campaign remains paused. |

`inventory.json` is reproducible structural evidence. Its individual rows remain
UNREVIEWED until explicit field-level dispositions are reconciled; report
ownership is not automatically converted to PASS.

## Open embedded-document drift (UI-02)

`verify-embedded.rb` parses the generated Go raw-string representation, including
escaped backticks. It normalizes JSON object keys and only the documented
optional-parameter default `required: false`. It does NOT ignore constraints,
descriptions or extensions. Its exit status remains 1 for the current artifacts.

All 29 reported differences are `minimum: 0` / `minimum: 0.0` present in YAML but
absent from `SwaggerJSON`. The clean HEAD embedded file already has zero-minimum
entries only in its separate `FlatSwaggerJSON` assignment, and the regenerated
file retains that distinction. This is a pre-existing representation issue, not
evidence that this documentation update removed all runtime lower-bound checks.
`api/api.go` loads both embedded representations; the complete runtime validation
effect needs a separate trace and tests. Do not infer it from this parity result.

Original-spec UI consumption, served Swagger consumption and `/meta` consumption
are consequently different contracts today. Fix the representation/delivery
contract before declaring UI validation parity. Do not suppress the 29 findings
or remove YAML constraints just to make the comparison pass.

## Reproduction

Run from the campaign worktree:

```sh
ruby api/contract-audit/inventory.rb --summary
swagger validate api/swagger.yml
swagger validate api/swagger-extras.yml
ruby api/contract-audit/verify-embedded.rb
git diff --check
```

The parity command is expected to fail until UI-02 is resolved. The temporary
generator output used for the model comparison was
`/private/tmp/swagger-contract-audit.NaidNt/src/github.com/loxilb-io/loxilb/api`;
that temporary path is not durable evidence or a production artifact.

Generator invocation, after building the pinned executable into that temporary
directory, used `generate server --name LoxilbRestAPI --principal 'interface{}'
--exclude-main --skip-operations` with the main spec and a temporary target.
Only model files and `embedded_spec.go` were synchronized. Hand-maintained
configuration, handlers and generated operation implementations were not replaced.
Extras is embedded directly by `api/api.go` using `go:embed swagger-extras.yml`.

## Tooling failures resolved during integration

- Two incorrectly indented networking descriptions were caught by YAML parsing
  and moved to their intended nested `type` properties before final validation.
- An initial generator attempt used the wrong Go toolchain/GOPATH context and
  attempted an unavailable download. The pinned offline generation succeeded
  after correcting that context; this was tooling, not a product build failure.
- The first embedded-text extractor did not handle generated backtick escapes.
  The checked-in verifier corrects that parsing issue. The remaining 29 mismatches
  are real document differences, not that extractor failure.

No masking baseline, product fix, testbed mutation, commit, push or consumer-repo
vendoring was performed.
