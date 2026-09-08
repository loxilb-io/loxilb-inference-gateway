# Relationship metadata for UI consumers

Version: 1. Status: partial static audit; no UI integration or runtime qualification.

## Delivery limitation

The current `/meta` projection is NOT a complete validation contract. Its
`SwaggerDoc` intake retains paths/definitions but not top-level extensions;
`processSchema` exports selected type/format/description/enum information while
dropping minimum/maximum/default and other constraints. For simple query/path
parameters even descriptions and enums are not preserved by that projection.
It also selects one body-bearing method per path rather than representing every
operation independently. Source: `api/restapi/handler/metadata.go`.

UI consumers must read the version-pinned original specs and this extension, or
wait for an explicitly designed metadata API upgrade. Adding descriptions or
extensions does not automatically make `/meta` or an existing UI consume them.
The original audit found 29 zero-minimum constraints lost from generated
`SwaggerJSON`; see `validation.md` and its preserved failing evidence. Stage S01
adds source-preserving synchronization and explicit parity gates. See
`stages/README.md` for qualification; no deployed document is automatically
upgraded by a source fix. `/meta` projection and UI integration remain separate
open work. The generator issue alone does not establish the behavior of validators
using the separate flattened representation.

`x-loxilb-contract-relations` is a project extension in `swagger.yml`. It currently
covers selected AI topology/admission relationships only. Absence of a rule is
not permission to accept a combination. Scalar schema validation, all server
checks, external readiness, and lifecycle rules still apply.

## Evaluation semantics

- `scope` resolves a schema reference. Each `field` is an RFC 6901 JSON Pointer
  into the effective request object for that schema, NOT into the Swagger file.
- For PATCH, evaluate the merged candidate against the current declaration;
  do not require omitted key fields in the raw partial payload. For replace-POST,
  do not invent PATCH retention semantics for fields the server does not preserve.
  The current LB PATCH handler rejects FullProxy and implements only selected
  L4 overlays; these AI relationships do not grant PATCH support to AI fields.
- `missing` substitutes only an absent property. It never substitutes explicit
  null, an empty string, false, or zero. Reject type errors through the standard
  schema checks before evaluating relationships. Do not coerce strings to numbers.
- Predicates: `in` uses typed equality with one of `values`; `greater-than`
  compares a number to `value`; `nonempty-string` requires a string of length > 0
  without implicit trimming. A missing value without a substitution makes a
  predicate false. A false `when` makes the rule not applicable, not violated.
- `requires`: when the predicate is true, all `require` predicates must be true.
- `filtered-count`: when true, count array elements matching each item's relative
  `field` and `equals`; every count must meet its `minimum` independently.
- `sum-bound`: resolve each term's `missing`, then its explicit numeric `zero`
  substitution, sum using non-wrapping arithmetic, add `offset`, and compare to
  `maximum`. Scalar validity and non-negative port/rank checks remain separate.
- `conditional-join-byte-bound`: encode the named string fields as UTF-8, choose
  the listed join format from field presence, include every literal separator,
  and compare the resulting byte count to `maximum`. For
  `LB-ENDPOINT-HASH-KEY-BYTES`, an empty path with a non-empty model deliberately
  uses `host||model`; this rule is independent of each field's own fixed-array
  limit.
- `enforcement: server-static` means the cited source contains a server check.
  It does not mean the deployed binary, generated bindings, or every entry point
  has been runtime-verified. `evidence` is a repository file and function anchor.
- Unknown metadata versions, operators, or kinds are unresolved conditions.
  Display them and rely on server admission; never report them as validated.

## Important relationships that are not yet executable metadata

| Relationship | UI behavior | Server/evidence boundary |
|---|---|---|
| Engine and hash algorithm | Offer only vLLM CBOR algorithms, SGLang raw hash, or TRT block hash for the selected engine; omit an explicit algorithm for llama.cpp. | `rules.go:kvHashAlgoValidate`; deployment hash settings still need parity. |
| Model and tokenizer | Require a model name for Exact; explain tokenizer readiness separately. | `rules.go:kvExactRuntimeValidate`; a UI cannot infer host artifact readiness. |
| Profile and API surfaces | Fetch profile discovery; offer a subset of supportedApis and show alias restrictions. | Admission rechecks the published generation; discovery can be stale. |
| Profile attachment on update | Warn that effective legacy both-surfaces may narrow; retain the same raw kvExactApiMode declaration. | Existing binding cannot be removed/swapped; only unbound-to-bound migration is allowed. |
| Engine on update | Disable family switching; offer an explicit delete/recreate workflow. | Omitted engine and vllm are equivalent for this guard, unlike raw API-surface identity. |
| SGLang bootstrap vs NIXL | Explain engine-specific transport ports; do not present them as interchangeable. | Deployment settings and both endpoint roles must be checked. |
| TRT event ownership | Explain sole-consumer drain-on-read ownership and endpoint admission status. | Not derivable from a form; requires external runtime evidence. |
| CHWBL knobs | Show declared value separately from effective/unsupported state. | Several fields are not wired; readback is not behavioral proof. |
| Warm-up | Do not show configured seconds as an active readiness barrier. | Start timestamp lifecycle is missing in production code. |
| P/D threshold reset | Explain current zero-retains behavior and approved future zero-resets behavior separately. | Presence-aware update implementation is pending; do not emit reset actions yet. |
| Profile set vs binding digest | Compare like identities; never equate setDigest and bindingDigest. | Registry generation and per-rule binding are different identities. |

Do not generate release tests solely from these descriptions. Each relationship
needs an independent algorithm/lifecycle oracle, rejection-side-effect checks,
and model/engine tuple evidence where applicable. Neither this extension nor a
successful GET makes the UI or Gateway production-qualified.
