# LoxiLB contract relationship metadata

`x-loxilb-contract-relations` is a project extension in `api/swagger.yml` for
describing selected cross-field constraints. It is advisory metadata for API
consumers and is not a replacement for server-side validation. The absence of
a relationship does not grant permission for an otherwise invalid request.

## Version 1 semantics

- `scope` is a local Swagger schema reference. Each relationship `field` is an
  RFC 6901 JSON Pointer into the effective request object for that schema, not
  into the Swagger document.
- For PATCH, evaluate a merged candidate only when the operation itself supports
  those fields. Relationship metadata does not add PATCH support.
- `missing` substitutes only an absent property. It does not replace explicit
  `null`, an empty string, `false`, or zero. Apply ordinary schema type checks
  first and do not coerce strings to numbers.
- `in` uses typed equality against `values`; `greater-than` compares a number to
  `value`; `nonempty-string` requires a string whose length is greater than zero.
  A missing value without a substitution makes the predicate false.
- `requires` applies all `require` predicates when `when` is true.
- `filtered-count` counts matching array elements and requires every declared
  minimum independently.
- `sum-bound` applies each term's `missing` substitution, then its explicit
  numeric `zero` substitution, adds the terms and `offset` without wrapping,
  and compares the result with `maximum`.
- `conditional-join-byte-bound` UTF-8 encodes the named string fields, selects
  the declared conditional join format, and compares the complete encoded byte
  length, including separators, with `maximum`.
- `enforcement: server-static` means the server has a corresponding static
  rejection path. It is not evidence of a particular deployment, engine,
  model, data plane, or runtime readiness.

Consumers must treat unknown versions, operators, or relationship kinds as
unresolved. The server remains authoritative.
