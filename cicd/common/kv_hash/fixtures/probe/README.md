# KV-exact attestation probe fixtures (plan §5)

Committed source set for the byte-exact `/tokenize` token-parity probes the
attestation ladder runs against every endpoint of a strict KV-exact rule.
Deployment stages a profile's fixture directory to the gateway's profile
registry trust root as `probefixtures/<profileId>/`, where the gateway loads
it with the registry's trusted-file discipline (beneath-only resolution, no
symlinks, owner/mode/size checks).

## Layout

```
probe/<profileId>/<name>.request.json   exact probe request bytes, sent VERBATIM
probe/<profileId>/<name>.expect.json    {"requestSha256", "expectedTokenIds", "api"}
```

- `requestSha256` pins the request bytes; a drifted request file is an
  attestation failure (`probe_fixtures_missing`), never silently re-pinned.
- `expectedTokenIds` is the Gateway's own profile-bound render+encode of the
  probe, cross-validated offline by the CI oracle (`oracleEngine` /
  `oracleVersion` from the profile). The probe compares the FULL token
  array — never a length or prefix check.
- `api` is `completions` or `chat`; both probe shapes POST to `/tokenize`.

## Request-payload rules (normative, plan §5)

- `add_special_tokens: false` is REQUIRED on both shapes (vLLM's completion
  default is `true`; a defaulted probe would not test the deployed contract).
- `chat_template` is NEVER present (it would validate a request-supplied
  template, not the deployed effective one). `add_generation_prompt` /
  `continue_final_message` mirror the profile's `renderPolicy`.
- Fixture set per profile: plain, explicit-system, multi-turn, string vs
  content-part form, and one fixture per declared `supportedFeatures` entry.

## Regeneration discipline

Fixture regeneration is a **profile-revision event**, never an in-place
edit: token IDs are re-derived with the profile's pinned tokenizer artifact,
re-verified against the CI oracle, and the new sha256 set lands in the same
review as the profile revision that motivated it.

No fixture sets are committed yet: banking real per-profile sets requires
the live engine + oracle pass and happens with the live-qualification
legs (this directory's format is pinned now so the ladder's loader, tests, and
staging path are stable). The GPU-free suites generate their own fixture
pairs in test-local registry roots.
