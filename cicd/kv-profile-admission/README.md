# kv-profile-admission — strict KV-exact admission matrix (GPU-free)

Validates the profile-bound ("strict") KV-exact rule admission surface
end-to-end against a live gateway, without any GPU or inference engine:
a trusted `ModelPromptProfile` registry is staged from the committed
`cicd/common/kv_hash` tokenizer fixtures and volume-mounted at
`/etc/loxilb/kvprofiles` before the gateway starts, so strict rules
resolve real profiles and real compiled engine contracts.

## What it proves

| Leg | Claim | Red twin (single-input change) |
|-----|-------|-------------------------------|
| A1  | Strict vllm rule admits; status read-back proves profile + contract + binding identity (`bindingGen`, digest, evidence level) | R1 unknown profile refuses |
| A2  | One profile reused by three separate Rules, each with its own rule identity | — (cardinality half in A6) |
| A6  | Same VIP:port serves two models as two Rules | R2 model outside the profile's alias policy refuses |
| A4  | Engine family selects the adapter + hash contract (vllm/sha256_cbor, sglang/sha256_sglang) | R4/R5 llamacpp / trtllm exact refuse typed; R6 cross-engine hash algo refuses |
| A10 | Strict rules are never READY (or silently legacy) unattested; legacy rules say `LEGACY_ACTIVE_UNATTESTED` | — (state vocabulary is closed) |
| W   | Bindable VIP earns a full contract-word ACK (`enforcement.lastAckAt`); unbindable VIP surfaces an honest fault, never a fake ACK | the two W legs are each other's twin |
| A3  | `kvModelProfile` / `kvExactApiMode` are replace-only (409), read-back unchanged | A1 admits the same body with the original profile |
| A5  | binding identity/generation: endpoint-set replace keeps `ruleIdentity`+`bindingGen` stable; delete+recreate mints a new `ruleIdentity` with a fresh gen space (protection = identity+gen pair) | — (compares identity + generation directly) |
| R1–R8 | Every refusal answers a CLASSIFIED 400 carrying the refusal wording (never an internal 500 with a correlation ref) and leaves ZERO state: no rule, no kv-exact status entry, no kv metric series for the port | A1/A2 admit the single-input-away green bodies |
| T   | The admitted rule actually routes to a backend (Tier-2 path) | — |

The vllm seed-absent refusal and the registry trust/parse refusals are
covered at the unit layer (they need per-case process env / file identity
control that a shared container cannot provide per-leg).

## Topology

- `llb1` — loxilb gateway (`LLB_KV_NONE_HASH_SEED=0`), profile registry and
  tokenizer roots mounted read-only from root-owned stages.
- `l3h1` — client (10.10.10.1), VIP = 10.10.10.254.
- `l3ep1/l3ep3` — reflect-echo prefill EPs (31.31.31.1 / 33.33.33.1).
- `l3ep2` — reflect-echo decode EP (32.32.32.1).

## Run

```bash
./config.sh && ./validation.sh; ./rmconfig.sh
```
