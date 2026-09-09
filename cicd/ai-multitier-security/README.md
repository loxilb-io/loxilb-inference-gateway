# AI multi-tier security and credential-ownership gates

This slice proves that mandatory API-key admission is evaluated before the AI
routing hierarchy.  It is intentionally diagnostic: every denial is paired
with a backend request counter, so a client-visible 401/503 is not mistaken for
a secure result when the same request was also forwarded upstream.

S04 adds the independent header-ownership contract. `api_key_auth` omitted
means the gateway does not own `X-Api-Key`, so a backend credential passes
through even when SSE or P/D turns on AI accounting. Explicit `disabled` and
`required` both reserve the gateway namespace and strip before dispatch.

## Gates

- `check_security_order.py`: source wiring. HTTP/2 captures the credential in
  per-stream state, calls the shared admission helper before L7/model/tier and
  fallback selection, and strips the key after L7 mutation but before backend
  submission. It also protects the existing HTTP/1 denial exit and requires
  both protocol adapters to use the shared policy-only ownership predicate.
- `make -C loxilb-ebpf/common test_aisec`: C unit matrix for undeclared,
  required, explicitly disabled and corrupt wire policies; 401/403/429/503
  mapping; 255/256-byte credential bounds; HTTP/2 header preservation or
  stripping according to the policy wire value alone.
- `runtime_h2.sh`: live TLS/HTTP2 dataplane proof using the existing
  `e2ehttpsproxy-prefix` topology. An omitted-policy SSE control reaches the
  backend with its backend-owned key intact, while an explicitly disabled
  control reaches it only after the Gateway key is stripped. With no policy
  store configured, required
  keyless and presented-key requests both return 503 with backend counter delta
  zero. It also proves that known credential bytes are absent from the data-plane
  log while presence-only denial records exist. Configured-store 401/403/429
  semantics remain covered by the C matrix and the existing `ai-authsep` runtime
  campaign.

Run the live gate on a Linux controller:

```bash
export LOXILB_DOCKER_IMAGE=loxilb-inference-gateway:your-tag
export S03_UNIT_IMAGE=loxilb-inference-gateway:your-test-build-tag
cd cicd/e2ehttpsproxy-prefix
./config.sh
cd ../ai-multitier-security
./runtime_h2.sh
cd ../e2ehttpsproxy-prefix
./rmconfig.sh
```

When the controller does not provide Go, `runtime_h2.sh` compiles its two
standard-library-only probes inside `S03_UNIT_IMAGE` with networking disabled.
The temporary binaries are removed on every exit path.

The runtime leg/disabled/required policy grid is crossed with plain, SSE, P/D and
SSE+P/D shapes by `../ai-authsep/tiers.sh`. P/D admit mechanics are recorded but
not asserted against its generic HTTP mock. The separate engine scenarios own
positive semantic routing: `../sglang-loxilb-kvcache/` simultaneously exercises
a role-partitioned vLLM P/D rule (`kvExactMode=1`) and a single-pool SGLang rule
(`kvExactMode=3`). This distinction keeps header-ownership proof independent
from engine contract qualification.
