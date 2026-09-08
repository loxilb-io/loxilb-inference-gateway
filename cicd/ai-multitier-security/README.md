# AI multi-tier mandatory-security gates

This slice proves that mandatory API-key admission is evaluated before the AI
routing hierarchy.  It is intentionally diagnostic: every denial is paired
with a backend request counter, so a client-visible 401/503 is not mistaken for
a secure result when the same request was also forwarded upstream.

## Gates

- `check_security_order.py`: source wiring. HTTP/2 captures the credential in
  per-stream state, calls the shared admission helper before L7/model/tier and
  fallback selection, and strips the key after L7 mutation but before backend
  submission. It also protects the existing HTTP/1 denial exit.
- `make -C loxilb-ebpf/common test_aisec`: C unit matrix for undeclared,
  required, explicitly disabled and corrupt wire policies; 401/403/429/503
  mapping; 255/256-byte credential bounds; HTTP/2 header stripping.
- `runtime_h2.sh`: live TLS/HTTP2 dataplane proof using the existing
  `e2ehttpsproxy-prefix` topology. An explicitly disabled control reaches the
  backend without leaking the key. With no policy store configured, required
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

The runtime leg proves the common gate through the HTTP/2 Tier-2/fallback path.
Tier 0, Tier 1 and Tier 1.5 engine-specific positive routing verdicts remain in
the three-model GPU campaign; the source-order gate prevents those selectors
from moving ahead of admission in the meantime.
