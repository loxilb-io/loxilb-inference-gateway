# L7 TLS — ALPN, Cipher/Version Pinning, HSTS, mTLS & Certificate Management

> L7 TLS termination and certificate management for the inference gateway.
> Covers ALPN negotiation, TLS version/cipher pinning, HSTS, mTLS (client-cert + CRL + SAN/CN
> matching), the `tls-hello` health probe, per-probe CA/verify, certId certificate management, backend
> re-encryption, and VIP QoS association.
>
> TLS termination runs in the userspace sockproxy (`mode=4`, `security=1`). All fields below are
> **additive/optional** — omitting them preserves prior behavior (TLS 1.2–1.3, no HSTS, no mTLS).
>
> **Verification:** 14/14 checks passing (2026-06-08).

---

## 1. ALPN negotiation

`alpn_protocols` on the listener advertises which HTTP versions LoxiLB offers during the TLS
handshake. It maps to the existing `backend_protocol_cap` enum:

| `alpn_protocols` | cap | Meaning |
|---|---|---|
| `["h2","http/1.1"]` | 2 | offer both (default behavior when unset) |
| `["h2"]` | 1 | HTTP/2 only |
| `["http/1.1"]` | 0 | HTTP/1.1 only |

```json
{ "alpn_protocols": ["h2", "http/1.1"] }
```

Test with `openssl s_client -alpn h2 -connect <vip>:<port>` — the negotiated protocol appears in the
handshake output.

> **Caveat:** ALPN advertises to the *client*. If a client negotiates `h2` but the backend pool is
> h1-only, the AI-GW H2 path has no h2→h1 downgrade and returns an empty body. Use h2c backends or set
> `alpn_protocols: ["http/1.1"]`.

---

## 2. TLS version & cipher pinning

Applied to **both** the client (listener) and backend (pool) SSL contexts:

| Field | Type | Meaning | Default |
|---|---|---|---|
| `tls_versions` | `[]string` | Allowed versions, e.g. `["TLSv1.2","TLSv1.3"]`; collapsed to a min..max range | TLS 1.2–1.3 |
| `tls_ciphers` | `string` | OpenSSL cipher string; passed to both `SSL_CTX_set_cipher_list` (1.2) and `SSL_CTX_set_ciphersuites` (1.3) | today's hardcoded list |

```json
{ "tls_versions": ["TLSv1.2", "TLSv1.3"],
  "tls_ciphers": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384" }
```

A handshake outside the pinned range or using a disallowed cipher is **rejected** (no silent
downgrade). Verify: `openssl s_client -tls1_1 ...` and `openssl s_client -cipher NULL-MD5 ...` should
both fail.

---

## 3. HSTS header injection

RFC 6797 `Strict-Transport-Security` synthesis on HTTPS responses (H1 splice **and** H2 nghttp2).
Triple-gated: only fires when `have_ssl && has_l7_policy && hsts_max_age > 0`.

| Field | Meaning |
|---|---|
| `hsts_max_age` | seconds; `0` = no HSTS (default-off) |
| `hsts_include_subdomains` | append `; includeSubDomains` |
| `hsts_preload` | append `; preload` |

```json
{ "hsts_max_age": 31536000, "hsts_include_subdomains": true, "hsts_preload": false }
```

Verify on both protocols: `curl -kis https://vip/` and `curl -kis --http2 https://vip/` — the response
must carry `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

---

## 4. mTLS — client certificates, CRL & SAN/CN matching

### 4.1 Frontend (client → LoxiLB) mTLS

| Field | Meaning |
|---|---|
| `mtls_frontend.mode` | `0` off · `1` optional · `2` mandatory · `3` auto (optional→mandatory on cert arrival) |
| `mtls_frontend.client_ca_path` | CA bundle that validates the client cert chain |
| `mtls_frontend.client_crl_path` | CRL file for revocation (leaf-only); if empty, auto-derived as a sibling of `client_ca_path` |
| `mtls_frontend.client_cn_pattern` | `fnmatch` pattern matched against **SAN-DNS first, then CN** (wildcards supported) |
| `mtls_frontend.require_client_cn` | enforce that the CN/SAN pattern matched |

```json
{ "mtls_frontend": {
    "mode": 2,
    "client_ca_path": "/etc/tls/client-ca.pem",
    "client_crl_path": "/etc/tls/client-ca.crl",
    "client_cn_pattern": "*.corp.example.com" } }
```

### 4.2 Verification flow

1. Client cert chain arrives → OpenSSL chains it against `client_ca_path`.
2. If a CRL is configured, the **leaf** cert is checked for revocation
   (`X509_V_FLAG_CRL_CHECK` — leaf-only, *not* full-chain). A revoked cert → handshake rejected.
3. If `client_cn_pattern` is set: try each **SAN-DNS** entry first; if none match (or none present),
   fall back to the **CN**. Pattern match via `fnmatch(..., FNM_CASEFOLD)`.

| Cert shape | Matched via |
|---|---|
| Modern (SAN-DNS + CN) | SAN-DNS first, CN fallback |
| SAN-only (empty CN) | SAN-DNS — **now accepted** (this was the fix) |
| Legacy CN-only | CN fallback |

> **CRL gotcha (learned on the live gate):** the CA that *signs the CRL* must itself have
> `keyUsage = …, cRLSign`. A CA without `cRLSign` makes the CRL silently ineffective and a revoked
> cert false-passes. Generate a dedicated client CA with
> `keyUsage=critical,keyCertSign,cRLSign`. Check with
> `openssl x509 -in ca.crt -text | grep -A1 'Key Usage'`.

### 4.3 Backend re-encryption (pool → backend mTLS)

Reference uploaded material by **certId** (not inline paths — this reclaimed the `proxy_arg` budget):

| Field | Meaning |
|---|---|
| `backend_ca_cert_id` | certId of the CA bundle that validates the backend's cert |
| `backend_client_cert_id` | certId of LoxiLB's client cert+key presented to the backend |

Resolved at backend `SSL_CTX` build time by the certId registry.

---

## 5. Health probing over TLS

### 5.1 `tls-hello` probe

A handshake-only liveness probe: completes a TLS handshake (ClientHello→ServerHello) but **does not
validate** the server chain. SNI is taken from the member's `domainName`.

```json
{ "probeType": "tls-hello", "probePort": 443, "domainName": "example.com" }
```

- **UP** if the handshake completes (any cert).
- **DOWN** on a non-TLS port, an unreachable backend, or a version/cipher mismatch.

Lighter than a full HTTPS content probe; good for "is TLS alive on this port" checks.

### 5.2 Per-probe CA override & verify toggle

For HTTPS content probes (control-plane only — no dataplane change):

| Field | Type | Meaning |
|---|---|---|
| `probeCAPath` | `*string` | Custom CA bundle for this probe; empty → system default |
| `probeVerify` | `*bool` | `nil`/`true` = full chain validation (default); `false` = `InsecureSkipVerify` |

`probeVerify` is a pointer so `nil` ("use default", verify ON) is distinct from explicit `false`.

```json
{ "probeType": "https", "probeCAPath": "/etc/tls/backend-ca.pem", "probeVerify": false }
```

---

## 6. Certificate management — certId registry

A certId is an **opaque management handle** for TLS material. Material persists under
`/etc/loxilb/certs/<certId>/` (dir `0700`, key `0600`) and is registered in the SNI store; the
registry auto-derives hostnames from the leaf cert's SAN (DNS) or CN.

Resource: **`/config/cert`** (swagger lines 701 / 735).

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/config/cert` | Upload inline PEM under a certId (certId optional — minted if absent) |
| `PUT` | `/config/cert/{certId}` | Atomic zero-downtime rotation |
| `GET` | `/config/cert` | List all (metadata only — keys never returned) |
| `GET` | `/config/cert/{certId}` | One cert's metadata (id + derived hostnames + public cert/chain) |
| `DELETE` | `/config/cert/{certId}` | Remove material + SNI registration |

### 6.1 Upload

```bash
curl -X POST http://localhost:11111/netlox/v1/config/cert \
  -H "Content-Type: application/json" \
  -d '{
    "certId": "my-tls-cert",
    "certPEM": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "keyPEM":  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
# → { "certId": "my-tls-cert", "hostnames": ["example.com","*.example.com"] }
```

The `Cert` model (swagger ~line 9998): `certId`, `certPEM`, `keyPEM`, optional `chainPEM`; output-only
`hostnames`. `certId` must be 1–63 chars with no path-traversal (`/`, `\`, `..` rejected).

### 6.2 Rotate (zero-downtime)

```bash
curl -X PUT http://localhost:11111/netlox/v1/config/cert/my-tls-cert \
  -H "Content-Type: application/json" \
  -d '{ "certPEM": "...(new)...", "keyPEM": "...(new)..." }'
```

The new material swaps in under the SNI lock; in-flight TLS connections keep the old context until they
close. Unknown certId → `404`; malformed PEM → `400`.

### 6.3 Reference a certId from a listener

```bash
curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{ "serviceArguments": {
          "externalIP":"10.0.0.1", "port":443, "protocol":"tcp",
          "mode":4, "security":1,
          "cert_id":"my-tls-cert",
          "alpn_protocols":["h2","http/1.1"],
          "tls_versions":["TLSv1.2","TLSv1.3"],
          "hsts_max_age":31536000 } }'
```

---

## 7. VIP QoS association

`vip_qos_policy_id` ties the LB rule to a pre-existing `/config/policy` ident (the policer):

```json
{ "vip_qos_policy_id": "qos-policy-1" }
```

A dangling reference returns `PolNoExistErr` (no silent drop) — create the policy first.

---

## 8. Validation

The behaviors below are covered by unit tests run on a Linux testbed via
`go test ./api/restapi/handler/...` (the handler package builds against the eBPF dataplane, so it does
not build on macOS), plus the end-to-end mTLS scenarios `cicd/e2ehttpsproxy-mtls` and
`cicd/httpsproxy-mtls`.

| Assert | FR | Checks |
|---|---|---|
| (a) | | `openssl s_client -alpn h2` negotiates `h2` on the h2 pool; h1-only pool advertises only `http/1.1` |
| (b) | | TLSv1.1 **and** a disallowed cipher (NULL-MD5) are both rejected |
| (c) | | `Strict-Transport-Security: max-age=N` present over H1 **and** H2 |
| (d) | | `tls-hello` marks the non-TLS member DOWN, the TLS member UP |
| (e) | | Revoked client leaf rejected; valid client cert passes (`Verify return code: 0`) |
| (f) | | SAN-only (no-CN) client cert accepted |
| (g) | all | AI regression guard — re-run `cicd/vllm-pd-disagg` on the same build → `SCENARIO-vllm-pd-disagg [PASS]` |
| (+) | | cert-rotation soft assert (`PUT` atomic swap) — non-fatal |

**Fixtures:** a dedicated **client CA with `cRLSign`**, valid/revoked/SAN-only client leaves, and a
PEM CRL revoking the `client-revoked` leaf only. The mTLS scenarios fetch `minica` on demand to
generate the test cert material.

---

## 9. Troubleshooting (TLS)

| Symptom | Cause | Fix |
|---|---|---|
| ALPN negotiates h2 but body is empty | h2 client + h1-only backend, no downgrade | h2c backend, or `alpn_protocols:["http/1.1"]` |
| Revoked client cert still accepted | Signing CA lacks `cRLSign` | Use a CA with `keyUsage=critical,keyCertSign,cRLSign`; sign leaves *and* CRL with it |
| SAN-only client cert rejected | Old CN-only matching | Fixed (SAN-DNS first) — confirm you're on a post-77 build |
| TLSv1.1 not rejected despite pinning | `tls_versions` not applied to the SSL_CTX | Confirm the field is on the listener and the build applies `proxy_apply_tls_version_cipher` |
| HSTS header missing | Plain-HTTP listener, `have_ssl=0`, `has_l7_policy=0`, or `hsts_max_age=0` | Need `security=1` + an L7 policy + `hsts_max_age>0` |
| HSTS missing only on H2 | Raw `\r\n` write on h2 socket | Use the nghttp2 injector (`proxy_h2_inject_resp_headers`) |
| `tls-hello` always DOWN | Probing the wrong (non-TLS) port, or handshake fails | Verify with `openssl s_client -connect <ep>:<port>`; fix `probePort` |
| Cert rotation `PUT` → 503 | CGO `proxy_rotate_cert` failed (certId absent / bad PEM) | `POST` before `PUT`; validate PEM with `openssl x509 -text` |
| Per-probe CA ignored | `probeCAPath` file missing/unreadable | Ensure the file exists and is readable by the loxilb process |

---

## 10. Developer pointers

| Area | Location |
|---|---|
| ALPN | `loxilb-ebpf/common/sockproxy_ssl.c` (`alpn_select_callback`, `proxy_client_ssl_ctx_init`) |
| Version/cipher pinning | `sockproxy_ssl.c` (`proxy_tls_proto_from_ordinal`, `proxy_apply_tls_version_cipher`) |
| HSTS | `sockproxy_l7policy.c` (synthesize), `sockproxy_http.c` (H1), `sockproxy_h2.c` (H2 nghttp2) |
| mTLS SAN/CN + CRL | `loxilb-ebpf/common/sockproxy_mtls.c` (`mtls_match_cn_pattern`, CRL load + `X509_V_FLAG_CRL_CHECK`, `proxy_certid_resolve_backend`) |
| certId registry (C) | `sockproxy_ssl.c` (`proxy_register_cert` / `proxy_rotate_cert` / `proxy_delete_cert`), `sockproxy_ssl.h` |
| `proxy_arg` TLS carrier | `loxilb-ebpf/common/sockproxy.h` (tls version/cipher scalars, `client_cn_pattern`, `client_crl_path`, `backend_*_cert_id`) — `_Static_assert(sizeof <= 4096)` |
| `tls-hello` probe (Go) | `pkg/loxinet/rules.go` (`HostProbeTLSHello`, `tlsHelloProbe`) |
| Per-probe CA/verify (Go) | `pkg/loxinet/rules.go` (`httpsContentProbe`), `common/common.go` (`EndPointMod.ProbeVerify`/`ProbeCAPath`) |
| VIP QoS | `pkg/loxinet/qospol.go` (`PolAssociateLbRule`), `rules.go`, `common.go` (`VipQosPolicyId`) |
| Cert REST | `api/restapi/handler/cert.go`; `api/swagger.yml` (`/config/cert`, `Cert` model) |

> **Note for maintainers:** the tree-committed `api/restapi/embedded_spec.go` / `api/models/cert.go`
> can lag `swagger.yml` between phases (regenerated at build time). Regenerate via
> `api/build_api.sh` and commit at merge for tree self-consistency.

To extend TLS handling (new cipher option, per-pool SSL_CTX cache, hot listener override), see
[Developer guide §TLS recipes](07-developer-guide.md#tls-extension-recipes).
