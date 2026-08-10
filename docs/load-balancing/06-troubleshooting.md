# Troubleshooting — L4 / L7 / TLS / AI-Gateway

> Cross-cutting symptom → cause → fix index, plus the CICD-harness gotchas that cause *false*
> failures. Feature-specific tables also live in each feature doc; this is the consolidated map and the
> place QA should start.

---

## 1. First-line diagnostics

Before chasing a symptom, confirm the basics:

```bash
B=http://localhost:11111/netlox/v1

# Is the API up and the rule present?
curl -s $B/config/loadbalancer/all | jq '.[].serviceArguments | {externalIP,port,protocol,mode,security}'

# Is the data plane loaded? (on the loxilb host/container)
bpftool prog list | head
bpftool map list  | head

# For L7/TLS/AI: is the rule fullproxy?  mode==4 is required.
# For TLS: security==1 is required.
```

**The three most common root causes of "nothing works":**

1. **Rule isn't fullproxy** (`mode != 4`) → no L7/TLS/AI behavior at all.
2. **VIP isn't local** to the loxilb node → the sockproxy can't bind it; every L7 attach reports zero
   entries and connections time out.
3. **Stale binary/image on the testbed** → you're testing old code. `docker cp` your fresh `loxilb`
   in, or rebuild the image; confirm with `strings ./loxilb | grep -c <a-symbol-from-your-change>`.

---

## 2. L4 (data model)

| Symptom | Cause | Fix |
|---|---|---|
| `PATCH` → `404` | Rule doesn't exist (PATCH only mutates) | `POST` to create first |
| `PATCH` → `400` | Tried to change immutable field (key/security/egress/mode/protocol) | `DELETE`+`POST` (accepts in-flight drop) |
| All members vanished after PATCH | Sent partial or empty `endpoints[]` | Omit `endpoints` to leave them; send the full desired set to reconcile |
| Backup member never takes traffic | A primary is still up | Backup activates only when *all* primaries are down; verify primary health |
| Backup keeps serving after recovery | (Should auto-failback) | Confirm primary probes pass; failback is immediate on recovery |
| `monitorAddress` not probed | Set on rule not endpoint, or no probe configured | Put it on the endpoint; ensure a probe exists |
| `connectionLimit` not enforced | `0`/absent = unlimited; or limit is per-rule not per-EP | Set a non-zero limit; remember it's the rule aggregate |
| IPv6 GET → `404` | Missing brackets / shell glob | `curl -g` + `[2001:db8::1]` form |
| stats/`lastUpdated` reset | In-memory, not persisted | Expected across restart |
| `?projectId=` leaks other tenants | Filter ≠ authz | Enforce tenancy upstream (Keystone/driver) |

---

## 3. L7 content routing

| Symptom | Cause | Fix |
|---|---|---|
| Policy attaches, never matches | Not fullproxy | `mode=4` |
| H2 connection corrupted on redirect/reject | Raw `HTTP/1.1\r\n` on h2 socket | Use nghttp2 emitters (`proxy_h2_send_l7_synthetic`) |
| H2 client empty body | h2 client + h1-only backend (no downgrade) | h2c backend or pin pool to http/1.1 |
| Inserted header missing at backend | Control char (silently skipped) or >8 filters | name ≤63 / value ≤255, no CR/LF/NUL, ≤8/route |
| `REGEX` rule rejected at attach | Invalid POSIX ERE | Validate with `grep -E` |
| Cookie affinity breaks on failover | (Shouldn't) binding on `proxy_fd_ent` | Confirm stateless-cookie path (the default) |
| Wrong routing counts in tests | Counting health-probe noise | `grep -c 'POST /v1/...'`, warm up first |

---

## 4. L7 TLS

| Symptom | Cause | Fix |
|---|---|---|
| Revoked client cert still accepted | Signing CA lacks `cRLSign` | Use CA with `keyUsage=critical,keyCertSign,cRLSign`; sign leaves **and** CRL with it. Check: `openssl x509 -in ca.crt -text \| grep -A1 'Key Usage'` |
| SAN-only client cert rejected | Old CN-only matching | Current builds match SAN-DNS first; upgrade if you still see this |
| TLSv1.1 / weak cipher not rejected | `tls_versions`/`tls_ciphers` not applied | Confirm fields on listener; build applies `proxy_apply_tls_version_cipher` |
| ALPN h2 negotiated but empty body | h1-only backend | h2c backend or `alpn_protocols:["http/1.1"]` |
| HSTS header absent | Not HTTPS / `have_ssl=0` / no L7 policy / `hsts_max_age=0` | Need `security=1` + L7 policy + `hsts_max_age>0` |
| HSTS absent only on H2 | Raw bytes on h2 | nghttp2 injector (`proxy_h2_inject_resp_headers`) |
| `tls-hello` always DOWN | Wrong port / handshake fails | `openssl s_client -connect <ep>:<port>`; fix `probePort` |
| Cert `PUT` → `404` or `400` | `404` = unknown certId; `400` = bad PEM / rotation failure | `POST` before `PUT`; `openssl x509 -text` to validate |
| Per-probe CA ignored | File missing/unreadable | Ensure readable by loxilb |
| mTLS probe can't see cert in netns | Cert not visible to `ip netns exec` probe | Place fixtures where the netns probe reads them |

---

## 5. AI-Gateway (vLLM)

| Symptom | Cause | Fix |
|---|---|---|
| EP death undetected | No probe on rule | `"probetype":"tcp", "probeTimeout":5, "probeRetries":3` |
| `502 {"error":"backend_unreachable"}` | Connect failover retried every healthy EP and all failed | Check backend reachability from the gateway node and probe/health state |
| `503 {"error":"no_healthy_backend"}` | Entire pool marked down | Fix the backends or the probe config marking them down — the rule is fine |
| `502 {"error":"pd_decode_backend_died"}` | Decode worker died mid-stream (KV state lost; prefill death is retried transparently) | Client retries the request; investigate the decode worker crash |
| Mutating REST → `503` + `Retry-After: 5` after gateway restart | Boot-config gate: mutations refused until boot snapshot replay settles | Expected — retry after the interval; not an outage |
| `loxilb_lb_select_failure_shutdown_total` increasing | Requests dropped with a silent TCP reset instead of an HTTP error | Should stay flat — growth means a failover path regressed; capture logs and file a bug |
| SSE cuts off / client hangs | `[DONE]` stripped/double-counted (older builds) | Use a current build; `validation-resilience.sh` R4a |
| `restore_rate = 0/100` | Consumer-respawn gap (older builds) / single-host `/sys/fs/bpf` stomping / stale binary | Current build on a 2-host testbed; `docker cp` your binary |
| `restore_rate` low non-zero | Health-gate rejecting on new master | `loxilb_sockproxy_sync_health_reject_total`; verify EP reachability |
| No replication to backup | Consumers not spawned on master | `grep consumerLoop start peer=`; absent ⇒ the coordinator never started consumers |
| WRR weights ignored | P/D mode active | Expected — roles drive P/D, not weights |
| `Killed node …` log line | End-of-test cleanup | Not an OOM |

`restore_rate` diagnostic block:
```bash
docker exec llb1 grep -c 'consumerLoop start peer=' /var/log/loxilb/loxilb-stdout.log  # ≥1
strings ./loxilb | grep -c SOCKPROXY_SYNC                                               # ≥10
curl -s http://llb1:11111/metrics | grep loxilb_sockproxy_sync_health_reject_total      # low
docker exec llb2 curl -s http://31.31.31.1:8000/v1/models                               # 200
```

---

## 6. CICD harness gotchas (false failures)

These cause gates to *fail or hang for reasons unrelated to the code under test*. Rule out before
filing a bug.

| Gotcha | Symptom | Mitigation |
|---|---|---|
| **Stale netns from a prior run** | "Address already assigned" on VIP; `:11111` unreachable | Pre-clean: `./rmconfig.sh; docker rm -f $(docker ps -aq); sudo ip -all netns delete` |
| **Non-local VIP** | All L7/TLS attaches show 0 entries; timeouts | VIP = the loxilb node's own address |
| **eBPF load race** | `HTTP 000` on the seed POST | Poll `GET /config/loadbalancer/all` to `200` before seeding |
| **Private ghcr backend images** | Backend containers fail to pull | `docker login ghcr.io` once on the runner with `$GHCR_TOKEN` |
| **Stale registry image** | Harness silently tests old binary | `make docker-u24` or `docker cp ./loxilb` into the containers |
| **socat banners for h2 gates** | h2 asserts can't see headers/cookies/redirects | Use real HTTP servers + h2c |
| **API readback under load** | `curl` GET returns empty → false "field=''" | `--max-time 8` + retry; the API is fine |
| **Counting log lines with `wc -l`** | Routing counts off | Count real traffic (`grep -c`), warm up first |
| **Concurrent gate runs** | netns collision; teardown wipes an active run | One gate at a time; don't background them |
| **CRL CA without `cRLSign`** | Revocation silently ineffective | Dedicated client CA with `cRLSign` |

> Keep this hard-won catalog of gate gotchas in mind (netns pre-clean, API readiness, in-container
> logs, spurious harness flakes) when diagnosing intermittent test failures.

---

## 7. Where to look next

- Build/test commands and the developer workflow: [Developer guide](07-developer-guide.md).
- Feature-specific behavior and field semantics: the feature docs (03–04).
