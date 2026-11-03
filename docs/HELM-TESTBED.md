# A test bed on an existing cluster: gateway, Endpoint Picker, Keycloak and SIEM

[`deploy/helm/testbed/igw-testbed.sh`](../deploy/helm/testbed/igw-testbed.sh)
builds a complete inference-gateway test bed on a Kubernetes cluster you
already have, in one command. It installs the Helm chart from
[HELM-INSTALL.md](HELM-INSTALL.md). Around it, it installs what the chart does
not ship yet:

- an Endpoint Picker in front of simulated model servers
- an API-key store
- an identity provider
- a syslog receiver

Then it wires all of them to the gateway. A second command sends requests
through the gateway and checks authentication, Endpoint Picker routing and
audit delivery.

The script is for evaluation and testing. Everything it creates uses test
credentials and pod-local storage; see [§7](#7-limits).

## 1. What it builds

```
client pod ──HTTP──► VIP:8080  loxilb-igw (DaemonSet, hostNetwork, on LOXILB_NODE)
                         │  JWT check against Keycloak's JWKS, key store in PostgreSQL
                         │  ext_proc (gRPC/TLS) ──► llm-d EPP ──► picks one model server
                         ├─ HTTP ──► llm-d inference-sim pods (the pool)
                         └─ audit trail, syslog over TLS ──► syslog receiver
kube-loxilb: InferencePool ──► Service ──► loxilb rule (eppEndpoint, api_key_auth=jwt)
```

| Component | Namespace | Source |
|---|---|---|
| loxilb-igw, kube-loxilb, GatewayClass, Gateway | `kube-system` (release `igw`); Gateway in `llm` | this repository's chart, `deploy/helm/loxilb-inference-gateway` |
| InferencePool, Endpoint Picker (EPP), HTTPRoute | `llm` (release `sim-pool`) | llm-d Router chart `llm-d-router-gateway`, cloned at `LLMD_REF` (v1.0.0) |
| Model servers, `SIM_REPLICAS` of them | `llm` | `ghcr.io/llm-d/llm-d-inference-sim` |
| PostgreSQL API-key store | `aigw` | `postgres`, bootstrapped with `scripts/aigw-db-bootstrap.sql` |
| Keycloak, realm `aigw` | `aigw` | `quay.io/keycloak/keycloak`, realm from `cicd/ai-jwtauth/mkrealm.py` imported at start |
| JWTAuthProfile `kc` | cluster | kube-loxilb CRD shipped with the chart |
| syslog receiver (RFC 5425, TLS) | `aigw` | `cicd/audit-sink/syslog_receiver.py` on `python:3.12-slim` |

The script connects them as follows:

- **Key store**: the gateway connects as `aigwuser` (`--aikey-db-*`). The
  password comes from a Secret.
- **JWT auth**: the pool carries `loxilb.io/api-key-auth: jwt`,
  `loxilb.io/jwt-auth-profile: kc` and `loxilb.io/sse-mode: "true"`. So one
  loxilb rule holds both the Endpoint Picker and the credential policy.
- **Audit sink**: the gateway's compliance sink points at the receiver. It
  verifies the receiver against a run CA, mounted through
  `loxilb-igw.trust`.

## 2. Before you start

**On your workstation**: `kubectl` with a context on the cluster, `helm` 3,
`git`, `openssl`, `python3` and `curl`. The script reaches the cluster only
through kubectl. The gateway's management API goes through a port-forward and
requests go through a client pod, so the workstation does not need to reach the
nodes.

**The cluster**:

- Kubernetes 1.30 or newer (the chart's `kubeVersion`).
- Nodes that can pull from `ghcr.io`, `quay.io` and Docker Hub.
- **One node for loxilb.** The VIP must be an address of that node, because
  fullproxy binds the listener to it.
  - Set `LOXILB_NODE` to the node's `kubernetes.io/hostname` and `VIP` to its
    address.
  - The script tolerates the control-plane taints, including the
    `node-role.kubernetes.io/etcd:NoExecute` that Rancher RKE2 puts on etcd
    nodes.
  - It keeps loxilb off Docker bridges (`docker.`, `br-.`) for nodes that also
    run Docker.
- Every node's `/etc/hosts` maps `localhost` to `127.0.0.1`. Some cloud images
  omit it, and then RKE2's kube-apiserver probes (`kubectl --server=https://localhost:6443`)
  fail inside the hostNetwork pod and the control plane restarts every few
  minutes. Check with
  `grep -E '^127\.0\.0\.1[[:space:]]+localhost' /etc/hosts`.

**A kube-loxilb image** from its `feat/auth-annotation` branch (commit 3c98a39
or later). That branch carries the Endpoint Picker and credential-policy
support, and no published tag has it yet. Either push it to a registry the
nodes can pull from and set `KLB_IMAGE`, or build it on `LOXILB_NODE` and import
it into the node's container runtime:

```bash
git clone -b feat/auth-annotation https://github.com/loxilb-io/kube-loxilb.git
docker build -t local/kube-loxilb:auth-annotation kube-loxilb
# RKE2: import into its containerd
docker save local/kube-loxilb:auth-annotation | \
  /var/lib/rancher/rke2/bin/ctr --address /run/k3s/containerd/containerd.sock -n k8s.io images import -
```

With an imported image, set `KLB_PULL_POLICY=Never`.

**A gateway image whose `/version` lists `epp`, `api_key_auth` and
`jwt_auth_profile`.** The default `ghcr.io/loxilb-io/loxilb-inference-gateway:latest`
has all three since the Endpoint Picker merge (2026-10-27). `up` warns if one is
missing.

## 3. Configure

Copy the example and set at least `VIP`, `KLB_IMAGE` and usually
`LOXILB_NODE`:

```bash
cd deploy/helm/testbed
cp testbed.env.example testbed.env
$EDITOR testbed.env
```

| Setting | Default | Meaning |
|---|---|---|
| `VIP` | (required) | address of `LOXILB_NODE`; the Gateway's address and the listener's bind address |
| `KLB_IMAGE` | (required) | kube-loxilb image, see §2 |
| `KLB_PULL_POLICY` | `IfNotPresent` | `Never` for an image imported on the node |
| `LOXILB_NODE` | empty | node loxilb and kube-loxilb are pinned to; empty means every control-plane node |
| `LISTENER_PORT` | `8080` | Gateway listener port |
| `IGW_IMAGE` | `ghcr.io/loxilb-io/loxilb-inference-gateway:latest` | gateway image |
| `MODEL` | `llama-70b` | model name the simulators serve. The realm grants alice `model:llama-70b` and bob `model:mistral-7b` |
| `SIM_REPLICAS` | `3` | model servers in the pool |
| `LLMD_REF`, `EPP_IMAGE_TAG` | `v1.0.0` | llm-d Router chart source and EPP image |
| `EPP_FAILURE_MODE` | `FailClose` | `FailOpen` lets loxilb's own selection serve while the EPP is down |
| `RELEASE`, `RELEASE_NS`, `LLM_NS`, `AIGW_NS`, `POOL` | `igw`, `kube-system`, `llm`, `aigw`, `sim-pool` | names |
| `EXTRA_VALUES` | empty | a values file for the gateway chart, applied after the generated one |
| `WORK` | `deploy/helm/testbed/_work` | generated values, certificates and the llm-d checkout |

Every setting can also be passed as an environment variable instead of a file.

## 4. Bring it up

```bash
./igw-testbed.sh -c testbed.env up
```

`up` is idempotent; run it again after changing the configuration. In order, it:

1. Installs the CRDs.
   - Gateway API CRDs only when missing. Clusters that already have them keep
     theirs; RKE2 1.36 ships v1.6.1 through its Traefik chart, and the gateway
     works with it.
   - The llm-d Router CRD set: InferencePool `v1` and the `llm-d.ai` objects
     its EPP watches.
2. Starts PostgreSQL and runs the bootstrap SQL. The passwords are random and
   kept in the Secret `aigw/aigw-db`.
3. Starts Keycloak with the generated realm. The admin password is random, in
   `aigw/keycloak-admin`. The issuer is pinned to the Keycloak Service address
   (`KC_HOSTNAME`), so a token minted through any URL carries the issuer the
   gateway expects.
4. Starts the syslog receiver. A run CA signs a server certificate whose SAN
   is the receiver Service's IP. The CA goes into the ConfigMap
   `aigw-integration-ca` the gateway mounts.
5. Installs the gateway chart (`helm upgrade --install`) with generated values
   (`$WORK/values-gateway.yaml`) and checks the image's `/version` features.
6. Starts the model servers and installs the llm-d Router chart. Then waits
   until kube-loxilb reports the InferencePool's endpoint picker as resolved.
7. Creates the JWTAuthProfile `kc`, waits until it is programmed on the
   gateway, and annotates the pool for JWT auth.
8. Points the gateway's audit sink at the receiver and waits until it is
   connected.

It ends with `status`: the pods, the Gateway, the pool's conditions, the
gateway's rules and the sink state.

## 5. Check it

```bash
./igw-testbed.sh -c testbed.env test               # auth, EPP routing, audit delivery
./igw-testbed.sh -c testbed.env test --failclose   # also: EPP down -> 503, back -> 200
```

A client pod mints tokens from Keycloak and sends requests to `VIP:LISTENER_PORT`:

| Check | Expected |
|---|---|
| no token | 401 |
| bob, who lacks the `model:` role | 403 |
| tampered token | 401 |
| alice, 10 requests | 10 × 200 |
| alice, `stream: true` | SSE `data:` lines |
| gateway log | one `[EPP] ... -> <pod>` decision per served request (11) |
| syslog receiver | more records than before, no framing or header errors |
| `--failclose` | EPP scaled to 0: 503 `epp_unavailable`; back to 1: 200 again |

The last line reads `RESULT: PASS` or `RESULT: FAIL`, and the exit code follows
it:

```
### requests from a client pod to 10.0.0.14:8080 (model llama-70b)
[OK]   no token: 401 (401)
[OK]   bob (no model:llama-70b role): 403 (403)
[OK]   tampered token: 401 (401)
[OK]   alice: 10 of 10 served (10)
[OK]   alice stream: SSE data lines (yes)
[OK]   every served request went through the EPP (11) (11)
[OK]   audit records reached the syslog receiver (yes)
[OK]   syslog framing/header errors (0/0)
### FailClose: EPP scaled to 0
[OK]   EPP down: request refused with 503 (503)
[OK]   EPP down: error epp_unavailable (yes)
### FailClose: EPP scaled back to 1
[OK]   EPP back: requests served again (200)

RESULT: PASS (11 checks)
```

That run was on a seven-node Rancher RKE2 v1.36.5 cluster (calico), with
loxilb on one control-plane node.

The script waits for the EPP pod to be gone before it expects the 503. The EPP
keeps answering on open streams during its termination grace period (130 s), so
requests sent while it terminates are still served.

To try requests yourself:

```bash
# a token for alice (the issuer is pinned, so a port-forward works)
kubectl -n aigw port-forward svc/keycloak 18080:8080 &
TOKEN=$(curl -s -d client_id=aigw-client -d username=alice -d password=alicepw \
  -d grant_type=password http://127.0.0.1:18080/realms/aigw/protocol/openid-connect/token | jq -r .access_token)
# from a host that reaches the VIP
curl http://<VIP>:8080/v1/chat/completions -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama-70b","messages":[{"role":"user","content":"hi"}]}'
# the gateway's management API
kubectl -n kube-system port-forward svc/loxilb-lb-mgmt 11111:11111 &
curl -s http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all | jq
# what the SIEM received
kubectl -n aigw port-forward svc/syslog 16515:6515 &
curl -s http://127.0.0.1:16515/__stats | jq
```

## 6. Status and teardown

```bash
./igw-testbed.sh -c testbed.env status
./igw-testbed.sh -c testbed.env down
```

`down` removes things in this order:

1. The audit sink is disabled.
2. The llm-d release goes first, so kube-loxilb is still running to remove the
   Service and rule it derived from the pool.
3. The JWTAuthProfile, the model servers and the gateway release.
4. The Secret and ConfigMap the script put into the release namespace, and the
   namespaces the script created. A namespace that existed before `up` is
   kept.

`down` leaves two things in place: the CRDs, and loxilb's node-local state on
`LOXILB_NODE` (`/etc/loxilb`, `/var/log/loxilb`). A later `up` replays that
snapshot. To start from scratch, remove those directories on the node after
`down`.

## 7. Limits

- **Test credentials.**
  - The realm's users have fixed passwords from `cicd/ai-jwtauth/mkrealm.py`
    (`alice`/`alicepw`, `bob`/`bobpw`, …).
  - Keycloak runs `start-dev` over plain HTTP.
  - Database and admin passwords are random but stored as ordinary Secrets.
- **No persistence.** PostgreSQL and the receiver keep their data in `emptyDir`.
  API keys, quotas and received audit records go with the pod.
- **One loxilb instance**, on `LOXILB_NODE`. With `LOXILB_NODE` empty, loxilb runs
  on every control-plane node, and the VIP has to be bindable on the master
  kube-loxilb elects.
- **The management API is unauthenticated** (no `--userservice`), as in the
  chart's default.
- **Simulated model servers.** Real vLLM on GPUs needs the NVIDIA device plugin
  or GPU Operator; replace the `sim` Deployment and keep the `app: <POOL>` label.

## 8. Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| kube-loxilb pod `ErrImageNeverPull` | `KLB_PULL_POLICY=Never` and the image is not on `LOXILB_NODE` | import it there (§2), or use a registry image |
| `up` warns the gateway does not list `epp` / `api_key_auth` | an older gateway image | set `IGW_IMAGE` to a build from `main` after 2026-10-27; a node may hold an older `:latest` (`IGW_PULL_POLICY` defaults to `Always`) |
| `timed out ... InferencePool ... to resolve` | the EPP Service is missing or kube-loxilb is not running | `kubectl -n llm get inferencepool <POOL> -o yaml`, `kubectl -n kube-system logs deploy/igw-kube-loxilb` |
| requests get 503 `policy_store_unavailable` | the gateway cannot reach its key store | `kubectl -n kube-system logs ds/igw-loxilb-igw \| grep AIKey`; the Secret `aigw-db-dp` must match `aigw/aigw-db` |
| 401 `invalid_token` with a fresh token | the token's `iss` differs from the profile's issuer | mint through Keycloak with `KC_HOSTNAME` set (the script does); check `kubectl get jwtauthprofile kc -o yaml` |
| audit sink not `connected` | the receiver's certificate or CA | the SAN must be the receiver Service IP; `kubectl -n kube-system get cm aigw-integration-ca` |
| control plane restarts every few minutes, first master stuck at `waiting for probes: calico` (RKE2) | `localhost` missing from `/etc/hosts` | §2 |
