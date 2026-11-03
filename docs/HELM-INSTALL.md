# Install on Kubernetes with Helm

The chart in [`deploy/helm/loxilb-inference-gateway`](../deploy/helm/loxilb-inference-gateway)
installs the inference-gateway stack in one release: the loxilb data plane as a
DaemonSet, the kube-loxilb controller that turns Gateway API objects into loxilb
rules, and the GatewayClass, Gateway, InferencePool and HTTPRoute objects that
describe your model-server pools. This guide is for operators who install the
chart on their own cluster. The chart's own [README](../deploy/helm/loxilb-inference-gateway/README.md)
has the values table; `cicd/k3d-helm-inference-gwapi` is a complete, runnable
example on a throw-away k3d cluster.

Throughout, the release is called `igw` and installed into `kube-system`, the
namespace the chart was validated in. Model servers live in a namespace called
`llm`. Change the names as you like; the commands use them literally.

## 1. What a release contains

| Component | Resource | Notes |
|---|---|---|
| loxilb-inference-gateway (subchart `loxilb-igw`) | DaemonSet `igw-loxilb-igw`, Services `loxilb-lb-service` (headless discovery) and `loxilb-lb-mgmt` (management REST, port 11111) | privileged, hostNetwork, placed on control-plane nodes by default |
| kube-loxilb (subchart `kube-loxilb`) | Deployment `igw-kube-loxilb`, ServiceAccount, ClusterRole, loxilb CRDs (`crds/`) | finds loxilb through `loxilb-lb-service`; waits for its REST before starting |
| Inference objects | GatewayClass `loxilb-gc`, Gateway `inference-gw`, one InferencePool + HTTPRoute per `inference.pools[]` | kube-loxilb derives a LoadBalancer Service `<pool>-inference` and a fullproxy rule from each pool |
| Hooks | Job `igw-loxilb-inference-gateway-crd-precheck` (pre-install, pre-upgrade), Job `igw-loxilb-inference-gateway-drain` (pre-delete) | hook resources are not part of the release and are cleaned up by Helm |
| Tests | Pods `igw-loxilb-inference-gateway-test-igw-version` and `-test-pool-rule` | run by `helm test`; see §5 |

By default loxilb selects endpoints itself; the pool's `loxilb.io/*`
annotations, rendered from `inference.pools[]`, are the policy. A pool can
instead name an Endpoint Picker (EPP) that the gateway asks per request (§9).
The chart does not deploy the picker: it is a separate install.

## 2. Prerequisites

### 2.1 Cluster

- Kubernetes 1.30 or newer. The Gateway API v1.5.1 CRDs use CEL functions
  that older API servers do not have, and the chart's precheck hook fails
  below that.
- Helm 3.
- Nodes that will run loxilb: the DaemonSet runs privileged with hostNetwork,
  tolerates the control-plane taints and, by default, is pinned to nodes with
  the `node-role.kubernetes.io/control-plane` label (`loxilb-igw.affinity`,
  `loxilb-igw.tolerations`, `loxilb-igw.nodeSelector`). The eBPF data plane
  needs a recent kernel; see the
  [system requirements](https://loxilb-io.github.io/loxilbdocs-inference-gateway/latest/reference/system-requirements/).
  loxilb keeps its snapshot in `/etc/loxilb` and its audit trail under
  `/var/log/loxilb` on each node (hostPath, created on demand).
- The release namespace. `kube-system` is the one the chart was validated in;
  kube-loxilb runs with `priorityClassName: system-node-critical`, which some
  clusters restrict to `kube-system` (set `kube-loxilb.priorityClassName`
  otherwise).

### 2.2 Gateway API and Inference Extension CRDs

The Gateway API and Gateway API Inference Extension CRDs are a cluster-wide
version decision and belong to their projects, so the chart does not ship them.
The tested versions are Gateway API **v1.5.1, standard channel** and
Inference Extension **v1.6.0**. Install them before the chart:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
kubectl apply -k "https://github.com/kubernetes-sigs/gateway-api-inference-extension/config/crd?ref=v1.6.0"
```

or let the chart's pre-install hook apply them with `--set crds.installGatewayAPI=true`.

The pre-install and pre-upgrade hook checks them. It fails when they are
missing or when the Inference Extension is older than v1.6.0 (there
`InferencePool.spec.endpointPickerRef` is required and this chart renders pools
without one). A different bundle version only produces a warning unless
`crds.precheck.strictVersion=true`. The six loxilb CRDs (LoxiURL, BGP peers and
policies, Egress) and `JWTAuthProfile` ship in the kube-loxilb subchart's
`crds/` directory and follow Helm's rules for that directory: installed on the
first install, never upgraded or deleted by Helm.

### 2.3 Images

| Image | Default | What to do |
|---|---|---|
| loxilb-inference-gateway | `ghcr.io/loxilb-io/loxilb-inference-gateway:v0.9.9.1` (Ubuntu 22.04 base) | use a tag you have tested, or build your own per [BUILD.md](BUILD.md); for the Endpoint Picker and authenticated pools it must list `epp`, `api_key_auth` and `jwt_auth_profile` (below) |
| kube-loxilb | `ghcr.io/loxilb-io/kube-loxilb:latest` | **must be built**: no published tag carries the inference-gateway integration, and `:latest` does not know `--inferenceExtension` |
| precheck, drain and `helm test` helpers | `alpine/k8s:1.34.12`, `curlimages/curl:8.23.0` | mirror them in a private registry if your nodes cannot reach Docker Hub (`crds.precheck.image`, `hooks.drain.image`, `tests.curlImage`, `tests.kubectlImage`) |

Build kube-loxilb from the `feat/auth-annotation` branch, commit 830fa59 or
later. That branch has the Gateway API inference integration, carries the
credential-policy annotations into the loxilb rule and manages the
`JWTAuthProfile` CRD the chart ships. Older integration branches work for pools
without authentication but install authenticated pools **without** their
policy (§8).

```bash
git clone --depth 1 -b feat/auth-annotation https://github.com/loxilb-io/kube-loxilb.git
docker build -t registry.example.com/kube-loxilb:auth-annotation-830fa59 kube-loxilb
docker push registry.example.com/kube-loxilb:auth-annotation-830fa59
```

Then set `kube-loxilb.image.repository` and `kube-loxilb.image.tag`. NOTES
warns as long as the tag is `latest`. Pull secrets for every pod of every
subchart go in `global.imagePullSecrets`.

kube-loxilb checks what the gateway image can enforce in `/netlox/v1/version`
under `features` before it sends a rule: `epp` for an Endpoint Picker (§9),
`api_key_auth` and `jwt_auth_profile` for authenticated pools (§8). The default
`v0.9.9.1` lists all three, as does a `main` build since the Endpoint Picker
merge (2026-10-27). If you override the tag: a `:latest` a node pulled before
that merge does not list `epp`, and with the default
`pullPolicy: IfNotPresent` it stays; pull it again or pin a newer tag. Check a
running gateway with:

```bash
kubectl -n kube-system run igw-version --rm -i --restart=Never --image=curlimages/curl:8.23.0 -- \
  curl -s http://loxilb-lb-mgmt.kube-system.svc:11111/netlox/v1/version
```

### 2.4 The VIP

kube-loxilb assigns the Gateway its address from `kube-loxilb.cidrPools`.
InferencePool rules run in fullproxy mode, and fullproxy **binds a socket** on
the address, so the VIP has to be an address the loxilb node owns: in practice
the node IP of the node that runs loxilb, or a secondary address you configured
on that node. An address that is only routed or announced to the node, but not
configured on one of its interfaces, does not work here: the gateway refuses
the rule with 400, `externalIP <VIP> is not an address of this gateway`, and
kube-loxilb reports `LoxiLBRejected`. Give the pool as a single-host range:

```bash
--set kube-loxilb.cidrPools.defaultPool=<VIP>/32
```

With several loxilb instances (several control-plane nodes), the default
`kube-loxilb.setRoles` makes kube-loxilb elect the master that holds the VIP;
a standby keeps the rules without a listener until it takes the VIP over. This
layout is not yet covered by a scenario in this repository.

### 2.5 Namespaces and model servers

The chart creates no namespaces and no model servers. Before `helm install`:

- The Gateway namespace (`inference.gateway.namespace`, default `llm`) and each
  pool's namespace (`inference.pools[].namespace`, default `llm`) must exist:
  `kubectl create namespace llm`.
- The model-server pods must carry the labels in `inference.pools[].selector`
  and serve the OpenAI-style API on `inference.pools[].targetPort`. kube-loxilb
  builds the rule's endpoints from those pods; a pool whose selector matches
  nothing produces a rule with no endpoints.

## 3. Values

Write a values file. Do not pass pool fields with `--set inference.pools[0].…`:
Helm replaces the whole list and the pool loses the defaults it did not name.

```yaml
# my-values.yaml
kube-loxilb:
  image:
    repository: registry.example.com/kube-loxilb
    tag: auth-annotation-830fa59
  cidrPools:
    defaultPool: 10.0.0.10/32          # the loxilb node's address

loxilb-igw:
  image:
    repository: ghcr.io/loxilb-io/loxilb-inference-gateway
    tag: v0.9.9.1

inference:
  gateway:
    name: inference-gw
    namespace: llm
    listeners:
      - name: http
        protocol: HTTP
        port: 8080
        allowedRoutes:
          namespaces:
            from: All
  pools:
    - name: vllm-qwen3
      namespace: llm
      selector:
        app: vllm-qwen3
      targetPort: 8000
      modelName: qwen3-32b
      epselect: chwbl
      sseMode: true
      auth:
        mode: none
      route:
        name: llm-route
```

| Values | What they set |
|---|---|
| `kube-loxilb.cidrPools`, `kube-loxilb.setRoles`, `kube-loxilb.image`, `kube-loxilb.extraArgs` | the VIP pool, the master election, the controller image, further `kube-loxilb` flags |
| `kube-loxilb.loxiURL` with `loxilb-igw.enabled=false` | drive an external loxilb-inference-gateway instead of the in-cluster DaemonSet |
| `loxilb-igw.image`, `loxilb-igw.loxilb.*` | the gateway image and its flags: `egrHooks`, `blacklist`, `configPath`, `audit.dir`, `audit.required`, `mgmtProfile`, free `extraArgs` |
| `loxilb-igw.persistence` | hostPath for `/etc/loxilb` (snapshot) and `/var/log/loxilb` (audit) |
| `loxilb-igw.tls`, `loxilb-igw.trust` | TLS on the management REST from an existing Secret; a CA bundle ConfigMap mounted at `/run/integration-ca` for JWKS and audit-sink TLS |
| `loxilb-igw.mgmtService` | the ClusterIP in front of the management REST that hooks and tests use |
| `inference.gatewayClass`, `inference.gateway` | the GatewayClass and the Gateway with its listeners |
| `inference.pools[]` | one InferencePool + HTTPRoute each, see below |
| `inference.externalEndpointPicker` | an Endpoint Picker for every pool (§9) |
| `crds.*` | the precheck hook and `installGatewayAPI` |
| `hooks.drain.*` | the pre-delete drain (§7) |
| `tests.*` | the `helm test` pods and the loxilb URL they call |

Each pool field maps to an annotation kube-loxilb reads:

| Pool field | Annotation | Meaning |
|---|---|---|
| `modelName` | `loxilb.io/model-name` | the `model` a request has to name to be routed to this pool |
| `epselect` | `loxilb.io/epselect` | endpoint selection: `chwbl`, `gpuaware`, `wrr-hash` |
| `sseMode` | `loxilb.io/sse-mode` | SSE-aware streaming; also arms API-key and rate-limit enforcement on the rule |
| `auth.mode`, `auth.jwtAuthProfile` | `loxilb.io/api-key-auth`, `loxilb.io/jwt-auth-profile` | credential policy, §8; `none` renders no annotation |
| `annotations` | verbatim | any other `loxilb.io/*` annotation (`kv-exact-mode`, `pd-disagg`, `chwbl-*`, …) |
| `route.hostnames`, `route.matches` | HTTPRoute `hostnames`, `rules[0].matches` | optional; an empty `matches` routes the `/` prefix |

`lbmode=fullproxy` and `usepodnetwork=yes` are imposed by kube-loxilb on every
InferencePool and are therefore not values.

Every pool attaches to every listener of the Gateway and becomes its own
LoadBalancer Service on the Gateway address and the listener port. Two pools on
one listener therefore compete for the same address and port, and kube-loxilb
reports `ExternalIPUnavailable` on the one that loses. The validated layout is
one pool per Gateway; routing several models through one port is not expressed
by this chart yet.

## 4. Install

```bash
helm install igw deploy/helm/loxilb-inference-gateway -n kube-system \
  -f my-values.yaml --wait --timeout 10m
```

What happens, in order: the precheck Job runs and checks (or applies) the CRDs;
Helm installs the loxilb CRDs from `crds/`; the loxilb DaemonSet starts; the
kube-loxilb Deployment starts, its `wait-for-loxilb` initContainer polling
`loxilb-lb-service` until `/netlox/v1/version` answers with the
`loxilb-inference-gateway` product; the GatewayClass, Gateway, InferencePool
and HTTPRoute are created and kube-loxilb turns each pool into a Service and a
loxilb rule. `--wait` returns when the DaemonSet and the Deployment are ready;
the rule follows a few seconds later.

Read the NOTES Helm prints. They list what was installed, the prerequisite
commands if the precheck failed, and **Warnings** for the situations in which a
release installs but does not do what the values ask: authentication set with a
kube-loxilb that may not carry it, JWT profiles that need a `JWTAuthProfile`, a
gateway without an API-key store, the `latest` kube-loxilb tag.

## 5. Verify

```bash
helm test igw -n kube-system --logs
```

Two pods run. `test-igw-version` calls the management REST and checks the
product is `loxilb-inference-gateway`. `test-pool-rule` checks, per pool and
listener, the chain that makes a pool reachable: kube-loxilb created the
Service `<pool>-inference` with the fullproxy and pod-network annotations, the
selector, the listener port and the pool's targetPort; the Service was given
the Gateway address; and loxilb holds a rule on that address and port in
fullproxy mode, with the declared `epselect` and `model_name`, with the pool's
pods as endpoints and with the host and path keys the request is matched on.
The test pods stay after the run so
`--logs` can read them and a failure can be inspected; the next `helm test`
replaces them and `helm uninstall` removes them.

Then look at the objects:

```bash
kubectl -n llm get gateway,httproute,inferencepool
kubectl -n llm get svc -l loxilb.io/inference-pool
kubectl -n kube-system get ds,deploy,svc -l app.kubernetes.io/instance=igw
```

The Gateway's `ADDRESS` is the VIP; the InferencePool should be `Accepted` and
the derived Service should show that address under `EXTERNAL-IP`. The rule as
loxilb holds it:

```bash
kubectl -n kube-system port-forward svc/loxilb-lb-mgmt 11111:11111 &
curl -s http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all | jq '.lbAttr[] | .serviceArguments'
```

Finally send a request through the VIP from a host that can reach it:

```bash
curl -s http://<VIP>:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen3-32b","messages":[{"role":"user","content":"hello"}]}'
```

## 6. Upgrade

```bash
helm upgrade igw deploy/helm/loxilb-inference-gateway -n kube-system \
  -f my-values.yaml --wait --timeout 10m
```

The precheck Job runs again (pre-upgrade) and the changed values are applied in
place. A change that touches only the Gateway objects or the pool annotations
restarts nothing: kube-loxilb updates the rule. A change to the loxilb image or
flags rolls the DaemonSet one node at a time; each instance replays its
snapshot from `/etc/loxilb` on start, and kube-loxilb reconciles the rules.
`helm rollback igw <revision>` works the same way.

Helm does not upgrade what is in `crds/`. When a newer chart changes the loxilb
CRDs, apply them yourself before the upgrade:

```bash
kubectl apply -f deploy/helm/loxilb-inference-gateway/charts/kube-loxilb/crds/
```

The Gateway API and Inference Extension CRDs are upgraded the way they were
installed (§2.2); the precheck warns when the bundle version differs from the
tested one.

## 7. Uninstall

```bash
helm uninstall igw -n kube-system
```

A pre-delete hook (`hooks.drain`) runs first: it deletes the chart's HTTPRoutes,
then its InferencePools, while kube-loxilb is still running, and waits (up to
`hooks.drain.timeoutSeconds`, 120 s by default) until the Services kube-loxilb
derived from them are gone. Without it, Helm would delete the pools and the
controller in one sweep and leave those Services behind, with their rules still
programmed on an external gateway. The drain also removes the `helm test` pods.
A drain timeout is reported as a warning and does not block the uninstall. Then
every release resource is removed.

Left behind on purpose:

- the CRDs, both the loxilb ones from `crds/` and the Gateway API and Inference
  Extension ones you installed in §2.2 (deleting a CRD deletes every custom
  resource of that kind cluster-wide, so this is never automatic);
- loxilb's hostPath directories on the nodes, `/etc/loxilb` with the snapshot
  and `/var/log/loxilb` with the audit trail;
- the `llm` namespace and the model servers, which were never the chart's.

A second `helm install` into the same cluster is supported: the precheck finds
the CRDs, Helm skips the ones in `crds/` that exist, and loxilb replays the
snapshot it left on the node. Remove `/etc/loxilb` on the nodes first if you
want a clean gateway instead.

## 8. Pools with authentication

`inference.pools[].auth` declares the credential policy of a pool:

| `auth.mode` | Rule field | Requests admitted |
|---|---|---|
| `none` (default) | unset | all; the gateway proxies `X-Api-Key` and `Authorization` untouched |
| `required` | `api_key_auth: required` | those with a valid API key from the key store |
| `jwt` | `api_key_auth: jwt` + `jwt_auth_profile` | those with a JWT the named profile verifies |
| `apikey-or-jwt` | `api_key_auth: apikey-or-jwt` + `jwt_auth_profile` | either |

Four conditions have to hold before such a pool does what it declares. NOTES
warns about the ones the chart can see; none of them is checked by `helm test`
in this chart version.

1. **kube-loxilb from `feat/auth-annotation` 830fa59 or later.** Older
   integration branches ignore the two annotations and install the rule without
   any policy, with no error anywhere. Check that the CRD it manages is served
   and that the rule reads back with the field:

   ```bash
   kubectl get crd jwtauthprofiles.jwtauthprofile.loxilb.io
   curl -s http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all | jq '.lbAttr[].serviceArguments | {port, api_key_auth, jwt_auth_profile}'
   ```

2. **An API-key store.** The gateway fails closed: a request that carries an
   identity but has no store to check it against is refused with 503
   `policy_store_unavailable`, and that includes a **verified JWT** on a
   JWT-only pool. Point the gateway at the PostgreSQL store described in
   [AI-KEY-STORE.md](AI-KEY-STORE.md) through `loxilb-igw.loxilb.extraArgs`,
   and mount the password file from a Secret (never put the password in an
   argument):

   ```yaml
   loxilb-igw:
     loxilb:
       extraArgs:
         - --aikey-db-host=postgres.aigw.svc
         - --aikey-db-port=5432
         - --aikey-db-user=aigwuser
         - --aikey-db-name=loxilb
         - --aikey-db-password-file=/run/secrets/aikey-db/password
     extraVolumes:
       - name: aikey-db
         secret:
           secretName: aigw-db
     extraVolumeMounts:
       - name: aikey-db
         mountPath: /run/secrets/aikey-db
         readOnly: true
   ```

   A later chart phase bundles PostgreSQL; this one needs an existing database.

3. **A `JWTAuthProfile` per profile name**, for the `jwt` and `apikey-or-jwt`
   modes. The resource is cluster-scoped and its name is the value of
   `auth.jwtAuthProfile`. kube-loxilb registers it on every gateway that
   advertises `jwt_auth_profile` in `/netlox/v1/version` and holds the pool's
   rule (`ProfileNotFound`, then `ProfileNotProgrammed`) until the profile is on
   every gateway. This chart version does not render profiles; create them by
   hand:

   ```yaml
   apiVersion: jwtauthprofile.loxilb.io/v1
   kind: JWTAuthProfile
   metadata:
     name: keycloak-main
   spec:
     issuer: https://keycloak.example.com/realms/llm
     audiences: ["llm-gateway"]
     # jwksUrl, algs, leewaySec, refreshSec, tenantClaim, defaultTenant,
     # userClaim, usernameClaim, modelsClaim, rolesClaim, modelRolePrefix,
     # modelAuthz, forwardIdentity, authorizationPassthrough, priorityClass
   ```

   `kubectl get jwtauthprofile` shows a `PROGRAMMED` column; `status.peers`
   names the gateway that is missing it. An issuer reached over TLS with a
   private CA needs `loxilb-igw.trust` (a ConfigMap of PEM files).

4. **One policy per listener.** The gateway reads the credential policy once per
   listener (address, port, protocol), before a request is matched to a rule.
   Every pool that attaches to the same listener must therefore declare the same
   `auth.mode` and `auth.jwtAuthProfile`; the gateway refuses a rule that
   disagrees with 400, and kube-loxilb reports `ListenerAuthConflict` on it. An
   unset policy (`none`) and an explicit `disabled` written through
   `annotations` are different values.

Set `sseMode: true` on an authenticated pool: enforcement (key validation and
rate limiting) engages on fullproxy rules with `sse_mode`. The full semantics,
the key lifecycle and the data-plane behaviour are in
[AI Gateway Controls](load-balancing/19-ai-gateway-controls.md).

A complete pool:

```yaml
inference:
  pools:
    - name: vllm-qwen3
      namespace: llm
      selector:
        app: vllm-qwen3
      targetPort: 8000
      modelName: qwen3-32b
      epselect: chwbl
      sseMode: true
      auth:
        mode: apikey-or-jwt
        jwtAuthProfile: keycloak-main
      route:
        name: llm-route
```

After the install, a request without a credential should get 401 and a request
with a key from the store (or a token from the issuer) should be served.

## 9. Pools with an Endpoint Picker

An Endpoint Picker (for example the [llm-d Router](https://github.com/llm-d/llm-d-router)
EPP) chooses the model-server pod for each request from the servers' own
metrics. With `inference.externalEndpointPicker.enabled=true` every pool
the chart renders gets an `endpointPickerRef`:

```yaml
inference:
  externalEndpointPicker:
    enabled: true
    name: vllm-qwen3-epp      # the picker's Service, in each pool's namespace
    port: 9002                # its ext_proc port
    failureMode: FailOpen     # or FailClose
```

What happens to a request:

1. kube-loxilb resolves the Service to its cluster IP and port and puts it on
   the pool's rule (`eppEndpoint`, `eppFailureMode`). The address is a cluster
   IP, so the node running loxilb has to reach Service IPs; with kube-proxy or
   an eBPF replacement on that node it does.
2. The gateway asks the picker over ext_proc (gRPC, TLS by default, certificate
   not verified) which pod serves the request, and proxies it there.
3. When the picker cannot be reached, `failureMode` decides. `FailOpen`:
   loxilb's own selection (`epselect`) serves the request. `FailClose`: the
   gateway answers 503 `epp_unavailable` and nothing reaches the model
   servers.

Four things to know:

- **The chart does not deploy the picker.** Install it beside the release, so
  that the Service `name` exists in each pool's namespace. Until it does, the
  pool's `ResolvedRefs` condition is False (`InvalidExtensionRef`): `FailOpen`
  pools are served by loxilb, and `FailClose` pools answer every request with
  503.
- **The gateway needs the picker client.** Only a build that lists `epp` under
  `features` in `/netlox/v1/version` calls the picker; v0.9.9.1 and `main`
  builds since 2026-10-27
  do (§2.3). On any other build kube-loxilb sends a `FailOpen` rule without the
  picker, with a warning event, and refuses a `FailClose` one
  (`EndpointPickerUnsupported`).
- **Tuning is per pool, through `annotations`.** `loxilb.io/epp-timeout-ms`
  sets the picker deadline, including the dial (default 3000).
  `loxilb.io/epp-plaintext: "true"` is for a picker that serves ext_proc
  without TLS; set it only when the picker does.
- **Not with prefill/decode.** A pool with a picker cannot also set
  `loxilb.io/pd-disagg`; kube-loxilb refuses it, because the picker
  orchestrates prefill and decode itself.

## 10. Troubleshooting

Start with the events kube-loxilb raises on the pool's Service and the
InferencePool status; most problems surface there with a reason:

```bash
kubectl -n llm describe inferencepool vllm-qwen3
kubectl -n llm get events --field-selector involvedObject.name=vllm-qwen3-inference
kubectl -n kube-system logs deploy/igw-kube-loxilb
```

| Reason | Meaning | What to do |
|---|---|---|
| `ExternalIPUnavailable` | no address and port could be allocated; retried | another pool or Service already holds the VIP and listener port, or `cidrPools` is exhausted |
| `InvalidInferenceConfig` | the annotations are malformed or combine options loxilb rejects | fix the pool fields or free-form `annotations` |
| `InferenceGatewayRequired` | the loxilb reached is plain upstream loxilb, not loxilb-inference-gateway | check `loxilb-igw.image` or `kube-loxilb.loxiURL` |
| `LoxiLBRejected`, `RuleMissing` | the gateway refused the rule, or the rule disappeared from it | read the gateway's answer in the kube-loxilb log; the gateway's own log names the reason |
| `AuthNotSupported` | the pool declares a policy and a gateway does not enforce it | upgrade the gateway image; the rule is not sent to that peer |
| `ListenerAuthConflict` | another pool on the same listener declares a different policy | §8, condition 4 |
| `EndpointPickerUnsupported` | a `FailClose` pool on a gateway without the picker client | use a gateway image that lists `epp` (§2.3, §9) |
| `ProfileNotFound`, `ProfileNotProgrammed` | the named `JWTAuthProfile` does not exist, or is not on every gateway yet | create it, then check its `PROGRAMMED` column and `status.peers` |
| `KvExactTokenizerRequired`, `GPUMonitoringDisabled` | the routing mode needs a tokenizer or GPU monitoring that is not armed in loxilb | configure loxilb for that mode or choose another `epselect` |

Other symptoms:

- **`helm install` fails in the pre-install hook.** The hook's pod is kept so
  it can be read: `kubectl -n kube-system logs job/igw-loxilb-inference-gateway-crd-precheck`.
  Missing CRDs: install them (§2.2) or set `crds.installGatewayAPI=true`. The
  failed release stays in Helm's history: `helm uninstall igw -n kube-system`,
  then install again.
- **kube-loxilb stays in `Init`.** Its `wait-for-loxilb` initContainer has not
  seen loxilb's REST answer with the expected product (default timeout 600 s):
  `kubectl -n kube-system logs deploy/igw-kube-loxilb -c wait-for-loxilb`. Check
  the DaemonSet is running on a node (`kubectl -n kube-system get ds,pod -l
  app.kubernetes.io/instance=igw -o wide`), that the node matches
  `loxilb-igw.affinity`, and that `loxilb-lb-service` has endpoints.
- **kube-loxilb crashes with `flag provided but not defined: -inferenceExtension`.**
  The image is the published `:latest`; build `feat/auth-annotation` (§2.3).
- **The gateway answers 503 `audit_unavailable` and kube-loxilb programs
  nothing.** The audit directory on the node has the wrong mode. The chart
  mounts the parent (`/var/log/loxilb`) so that loxilb creates
  `/var/log/loxilb/audit` itself with mode 0700; a directory that already
  existed with 0755 (for instance pre-created by hand, or by an older
  manifest's hostPath) is refused. On the node: `chmod 0700 /var/log/loxilb/audit`
  or remove it and let loxilb recreate it.
- **The rule exists but requests time out.** The pool's selector matches no
  pods, or the pods do not listen on `targetPort`:
  `kubectl -n llm get endpointslices -l kubernetes.io/service-name=vllm-qwen3-inference`.
- **`LoxiLBRejected` with `externalIP … is not an address of this gateway`.**
  The VIP is not configured on the loxilb node (§2.4). Only a standby instance
  keeps such a rule, without a listener, until it takes the VIP over; a single
  instance or the master refuses it.
- **Requests get 503 `epp_unavailable`.** A `FailClose` pool whose picker is
  not reachable: its Service is missing (`ResolvedRefs` False on the pool), it
  has no ready pod, or it does not answer within `loxilb.io/epp-timeout-ms`.
  The gateway's log names the reason; with TLS on one side only, set
  `loxilb.io/epp-plaintext` to match the picker (§9).
- **Requests get 503 `policy_store_unavailable`.** The pool declares a policy and
  the gateway has no API-key store (§8, condition 2).
- **A rule is refused with 400 `… is already on this address, port and protocol
  with a different value`.** Two pools on one listener with different `auth`
  (§8, condition 4).
- **`helm uninstall` reported a drain timeout and a Service `<pool>-inference`
  survives.** Delete it by hand: `kubectl -n llm delete svc -l loxilb.io/inference-pool`.
  On an external gateway also delete the rule through its REST.
- **Images imported into a local cluster are not found.** On Docker 29 with the
  containerd image store, `k3d image import` needs an explicit
  `docker save --platform`; `cicd/common/k8s-inference/k3d_common.sh` shows the
  working sequence.

## 11. A reference run

`cicd/k3d-helm-inference-gwapi` does everything above on a k3d cluster: it
builds kube-loxilb from `feat/auth-annotation`, installs the Gateway API and
Inference Extension CRDs, starts mock model servers in `llm`, runs `helm
install` with `values-k3d-dev.yaml` and the node IP as VIP, runs `helm test`,
replays the assertions of `cicd/k3d-incluster-inference-gwapi` against the
release, and then walks it through `helm upgrade`, `helm uninstall` and a
second `helm install`. Its `config.sh` is the install command above with the
values a real cluster would get from you.
