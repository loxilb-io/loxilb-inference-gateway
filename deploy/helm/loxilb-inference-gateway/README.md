# loxilb-inference-gateway Helm chart

One release for the inference-gateway stack: the loxilb data plane
(`charts/loxilb-igw`, a DaemonSet), the kube-loxilb controller
(`charts/kube-loxilb`, branch `feat/auth-annotation`) and the Gateway
API objects that express the endpoint-selection policy (`templates/inference/`:
GatewayClass, Gateway, one InferencePool + HTTPRoute per `inference.pools[]`).

By default loxilb selects endpoints itself (`epselect` chwbl / gpuaware /
wrr-hash, KV-exact, prefill/decode), and the pool's `loxilb.io/*` annotations
are the policy. `inference.externalEndpointPicker` points every pool at an
Endpoint Picker (EPP) instead, which the gateway asks per request over
ext_proc. The chart does not deploy the picker; install it beside the release.

## Install

The operator's guide, from prerequisites to troubleshooting, is
[`docs/HELM-INSTALL.md`](../../../docs/HELM-INSTALL.md); this README is the
chart's reference.

Prerequisites: Kubernetes >= 1.30, the Gateway API CRDs (v1.5.1, standard
channel) and the Inference Extension CRDs (v1.6.0). The pre-install hook checks
them and fails with the install commands when they are missing; set
`crds.installGatewayAPI=true` to have it apply them.

```bash
helm install igw deploy/helm/loxilb-inference-gateway -n kube-system \
  --set kube-loxilb.cidrPools.defaultPool=<VIP>/32 \
  --set kube-loxilb.image.repository=<image built from feat/auth-annotation> \
  --set kube-loxilb.image.tag=<tag>
helm test igw -n kube-system --logs
```

The VIP must be an address the loxilb node can bind (fullproxy binds a socket):
in the k3d testbed it is the node IP. With several loxilb instances the default
`kube-loxilb.setRoles` makes kube-loxilb elect the master that holds the VIP;
a standby keeps the rules without a listener until it takes the VIP over. The
published `kube-loxilb:latest` does not yet include the inference-gateway
integration; build `feat/auth-annotation` (830fa59 or later, which also carries
the credential-policy annotations and the `JWTAuthProfile` CRD this chart ships)
as `cicd/common/k8s-inference/k3d_common.sh` does.

`inference.pools[].auth` needs that kube-loxilb, a `JWTAuthProfile` per profile
name (phase 2 renders them) and a gateway with its API-key store configured
(`--aikey-db-*`): without the store the gateway refuses every verified token
with 503 `policy_store_unavailable`. NOTES.txt warns on each of these.

The chart is an ordinary Helm chart: `helm install` it directly as above. The
k3d scenario `cicd/k3d-helm-inference-gwapi` is only a wrapper that brings up a
cluster, the mock model servers and the CRDs and then runs the same `helm
install`, `helm test`, `helm upgrade`, `helm uninstall` and `helm install` again.

## Upgrade and uninstall

`helm upgrade` runs the CRD precheck again (pre-upgrade) and applies the changed
values; a change that touches only the Gateway objects restarts nothing.
`helm uninstall` first runs a pre-delete drain (`hooks.drain`): it deletes the
chart's HTTPRoutes and InferencePools while kube-loxilb is still running and
waits until the Services kube-loxilb derived from them are gone, because Helm
alone would delete the pools and kube-loxilb in one sweep and leave those
Services (and, on an external gateway, their rules) behind. Then every release
resource is removed. Left behind on purpose: the CRDs
(Helm never deletes `crds/`), loxilb's hostPath directories on the nodes
(`/etc/loxilb` with the snapshot, `/var/log/loxilb` with the audit trail). The
`helm test` pods stay after a test run so `helm test --logs` can read them; the
drain removes them at uninstall. A second `helm install` into
the same cluster is supported: the precheck finds the CRDs, Helm skips the ones
in `crds/` that exist, and loxilb replays the snapshot it left on the node.

## Values

| Key | What it does |
|---|---|
| `inference.gatewayClass`, `inference.gateway` | the GatewayClass and Gateway (namespace `llm` by default) |
| `inference.pools[]` | pod selector + targetPort, `modelName`, `epselect`, `sseMode`, free `annotations`, `auth`, `route` |
| `inference.externalEndpointPicker` | `enabled`, the picker Service `name` and `port` (9002), `failureMode` (FailOpen / FailClose) |
| `loxilb-igw.*` | image, flags (`loxilb.*`), hostPath persistence for `/etc/loxilb` and the audit dir (its parent is mounted; loxilb creates the 0700 directory itself), optional trust ConfigMap at `/run/integration-ca`, management Service |
| `kube-loxilb.*` | image, `cidrPools`, `setRoles`, `loxiURL` (external loxilb), `extraArgs`, the wait-for-loxilb initContainer |
| `crds.*` | pre-install check, `installGatewayAPI` |
| `tests.*` | `helm test` images and the loxilb URL they call |

`values-k3d-dev.yaml` is the profile `cicd/k3d-helm-inference-gwapi` installs;
it reproduces `cicd/k3d-incluster-inference-gwapi` so that scenario's
`validation.sh` is the chart's oracle.

## Layout and phases

This is phase 1 (core).
Keycloak (JWT profiles), SIEM (audit sink) and PostgreSQL (API-key store)
subcharts, with the `igw-configure` hook that applies REST-side configuration,
come next. The subcharts are vendored as directories under `charts/`; do not
run `helm dependency update` against them.
