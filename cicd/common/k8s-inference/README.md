# common/k8s-inference — shared testbed for the k3d in-cluster inference scenarios

Shared by [`k3d-incluster-inference-svc`](../../k3d-incluster-inference-svc) and
[`k3d-incluster-inference-gwapi`](../../k3d-incluster-inference-gwapi): both run
**loxilb-inference-gateway and kube-loxilb as Pods** inside a single-node k3d
cluster and validate the inference-gateway control path end to end.

| File | Role |
|---|---|
| `k3d_common.sh` | bring-up/teardown/assert helpers (cluster, images, loxilb, mock, kube-loxilb, client, REST/ss checks) |
| `loxilb-incluster.yml` | in-cluster loxilb DaemonSet + discovery Service, adapted for k3d (no `mkllb-cgroup` initContainer — the rancher/k3s node image has no bash — and no `--localsockpolicy`) |
| `mock-vllm.yaml` | `llm/vllm-qwen3` Deployment running `cicd/vllm-pd-disagg/mock_vllm.py` from a ConfigMap; OpenAI-shaped JSON, SSE for `stream:true`, pod identity via the `X-Served-By` header |
| `render-kube-loxilb.py` | rewrites the kube-loxilb checkout's `manifest/gateway-api/kube-loxilb.yaml` (image + args only) so RBAC changes there are picked up instead of drifting |

Design decisions (found the hard way — see the scenario READMEs):

- **VIP = the node container's IP.** fullproxy binds a socket, and an address
  loxilb owns only as a /32 rule device cannot be bound.
- **k3s >= 1.33, k3d >= 5.7.** Gateway API v1.5.1 CRDs use CEL `isIP()`
  (Kubernetes >= 1.30); older k3d cannot boot that k3s. A private k3d is
  downloaded to `.bin/` when the system one is too old.
- **kube-loxilb is built from `integration/inference-gateway`** at run time
  (no published image tag yet). Preset `KLB_IMAGE` to skip the build.

Knobs: `IGW_IMAGE`, `KLB_IMAGE`, `KLB_REPO`, `KLB_REF`, `K3S_IMAGE`,
`K3D_VERSION`, `CLIENT_IMAGE`, `GWAPI_VERSION`, `GIE_VERSION`.

Host requirements: docker, kubectl, git, curl, jq, python3 (+PyYAML).
