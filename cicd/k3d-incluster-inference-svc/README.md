# k3d-incluster-inference-svc — inference gateway via Service annotations, in-cluster

loxilb-inference-gateway and kube-loxilb (branch `integration/inference-gateway`)
run **as Pods** in a single-node k3d cluster. An ordinary `LoadBalancer` Service
annotated with `loxilb.io/lbmode=fullproxy`, `usepodnetwork`, `epselect=chwbl`,
`chwbl-prefix-hash-level`, `sse-mode` and `model-name` must become a working
inference rule; a `chwbl`+`onearm` Service must be refused with an event.

Backends are mock vLLM pods (`cicd/vllm-pd-disagg/mock_vllm.py` via ConfigMap):
OpenAI-shaped JSON, SSE for `stream:true`, and an `X-Served-By: <pod>` header —
the delivery proof that says *which* endpoint served, which a 200 alone cannot.

```
host ── docker network k3d-igw-svc
        ├── k3d-igw-svc-server-0        k3s v1.33 node (privileged container)
        │     ├── loxilb-lb DaemonSet   hostNetwork; REST :11111; VIP = node IP
        │     ├── kube-loxilb           built from integration/inference-gateway
        │     └── llm/vllm-qwen3 ×2     mock vLLM pods (10.42.0.0/16)
        └── igw-client-igw-svc          curl client
```

## Run

```bash
./config.sh       # ~3 min: cluster, images, loxilb, mocks, kube-loxilb, services
./validation.sh   # the assertions below
./rmconfig.sh     # teardown (cluster + client)
```

## What is asserted

| # | Check | Proves |
|---|---|---|
| 1 | Service EXTERNAL-IP = `llb-<node-ip>` | kube-loxilb found in-cluster loxilb and allocated from the pool |
| 2 | rule: `sel=8` `mode=4` `model_name` `chwbl_prefix_hash_level=2` `sse_mode` + `host`/`path_prefix`/`path_match_mode` | flavor detected; inference fields and the L7 lookup key are on the wire |
| 3 | rule endpoints = pod IPs | `usepodnetwork` produced pod endpoints |
| 4 | socket bound on VIP:8000 (`/proc/net/tcp` in the node netns) | `mode=4` is real — a rule that failed to bind reads back identically over REST |
| 5 | request naming the model → 200, `X-Served-By` ∈ pods | traffic traverses proxy → pod |
| 6 | unknown model → 503 `model_unavailable` | `model_name` selects rather than decorates |
| 7 | identical prompt ×5 → one pod | CHWBL prefix-hash affinity |
| 8 | `stream:true` → `data:` events + `[DONE]` | SSE path through fullproxy |
| 9 | valid Service: no warnings; `chwbl`+`onearm`: `InvalidInferenceConfig`, no IP, no rule | refusal is loud, not a silent downgrade |
| 10 | scale 2→3 → 3 endpoints; delete Service → rule gone | reconcile and the L7-keyed delete (needs the kube-loxilb delete fix) |

Environment knobs are documented in [`common/k8s-inference`](../common/k8s-inference/README.md).
