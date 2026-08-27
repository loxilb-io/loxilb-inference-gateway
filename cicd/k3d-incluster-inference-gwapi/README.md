# k3d-incluster-inference-gwapi — InferencePool end to end, in-cluster

The Gateway API path of the inference gateway, on the same in-cluster topology
as [`k3d-incluster-inference-svc`](../k3d-incluster-inference-svc): loxilb and
kube-loxilb (`integration/inference-gateway`, started with `--gatewayAPI
--inferenceExtension`) run as Pods in a single-node k3d cluster. An
`InferencePool` referenced from an HTTPRoute must become a LoadBalancer Service,
then an inference rule on loxilb, then served traffic.

The checks are ported from kube-loxilb's `test/e2e-inference-gwapi` (which runs
loxilb as an external container) — same assertions, same reasons:

1. the pool becomes `vllm-qwen3-inference` with `fullproxy`/`usepodnetwork` imposed
2. the Service carries the gateway's address
3. the rule has `sel=8`/`mode=4`/`model_name`, pod endpoints, and the
   `host`/`path_prefix`/`path_match_mode` lookup key — plus: exactly one rule on
   the listener, no `<gw>-ingress-service` for it, and a socket actually bound
4. `status.parents[]` reports Accepted/ResolvedRefs under the right Gateway
5. `endpointPickerRef` + `FailClose` is refused (`NotSupportedByParent`), no Service
6. switching to `FailOpen` accepts it (status polled — it lands a moment after the Service)
7. deleting the route deletes the Service **and its loxilb rule** (needs the
   kube-loxilb L7-keyed delete fix)
8. a request naming the model is answered by a pool pod (`X-Served-By`), an
   unknown model gets 503, and `stream:true` yields SSE `data:`/`[DONE]`

CRDs: Gateway API v1.5.1 standard channel + Inference Extension v1.6.0
(`endpointPickerRef` optional from v1.6.0; the CEL in v1.5.1 needs k8s ≥ 1.30,
hence the k3s v1.33 node — see [`common/k8s-inference`](../common/k8s-inference/README.md)).

```bash
./config.sh       # cluster, images, loxilb, mocks, CRDs, kube-loxilb, gateway objects
./validation.sh
./rmconfig.sh
```
