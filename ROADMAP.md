# Roadmap

This roadmap captures the direction of loxilb-inference-gateway. It is
intentionally short and honest: items here are intent, not commitments, and
priorities shift with community feedback. For what the project explicitly does
*not* aim to be, see the **scope & non-goals** section of the
[README](README.md#where-it-fits-scope--non-goals).

The base load balancer follows [upstream loxilb](https://github.com/loxilb-io/loxilb);
this roadmap covers only the inference-gateway delta.

## Near term

- **A reproducible benchmark ("well-lit path").** Publish one credible number —
  P90 TTFT under cache-aware routing vs. round-robin, measured with
  [inference-perf](https://github.com/kubernetes-sigs/inference-perf) — packaged
  as a `cicd/` scenario so anyone can reproduce it, and surfaced as a
  Key-Results block in the README.
- **TTFT-adaptive controller quickstart.** `loxilb-ai-controller` exists but has
  no runnable scenario; its flags live only in
  `cmd/loxilb-ai-controller/options.go`. Add a documented quickstart and a CI
  scenario that exercises it.
- **Document `loxilb-kv-agent` (DOCA).** The KV-agent component is currently
  undocumented and not wired into any CI scenario. Document its role and add a
  minimal deployment example.

## Exploring

- **Aggregated single-pool vLLM KV-exact.** Today KV-exact routing for vLLM
  requires a prefill/decode topology; single-role KV-exact ships only for
  SGLang. Extending exact-cache routing to an aggregated single vLLM pool is
  under investigation.
- **Gateway API Inference Extension (GIE) alignment.** The KV-cache-aware
  selector already plays the role of an endpoint picker over an inference pool
  (see the README scope note). Whether to expose that natively through the
  Kubernetes Gateway API `InferencePool` / endpoint-picker vocabulary — versus
  keeping it a self-contained data-path feature — is an open decision to be
  driven by user demand.

## Sustainability

- **Shrink the fork diff by upstreaming.** Where features are broadly useful,
  move them toward upstream loxilb (candidate order: AI metrics → AI control
  plane → `ai_*` control-plane hooks) to reduce long-term merge burden. The
  automated upstream-sync chain and merge-only model are documented in
  [docs/UPSTREAM-SYNC.md](docs/UPSTREAM-SYNC.md).

## How to influence this roadmap

Open an issue or start a discussion describing your serving stack and the
routing problem you need solved. Real deployment feedback moves items from
*Exploring* to *Near term* faster than anything else.
