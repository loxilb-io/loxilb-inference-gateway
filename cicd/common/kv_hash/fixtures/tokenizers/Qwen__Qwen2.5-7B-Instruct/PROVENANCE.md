<!-- provenance note (mirrors Qwen__Qwen3-0.6B/CLAUDE.md convention) -->
# tokenizer.json provenance — Qwen/Qwen2.5-7B-Instruct

- **Model of record:** `Qwen/Qwen2.5-7B-Instruct` (the production-size model a production
  GPU fleet serves per `cicd/vllm-kvcache-routing-byo/inventory.yaml` and
  `bench/testbed/env-compat-check.sh` `KV_MODEL` default).
- **Artifact:** `tokenizer.json` (fast HF tokenizer of record), sourced from the
  Hugging Face Hub repo `Qwen/Qwen2.5-7B-Instruct` at the pinned fleet weights.
- **sha256:** `c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539`
**Why it lives here:** ( hash-drift oracle) hashes prompt blocks the SAME
  way the served vLLM publisher does. The tokenizer.json is the byte-of-record so
  block boundaries + token ids are exact; a tokenizer swap on the big model changes
 the block hashes and fails LOUD rather than silently measuring round-robin
  (Pitfall 2). Provenance is the served-model tokenizer — no hand-authored hashes.
- **Parity triad (fixed at generation):** block-size 16, `PYTHONHASHSEED=0`,
  `LLB_KV_NONE_HASH_SEED=0`.
- **Layout mirrors** `Qwen__Qwen3-0.6B/` (slug = `ReplaceAll(model,"/","__")`).
