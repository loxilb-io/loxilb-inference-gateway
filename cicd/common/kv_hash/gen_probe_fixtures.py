#!/usr/bin/env python3
"""Generate committed vLLM /tokenize probe fixtures for a profile.

Each fixture = <name>.request.json (bytes sent verbatim to /tokenize) +
<name>.expect.json {requestSha256, expectedTokenIds, api}. The expected IDs
come from the SAME committed tokenizer.json the profile pins, encoded with
special tokens (the vLLM /tokenize default: add_special_tokens=true).
"""
import hashlib, json, os, sys
from tokenizers import Tokenizer

tok_path, out_dir, model = sys.argv[1], sys.argv[2], sys.argv[3]
tok = Tokenizer.from_file(tok_path)
os.makedirs(out_dir, exist_ok=True)

FIXTURES = {
    "basic-ascii": "The quick brown fox jumps over the lazy dog.",
    "multiline-punct": "KV-exact routing attestation probe.\nLine two: numbers 12345, symbols #!@%.\n",
    "unicode-mix": "Tokenizer parity check: café naïve 안녕하세요 你好 こんにちは.",
}

for name, prompt in FIXTURES.items():
    req = json.dumps({"model": model, "prompt": prompt}, ensure_ascii=False).encode("utf-8")
    ids = tok.encode(prompt, add_special_tokens=True).ids
    with open(os.path.join(out_dir, name + ".request.json"), "wb") as f:
        f.write(req)
    exp = {
        "requestSha256": hashlib.sha256(req).hexdigest(),
        "expectedTokenIds": ids,
        "api": "completions",
    }
    with open(os.path.join(out_dir, name + ".expect.json"), "w") as f:
        json.dump(exp, f, indent=1)
    print(f"{name}: {len(ids)} tokens")
