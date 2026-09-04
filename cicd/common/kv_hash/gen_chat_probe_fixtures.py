#!/usr/bin/env python3
"""Generate committed chat-surface probe fixtures from the HF render-parity goldens.

Each fixture = chat-<case>.request.json (the exact chat request bytes the
attestor re-derives) + chat-<case>.expect.json {requestSha256,
expectedTokenIds, api:"chat"}. The expected IDs are the goldens'
`templated_ids` — apply_chat_template(tokenize=True) from the offline HF
oracle (gen_chat_render_fixtures.py) — so no live engine is consulted.
Every consumed case must carry encode_rendered_matches_templated=true (the
one-tokenizer-path invariant the goldens proved), and the banked template
artifact must still hash to the goldens' template_sha256: fixtures derived
from drifted inputs would pin a parity the executor can no longer reproduce.

Usage: gen_chat_probe_fixtures.py <fixtures_dir> <model_slug> <out_dir>
"""
import hashlib, json, os, sys

fixtures_dir, slug, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]

with open(os.path.join(fixtures_dir, "kv_chat_render_parity.json")) as f:
    parity = json.load(f)
with open(os.path.join(fixtures_dir, "templates", "SOURCES.json")) as f:
    sources = json.load(f)

model = parity["models"][slug]
served = sources["templates"][slug]["model"]

tpl_path = os.path.join(fixtures_dir, "templates", slug, "chat_template.jinja")
with open(tpl_path, "rb") as f:
    tpl_sha = hashlib.sha256(f.read()).hexdigest()
if tpl_sha != model["template_sha256"]:
    sys.exit(f"banked template {tpl_path} digest {tpl_sha} != goldens' "
             f"{model['template_sha256']} — regenerate the goldens first")

os.makedirs(out_dir, exist_ok=True)
for name, case in sorted(model["cases"].items()):
    if not case["encode_rendered_matches_templated"]:
        sys.exit(f"case {name}: goldens record encode(render) != templated ids "
                 "— the invariant this fixture would pin does not hold")
    msgs = []
    for m in case["messages"]:
        if sorted(m.keys()) != ["content", "role"]:
            sys.exit(f"case {name}: message keys {sorted(m.keys())} beyond "
                     "role/content — the gateway parse would drop fields")
        msgs.append({"role": m["role"], "content": m["content"]})
    req = json.dumps({"model": served, "messages": msgs},
                     ensure_ascii=False).encode("utf-8")
    exp = {
        "requestSha256": hashlib.sha256(req).hexdigest(),
        "expectedTokenIds": case["templated_ids"],
        "api": "chat",
    }
    with open(os.path.join(out_dir, f"chat-{name}.request.json"), "wb") as f:
        f.write(req)
    with open(os.path.join(out_dir, f"chat-{name}.expect.json"), "w") as f:
        json.dump(exp, f, indent=1)
    print(f"chat-{name}: {len(case['templated_ids'])} tokens")
