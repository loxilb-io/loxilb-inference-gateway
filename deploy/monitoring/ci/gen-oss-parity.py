#!/usr/bin/env python3
"""
OSS metric-parity artifact generator and contract gate.

Answers one question the metric manifest cannot: of the families this gateway
exports, which does upstream OSS loxilb also export, and where the two agree on
name but not on shape?

The manifest's `owner: "loxilb"` means "emitted by the loxilb binary in THIS
repo". It says nothing about upstream, and the fork carries metric changes, so
209 families carrying that owner is not a statement of parity. This produces
`deploy/monitoring/manifest/oss-parity.json`, which is.

Three verdicts per family, and the middle one is the reason this exists:

  present-identical  upstream exports it with the same type and label set
  present-divergent  upstream exports the NAME but a different type or labels
  absent             upstream does not export it

`present-divergent` is the dangerous case and must be treated exactly like
`absent` by a consumer. An absent family leaves a panel empty, which is
visibly wrong. A divergent one renders -- with the wrong unit, or with a
`sum by (label)` over a label upstream does not have, silently collapsing
every series into one. A panel that is confidently wrong beats an empty panel
only in the sense that nobody notices.

Both sides come from the same AST extractor (tools/metric-manifest), so the
comparison is apples to apples and needs no build of either tree.

Usage:
  gen-oss-parity.py --upstream /path/to/loxilb            # write the artifact
  gen-oss-parity.py --upstream /path/to/loxilb --check    # fail if stale
  gen-oss-parity.py --self-test                           # prove the gates fire
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
MANIFEST = os.path.join(REPO, "deploy", "monitoring", "manifest",
                        "metric-manifest.json")
ARTIFACT = os.path.join(REPO, "deploy", "monitoring", "manifest",
                        "oss-parity.json")
UPSTREAM_REPO = "https://github.com/loxilb-io/loxilb"
SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
def extract(tree, go="go", repo_root=REPO):
    """Run the AST extractor over `tree` and return its definitions.

    Raises when a definition could not be resolved to a name. That is not
    pedantry: an unresolved definition is a family that exists and that this
    artifact would report as absent, and "absent" is the verdict a consumer
    acts on by hiding a panel. Failing here turns a silently wrong artifact
    into a build error naming the file to teach the extractor about.
    """
    out = subprocess.run(
        [go, "run", "./tools/metric-manifest", "-root", os.path.abspath(tree)],
        cwd=repo_root, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"extractor failed on {tree}:\n{out.stderr}")
    # A tree with no Go files marshals as JSON null, not [].
    defs = json.loads(out.stdout) or []
    # Zero families is never a real answer about loxilb, and it is the most
    # dangerous possible one: every gateway family would be classified absent,
    # and a consumer denying by default on absent would hide its whole
    # dashboard. The overwhelmingly likely cause is --upstream pointing
    # somewhere that is not a loxilb checkout.
    if not defs:
        raise RuntimeError(
            f"no metric definitions found under {tree} -- is that a loxilb "
            f"checkout? Refusing to report every family absent.")
    bad = [d for d in defs if d.get("unresolved") or not d.get("name")]
    if bad:
        where = ", ".join(f"{d.get('file')}:{d.get('line')}" for d in bad[:5])
        raise RuntimeError(
            f"{len(bad)} unresolved metric definition(s) in {tree} ({where}). "
            f"Each is a family that would be reported absent upstream. Teach "
            f"the extractor the registration pattern rather than shipping the "
            f"artifact with a hole in it.")
    return defs


def fold_upstream(defs):
    """Collapse upstream definitions to one entry per family name.

    A name registered twice with different shapes is not something to average:
    it is reported as divergent-by-construction so it can never read as
    identical.
    """
    by_name = {}
    for d in defs:
        shape = {"type": d["type"], "labels": sorted(d.get("labels") or [])}
        prev = by_name.get(d["name"])
        if prev is None:
            by_name[d["name"]] = shape
        elif prev != shape:
            prev["inconsistent"] = True
    return by_name


# ---------------------------------------------------------------------------
# Join
# ---------------------------------------------------------------------------
def classify(gw, up):
    """Return (verdict, divergences) for one gateway family."""
    if up is None:
        return "absent", []
    diffs = []
    if up.get("inconsistent"):
        diffs.append("upstream registers this name with more than one shape")
    if gw["type"] != up["type"]:
        diffs.append(f"type: gateway={gw['type']} upstream={up['type']}")
    g_labels, u_labels = set(gw["labels"]), set(up["labels"])
    if g_labels != u_labels:
        only_gw = sorted(g_labels - u_labels)
        only_up = sorted(u_labels - g_labels)
        if only_gw:
            diffs.append("labels only on gateway: " + ", ".join(only_gw))
        if only_up:
            diffs.append("labels only upstream: " + ", ".join(only_up))
    return ("present-divergent" if diffs else "present-identical"), diffs


def build(manifest, upstream_defs, upstream_revision, source_revision,
          generated_at):
    up = fold_upstream(upstream_defs)
    families, counts = [], {"present-identical": 0, "present-divergent": 0,
                            "absent": 0}
    for f in manifest["families"]:
        gw = {"type": f["type"], "labels": sorted(f.get("labels") or [])}
        verdict, diffs = classify(gw, up.get(f["name"]))
        counts[verdict] += 1
        entry = {
            "name": f["name"],
            "owner": f.get("owner", ""),
            "class": f.get("class", ""),
            "parity": verdict,
            "present_upstream": verdict != "absent",
            "gateway": gw,
        }
        if verdict != "absent":
            entry["upstream"] = {k: v for k, v in up[f["name"]].items()
                                 if k != "inconsistent"}
        if diffs:
            entry["divergence"] = diffs
        families.append(entry)
    families.sort(key=lambda e: e["name"])

    gw_names = {f["name"] for f in manifest["families"]}
    upstream_only = sorted(n for n in up if n not in gw_names)

    return {
        "schema_version": SCHEMA_VERSION,
        "provenance": {
            "generated_at": generated_at,
            "source_revision": source_revision,
            "upstream_repository": UPSTREAM_REPO,
            "upstream_revision": upstream_revision,
        },
        "contract": {
            "gateway_families": len(families),
            "upstream_families": len(up),
            "present_identical": counts["present-identical"],
            "present_divergent": counts["present-divergent"],
            "absent": counts["absent"],
            "upstream_only": len(upstream_only),
        },
        # Families upstream exports that this gateway does not. Recorded so the
        # artifact cannot be read as "the gateway is a superset of upstream",
        # which it is not.
        "upstream_only": upstream_only,
        "families": families,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def git_rev(tree, required):
    """Read a tree's HEAD.

    `required` separates the two revisions this artifact carries, which are not
    equally important. The UPSTREAM revision is load-bearing: it is what the
    parity set was computed against and what CI checks out to re-verify, so not
    knowing it is fatal. The gateway's own revision is provenance only -- it is
    excluded from the --check comparison because it moves on every commit -- so
    a tree that is not a git checkout (an export, a tarball, an rsync'd build
    directory) must still be able to verify the artifact. Failing there would
    have made --check unusable off a git checkout while passing in CI, where
    actions/checkout always provides one.
    """
    out = subprocess.run(["git", "-C", tree, "rev-parse", "HEAD"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        if required:
            raise RuntimeError(
                f"cannot read a revision from {tree}: {out.stderr.strip()}")
        return ""
    return out.stdout.strip()


def utc_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "+00:00")


def dump(doc):
    return json.dumps(doc, indent=1, sort_keys=False) + "\n"


# ---------------------------------------------------------------------------
# Self-test: every gate must be able to go red
# ---------------------------------------------------------------------------
def self_test():
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"  {'ok  ' if cond else 'FAIL'} {label}")
        ok = ok and cond

    ident = {"type": "counter", "labels": ["a", "b"]}
    check("identical shapes are identical",
          classify(ident, dict(ident))[0] == "present-identical")
    check("a missing family is absent",
          classify(ident, None)[0] == "absent")
    check("a differing type is divergent, not identical",
          classify(ident, {"type": "gauge", "labels": ["a", "b"]})[0]
          == "present-divergent")
    check("a label upstream lacks is divergent",
          classify(ident, {"type": "counter", "labels": ["a"]})[0]
          == "present-divergent")
    check("an extra upstream label is divergent too",
          classify(ident, {"type": "counter", "labels": ["a", "b", "c"]})[0]
          == "present-divergent")
    check("label ORDER alone is not a divergence",
          classify({"type": "counter", "labels": ["a", "b"]},
                   {"type": "counter", "labels": ["b", "a"]})[0]
          == "present-identical")
    v, d = classify(ident, {"type": "counter", "labels": ["a", "b"],
                            "inconsistent": True})
    check("an inconsistent upstream registration can never read as identical",
          v == "present-divergent" and any("more than one shape" in x for x in d))

    # The fold must not silently pick a winner between two shapes.
    folded = fold_upstream([
        {"name": "m", "type": "counter", "labels": ["a"]},
        {"name": "m", "type": "gauge", "labels": []},
    ])
    check("folding two shapes for one name marks it inconsistent",
          folded["m"].get("inconsistent") is True)

    # A divergence must name what differs; a bare verdict is not actionable.
    _, diffs = classify(ident, {"type": "gauge", "labels": ["a"]})
    check("a divergence explains itself",
          any("type:" in x for x in diffs) and any("labels" in x for x in diffs))

    print("self-test:", "every gate can go red" if ok else "A GATE IS DEAD")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream", help="path to a loxilb-io/loxilb checkout")
    ap.add_argument("--go", default="go")
    ap.add_argument("--check", action="store_true",
                    help="fail when the committed artifact is not what this "
                         "run would write")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.upstream:
        print("--upstream is required (or --self-test)", file=sys.stderr)
        return 2
    if not os.path.isdir(args.upstream):
        print(f"upstream checkout not found: {args.upstream}", file=sys.stderr)
        return 2

    with open(MANIFEST, encoding="utf-8") as fh:
        manifest = json.load(fh)

    try:
        upstream_defs = extract(args.upstream, args.go)
    except RuntimeError as e:
        print(f"oss-parity: {e}", file=sys.stderr)
        return 1

    try:
        upstream_revision = git_rev(args.upstream, required=True)
    except RuntimeError as e:
        print(f"oss-parity: {e}", file=sys.stderr)
        return 1
    source_revision = git_rev(REPO, required=False)

    committed = None
    if os.path.exists(ARTIFACT):
        with open(ARTIFACT, encoding="utf-8") as fh:
            committed = json.load(fh)

    # Provenance is not part of the comparison: generated_at always moves, and
    # the gateway revision moves on every commit. What must not move silently
    # is the parity set itself.
    generated_at = utc_now()
    doc = build(manifest, upstream_defs, upstream_revision, source_revision,
                generated_at)

    c = doc["contract"]
    print(f"oss-parity: {c['gateway_families']} gateway families vs "
          f"{c['upstream_families']} upstream | identical "
          f"{c['present_identical']} / divergent {c['present_divergent']} / "
          f"absent {c['absent']} | upstream-only {c['upstream_only']}")
    for e in doc["families"]:
        if e["parity"] == "present-divergent":
            print(f"  divergent  {e['name']}: {'; '.join(e['divergence'])}")

    if args.check:
        if committed is None:
            print("  ERROR no committed oss-parity.json; generate and commit it",
                  file=sys.stderr)
            return 1
        want = {k: v for k, v in doc.items() if k != "provenance"}
        have = {k: v for k, v in committed.items() if k != "provenance"}
        if want != have:
            print("  ERROR committed oss-parity.json is stale: the parity set "
                  "moved. Regenerate against the pinned upstream revision and "
                  "commit the diff.", file=sys.stderr)
            return 1
        if committed.get("provenance", {}).get("upstream_revision") != upstream_revision:
            print(f"  note: parity set unchanged, but the upstream checkout is "
                  f"{upstream_revision[:12]} and the artifact pins "
                  f"{committed['provenance'].get('upstream_revision', '')[:12]}")
        print("oss-parity: committed artifact is current")
        return 0

    with open(ARTIFACT, "w", encoding="utf-8") as fh:
        fh.write(dump(doc))
    print(f"wrote {os.path.relpath(ARTIFACT, REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
