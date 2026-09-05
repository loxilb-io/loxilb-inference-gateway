#!/usr/bin/env python3
"""
Metric ownership manifest generator and contract gate.

Merges the AST-extracted metric definitions (tools/metric-manifest) with the
human-owned metadata in manifest-overlay.json and writes the committed
manifest (deploy/monitoring/manifest/metric-manifest.json). Enforces, in one
place, the monitoring ownership contract:

  1. Every metric family constructor in the Go tree is classified: owner
     binary, applicability class, packaged or not. Unclassifiable files fail.
  2. The per-owner and per-class counts match the pinned expected block, so a
     new or deleted family is a deliberate, reviewed manifest change.
  3. Every family has an activation entry (how it appears at runtime: eager,
     lazy vector, collector-gated, ...); stale or missing entries fail.
  4. Non-test Go string literals that look like metric names resolve to real
     families (or an explicitly allowed exception) — the drift class where a
     panel references a name no constructor emits. Test files are excluded:
     mock names in *_test.go are not part of the exporter surface.
  5. Dashboard and alert-rule expressions are cross-referenced into per-family
     consumer lists; coverage counts are recorded in the manifest so coverage
     changes show up as reviewable diffs.
  6. Optionally (--locked-rev-check), the extractor runs against the locked
     product revision and the family-set delta must match the overlay's
     expectations, additively: families may be new at HEAD, but a family that
     existed at the locked revision must still exist.

Run:
    python3 deploy/monitoring/ci/gen-metric-manifest.py            # regenerate
    python3 deploy/monitoring/ci/gen-metric-manifest.py --check    # CI gate
    python3 deploy/monitoring/ci/gen-metric-manifest.py --check --locked-rev-check
    python3 deploy/monitoring/ci/gen-metric-manifest.py --self-test

Stdlib-only; needs a Go toolchain unless --defs supplies extractor output.
Exit 0 = clean, 1 = contract violation, 2 = environment/usage error.
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

HIST_SUFFIXES = ("_bucket", "_count", "_sum")
METRIC_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_:])((?:loxilb|doca|aictrl)_[a-z0-9_]+)(?![A-Za-z0-9_:])")
LITERAL = re.compile(r'"((?:loxilb|doca|aictrl)_[a-z0-9_]+)"')
SKIP_DIRS = {".git", "loxilb-ebpf", "vendor", "node_modules", "3rdparty",
             "__pycache__"}


def fail(errors):
    for e in errors:
        print(f"  ERROR {e}")
    print(f"\nmetric-manifest: {len(errors)} violation(s)")
    return 1


# ---------------------------------------------------------------------------
# extractor
# ---------------------------------------------------------------------------
def run_extractor(repo_root, go="go"):
    r = subprocess.run(
        [go, "run", "./tools/metric-manifest", "-root", repo_root],
        capture_output=True, text=True, cwd=repo_root)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(2)
    return json.loads(r.stdout)


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
def classify(defs, overlay, errors):
    rules = overlay["classification"]
    default_rule = next(r for r in rules if "default_owner" in r)
    out = []
    for d in defs:
        f = d["file"]
        hit = None
        for r in rules:
            if "prefix" in r and f.startswith(r["prefix"]):
                hit = r
                break
            if "file" in r and f == r["file"]:
                hit = r
                break
        if hit is None:
            hit = {"owner": default_rule["default_owner"],
                   "class": default_rule["class"],
                   "packaged": default_rule["packaged"]}
        e = dict(d)
        e["owner"] = hit["owner"]
        e["class"] = hit["class"]
        e["packaged"] = hit["packaged"]
        out.append(e)
        if d.get("unresolved") or "?" in d.get("labels", []):
            errors.append(f"{d['file']}:{d['line']}: family '{d['name']}' has "
                          f"an unresolved name or label (extractor could not "
                          f"reduce it to a string)")
    seen = {}
    for e in out:
        key = (e["owner"], e["name"])
        if key in seen:
            errors.append(f"duplicate family '{e['name']}' for owner "
                          f"'{e['owner']}': {seen[key]} and "
                          f"{e['file']}:{e['line']}")
        else:
            seen[key] = f"{e['file']}:{e['line']}"
    return out


def check_counts(fams, overlay, errors):
    exp = overlay["expected"]
    owners, classes = {}, {}
    for e in fams:
        owners[e["owner"]] = owners.get(e["owner"], 0) + 1
        classes[e["class"]] = classes.get(e["class"], 0) + 1
    if len(fams) != exp["total"]:
        errors.append(f"total families {len(fams)} != expected {exp['total']}")
    for k, v in exp["owners"].items():
        if owners.get(k, 0) != v:
            errors.append(f"owner '{k}' has {owners.get(k, 0)} families, "
                          f"expected {v}")
    for k in owners:
        if k not in exp["owners"]:
            errors.append(f"unexpected owner '{k}' ({owners[k]} families)")
    for k, v in exp["classes"].items():
        if classes.get(k, 0) != v:
            errors.append(f"class '{k}' has {classes.get(k, 0)} families, "
                          f"expected {v}")
    for k in classes:
        if k not in exp["classes"]:
            errors.append(f"unexpected class '{k}' ({classes[k]} families)")


def check_activation(fams, overlay, errors):
    act = overlay["activation"]
    names = {e["name"] for e in fams}
    for e in fams:
        if e["name"] not in act:
            errors.append(f"family '{e['name']}' has no activation entry in "
                          f"the overlay")
    for n in act:
        if n not in names:
            errors.append(f"overlay activation entry '{n}' matches no family "
                          f"(stale after a rename/removal?)")


# ---------------------------------------------------------------------------
# literal reconciliation (non-test Go sources)
# ---------------------------------------------------------------------------
def scan_literals(repo_root):
    found = {}
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".go") or fn.endswith("_test.go"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(p, repo_root)
            for m in LITERAL.finditer(text):
                found.setdefault(m.group(1), set()).add(rel)
    return found


def check_literals(fams, overlay, repo_root, errors):
    names = {e["name"] for e in fams}
    allowed = overlay.get("allowed_extra_literals", {})
    for lit, files in sorted(scan_literals(repo_root).items()):
        if lit in names or lit in allowed:
            continue
        where = ", ".join(sorted(files)[:3])
        errors.append(f"string literal '{lit}' ({where}) matches no metric "
                      f"family constructor and no allowed exception")


# ---------------------------------------------------------------------------
# consumers: dashboards + alert rule expressions
# ---------------------------------------------------------------------------
def dashboard_refs(mon_dir):
    refs = {}
    for f in sorted(glob.glob(os.path.join(mon_dir,
                                           "grafana/dashboards/*.json"))):
        name = os.path.basename(f)
        d = json.load(open(f, encoding="utf-8"))

        def walk(panels):
            for p in panels or []:
                for t in p.get("targets") or []:
                    expr = t.get("expr")
                    if expr:
                        for m in METRIC_TOKEN.finditer(expr):
                            refs.setdefault(m.group(1), set()).add(name)
                walk(p.get("panels"))
        walk(d.get("panels"))
    return refs


def rule_refs(mon_dir):
    """Expression text only — rule comments do not count as consumption."""
    refs = {}
    for f in sorted(glob.glob(os.path.join(mon_dir, "prometheus/rules/*.yml"))):
        name = os.path.basename(f)
        in_expr, indent = False, 0
        for line in open(f, encoding="utf-8"):
            s = line.rstrip("\n")
            m = re.match(r"^(\s*)expr:\s*(.*)$", s)
            if m:
                in_expr, indent = True, len(m.group(1))
                rest = m.group(2).strip()
                if rest and rest not in (">-", ">", "|", "|-", ">+"):
                    for t in METRIC_TOKEN.finditer(rest):
                        refs.setdefault(t.group(1), set()).add(name)
                continue
            if in_expr:
                if not s.strip():
                    continue
                if len(s) - len(s.lstrip()) > indent:
                    for t in METRIC_TOKEN.finditer(s.strip()):
                        refs.setdefault(t.group(1), set()).add(name)
                    continue
                in_expr = False
    return refs


def attach_consumers(fams, mon_dir):
    dash = dashboard_refs(mon_dir)
    rules = rule_refs(mon_dir)
    names = {e["name"] for e in fams}

    def base(ref):
        for suf in HIST_SUFFIXES:
            if ref.endswith(suf) and ref[: -len(suf)] in names:
                return ref[: -len(suf)]
        return ref

    by_base = {}
    for src in (dash, rules):
        for ref, files in src.items():
            by_base.setdefault(base(ref), set()).update(files)
    for e in fams:
        e["consumers"] = sorted(by_base.get(e["name"], ()))


def check_waivers(fams, overlay, errors):
    """Attach and validate coverage waivers.

    A waiver is the deliberate, documented decision that a default-class
    family has NO dashboard/rule consumer: the overlay entry must name the
    operational question and the alternative diagnostic. The gate keeps
    waivers honest: unknown names, non-default families, referenced
    families (stale waiver), and throwaway reasons all fail.
    """
    waivers = overlay.get("coverage_waivers", {})
    names = {e["name"] for e in fams}
    for wname in sorted(waivers):
        if wname not in names:
            errors.append(f"coverage waiver names unknown family '{wname}' "
                          f"— typo, or the family was removed")
    for e in fams:
        e["waiver"] = waivers.get(e["name"], "")
        if not e["waiver"]:
            continue
        if e["class"] != "default":
            errors.append(f"coverage waiver on '{e['name']}' is meaningless: "
                          f"class '{e['class']}' is outside the default "
                          f"coverage surface")
        if e["consumers"]:
            errors.append(f"stale coverage waiver: '{e['name']}' is now "
                          f"referenced by {e['consumers']} — drop the waiver")
        if len(e["waiver"]) < 40:
            errors.append(f"coverage waiver for '{e['name']}' is too thin "
                          f"({len(e['waiver'])} chars): state the operational "
                          f"question and the alternative diagnostic")


def coverage_counts(fams):
    packaged = [e for e in fams if e["class"] == "default"]
    referenced = [e for e in packaged if e["consumers"]]
    waived = [e for e in packaged
              if e.get("waiver") and not e["consumers"]]
    unref = [e for e in packaged
             if not e["consumers"] and not e.get("waiver")]
    return {"default_families": len(packaged),
            "default_referenced": len(referenced),
            "default_waived": len(waived),
            "default_unreferenced": len(unref)}


# ---------------------------------------------------------------------------
# locked product revision delta
# ---------------------------------------------------------------------------
def locked_rev_names(repo_root, rev, go="go"):
    ok = subprocess.run(["git", "cat-file", "-e", f"{rev}^{{commit}}"],
                        cwd=repo_root, capture_output=True)
    if ok.returncode != 0:
        f = subprocess.run(["git", "fetch", "origin", rev],
                           cwd=repo_root, capture_output=True, text=True)
        if f.returncode != 0:
            print(f"locked revision {rev} unavailable and fetch failed:\n"
                  f"{f.stderr}", file=sys.stderr)
            sys.exit(2)
    with tempfile.TemporaryDirectory() as td:
        wt = os.path.join(td, "locked")
        r = subprocess.run(["git", "worktree", "add", "--detach", wt, rev],
                           cwd=repo_root, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"git worktree add failed:\n{r.stderr}", file=sys.stderr)
            sys.exit(2)
        try:
            # The extractor source comes from HEAD; only -root points at the
            # locked checkout, so old revisions without tools/ still work.
            out = subprocess.run(
                [go, "run", "./tools/metric-manifest", "-root", wt],
                capture_output=True, text=True, cwd=repo_root)
            if out.returncode != 0:
                print(out.stderr, file=sys.stderr)
                sys.exit(2)
            return {d["name"] for d in json.loads(out.stdout)}
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", wt],
                           cwd=repo_root, capture_output=True)


def check_locked_rev(fams, overlay, repo_root, go, errors):
    cfg = overlay["locked_revision"]
    locked = locked_rev_names(repo_root, cfg["rev"], go)
    head = {e["name"] for e in fams}
    missing_at_locked = sorted(head - locked)
    removed_at_head = sorted(locked - head)
    expect = sorted(cfg["expect_missing_at_locked"])
    if missing_at_locked != expect:
        errors.append(f"families missing at locked revision "
                      f"{cfg['rev'][:12]} = {missing_at_locked} != expected "
                      f"{expect} — update the overlay deliberately if the "
                      f"delta really changed")
    if removed_at_head:
        errors.append(f"families present at locked revision but gone at "
                      f"HEAD (renames/deletions break the additive "
                      f"contract): {removed_at_head}")


# ---------------------------------------------------------------------------
# manifest assembly
# ---------------------------------------------------------------------------
def build_manifest(fams, overlay, coverage):
    act = overlay["activation"]
    pri = overlay["priority"]
    review = set(overlay.get("privacy_review_labels", ()))
    entries = []
    for e in sorted(fams, key=lambda x: (x["owner"], x["name"])):
        entries.append({
            "name": e["name"],
            "owner": e["owner"],
            "class": e["class"],
            "packaged": e["packaged"],
            "type": e["type"],
            "labels": e["labels"],
            "activation": act.get(e["name"], ""),
            "priority": pri["overrides"].get(e["name"], pri["default"]),
            "privacy": ("label-review"
                        if set(e["labels"]) & review else "none"),
            "consumers": e["consumers"],
            "waiver": e.get("waiver", ""),
            "source": f"{e['file']}:{e['line']}",
        })
    return {"contract": overlay["expected"], "coverage": coverage,
            "families": entries}


# ---------------------------------------------------------------------------
# self-test: prove each gate can go red
# ---------------------------------------------------------------------------
def self_test(overlay):
    base = [{"name": "loxilb_x_total", "type": "counter", "vec": False,
             "labels": [], "file": "api/prometheus/prometheus.go", "line": 1,
             "mechanism": "promauto"}]
    failures = []

    def expect_red(what, errs):
        if errs:
            print(f"  ok    {what}: caught ({errs[0][:70]}...)")
        else:
            failures.append(what)
            print(f"  MISSED {what}: gate did not fire")

    errs = []
    fams = classify(base, overlay, errs)
    check_counts(fams, overlay, errs)
    expect_red("count mismatch", errs)

    errs = []
    bad = dict(base[0], labels=["?"])
    classify([bad], overlay, errs)
    expect_red("unresolved label", errs)

    errs = []
    dup = [base[0], dict(base[0], line=2)]
    classify(dup, overlay, errs)
    expect_red("duplicate family", errs)

    errs = []
    fams = classify(base, overlay, [])
    check_activation(fams, overlay, errs)
    expect_red("activation entry missing/stale", errs)

    errs = []
    ovl = json.loads(json.dumps(overlay))
    ovl["coverage_waivers"] = {"loxilb_no_such_family_total":
                               "long enough reason " * 3}
    fams = classify(base, ovl, [])
    for e in fams:
        e["consumers"] = []
    check_waivers(fams, ovl, errs)
    expect_red("waiver naming unknown family", errs)

    errs = []
    ovl["coverage_waivers"] = {"loxilb_x_total": "long enough reason " * 3}
    fams = classify(base, ovl, [])
    for e in fams:
        e["consumers"] = ["loxilb-overview.json"]
    check_waivers(fams, ovl, errs)
    expect_red("stale waiver on referenced family", errs)

    errs = []
    ovl["coverage_waivers"] = {"loxilb_x_total": "meh"}
    fams = classify(base, ovl, [])
    for e in fams:
        e["consumers"] = []
    check_waivers(fams, ovl, errs)
    expect_red("throwaway waiver reason", errs)

    errs = []
    ovl = json.loads(json.dumps(overlay))
    ovl["classification"] = [c for c in overlay["classification"]
                             if "default_owner" in c]
    ctl = [{"name": "aictrl_y", "type": "gauge", "vec": False, "labels": [],
            "file": "cmd/loxilb-ai-controller/metrics.go", "line": 1,
            "mechanism": "promauto"}]
    fams = classify(ctl, ovl, [])
    check_counts(fams, ovl, errs)
    expect_red("classification fallthrough to wrong class", errs)

    if failures:
        print(f"\nself-test: {len(failures)} gate(s) cannot fire: {failures}")
        return 1
    print("\nself-test: every gate can go red")
    return 0


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo-root", default=None)
    ap.add_argument("--defs", default=None,
                    help="pre-extracted definitions JSON (skips the Go run)")
    ap.add_argument("--go", default="go")
    ap.add_argument("--check", action="store_true",
                    help="verify the committed manifest instead of writing it")
    ap.add_argument("--locked-rev-check", action="store_true",
                    help="also diff the family set against the locked "
                         "product revision")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(args.repo_root or
                                os.path.join(here, "..", "..", ".."))
    mon_dir = os.path.join(repo_root, "deploy", "monitoring")
    overlay_path = os.path.join(here, "manifest-overlay.json")
    manifest_path = os.path.join(mon_dir, "manifest", "metric-manifest.json")
    overlay = json.load(open(overlay_path, encoding="utf-8"))

    if args.self_test:
        return self_test(overlay)

    defs = (json.load(open(args.defs, encoding="utf-8")) if args.defs
            else run_extractor(repo_root, args.go))

    errors = []
    fams = classify(defs, overlay, errors)
    check_counts(fams, overlay, errors)
    check_activation(fams, overlay, errors)
    check_literals(fams, overlay, repo_root, errors)
    attach_consumers(fams, mon_dir)
    check_waivers(fams, overlay, errors)
    coverage = coverage_counts(fams)
    if args.locked_rev_check:
        check_locked_rev(fams, overlay, repo_root, args.go, errors)
    if errors:
        return fail(errors)

    manifest = build_manifest(fams, overlay, coverage)
    print(f"metric-manifest: {len(fams)} families | default "
          f"{coverage['default_families']} "
          f"({coverage['default_referenced']} referenced / "
          f"{coverage['default_waived']} waived / "
          f"{coverage['default_unreferenced']} unreferenced)")

    rendered = json.dumps(manifest, indent=1, sort_keys=False) + "\n"
    if args.check:
        try:
            committed = open(manifest_path, encoding="utf-8").read()
        except OSError:
            return fail([f"{manifest_path} missing — run the generator and "
                         f"commit the manifest"])
        if committed != rendered:
            return fail(["committed manifest is stale: regenerate with "
                         "gen-metric-manifest.py and commit the diff"])
        print("metric-manifest: committed manifest is current")
        return 0

    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    print(f"wrote {os.path.relpath(manifest_path, repo_root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
