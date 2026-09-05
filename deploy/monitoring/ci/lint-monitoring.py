#!/usr/bin/env python3
"""
Tier-0 static correctness gate for the LoxiLB monitoring stack.

Hermetic (no loxilb, no traffic, no network) checks over deploy/monitoring/ and
the exporter source. Catches the class of silent drift that manual validation
cannot re-catch on every change: a dashboard/alert referencing a metric the
exporter no longer emits, a broken PromQL expr, an alert annotation pointing at a
panel that was renamed, a panel wired to the wrong datasource.

See docs/MONITORING-CICD.md (Tier 0). Run locally:

    python3 deploy/monitoring/ci/lint-monitoring.py

Exit 0 = clean, 1 = at least one ERROR. WARNINGs never fail the build.
promtool checks are skipped (with a WARNING) when promtool is absent; CI installs
it so the full gate runs there.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# --- metric names that are legitimately NOT loxilb exporter families ----------
# Prometheus/Go runtime + self-scrape names used by a few panels and the soak
# checks. Prefix match.
INFRA_PREFIXES = (
    "up", "scrape_", "prometheus_", "process_", "go_", "promhttp_", "ALERTS",
)
# Metric families that are registered lazily / conditionally: absent on an idle
# system by design (§3.5). Panels over these SHOULD set noValue.
LAZY_PREFIXES = ("loxilb_ai_", "loxilb_l4_error_")

# Package-boundary deny-list: metric surfaces owned by components outside the
# default product profile (DPU/DOCA hardware profile, the standalone AI
# controller, the standalone KV agent's gateway-side liveness gauge). The
# default dashboards and rules must not reference them at all — not as hidden
# panels, fallbacks inside a larger expression, or "No data" placeholders. A
# separately versioned profile is the only way to consume them.
BOUNDARY_DENY_PREFIXES = ("doca_", "aictrl_")
BOUNDARY_DENY_EXACT = {"loxilb_kv_agent_up"}


def boundary_violation(ref):
    return ref.startswith(BOUNDARY_DENY_PREFIXES) or ref in BOUNDARY_DENY_EXACT

METRIC_TOKEN = re.compile(r"\b((?:loxilb|doca|aictrl)_[a-z0-9_]+)\b")
HIST_SUFFIXES = ("_bucket", "_count", "_sum")

# Grafana datasource sentinels that are not the Prometheus datasource.
BUILTIN_DS = {"-- Grafana --", "-- Mixed --", "-- Dashboard --", "__expr__",
              "grafana", "datasource"}
EXPECTED_DS_UID = "loxilb-prom"


class Report:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def err(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def warn(self, where, msg):
        self.warnings.append(f"{where}: {msg}")

    def dump(self):
        for w in self.warnings:
            print(f"  WARN  {w}")
        for e in self.errors:
            print(f"  ERROR {e}")
        print()
        print(f"monitoring-lint: {len(self.errors)} error(s), "
              f"{len(self.warnings)} warning(s)")
        return 0 if not self.errors else 1


# ---------------------------------------------------------------------------
# Exporter metric surface (the ground truth for name resolution)
# ---------------------------------------------------------------------------
def collect_exporter_metrics(repo_root):
    """The family names the binaries can actually emit.

    Primary source: the committed metric ownership manifest, which is derived
    from Go AST extraction (tools/metric-manifest) and therefore knows about
    Namespace/Subsystem-composed names that never appear as a single string
    literal. gen-metric-manifest.py --check keeps that file honest in the same
    CI run, so trusting it here does not weaken the gate.

    Fallback (manifest missing, e.g. an old checkout): a literal scan over
    non-test Go sources. Test files are excluded either way — a mock metric
    name in *_test.go is not part of the exporter surface and must not make a
    dashboard reference resolve."""
    manifest = os.path.join(repo_root, "deploy", "monitoring", "manifest",
                            "metric-manifest.json")
    try:
        data = json.load(open(manifest, encoding="utf-8"))
        return {f["name"] for f in data["families"]}
    except (OSError, KeyError, json.JSONDecodeError):
        pass
    names = set()
    skip = {".git", "loxilb-ebpf", "vendor", "node_modules", "3rdparty"}
    lit = re.compile(r'"((?:loxilb|doca|aictrl)_[a-z0-9_]+)"')
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if not fn.endswith(".go") or fn.endswith("_test.go"):
                continue
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8",
                          errors="ignore") as fh:
                    for m in lit.finditer(fh.read()):
                        names.add(m.group(1))
            except OSError:
                pass
    return names


def is_known_metric(ref, exporter):
    if ref.startswith(INFRA_PREFIXES):
        return True
    if ref in exporter:
        return True
    for suf in HIST_SUFFIXES:
        if ref.endswith(suf) and ref[: -len(suf)] in exporter:
            return True
    return False


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------
def iter_panels(panels):
    """Yield every panel, recursing into collapsed-row child panels."""
    for p in panels or []:
        yield p
        if p.get("panels"):
            yield from iter_panels(p["panels"])


def ds_uid(obj):
    ds = obj.get("datasource")
    if isinstance(ds, dict):
        return ds.get("uid")
    if isinstance(ds, str):
        return ds
    return None


def lint_dashboards(mon_dir, exporter, rep):
    files = sorted(glob.glob(os.path.join(mon_dir, "grafana/dashboards/*.json")))
    if not files:
        rep.err("dashboards", "no dashboard JSON files found")
        return {}, []

    uids = {}
    title_to_panels = {}          # dashboard title -> set(panel titles)
    all_exprs = []                # (file, expr) for PromQL parse

    for f in files:
        name = os.path.basename(f)
        try:
            d = json.load(open(f, encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            rep.err(name, f"invalid JSON: {e}")
            continue

        uid = d.get("uid")
        title = d.get("title")
        if not uid:
            rep.err(name, "missing top-level uid")
        elif uid in uids:
            rep.err(name, f"duplicate uid '{uid}' (also in {uids[uid]})")
        else:
            uids[uid] = name
        if not title:
            rep.err(name, "missing top-level title")

        tvars = {v.get("name") for v in
                 d.get("templating", {}).get("list", [])}
        # bootstrap dashboard is intentionally variable-free
        if "instance" not in tvars and uid != "loxilb-bootstrap":
            rep.warn(name, "no $instance template variable (§3.8)")

        panel_ids = {}
        panel_titles = set()
        panels = list(iter_panels(d.get("panels", [])))
        for p in panels:
            pid = p.get("id")
            if pid is not None:
                if pid in panel_ids:
                    rep.err(name, f"duplicate panel id {pid} "
                                  f"('{p.get('title')}' & '{panel_ids[pid]}')")
                else:
                    panel_ids[pid] = p.get("title")
            if p.get("title"):
                panel_titles.add(p["title"])

            if p.get("type") == "row":
                continue

            # datasource consistency (panel level + each target)
            for scope, obj in [("panel", p)] + \
                    [("target", t) for t in (p.get("targets") or [])]:
                u = ds_uid(obj)
                if u and u not in BUILTIN_DS and u != EXPECTED_DS_UID:
                    rep.err(name, f"panel '{p.get('title')}' {scope} datasource "
                                  f"uid '{u}' != '{EXPECTED_DS_UID}'")

            lazy = False
            for t in p.get("targets") or []:
                expr = t.get("expr")
                if not expr or not expr.strip():
                    continue
                all_exprs.append((name, expr))
                for m in METRIC_TOKEN.finditer(expr):
                    ref = m.group(1)
                    if boundary_violation(ref):
                        rep.err(name, f"panel '{p.get('title')}' references "
                                      f"'{ref}', which belongs to a component "
                                      f"outside the default package boundary")
                    elif not is_known_metric(ref, exporter):
                        rep.err(name, f"panel '{p.get('title')}' references "
                                      f"unknown metric '{ref}' "
                                      f"(not in exporter source)")
                    if ref.startswith(LAZY_PREFIXES):
                        lazy = True
                # $instance coverage on loxilb selectors (warn only)
                if "loxilb_" in expr and "$instance" not in expr \
                        and uid != "loxilb-bootstrap":
                    rep.warn(name, f"panel '{p.get('title')}' selector without "
                                   f"$instance filter")

            if lazy:
                fc = (p.get("fieldConfig") or {}).get("defaults") or {}
                if "noValue" not in fc:
                    rep.warn(name, f"panel '{p.get('title')}' over a lazy/"
                                   f"conditional family without noValue (§3.5)")

        title_to_panels[title] = panel_titles

    return title_to_panels, all_exprs


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------
def extract_rule_exprs_and_annotations(rules_path):
    """Line-based extraction (stdlib-only, no PyYAML): pull every expr block's
    text and every (dashboard, panel) annotation pair. Good enough for token
    resolution and annotation mapping; promtool validates the actual rule
    syntax separately."""
    expr_text = []
    pairs = []           # (dashboard, panel)
    pending_dash = None
    in_expr = False
    expr_indent = 0
    with open(rules_path, encoding="utf-8") as fh:
        lines = fh.readlines()
    for line in lines:
        stripped = line.rstrip("\n")
        m = re.match(r"^(\s*)expr:\s*(.*)$", stripped)
        if m:
            in_expr = True
            expr_indent = len(m.group(1))
            rest = m.group(2).strip()
            if rest and rest not in (">-", ">", "|", "|-", ">+"):
                expr_text.append(rest)
            continue
        if in_expr:
            if stripped.strip() == "":
                continue
            indent = len(stripped) - len(stripped.lstrip())
            if indent > expr_indent:
                expr_text.append(stripped.strip())
                continue
            in_expr = False  # fall through to normal handling
        dm = re.match(r'^\s*dashboard:\s*"?(.+?)"?\s*$', stripped)
        if dm:
            pending_dash = dm.group(1)
            continue
        pm = re.match(r'^\s*panel:\s*"?(.+?)"?\s*$', stripped)
        if pm and pending_dash is not None:
            pairs.append((pending_dash, pm.group(1)))
            pending_dash = None
    return "\n".join(expr_text), pairs


def lint_rules(mon_dir, exporter, title_to_panels, rep):
    rules_path = os.path.join(mon_dir, "prometheus/rules/loxilb-alerts.yml")
    if not os.path.isfile(rules_path):
        rep.err("rules", f"{rules_path} not found")
        return
    expr_blob, pairs = extract_rule_exprs_and_annotations(rules_path)

    for m in METRIC_TOKEN.finditer(expr_blob):
        ref = m.group(1)
        if boundary_violation(ref):
            rep.err("loxilb-alerts.yml",
                    f"alert expr references '{ref}', which belongs to a "
                    f"component outside the default package boundary")
        elif not is_known_metric(ref, exporter):
            rep.err("loxilb-alerts.yml",
                    f"alert expr references unknown metric '{ref}'")

    for dash, panel in pairs:
        if dash not in title_to_panels:
            rep.err("loxilb-alerts.yml",
                    f"annotation dashboard '{dash}' matches no dashboard title")
        elif panel not in title_to_panels[dash]:
            rep.err("loxilb-alerts.yml",
                    f"annotation panel '{panel}' not found on '{dash}' (§3.7)")


# ---------------------------------------------------------------------------
# promtool (optional): rule validity + dashboard PromQL syntax
# ---------------------------------------------------------------------------
def find_promtool(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    return shutil.which("promtool")


def promtool_check_rules(promtool, mon_dir, rep):
    rules_path = os.path.join(mon_dir, "prometheus/rules/loxilb-alerts.yml")
    r = subprocess.run([promtool, "check", "rules", rules_path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        rep.err("promtool check rules",
                (r.stdout + r.stderr).strip() or "failed")


def _sub_macros(expr):
    expr = re.sub(r"\$__\w+", "5m", expr)      # __rate_interval/__interval/__range
    expr = re.sub(r"\$\{?\w+\}?", "x", expr)    # $instance/$service/$model/$tenant
    return expr


def promtool_check_exprs(promtool, exprs, rep):
    """Wrap each dashboard target expr as a recording rule and let promtool
    parse it. Batch first; on failure, re-run individually to pinpoint."""
    def run(items):
        rules = "groups:\n- name: lint\n  rules:\n"
        for i, (_, e) in enumerate(items):
            rules += f"  - record: lint_expr_{i}\n    expr: |\n"
            rules += "".join(f"        {ln}\n"
                             for ln in _sub_macros(e).splitlines() or [""])
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tf:
            tf.write(rules)
            path = tf.name
        try:
            return subprocess.run([promtool, "check", "rules", path],
                                  capture_output=True, text=True).returncode
        finally:
            os.unlink(path)

    if not exprs or run(exprs) == 0:
        return
    for item in exprs:
        if run([item]) != 0:
            fname, e = item
            rep.err(f"{fname} PromQL",
                    f"expr does not parse: {e[:120]}"
                    + ("..." if len(e) > 120 else ""))


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", default=None)
    ap.add_argument("--promtool", default=None,
                    help="path to promtool (default: $PATH)")
    ap.add_argument("--require-promtool", action="store_true",
                    help="fail (instead of warn) when promtool is absent, so "
                         "CI cannot silently skip rule and PromQL validation")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = args.repo_root or os.path.abspath(os.path.join(here, "..", "..", ".."))
    mon_dir = os.path.join(repo_root, "deploy", "monitoring")
    if not os.path.isdir(mon_dir):
        print(f"deploy/monitoring not found under {repo_root}", file=sys.stderr)
        return 2

    print(f"monitoring-lint: repo={repo_root}")
    rep = Report()

    exporter = collect_exporter_metrics(repo_root)
    print(f"  exporter metric names discovered: {len(exporter)}")
    if len(exporter) < 20:
        rep.err("exporter", "suspiciously few metric names found — is the "
                            "api/prometheus source present and readable?")

    title_to_panels, exprs = lint_dashboards(mon_dir, exporter, rep)
    lint_rules(mon_dir, exporter, title_to_panels, rep)

    promtool = find_promtool(args.promtool)
    if promtool:
        print(f"  promtool: {promtool}")
        promtool_check_rules(promtool, mon_dir, rep)
        promtool_check_exprs(promtool, exprs, rep)
    elif args.require_promtool:
        rep.err("promtool", "not found but required — rule-validity and "
                            "PromQL syntax checks did not run")
    else:
        rep.warn("promtool", "not found — skipped rule-validity and PromQL "
                             "syntax checks (CI installs promtool)")

    print()
    return rep.dump()


if __name__ == "__main__":
    sys.exit(main())
