#!/usr/bin/env python3
"""
Tier-1 live API sweeps for the LoxiLB monitoring stack (internal monitoring CI plan).

Complements lint-monitoring.py (Tier 0, static): these checks need a running
Prometheus + Grafana wired to a live loxilb, and validate the parts a static
gate cannot — the query engine accepts every shipped expression, the idle
system fires no alerts, and Grafana's provisioning + datasource wiring return
real data end-to-end.

Subcommands:
    promql       every dashboard + rule expression executes without error
                 through Prometheus /api/v1/query (Grafana macros substituted)
    alerts-idle  /api/v1/alerts contains zero `firing` alerts (0/0-guard
                 property: a quiet-but-scraped system must not page anyone)
    grafana      /api/health, all shipped dashboards provisioned, datasource
                 healthy, every panel target executes through the datasource
                 proxy (success required; non-empty counted and reported,
                 enforced globally via --min-nonempty and per-panel via
                 --require-panel "file.json:Panel title", repeatable — every
                 target of a required panel must return data)
    excluded-absent
                 no package-excluded family (manifest class != default) has
                 ANY live series — proves the running build actually excludes
                 what the manifest says it excludes, the live twin of the
                 static boundary deny-list
    cardinality  label-hygiene + series-budget audit: no family (manifest or
                 live TSDB) carries a prohibited label (prompts, keys, request
                 ids, free-form errors); every live series' label set stays
                 within the family's manifest-declared labels; per-family live
                 series count stays under budget (--max-series global cap,
                 --budget name=N overrides); families whose labels are flagged
                 privacy=label-review are reported as an access-boundary note

Exit 0 = clean, 1 = at least one failure. Stdlib-only.
"""

import argparse
import base64
import glob
import json
import os
import re
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MON_DIR = os.path.dirname(HERE)  # deploy/monitoring

# Grafana template macros/vars → concrete values a bare Prometheus accepts.
MACRO_SUBS = [
    (re.compile(r"\$__rate_interval\b"), "1m"),
    (re.compile(r"\$__interval\b"), "1m"),
    (re.compile(r"\$__range\b"), "5m"),
    # any remaining dashboard template variable ($instance, $model, $tenant,
    # $service, …) appears inside a regex matcher — match-all is the live
    # equivalent of Grafana's "All"
    (re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"), ".*"),
]


def substitute(expr):
    for pat, rep in MACRO_SUBS:
        expr = pat.sub(rep, expr)
    return expr


def http_get(url, user=None, password=None, timeout=15):
    req = urllib.request.Request(url)
    if user:
        tok = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {tok}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def prom_query(prom, expr):
    url = f"{prom}/api/v1/query?query={urllib.parse.quote(expr)}"
    return http_get(url)


# ---------------------------------------------------------------------------
# Expression harvesting (same sources Tier 0 lints, live-executed here)
# ---------------------------------------------------------------------------
def iter_panels(panels):
    for p in panels or []:
        yield p
        if p.get("panels"):
            yield from iter_panels(p["panels"])


def dashboard_exprs():
    """Yield (dashboard-file, panel-title, expr) for every target expr."""
    for path in sorted(glob.glob(os.path.join(MON_DIR, "grafana", "dashboards", "*.json"))):
        with open(path, encoding="utf-8") as fh:
            dash = json.load(fh)
        name = os.path.basename(path)
        for panel in iter_panels(dash.get("panels")):
            for tgt in panel.get("targets") or []:
                expr = tgt.get("expr")
                if expr:
                    yield name, panel.get("title", "?"), expr


def rule_exprs():
    """Yield (rule-file, alert-name, expr) from the shipped rule files.

    Stdlib-only YAML mining: exprs are either single-line (`expr: <e>`) or
    block-scalar (`expr: >-` + indented lines) — the two forms the shipped
    rules use.
    """
    for path in sorted(glob.glob(os.path.join(MON_DIR, "prometheus", "rules", "*.yml"))):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
        alert = "?"
        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r"\s*-\s*(?:alert|record):\s*(\S+)", line)
            if m:
                alert = m.group(1)
            m = re.match(r"(\s*)expr:\s*(.*)", line)
            if m:
                indent, rest = m.group(1), m.group(2).strip()
                if rest and rest not in (">-", ">", "|", "|-"):
                    yield name, alert, rest
                else:
                    block = []
                    i += 1
                    while i < len(lines):
                        nxt = lines[i]
                        if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= len(indent):
                            break
                        block.append(nxt.strip())
                        i += 1
                    yield name, alert, " ".join(b for b in block if b)
                    continue
            i += 1


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
def cmd_promql(args):
    failures = 0
    total = 0
    for src, ctx, expr in list(rule_exprs()) + list(dashboard_exprs()):
        total += 1
        live = substitute(expr)
        try:
            resp = prom_query(args.prom, live)
            if resp.get("status") != "success":
                print(f"  FAIL {src} [{ctx}]: {resp.get('error', resp)}")
                failures += 1
        except Exception as e:  # noqa: BLE001 — any transport/parse error is a failure
            print(f"  FAIL {src} [{ctx}]: {e}")
            failures += 1
    print(f"promql sweep: {total - failures}/{total} expressions executed cleanly")
    return 1 if failures else 0


def cmd_alerts_idle(args):
    resp = http_get(f"{args.prom}/api/v1/alerts")
    firing = [a for a in resp["data"]["alerts"] if a.get("state") == "firing"]
    if firing:
        for a in firing:
            print(f"  FIRING {a['labels'].get('alertname')} {a.get('labels')}")
        print(f"alerts-idle: {len(firing)} alert(s) firing on a quiet system")
        return 1
    pending = [a for a in resp["data"]["alerts"] if a.get("state") == "pending"]
    print(f"alerts-idle: 0 firing ({len(pending)} pending) — 0/0 guard holds")
    return 0


def cmd_excluded_absent(args):
    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    excluded = sorted(f["name"] for f in manifest["families"]
                      if f.get("class") != "default")
    if not excluded:
        print("excluded-absent: manifest lists no excluded families")
        return 0
    # One query for the whole set; histogram families expose their series as
    # <name>_bucket/_sum/_count, so the suffix alternation covers every type.
    pat = "^(" + "|".join(re.escape(n) for n in excluded) + ")(_bucket|_sum|_count)?$"
    resp = prom_query(args.prom, f'count by (__name__) ({{__name__=~"{pat}"}})')
    if resp.get("status") != "success":
        print(f"  FAIL excluded-absent query: {resp.get('error', resp)}")
        return 1
    present = sorted(r["metric"].get("__name__", "?") for r in resp["data"]["result"])
    if present:
        for name in present:
            print(f"  FAIL excluded family live in TSDB: {name}")
        print(f"excluded-absent: {len(present)} excluded serie(s) present — "
              "the running build emits families the package boundary bans")
        return 1
    print(f"excluded-absent: 0 of {len(excluded)} excluded families live — boundary holds")
    return 0


# Label names that must never appear on a shipped family, declared or live:
# request-scoped identifiers and free-form text explode cardinality and can
# carry user content (GW-MON-014). Enumerated-constant labels like `reason`
# or `result` are allowed; anything that would echo a prompt, credential,
# request id, or error string is not.
PROHIBITED_LABELS = frozenset({
    "prompt", "api_key", "apikey", "key", "token", "secret",
    "request_id", "req_id", "conv_id", "conversation_id",
    "error", "err", "message", "msg",
})

# Labels the scrape/rule pipeline attaches that no family declares itself.
PIPELINE_LABELS = frozenset({"__name__", "instance", "job", "cluster", "le", "quantile"})


def family_pattern(names):
    """Anchored regex matching the given family names incl. histogram series."""
    return "^(" + "|".join(re.escape(n) for n in names) + ")(_bucket|_sum|_count)?$"


def base_family(series_name, known):
    """Fold a live series name back to its manifest family name."""
    if series_name in known:
        return series_name
    for suf in ("_bucket", "_sum", "_count"):
        if series_name.endswith(suf) and series_name[: -len(suf)] in known:
            return series_name[: -len(suf)]
    return series_name


def cmd_cardinality(args):
    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    fams = {f["name"]: f for f in manifest["families"]}
    failures = 0

    # 1. Static: no family may DECLARE a prohibited label — guards the
    #    contract itself, independent of what is currently live.
    for name, f in sorted(fams.items()):
        bad = sorted(set(f["labels"]) & PROHIBITED_LABELS)
        if bad:
            print(f"  FAIL prohibited label declared: {name} {bad}")
            failures += 1

    # 2. Live: per-family series count within budget.
    budgets = {}
    for spec in args.budget or []:
        fam, _, cap = spec.partition("=")
        if fam not in fams:
            print(f"  FAIL --budget references unknown family: {fam}")
            failures += 1
            continue
        budgets[fam] = int(cap)
    resp = prom_query(args.prom,
                      f'count by (__name__) ({{__name__=~"{family_pattern(fams)}"}})')
    if resp.get("status") != "success":
        print(f"  FAIL cardinality count query: {resp.get('error', resp)}")
        return 1
    live_counts = {}
    for r in resp["data"]["result"]:
        fam = base_family(r["metric"].get("__name__", "?"), fams)
        live_counts[fam] = live_counts.get(fam, 0) + int(r["value"][1])
    total = sum(live_counts.values())
    for fam in sorted(live_counts):
        cap = budgets.get(fam, args.max_series)
        if live_counts[fam] > cap:
            print(f"  FAIL series budget: {fam} has {live_counts[fam]} series "
                  f"(cap {cap})")
            failures += 1
    if args.max_total and total > args.max_total:
        print(f"  FAIL total series budget: {total} loxilb series "
              f"(cap {args.max_total})")
        failures += 1

    # 3. Live: every live family's label names stay inside its declared set
    #    (plus pipeline labels). Catches undeclared-label drift AND any
    #    prohibited label that reached the wire.
    checked = 0
    for fam in sorted(live_counts):
        if fam not in fams:
            print(f"  FAIL live loxilb family not in manifest: {fam}")
            failures += 1
            continue
        url = (f"{args.prom}/api/v1/labels?match[]="
               + urllib.parse.quote(f'{{__name__=~"{family_pattern([fam])}"}}'))
        resp = http_get(url)
        if resp.get("status") != "success":
            print(f"  FAIL labels query for {fam}: {resp.get('error', resp)}")
            failures += 1
            continue
        checked += 1
        live_labels = set(resp["data"])
        extra = sorted(live_labels - set(fams[fam]["labels"]) - PIPELINE_LABELS)
        if extra:
            kind = ("PROHIBITED" if set(extra) & PROHIBITED_LABELS
                    else "undeclared")
            print(f"  FAIL {kind} live label(s) on {fam}: {extra}")
            failures += 1

    # 4. Access-boundary note (non-fatal): live families whose labels are
    #    flagged privacy=label-review (network/tenant identifiers) — access
    #    to this Prometheus must stay within the operator boundary.
    review = sorted(f for f in live_counts
                    if fams.get(f, {}).get("privacy") == "label-review")
    if review:
        print(f"  note: {len(review)} live famil(ies) carry privacy-review "
              f"labels (operator-boundary data): {', '.join(review)}")

    print(f"cardinality: {len(live_counts)} live families, {total} series, "
          f"{checked} label-audited, budgets {'OK' if not failures else 'VIOLATED'}")
    return 1 if failures else 0


def cmd_grafana(args):
    g, u, p = args.grafana, args.user, args.password
    failures = 0

    health = http_get(f"{g}/api/health", u, p)
    if health.get("database") != "ok":
        print(f"  FAIL /api/health: {health}")
        failures += 1

    shipped = {os.path.basename(f) for f in
               glob.glob(os.path.join(MON_DIR, "grafana", "dashboards", "*.json"))}
    found = http_get(f"{g}/api/search?type=dash-db", u, p)
    if len(found) < len(shipped):
        print(f"  FAIL provisioning: {len(found)} dashboards found, {len(shipped)} shipped")
        failures += 1
    else:
        print(f"  dashboards provisioned: {len(found)}/{len(shipped)}")

    ds = http_get(f"{g}/api/datasources/uid/loxilb-prom", u, p)
    if ds.get("uid") != "loxilb-prom":
        print(f"  FAIL datasource uid loxilb-prom not provisioned: {ds}")
        failures += 1

    required = {}  # "file.json:title" → [seen_any_target, all_targets_nonempty]
    for spec in args.require_panel or []:
        required[spec] = [False, True]

    proxy = f"{g}/api/datasources/proxy/uid/loxilb-prom/api/v1/query"
    total = nonempty = 0
    for src, title, expr in dashboard_exprs():
        total += 1
        live = substitute(expr)
        key = f"{src}:{title}"
        try:
            resp = http_get(f"{proxy}?query={urllib.parse.quote(live)}", u, p)
            got_data = resp.get("status") == "success" and bool(resp["data"]["result"])
            if resp.get("status") != "success":
                print(f"  FAIL {src} [{title}] via proxy: {resp.get('error', resp)}")
                failures += 1
            elif got_data:
                nonempty += 1
        except Exception as e:  # noqa: BLE001
            got_data = False
            print(f"  FAIL {src} [{title}] via proxy: {e}")
            failures += 1
        if key in required:
            required[key][0] = True
            required[key][1] = required[key][1] and got_data
    print(f"grafana panel sweep: {total} targets executed, {nonempty} returned data")
    if args.min_nonempty and nonempty < args.min_nonempty:
        print(f"  FAIL only {nonempty} panels returned data (< {args.min_nonempty}) — "
              "datasource wiring or traffic drive is broken")
        failures += 1
    for spec, (seen, all_ok) in sorted(required.items()):
        if not seen:
            print(f"  FAIL required panel not found in any dashboard: {spec}")
            failures += 1
        elif not all_ok:
            print(f"  FAIL required panel returned no data: {spec}")
            failures += 1
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("promql")
    sp.add_argument("--prom", default="http://127.0.0.1:9090")
    sp.set_defaults(fn=cmd_promql)

    sp = sub.add_parser("alerts-idle")
    sp.add_argument("--prom", default="http://127.0.0.1:9090")
    sp.set_defaults(fn=cmd_alerts_idle)

    sp = sub.add_parser("grafana")
    sp.add_argument("--grafana", default="http://127.0.0.1:3000")
    sp.add_argument("--user", default="admin")
    sp.add_argument("--password", default="ci-admin")
    sp.add_argument("--min-nonempty", type=int, default=0)
    sp.add_argument("--require-panel", action="append", metavar="FILE.json:TITLE",
                    help="panel whose every target must return data (repeatable)")
    sp.set_defaults(fn=cmd_grafana)

    sp = sub.add_parser("excluded-absent")
    sp.add_argument("--prom", default="http://127.0.0.1:9090")
    sp.add_argument("--manifest",
                    default=os.path.join(MON_DIR, "manifest", "metric-manifest.json"))
    sp.set_defaults(fn=cmd_excluded_absent)

    sp = sub.add_parser("cardinality")
    sp.add_argument("--prom", default="http://127.0.0.1:9090")
    sp.add_argument("--manifest",
                    default=os.path.join(MON_DIR, "manifest", "metric-manifest.json"))
    sp.add_argument("--max-series", type=int, default=500,
                    help="per-family live series cap (default 500)")
    sp.add_argument("--max-total", type=int, default=0,
                    help="total loxilb series cap (0 = unchecked)")
    sp.add_argument("--budget", action="append", metavar="FAMILY=N",
                    help="per-family cap override (repeatable)")
    sp.set_defaults(fn=cmd_cardinality)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
