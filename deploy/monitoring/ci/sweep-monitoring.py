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
                 enforced globally via --min-nonempty)

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

    proxy = f"{g}/api/datasources/proxy/uid/loxilb-prom/api/v1/query"
    total = nonempty = 0
    for src, title, expr in dashboard_exprs():
        total += 1
        live = substitute(expr)
        try:
            resp = http_get(f"{proxy}?query={urllib.parse.quote(live)}", u, p)
            if resp.get("status") != "success":
                print(f"  FAIL {src} [{title}] via proxy: {resp.get('error', resp)}")
                failures += 1
            elif resp["data"]["result"]:
                nonempty += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL {src} [{title}] via proxy: {e}")
            failures += 1
    print(f"grafana panel sweep: {total} targets executed, {nonempty} returned data")
    if args.min_nonempty and nonempty < args.min_nonempty:
        print(f"  FAIL only {nonempty} panels returned data (< {args.min_nonempty}) — "
              "datasource wiring or traffic drive is broken")
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
    sp.set_defaults(fn=cmd_grafana)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
