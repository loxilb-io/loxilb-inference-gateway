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
  6. Every packaged family carries a reviewed writer map: the ordered chain of
     Go symbols from the constructor to a production entry point, with each
     hop's receiver type recorded and re-verified against source on every run.
     A future "this family has no callers" claim is checked against that stored
     map instead of a re-run query.
  7. No default dashboard, alert rule, scrape job, or release test consumes a
     release-excluded experimental family.
  8. Optionally (--locked-rev-check), the extractor runs against the locked
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
import datetime
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
    scopes = overlay.get("runtime_scope_by_class", {})
    for k in sorted(classes):
        if not scopes.get(k):
            errors.append(f"class '{k}' has no runtime_scope_by_class entry; "
                          f"the manifest would publish a blank runtime scope")
    for k in sorted(set(scopes) - set(classes)):
        errors.append(f"runtime_scope_by_class entry '{k}' matches no class")


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


# ---------------------------------------------------------------------------
# writer map: constructor -> production entry point, recorded and re-verified
# ---------------------------------------------------------------------------
# Why a *stored* map rather than a query run at gate time: on 2026-09-10 a
# "zero callers" query classified four live parser families as dead. The query
# was right about the symbol it was given (ParseWithTimeoutOrDefault) and wrong
# about the family, because that symbol is a method on PluginRegistry while the
# production path goes through TraceParserRegistry. Two facts would have caught
# it -- the receiver type of every method hop, and the transitive chain up to an
# entry point -- and neither survives in a query result. So they are recorded
# here per family, reviewed, and re-checked against source on every run: the
# gate's job is to notice when the recorded chain stops matching the tree, not
# to re-derive reachability.
WRITER_STATUSES = {
    # Observed emitting real values on a live bed, with the value checked.
    "verified-runtime",
    # Writer path proven in source; the family stays absent until a named
    # configuration/traffic precondition is met. Requires
    # activation_precondition.
    "conditional-with-proven-writer",
    # Writer path proven in source and driven by a test, but not yet observed
    # on a bed.
    "verified-static",
    # Writer path recorded and re-verified against source, with nothing driving
    # it yet: no test, no bed observation, and no configuration gate that would
    # explain absence. This is the burn-down's intermediate state, not a
    # finished one -- the campaign's exit criteria (plan section B.7) accept
    # only verified-runtime, verified-static, conditional-with-proven-writer, or
    # a deliberate removal. It exists because the alternative was to record one
    # of those for a family nothing has exercised, which is the kind of
    # overclaim this whole gate was built to stop.
    "writer-mapped",
    # Reviewed and accepted as having no production writer. Requires a
    # rejection rationale naming the exact symbols queried and their receivers.
    "definition-only",
}

# Statuses that still owe verification work. Counted by their own ratchet so
# finishing the map cannot be mistaken for finishing the qualification.
UNVERIFIED_STATUSES = {"writer-mapped"}

ENTRY_POINT_KINDS = {
    "main",              # reached from process start-up
    "goroutine",         # launched by a long-running goroutine
    "event-loop",        # driven by a datapath/trace event dispatcher
    "cgo-export",        # //export, called from the C data plane
    "http-handler",      # REST/API request path
    "registry-collector",  # prometheus.Collector pulled by the registry
    "timer",             # ticker / periodic refresh
}

HOP_KEYS_FIRST = {"symbol", "kind", "receiver", "file", "def_line", "writes",
                  "entry_point", "note"}
HOP_KEYS_REST = {"symbol", "kind", "receiver", "file", "def_line", "call_line",
                 "calls", "entry_point", "note", "via"}
# A hop that dispatches through a function-valued variable ("metric seam"):
#   var echoFn = prom.IncKvAttestEcho   <- the binding
#   echoFn("ok")                        <- the call site
# The call site never names the writer, so a name search finds no caller at
# all -- the same blind spot as the receiver mismatch that made four live
# parser families look dead. Recording the binding site makes the hop
# checkable: the gate confirms the variable really is bound to the previous
# hop's symbol, so re-pointing the seam at something else fails here.
VIA_KEYS = {"var", "file", "line"}
ENTRY_KEYS = {"status", "activation_precondition", "writer_sources",
              "data_sources", "native_callers", "rejection",
              "queried_symbols", "evidence"}

# Most collectors reach production through the same start-up spine, so the last
# hops of their chains are identical. Repeating them per family would make the
# map larger than anyone will read, and a chain nobody reads is a comment. A
# chain may therefore end with {"tail": "<id>"}, expanded from
# writer_status.tails before any check runs -- so the anchors in a shared tail
# are re-verified once per referencing family, exactly as if they were inline.
# The published manifest carries the expanded chain: consumers see the whole
# path, not the reference.
TAIL_KEY = "tail"


def resolve_chain(chain, tails, at, errors):
    """Expand a trailing {"tail": id} reference into its hops."""
    if not isinstance(chain, list):
        return chain
    out = []
    for i, hop in enumerate(chain):
        if not isinstance(hop, dict) or TAIL_KEY not in hop:
            out.append(hop)
            continue
        if set(hop) != {TAIL_KEY}:
            errors.append(f"{at}[{i}] mixes a tail reference with hop fields; "
                          f"a tail element carries only '{TAIL_KEY}'")
            continue
        if i != len(chain) - 1:
            errors.append(f"{at}[{i}] references tail {hop[TAIL_KEY]!r} but is "
                          f"not the last element; a tail ends the chain")
            continue
        tail = tails.get(hop[TAIL_KEY])
        if not isinstance(tail, list) or not tail:
            errors.append(f"{at}[{i}] references unknown tail "
                          f"{hop[TAIL_KEY]!r}; declared tails are "
                          f"{sorted(tails)}")
            continue
        out.extend(tail)
    return out


def resolve_entry(ent, tails, family, errors):
    """Entry with both chains expanded; the original is left untouched."""
    if not isinstance(ent, dict):
        return ent
    out = dict(ent)
    for field in ("writer_sources", "data_sources"):
        if field in out:
            out[field] = resolve_chain(
                out[field], tails, f"writer_status['{family}'].{field}", errors)
    return out

# func Name(            -> name=Name, recv=""
# func (sa *T) Name(    -> name=Name, recv=T
# func (T) Name(        -> name=Name, recv=T   (unnamed receiver)
FUNC_DEF = re.compile(
    r"^func\s+"
    r"(?:\(\s*(?:[A-Za-z_]\w*\s+)?\*?(?P<recv>[A-Za-z_][\w.]*)\s*\)\s*)?"
    r"(?P<name>[A-Za-z_]\w*)\s*[\(\[]")


def _source_lines(repo_root, rel, cache):
    """File contents as a line list, or None when it cannot be read."""
    if rel not in cache:
        try:
            with open(os.path.join(repo_root, rel), encoding="utf-8",
                      errors="ignore") as fh:
                cache[rel] = fh.read().splitlines()
        except OSError:
            cache[rel] = None
    return cache[rel]


def _func_at(lines, lineno):
    """(name, receiver) of the func defined at 1-based lineno, else None."""
    if not lines or not 1 <= lineno <= len(lines):
        return None
    m = FUNC_DEF.match(lines[lineno - 1])
    if not m:
        return None
    return m.group("name"), (m.group("recv") or "")


def _func_end(lines, def_line):
    """1-based last line of the func body opened at def_line.

    gofmt puts a top-level func's closing brace in column 0, so the first such
    line after the signature ends the body. A file that is not gofmt-clean
    degrades to "the rest of the file", which can only make the body-range
    check more permissive, never wrongly red.
    """
    for i in range(def_line, len(lines)):
        if lines[i].startswith("}"):
            return i + 1
    return len(lines)


def _token_in(line, token):
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])",
                     line) is not None


def check_writer_chain(family, chain, field, repo_root, unverifiable, cache,
                       errors):
    """Verify one ordered writer chain against the source tree.

    chain[0] is the function that touches the family's constructor; every later
    hop must call the previous hop's symbol (or, for registry-mediated
    dispatch, name its receiver type), and the last hop must declare which kind
    of production entry point it is.
    """
    at = f"writer_status['{family}'].{field}"
    if not isinstance(chain, list) or not chain:
        errors.append(f"{at} must be a non-empty ordered chain from the "
                      f"constructor's writer to a production entry point")
        return
    for i, hop in enumerate(chain):
        first, last = i == 0, i == len(chain) - 1
        hop_at = f"{at}[{i}]"
        if not isinstance(hop, dict):
            errors.append(f"{hop_at} must be an object")
            continue
        allowed = HOP_KEYS_FIRST if first else HOP_KEYS_REST
        for k in sorted(set(hop) - allowed):
            errors.append(f"{hop_at} has unknown key '{k}' "
                          f"(allowed: {sorted(allowed)})")
        required = ({"symbol", "kind", "file", "def_line", "writes"} if first
                    else {"symbol", "kind", "file", "def_line", "call_line",
                          "calls"})
        missing = sorted(required - set(hop))
        if missing:
            errors.append(f"{hop_at} is missing {missing}")
            continue

        kind, recv = hop["kind"], hop.get("receiver", "")
        if kind not in ("func", "method"):
            errors.append(f"{hop_at} kind must be 'func' or 'method', "
                          f"got {kind!r}")
        if kind == "method" and not recv:
            errors.append(
                f"{hop_at} is a method and must record its receiver type. "
                f"This field exists because a method on the wrong receiver is "
                f"exactly how four live families were once called dead")
        if kind == "func" and recv:
            errors.append(f"{hop_at} is a plain func but records receiver "
                          f"{recv!r}")

        ep = hop.get("entry_point")
        if last and not ep:
            errors.append(f"{hop_at} is the end of the chain and must declare "
                          f"entry_point (one of {sorted(ENTRY_POINT_KINDS)})")
        if ep and not last:
            errors.append(f"{hop_at} declares entry_point but is not the last "
                          f"hop; the chain must end at the entry point")
        if ep and ep not in ENTRY_POINT_KINDS:
            errors.append(f"{hop_at} entry_point {ep!r} is not one of "
                          f"{sorted(ENTRY_POINT_KINDS)}")

        rel = hop["file"]
        if rel.startswith(unverifiable):
            # Declared out of reach (e.g. a submodule CI does not check out).
            # The shape is still validated; the anchor is not claimed.
            continue
        lines = _source_lines(repo_root, rel, cache)
        if lines is None:
            errors.append(f"{hop_at} names {rel}, which does not exist or "
                          f"cannot be read")
            continue

        got = _func_at(lines, hop["def_line"])
        if got is None:
            actual = (lines[hop["def_line"] - 1].strip()[:60]
                      if 1 <= hop["def_line"] <= len(lines) else "<past EOF>")
            errors.append(f"{hop_at} def_line {rel}:{hop['def_line']} is not a "
                          f"Go func definition (line reads: {actual!r}) — the "
                          f"code moved, so re-verify the chain")
            continue
        got_name, got_recv = got
        if got_name != hop["symbol"]:
            errors.append(f"{hop_at} records symbol '{hop['symbol']}' but "
                          f"{rel}:{hop['def_line']} defines '{got_name}'")
            continue
        if got_recv != recv:
            errors.append(
                f"{hop_at} records receiver {recv or '<none>'!r} for "
                f"'{hop['symbol']}' but {rel}:{hop['def_line']} declares "
                f"{got_recv or '<none>'!r}")
            continue

        end = _func_end(lines, hop["def_line"])
        if first:
            body = "\n".join(lines[hop["def_line"] - 1:end])
            if not _token_in(body, hop["writes"]):
                errors.append(f"{hop_at} claims '{hop['symbol']}' writes "
                              f"'{hop['writes']}', which does not appear in "
                              f"its body ({rel}:{hop['def_line']}-{end})")
            continue

        call_line = hop["call_line"]
        if not hop["def_line"] < call_line <= end:
            errors.append(f"{hop_at} call_line {call_line} is outside the body "
                          f"of '{hop['symbol']}' ({rel}:{hop['def_line']}-"
                          f"{end})")
            continue
        if not _token_in(lines[call_line - 1], hop["calls"]):
            errors.append(f"{hop_at} claims a call to '{hop['calls']}' at "
                          f"{rel}:{call_line}, which reads "
                          f"{lines[call_line - 1].strip()[:60]!r}")
        prev = chain[i - 1]
        links = {prev.get("symbol"), prev.get("receiver")} - {None, ""}
        via = hop.get("via")
        if via is not None:
            check_via(hop, via, prev, hop_at, repo_root, unverifiable, cache,
                      errors)
        elif hop["calls"] not in links:
            errors.append(f"{hop_at} calls '{hop['calls']}', which is neither "
                          f"the previous hop's symbol nor its receiver type "
                          f"({sorted(links)}) — the chain is not connected")


def check_via(hop, via, prev, hop_at, repo_root, unverifiable, cache, errors):
    """The call goes through a function-valued variable; verify the binding."""
    if not isinstance(via, dict) or set(via) != VIA_KEYS:
        errors.append(f"{hop_at}.via must record exactly {sorted(VIA_KEYS)}: "
                      f"the seam variable and where it is bound")
        return
    if hop["calls"] != via["var"]:
        errors.append(f"{hop_at} dispatches through '{via['var']}' but records "
                      f"calls '{hop['calls']}'; for a via hop they are the "
                      f"same name")
        return
    rel = via["file"]
    if rel.startswith(unverifiable):
        return
    lines = _source_lines(repo_root, rel, cache)
    if lines is None:
        errors.append(f"{hop_at}.via names {rel}, which does not exist or "
                      f"cannot be read")
        return
    if not 1 <= via["line"] <= len(lines):
        errors.append(f"{hop_at}.via line {rel}:{via['line']} is past EOF")
        return
    binding = lines[via["line"] - 1]
    want = prev.get("symbol")
    if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(via['var'])}\s*=\s*"
                     rf"(?:[A-Za-z_]\w*\.)?{re.escape(want)}(?![A-Za-z0-9_])",
                     binding):
        errors.append(
            f"{hop_at}.via claims {rel}:{via['line']} binds '{via['var']}' to "
            f"'{want}', but the line reads {binding.strip()[:70]!r} — a seam "
            f"pointed somewhere else emits nothing this map would notice")


def check_writers(fams, overlay, repo_root, errors):
    """Every packaged family has a reviewed, source-checked writer path.

    The end state is that no packaged family is unclassified. Until the
    burn-down finishes, `burndown.unclassified_max` is a one-way ratchet: the
    gate fails when unclassified families exceed it AND when it sits above the
    real count, so classifying families forces the ceiling down and it can
    never drift back up. At 0 this is exactly the gate WP-0 specifies.
    """
    block = overlay.get("writer_status")
    if not isinstance(block, dict):
        errors.append("overlay has no writer_status block; the writer-map gate "
                      "cannot run and would silently pass")
        return {}
    entries = block.get("families", {})
    unverifiable = tuple(block.get("unverifiable_roots", ()))
    tails = block.get("tails", {})
    by_name = {e["name"]: e for e in fams}
    packaged = {e["name"] for e in fams if e["class"] == "default"}
    cache = {}
    used_tails = set()
    unverified = []

    for name in sorted(entries):
        ent = entries[name]
        if isinstance(ent, dict):
            for field in ("writer_sources", "data_sources"):
                for hop in ent.get(field, ()) or ():
                    if isinstance(hop, dict) and TAIL_KEY in hop:
                        used_tails.add(hop[TAIL_KEY])
            ent = resolve_entry(ent, tails, name, errors)
        at = f"writer_status['{name}']"
        if not isinstance(ent, dict):
            errors.append(f"{at} must be an object")
            continue
        for k in sorted(set(ent) - ENTRY_KEYS):
            errors.append(f"{at} has unknown key '{k}' "
                          f"(allowed: {sorted(ENTRY_KEYS)})")
        if name not in by_name:
            errors.append(f"{at} names unknown family '{name}' — typo, or the "
                          f"family was removed and the entry is stale")
            continue
        if name not in packaged:
            errors.append(f"{at} is meaningless: class "
                          f"'{by_name[name]['class']}' is release-excluded, so "
                          f"it carries no writer-path obligation")
            continue

        status = ent.get("status")
        if status not in WRITER_STATUSES:
            errors.append(f"{at} status {status!r} is not one of "
                          f"{sorted(WRITER_STATUSES)}")
            continue
        if len(ent.get("evidence", "")) < 20:
            errors.append(f"{at} needs an evidence pointer someone else can "
                          f"open (doc section, run ID, or test name)")

        if status == "definition-only":
            if ent.get("writer_sources"):
                errors.append(f"{at} is definition-only but records "
                              f"writer_sources; pick one")
            if len(ent.get("rejection", "")) < 40:
                errors.append(f"{at} is definition-only and must state why no "
                              f"production writer reaches the constructor")
            queried = ent.get("queried_symbols")
            if not isinstance(queried, list) or not queried:
                errors.append(
                    f"{at} is definition-only and must list queried_symbols "
                    f"— the exact symbols checked, each with its receiver "
                    f"where it is a method. Without that the claim is the "
                    f"same shape as the withdrawn parser finding")
            else:
                for j, q in enumerate(queried):
                    if not isinstance(q, dict) or "symbol" not in q:
                        errors.append(f"{at}.queried_symbols[{j}] must be an "
                                      f"object with at least 'symbol'")
                    elif q.get("kind") == "method" and not q.get("receiver"):
                        errors.append(f"{at}.queried_symbols[{j}] is a method "
                                      f"and must record its receiver type")
            continue

        if status in UNVERIFIED_STATUSES:
            unverified.append(name)
        if status == "conditional-with-proven-writer" and \
                len(ent.get("activation_precondition", "")) < 20:
            errors.append(f"{at} is conditional and must name the "
                          f"configuration or traffic precondition that makes "
                          f"the family appear")
        check_writer_chain(name, ent.get("writer_sources"), "writer_sources",
                           repo_root, unverifiable, cache, errors)
        if "data_sources" in ent:
            check_writer_chain(name, ent["data_sources"], "data_sources",
                               repo_root, unverifiable, cache, errors)
        for j, nc in enumerate(ent.get("native_callers", ())):
            if not re.match(r"^[\w./-]+:\d+$", str(nc)):
                errors.append(f"{at}.native_callers[{j}] must be 'path:line', "
                              f"got {nc!r}")

    for tail_id in sorted(set(tails) - used_tails):
        errors.append(f"writer_status.tails['{tail_id}'] is referenced by no "
                      f"family; an unread chain is a comment, not a gate")

    unclassified = sorted(packaged - set(entries))
    burndown = block.get("burndown", {})
    ucap = burndown.get("unverified_max")
    if not isinstance(ucap, int) or ucap < 0:
        errors.append("writer_status.burndown.unverified_max must be a "
                      "non-negative integer; it is the ratchet on families "
                      f"whose status is one of {sorted(UNVERIFIED_STATUSES)}")
    elif len(unverified) > ucap:
        errors.append(
            f"{len(unverified)} families carry an unverified writer status, "
            f"above the ratchet of {ucap}: {unverified[:8]}"
            f"{' ...' if len(unverified) > 8 else ''}")
    elif ucap > len(unverified):
        errors.append(f"writer_status.burndown.unverified_max is {ucap} but "
                      f"only {len(unverified)} families are unverified; lower "
                      f"the ratchet to {len(unverified)} so it cannot drift "
                      f"back up")
    cap = block.get("burndown", {}).get("unclassified_max")
    if not isinstance(cap, int) or cap < 0:
        errors.append("writer_status.burndown.unclassified_max must be a "
                      "non-negative integer; it is the burn-down ratchet")
    elif len(unclassified) > cap:
        errors.append(
            f"{len(unclassified)} packaged families have no writer_status "
            f"entry, above the ratchet of {cap}: "
            f"{unclassified[:8]}{' ...' if len(unclassified) > 8 else ''}")
    elif cap > len(unclassified):
        errors.append(f"writer_status.burndown.unclassified_max is {cap} but "
                      f"only {len(unclassified)} families are unclassified; "
                      f"lower the ratchet to {len(unclassified)} so it cannot "
                      f"drift back up")
    return {"writer_classified": len(packaged) - len(unclassified),
            "writer_unclassified": len(unclassified),
            "writer_unverified": len(unverified)}


# ---------------------------------------------------------------------------
# release-excluded families must have no default consumer
# ---------------------------------------------------------------------------
def check_excluded_consumers(fams, overlay, repo_root, errors):
    """No release asset may depend on a RELEASE-EXCLUDED-EXPERIMENTAL family.

    This currently passes, which is the point: it locks a property the tree
    already holds, so reintroducing a dependency fails here rather than at
    release-acceptance time. The surfaces are declared in the overlay and each
    one must match at least one file -- a scan that reads nothing would pass
    forever and prove nothing.
    """
    cfg = overlay.get("excluded_consumer_scan")
    if not isinstance(cfg, dict):
        errors.append("overlay has no excluded_consumer_scan block; the "
                      "exclusion gate cannot run and would silently pass")
        return
    excluded = {e["name"] for e in fams if e["class"] != "default"}
    packaged = {e["name"] for e in fams if e["class"] == "default"}
    exempt = set(cfg.get("inventory_exempt", ()))
    for rel in sorted(exempt):
        if not os.path.exists(os.path.join(repo_root, rel)):
            errors.append(f"excluded_consumer_scan.inventory_exempt names "
                          f"{rel}, which does not exist — stale exemption")

    def strip_hist(ref):
        for suf in HIST_SUFFIXES:
            if ref.endswith(suf) and ref[:-len(suf)] in excluded | packaged:
                return ref[:-len(suf)]
        return ref

    for surface in cfg.get("surfaces", ()):
        pattern, kind = surface["glob"], surface["kind"]
        matched = sorted(glob.glob(os.path.join(repo_root, pattern),
                                   recursive=True))
        files = [f for f in matched if os.path.isfile(f)]
        if not files:
            errors.append(f"excluded_consumer_scan surface '{pattern}' "
                          f"({kind}) matches no file; a scan over nothing "
                          f"passes forever")
            continue
        for path in files:
            rel = os.path.relpath(path, repo_root)
            if rel in exempt:
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            hits = sorted({strip_hist(m.group(1))
                           for m in METRIC_TOKEN.finditer(text)} & excluded)
            if hits:
                errors.append(
                    f"{rel} ({kind}) consumes release-excluded experimental "
                    f"famil{'y' if len(hits) == 1 else 'ies'} {hits[:4]} — "
                    f"this release ships no dependency on them")


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
# SCHEMA_VERSION is the consumer-facing contract version of the manifest
# document. Bump it when a consumer that reads the previous version could
# misread this one: a field removed or renamed, or an existing field's meaning
# changed. Purely additive fields do not need a bump, but recording one costs
# nothing and tells a vendoring consumer what it is looking at.
#
#   1 -- first versioned document. Adds schema_version and provenance at the
#        root, and definition_mechanism per family; "type" now always carries
#        the runtime metric type, where it previously carried the literal
#        "desc" for families defined through prometheus.NewDesc.
#
# The WP-0 writer-map fields (release_scope, runtime_scope,
# implementation_status, activation_precondition, writer_sources,
# verification_evidence) are deliberately NOT a bump: they are purely
# additive, no existing field changed meaning, and a consumer written against
# version 1 reads this document correctly. Vendoring consumers still need to
# re-vendor to pick the fields up.
SCHEMA_VERSION = 1


def load_committed(manifest_path):
    """Return the committed manifest as a dict, or None if it is absent."""
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def strip_provenance(manifest):
    """The manifest with its provenance block removed, for content comparison."""
    return {k: v for k, v in manifest.items() if k != "provenance"}


def git_head(repo_root):
    """The revision being described, or "" when git cannot answer."""
    try:
        out = subprocess.run(["git", "-C", repo_root, "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def provenance_for(committed, fams, overlay, coverage, repo_root, now):
    """Provenance for the manifest about to be written.

    Rewritten only when the content changes. Keeping it otherwise means the
    file does not churn on every regeneration -- which would make the --check
    gate unusable and fill history with no-op diffs -- and gives the two fields
    a meaning worth reading: the revision and time at which this manifest last
    said something different.
    """
    candidate = build_manifest(fams, overlay, coverage, {})
    if committed is not None and \
            strip_provenance(committed) == strip_provenance(candidate):
        prev = committed.get("provenance")
        if isinstance(prev, dict) and prev:
            return prev
    return {
        "generated_at": now or datetime.datetime.now(
            datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "source_revision": git_head(repo_root),
    }


def check_types(fams, overlay, errors):
    """Every family must carry a real runtime metric type.

    prometheus.NewDesc cannot state the type -- it is chosen later, at the
    MustNewConstMetric/MustNewConstHistogram site that consumes the Desc -- so
    the extractor resolves it from there. A family still carrying "desc" means
    that resolution failed: the Desc is bound to no variable, is never emitted,
    or is emitted from a construct the extractor does not model. "conflict"
    means it is emitted with two different types, so no single type describes
    it. Both must fail generation rather than ship, because a consumer cannot
    render a family whose type is unknown or ambiguous, and a manifest that
    says "desc" silently pushes that guess onto every consumer.
    """
    valid = {"counter", "gauge", "histogram", "summary", "untyped"}
    for e in fams:
        t = e.get("type", "")
        if t == "desc":
            errors.append(
                f"{e['file']}:{e['line']}: family '{e['name']}' has no resolved "
                f"runtime type. It is defined with prometheus.NewDesc; bind the "
                f"Desc to a variable and emit it with MustNewConstMetric/"
                f"MustNewConstHistogram so the type can be read from there")
        elif t == "conflict":
            errors.append(
                f"{e['file']}:{e['line']}: family '{e['name']}' is emitted with "
                f"more than one metric type; a family must have exactly one")
        elif t not in valid:
            errors.append(
                f"{e['file']}:{e['line']}: family '{e['name']}' has unknown type "
                f"'{t}'")

    # The resolution is derived, so pin what it must resolve to: a counter
    # silently becoming a gauge would otherwise pass every check above.
    pinned = overlay.get("desc_runtime_types", {})
    by_name = {e["name"]: e for e in fams}
    for name, want in sorted(pinned.items()):
        e = by_name.get(name)
        if e is None:
            errors.append(f"desc_runtime_types pins unknown family '{name}' "
                          f"(remove the pin if the family is gone)")
            continue
        if e.get("mechanism") != "desc":
            errors.append(f"desc_runtime_types pins '{name}', which is no longer "
                          f"defined via prometheus.NewDesc "
                          f"(mechanism={e.get('mechanism')!r}); remove the pin")
            continue
        if e.get("type") != want:
            errors.append(f"family '{name}' resolved to type '{e.get('type')}', "
                          f"pinned as '{want}' ({e['file']}:{e['line']})")
    for e in fams:
        if e.get("mechanism") == "desc" and e["name"] not in pinned:
            errors.append(f"family '{e['name']}' is defined via prometheus.NewDesc "
                          f"but is not pinned in desc_runtime_types; add it with "
                          f"its runtime type ({e['file']}:{e['line']})")


def build_manifest(fams, overlay, coverage, provenance):
    act = overlay["activation"]
    pri = overlay["priority"]
    review = set(overlay.get("privacy_review_labels", ()))
    writer_block = overlay.get("writer_status", {})
    tails = writer_block.get("tails", {})
    # Publish the expanded chain: a consumer of the manifest reads the whole
    # path to the entry point, never a reference it would have to resolve.
    writers = {name: resolve_entry(ent, tails, name, [])
               for name, ent in writer_block.get("families", {}).items()}
    scopes = overlay.get("runtime_scope_by_class", {})
    entries = []
    for e in sorted(fams, key=lambda x: (x["owner"], x["name"])):
        w = writers.get(e["name"], {})
        entries.append({
            "name": e["name"],
            "owner": e["owner"],
            "class": e["class"],
            "packaged": e["packaged"],
            # The runtime metric type, always: counter|gauge|histogram|summary.
            "type": e["type"],
            # How the family is declared in source. Orthogonal to "type":
            # a "desc" family still has a real runtime type, resolved from the
            # site that turns its Desc into a metric.
            "definition_mechanism": e.get("mechanism", ""),
            "labels": e["labels"],
            "activation": act.get(e["name"], ""),
            "priority": pri["overrides"].get(e["name"], pri["default"]),
            "privacy": ("label-review"
                        if set(e["labels"]) & review else "none"),
            "consumers": e["consumers"],
            "waiver": e.get("waiver", ""),
            "source": f"{e['file']}:{e['line']}",
            # Release scope. Only "default" families are developed and
            # qualified by this release; everything else is
            # RELEASE-EXCLUDED-EXPERIMENTAL and must not appear in any default
            # dashboard, rule, scrape job, or release test.
            "release_scope": ("release" if e["class"] == "default"
                              else "excluded-experimental"),
            # Where the family can appear at runtime at all -- a different
            # question from whether this release qualifies it. Mapped from the
            # class in the overlay so the answer is reviewed, not inferred.
            "runtime_scope": scopes.get(e["class"], ""),
            # The reviewed writer map. "" means no reviewed decision exists
            # yet -- an honest gap, not an assertion that the family is dead.
            "implementation_status": w.get("status", ""),
            "activation_precondition": w.get("activation_precondition", ""),
            "writer_sources": w.get("writer_sources", []),
            "verification_evidence": w.get("evidence", ""),
        })
    return {"schema_version": SCHEMA_VERSION, "provenance": provenance,
            "contract": overlay["expected"], "coverage": coverage,
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

    def expect_green(what, errs):
        if errs:
            failures.append(what)
            print(f"  FALSE-RED {what}: {errs[0][:90]}")
        else:
            print(f"  ok    {what}: accepted")

    with tempfile.TemporaryDirectory() as root:
        writer_self_test(root, expect_red, expect_green)
        excluded_consumer_self_test(root, expect_red)

    if failures:
        print(f"\nself-test: {len(failures)} gate(s) cannot fire: {failures}")
        return 1
    print("\nself-test: every gate can go red")
    return 0


# The fixture the writer-map gate is tested against. Line numbers are load
# bearing -- the gate's whole job is to notice when a recorded line stops
# meaning what it claimed -- so keep this literal in sync with FIXTURE_CHAIN
# below if you touch it.
#
#   1 package fixture
#   2
#   3 var famTotal = 1
#   4
#   5 func recordFam() {
#   6     famTotal++
#   7 }
#   8
#   9 func decoy() {
#  10 }
#  11
#  12 func middle() {
#  13     recordFam()
#  14     decoy()
#  15 }
#  16
#  17 type Loop struct{}
#  18
#  19 func (l *Loop) Run() {
#  20     middle()
#  21 }
#  22
#  23 var seamFn = recordFam
#  24
#  25 func viaSeam() {
#  26     seamFn()
#  27 }
FIXTURE_GO = """package fixture

var famTotal = 1

func recordFam() {
\tfamTotal++
}

func decoy() {
}

func middle() {
\trecordFam()
\tdecoy()
}

type Loop struct{}

func (l *Loop) Run() {
\tmiddle()
}

var seamFn = recordFam

func viaSeam() {
\tseamFn()
}
"""

# recordFam is called only from middle, which is called only from one
# production entry point. That is the transitive shape the withdrawn parser
# finding missed, so the gate must accept it -- a writer map that only
# recognises direct calls would re-create the same false negative.
FIXTURE_CHAIN = [
    {"symbol": "recordFam", "kind": "func", "file": "pkg/fixture/fam.go",
     "def_line": 5, "writes": "famTotal"},
    {"symbol": "middle", "kind": "func", "file": "pkg/fixture/fam.go",
     "def_line": 12, "call_line": 13, "calls": "recordFam"},
    {"symbol": "Run", "kind": "method", "receiver": "Loop",
     "file": "pkg/fixture/fam.go", "def_line": 19, "call_line": 20,
     "calls": "middle", "entry_point": "event-loop"},
]

FIXTURE_FAMS = [{"name": "loxilb_fixture_total", "class": "default"},
                {"name": "doca_fixture_gauge", "class": "dpu-doca"}]


def writer_self_test(root, expect_red, expect_green):
    """Negative controls for check_writers, plus the transitive positive."""
    src = os.path.join(root, "pkg", "fixture")
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "fam.go"), "w", encoding="utf-8") as fh:
        fh.write(FIXTURE_GO)

    def overlay_with(entry, cap=0, name="loxilb_fixture_total", ucap=0,
                     tails=None):
        block = {"burndown": {"unclassified_max": cap, "unverified_max": ucap},
                 "families": {name: entry} if entry else {}}
        if tails is not None:
            block["tails"] = tails
        return {"writer_status": block}

    def chain(**mutate):
        c = json.loads(json.dumps(FIXTURE_CHAIN))
        for idx, patch in mutate.items():
            c[int(idx)].update(patch)
        return c

    def entry(**over):
        e = {"status": "verified-static",
             "evidence": "self-test fixture, gen-metric-manifest.py",
             "writer_sources": chain()}
        e.update(over)
        return e

    def run(ovl):
        errs = []
        check_writers(FIXTURE_FAMS, ovl, root, errs)
        return errs

    # The positive control comes first: if the gate cannot accept a valid
    # transitive chain, every red below is meaningless.
    expect_green("transitive chain accepted", run(overlay_with(entry())))

    expect_red("writer anchor drift (def_line is not a func)",
               run(overlay_with(entry(writer_sources=chain(**{"0": {"def_line": 6}})))))
    expect_red("writer receiver mismatch",
               run(overlay_with(entry(writer_sources=chain(**{"2": {"receiver": "PluginRegistry"}})))))
    expect_red("writer does not touch the recorded variable",
               run(overlay_with(entry(writer_sources=chain(**{"0": {"writes": "otherVar"}})))))
    expect_red("call site outside the recorded function body",
               run(overlay_with(entry(writer_sources=chain(**{"1": {"call_line": 20}})))))
    expect_red("chain not connected (calls a sibling, not the previous hop)",
               run(overlay_with(entry(writer_sources=chain(**{"1": {"call_line": 14, "calls": "decoy"}})))))
    expect_red("chain does not end at a declared entry point",
               run(overlay_with(entry(writer_sources=chain(**{"2": {"entry_point": None}})))))
    expect_red("method hop with no receiver recorded",
               run(overlay_with(entry(writer_sources=chain(**{"2": {"receiver": ""}})))))
    expect_red("data_sources chain is checked like writer_sources",
               run(overlay_with(entry(data_sources=chain(**{"0": {"def_line": 6}})))))
    expect_red("bad writer status token",
               run(overlay_with(entry(status="probably-fine"))))
    expect_red("conditional status with no activation precondition",
               run(overlay_with(entry(status="conditional-with-proven-writer"))))
    expect_red("throwaway writer evidence",
               run(overlay_with(entry(evidence="looks ok"))))
    expect_red("definition-only without the symbols actually queried",
               run(overlay_with({"status": "definition-only",
                                 "evidence": "self-test fixture, gen-metric-manifest.py",
                                 "rejection": "x" * 50})))
    expect_red("definition-only method claim with no receiver",
               run(overlay_with({"status": "definition-only",
                                 "evidence": "self-test fixture, gen-metric-manifest.py",
                                 "rejection": "x" * 50,
                                 "queried_symbols": [{"symbol": "Parse",
                                                      "kind": "method"}]})))
    expect_red("writer entry on a release-excluded family",
               run(overlay_with(entry(), cap=1, name="doca_fixture_gauge")))
    expect_red("writer entry for an unknown family",
               run(overlay_with(entry(), cap=1, name="loxilb_no_such_total")))
    expect_red("unclassified families above the ratchet",
               run(overlay_with(None, cap=0)))
    expect_red("ratchet left above the real unclassified count",
               run(overlay_with(entry(), cap=5)))
    expect_red("writer_status block missing entirely", run({}))

    # Shared tails: the hops behind a reference are checked exactly as if they
    # had been written inline, and a tail that no family reads is dead weight.
    tail_head = json.loads(json.dumps(FIXTURE_CHAIN[:1]))
    tail_rest = json.loads(json.dumps(FIXTURE_CHAIN[1:]))
    expect_green("tail reference expands and is accepted",
                 run(overlay_with(entry(writer_sources=tail_head +
                                        [{"tail": "loop"}]),
                                  tails={"loop": tail_rest})))
    bad_tail = json.loads(json.dumps(tail_rest))
    bad_tail[1]["receiver"] = "PluginRegistry"
    expect_red("hops inside a tail are checked, not trusted",
               run(overlay_with(entry(writer_sources=tail_head +
                                      [{"tail": "loop"}]),
                                tails={"loop": bad_tail})))
    expect_red("reference to an undeclared tail",
               run(overlay_with(entry(writer_sources=tail_head +
                                      [{"tail": "nope"}]),
                                tails={"loop": tail_rest})))
    expect_red("tail reference that does not end the chain",
               run(overlay_with(entry(writer_sources=[{"tail": "loop"}] +
                                      tail_head),
                                tails={"loop": tail_rest})))
    expect_red("declared tail no family references",
               run(overlay_with(entry(), tails={"loop": tail_rest})))

    # Dispatch through a function-valued seam: the call site names the
    # variable, never the writer, so the binding has to be checked or the hop
    # is just a claim.
    seam_chain = [json.loads(json.dumps(FIXTURE_CHAIN[0])),
                  {"symbol": "viaSeam", "kind": "func",
                   "file": "pkg/fixture/fam.go", "def_line": 25,
                   "call_line": 26, "calls": "seamFn",
                   "via": {"var": "seamFn", "file": "pkg/fixture/fam.go",
                           "line": 23},
                   "entry_point": "goroutine"}]

    def seam(**patch):
        c = json.loads(json.dumps(seam_chain))
        c[1].update(patch)
        return c

    expect_green("seam dispatch accepted when the binding checks out",
                 run(overlay_with(entry(writer_sources=seam()))))
    expect_red("seam bound to something other than the recorded writer",
               run(overlay_with(entry(writer_sources=seam(
                   via={"var": "seamFn", "file": "pkg/fixture/fam.go",
                        "line": 3})))))
    expect_red("seam hop whose calls is not the seam variable",
               run(overlay_with(entry(writer_sources=seam(calls="recordFam")))))

    # The unverified ratchet is one-way in both directions, like the
    # unclassified one: a writer-mapped family is mid-burn-down, not done.
    expect_red("unverified families above their ratchet",
               run(overlay_with(entry(status="writer-mapped"), ucap=0)))
    expect_red("unverified ratchet left above the real count",
               run(overlay_with(entry(), ucap=3)))
    expect_green("writer-mapped accepted under its ratchet",
                 run(overlay_with(entry(status="writer-mapped"), ucap=1)))


def excluded_consumer_self_test(root, expect_red):
    """Negative controls for check_excluded_consumers."""
    dash = os.path.join(root, "fixture-dashboards")
    os.makedirs(dash, exist_ok=True)
    with open(os.path.join(dash, "bad.json"), "w", encoding="utf-8") as fh:
        fh.write('{"panels":[{"targets":[{"expr":"rate(doca_fixture_gauge[5m])"}]}]}')

    errs = []
    check_excluded_consumers(
        FIXTURE_FAMS,
        {"excluded_consumer_scan": {
            "surfaces": [{"glob": "fixture-dashboards/*.json",
                          "kind": "dashboard"}]}},
        root, errs)
    expect_red("default asset consuming an excluded family", errs)

    errs = []
    check_excluded_consumers(
        FIXTURE_FAMS,
        {"excluded_consumer_scan": {
            "surfaces": [{"glob": "no-such-dir/*.json", "kind": "dashboard"}]}},
        root, errs)
    expect_red("scan surface that matches no file (vacuous gate)", errs)

    errs = []
    check_excluded_consumers(
        FIXTURE_FAMS,
        {"excluded_consumer_scan": {
            "surfaces": [{"glob": "fixture-dashboards/*.json",
                          "kind": "dashboard"}],
            "inventory_exempt": ["gone/inventory.json"]}},
        root, errs)
    expect_red("stale inventory exemption", errs)

    errs = []
    check_excluded_consumers(FIXTURE_FAMS, {}, root, errs)
    expect_red("excluded_consumer_scan block missing entirely", errs)


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
    ap.add_argument("--now", default=None,
                    help="ISO-8601 timestamp to record as generated_at "
                         "(default: now, UTC). Only used when the content "
                         "actually changes.")
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
    check_types(fams, overlay, errors)
    check_activation(fams, overlay, errors)
    check_literals(fams, overlay, repo_root, errors)
    attach_consumers(fams, mon_dir)
    check_waivers(fams, overlay, errors)
    writer_counts = check_writers(fams, overlay, repo_root, errors)
    check_excluded_consumers(fams, overlay, repo_root, errors)
    coverage = coverage_counts(fams)
    coverage.update(writer_counts)
    if args.locked_rev_check:
        check_locked_rev(fams, overlay, repo_root, args.go, errors)
    if errors:
        return fail(errors)

    committed = load_committed(manifest_path)
    manifest = build_manifest(fams, overlay, coverage,
                              provenance_for(committed, fams, overlay, coverage,
                                             repo_root, args.now))
    print(f"metric-manifest: {len(fams)} families | default "
          f"{coverage['default_families']} "
          f"({coverage['default_referenced']} referenced / "
          f"{coverage['default_waived']} waived / "
          f"{coverage['default_unreferenced']} unreferenced)")
    print(f"metric-manifest: writer map "
          f"{coverage.get('writer_classified', 0)} classified / "
          f"{coverage.get('writer_unclassified', 0)} still unclassified / "
          f"{coverage.get('writer_unverified', 0)} mapped but unverified")

    rendered = json.dumps(manifest, indent=1, sort_keys=False) + "\n"
    if args.check:
        if committed is None:
            return fail([f"{manifest_path} missing — run the generator and "
                         f"commit the manifest"])
        # Provenance is compared out. It records which revision last changed
        # the content, so on any later commit it differs by construction, and
        # comparing it would make the gate fail on every unrelated PR. The
        # content is what the gate is about; provenance is carried forward
        # untouched when the content has not moved, so it cannot drift either.
        if strip_provenance(committed) != strip_provenance(manifest):
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
