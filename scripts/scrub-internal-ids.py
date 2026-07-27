#!/usr/bin/env python3
# Scrub internal development tracking IDs from code comments and log strings for
# the open-source release. Removes ticket/phase/decision identifiers that read as
# unprofessional in a public project, while keeping the surrounding descriptive
# prose and descriptive [EVENT] log tags.
#
# SAFETY MODEL
#   - Dry-run by default; --apply to write; --check to gate (exit 1 if IDs remain).
#   - A multi-state lexer scrubs ONLY comment bodies and string-literal contents:
#       * // and # line comments, /* ... */ block comments
#       * "..." double-quoted and (Python) '...' single-quoted strings
#       * Python triple-quoted strings ("""/''')
#     Code position is never touched. Go backtick raw strings and C/Go char
#     literals are treated as OPAQUE (never scrubbed) so struct tags / URLs stay
#     intact. All string/comment delimiters are preserved, so syntax cannot break.
#   - Conservative pattern set: only well-formed ID families. Ambiguous bare
#     numeric forms (e.g. 44-04) are matched ONLY when prefixed by "Phase".
#
# Usage:
#     python3 scripts/scrub-internal-ids.py [PATHS...]         # dry-run
#     python3 scripts/scrub-internal-ids.py --apply [PATHS...]
#     python3 scripts/scrub-internal-ids.py --check [PATHS...]

import argparse
import os
import re
import sys

CODE_EXTS = (".go", ".c", ".h", ".py")
SKIP_DIRS = {".git", "vendor", "node_modules", "libbpf", ".codegraph"}

# --- ID token families (well-formed only) -----------------------------------
ID_TOKEN = re.compile(
    r"\b(?:"
    r"US-\d+[a-z]?|US-ERR\d+|"                       # user stories
    r"Phase \d+[A-Za-z]?(?:-\d+)?(?: M\d+)?|"        # phases incl. ""
    r"D-\d+[a-z]?|"                                  # decisions
    r"FR-\d+|REQ-M?\d+|FIX-\d+|"                     # requirements / fixes
    r"T-\d+(?:-\d+)+|"                               # test ids like 
    r"Bug [A-Z]"                                     # ""
    r")\b"
)

_EMPTY_PARENS = re.compile(r"\(\s*(?:,\s*)*\)")
_EMPTY_BRACKETS = re.compile(r"\[\s*\]")
_LEADING_PUNCT = re.compile(r"^(\s*)[:\-—|,]\s*")
_MULTISPACE = re.compile(r"[ \t]{2,}")
_SPACE_BEFORE_PUNCT = re.compile(r"(?<=\S)\s+([:.,;)])")


def _scrub_segment(seg):
    """Remove ID tokens from one comment/string segment and tidy the debris."""
    if not ID_TOKEN.search(seg):
        return seg
    out = ID_TOKEN.sub("", seg)
    out = re.sub(r"\(\s*,\s*", "(", out)
    out = re.sub(r",\s*,", ",", out)
    out = re.sub(r",\s*\)", ")", out)
    out = _EMPTY_PARENS.sub("", out)
    out = _EMPTY_BRACKETS.sub("", out)
    out = _SPACE_BEFORE_PUNCT.sub(r"\1", out)
    out = _LEADING_PUNCT.sub(r"\1", out)      # leading "ID: " / "ID - " scaffolding
    out = _MULTISPACE.sub(" ", out)
    return out


def _scan_quote(line, i, quote):
    """Return index just past the matching close quote (respecting \\ escapes)."""
    n = len(line)
    j = i + 1
    while j < n:
        if line[j] == "\\":
            j += 2
            continue
        if line[j] == quote:
            return j + 1
        j += 1
    return n  # unterminated on this line


def _rewrite_line(line, state, lc):
    """Multi-state lexer. state carries across lines and is one of:
       None, '/*' (block comment), '`' (go raw string, opaque),
       '\"\"\"' or \"'''\" (python triple string).
       Returns (new_line, new_state)."""
    out = []
    n = len(line)
    i = 0

    # --- continue a cross-line state -----------------------------------------
    if state == "/*":
        end = line.find("*/")
        if end == -1:
            return _scrub_segment(line), "/*"
        out.append(_scrub_segment(line[:end])); out.append("*/"); i = end + 2; state = None
    elif state == "`":                       # go raw string: opaque
        end = line.find("`")
        if end == -1:
            return line, "`"
        out.append(line[:end + 1]); i = end + 1; state = None
    elif state in ('"""', "'''"):            # python triple string: scrub body
        end = line.find(state)
        if end == -1:
            return _scrub_segment(line), state
        out.append(_scrub_segment(line[:end])); out.append(state); i = end + 3; state = None

    # --- normal scan ---------------------------------------------------------
    while i < n:
        ch = line[i]
        two = line[i:i + 2]
        three = line[i:i + 3]

        if lc == "#" and three in ('"""', "'''"):      # python triple string
            end = line.find(three, i + 3)
            if end == -1:
                out.append(three); out.append(_scrub_segment(line[i + 3:]))
                return "".join(out), three
            out.append(three); out.append(_scrub_segment(line[i + 3:end])); out.append(three)
            i = end + 3
            continue
        if (lc == "//" and two == "//") or (lc == "#" and ch == "#"):  # line comment
            out.append(lc); out.append(_scrub_segment(line[i + len(lc):]))
            return "".join(out), None
        if lc == "//" and two == "/*":                 # block comment
            end = line.find("*/", i + 2)
            if end == -1:
                out.append("/*"); out.append(_scrub_segment(line[i + 2:]))
                return "".join(out), "/*"
            out.append("/*"); out.append(_scrub_segment(line[i + 2:end])); out.append("*/")
            i = end + 2
            continue
        if lc == "//" and ch == "`":                    # go raw string: opaque
            end = line.find("`", i + 1)
            if end == -1:
                out.append(line[i:]); return "".join(out), "`"
            out.append(line[i:end + 1]); i = end + 1
            continue
        if ch == '"':                                   # double-quoted string
            j = _scan_quote(line, i, '"')
            out.append('"' + _scrub_segment(line[i + 1:j - 1]) + '"' if j <= n and j > i + 1
                       else line[i:j])
            i = j
            continue
        if ch == "'":
            j = _scan_quote(line, i, "'")
            if lc == "#":                               # python single-quoted string
                out.append("'" + _scrub_segment(line[i + 1:j - 1]) + "'" if j > i + 1 else line[i:j])
            else:                                       # go/c char literal: opaque
                out.append(line[i:j])
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out), None


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for dp, dns, fns in os.walk(p):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for fn in fns:
                if fn.endswith(CODE_EXTS):
                    yield os.path.join(dp, fn)


def process(path):
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return None
    lc = "#" if path.endswith(".py") else "//"
    state = None
    changed, new_lines = [], []
    for idx, line in enumerate(lines):
        nl = line.rstrip("\n")
        rewritten, state = _rewrite_line(nl, state, lc)
        if rewritten != nl:
            changed.append((idx + 1, nl, rewritten))
        new_lines.append(rewritten + ("\n" if line.endswith("\n") else ""))
    return changed, "".join(new_lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--show", type=int, default=25)
    args = ap.parse_args()

    total_files = total_changes = 0
    samples = []
    for f in iter_files(args.paths or ["."]):
        res = process(f)
        if not res:
            continue
        changed, content = res
        if args.check:
            for ln, old, _ in changed:
                print(f"{f}:{ln}: internal ID: {old.strip()[:100]}")
            total_changes += len(changed)
            continue
        if changed:
            total_files += 1
            total_changes += len(changed)
            for ln, old, new in changed:
                if len(samples) < args.show:
                    samples.append((os.path.relpath(f), ln, old.strip(), new.strip()))
            if args.apply:
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write(content)

    if args.check:
        print(f"\nremaining internal IDs: {total_changes}")
        return 1 if total_changes else 0

    print(f"--- sample changes ({len(samples)} shown) ---")
    for f, ln, old, new in samples:
        print(f"\n{f}:{ln}\n  -  {old}\n  +  {new}")
    verb = "rewrote" if args.apply else "would rewrite"
    print(f"\nscrub-internal-ids: {verb} {total_changes} line(s) in {total_files} "
          f"file(s). {'APPLIED.' if args.apply else 'DRY-RUN (use --apply).'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
