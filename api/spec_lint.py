#!/usr/bin/env python3
#
# Copyright (c) 2026 NetLOX Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Structural lint for the two API specifications.

Two properties that the existing gates cannot see:

  1. Duplicate mapping keys. `swagger diff` -- the only spec gate on the PR
     path -- parses with a duplicate-tolerant loader, and the repo's own spec
     tests read the generated JSON, where a duplicate has already collapsed.
     A stray key therefore round-trips cleanly through every check while the
     YAML source says two contradictory things.

  2. Security metadata. `swagger diff` compares paths, parameters and response
     schemas; it does not compare `securityDefinitions` or `security`. A spec
     can declare 401/403 responses while never stating that authentication
     exists, and nothing notices.

Run against both specs; exit non-zero on any violation.
"""

import re
import sys

import yaml


class DuplicateKeyError(Exception):
    pass


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys instead of last-wins."""


def _no_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise DuplicateKeyError(
                "duplicate mapping key %r at line %d (first seen at line %d)"
                % (key, key_node.start_mark.line + 1, mapping[key] + 1)
            )
        mapping[key] = key_node.start_mark.line
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates
)

VERBS = ("get", "post", "put", "delete", "patch", "head", "options")

# An operation may opt out of the global scheme, but only with a stated
# reason on the same line, so the exemption is reviewable rather than silent.
EMPTY_SECURITY = re.compile(r"^\s*security:\s*\[\s*\]\s*(#.*)?$")


def _has_reason(lines, n):
    """A stated reason is a trailing comment, or a comment block above."""
    if "#" in lines[n - 1]:
        return True
    return n >= 2 and lines[n - 2].lstrip().startswith("#")


def check_duplicates(path, errors):
    try:
        with open(path) as fh:
            return yaml.load(fh, Loader=StrictLoader)
    except DuplicateKeyError as exc:
        errors.append("%s: %s" % (path, exc))
        # Re-read permissively so the remaining checks still run.
        with open(path) as fh:
            return yaml.safe_load(fh)


def check_security(path, spec, errors):
    defs = spec.get("securityDefinitions")
    if not defs:
        errors.append(
            "%s: no securityDefinitions. Every route this document describes is "
            "authenticated; a spec that does not say so contradicts its own "
            "401/403 responses and generates clients that send no credential."
            % path
        )
        return

    has_global = bool(spec.get("security"))

    with open(path) as fh:
        lines = fh.readlines()

    # security: [] is an explicit opt-out, allowed only with a stated reason.
    # Checked against the source lines rather than the parsed tree, which
    # carries no comments.
    for n, line in enumerate(lines, 1):
        if EMPTY_SECURITY.match(line) and not _has_reason(lines, n):
            errors.append(
                "%s:%d: 'security: []' with no stated reason. Add a comment "
                "naming what enforces authentication instead." % (path, n)
            )

    for route, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for verb in VERBS:
            op = item.get(verb)
            if not isinstance(op, dict):
                continue
            if "security" not in op:
                if not has_global:
                    errors.append(
                        "%s: %s %s inherits no security scheme and declares none"
                        % (path, verb.upper(), route)
                    )
                continue
            if op["security"]:
                for entry in op["security"]:
                    for scheme in entry:
                        if scheme not in defs:
                            errors.append(
                                "%s: %s %s references undefined security scheme %r"
                                % (path, verb.upper(), route, scheme)
                            )
                continue


def main(argv):
    specs = argv[1:] or ["api/swagger.yml", "api/swagger-extras.yml"]
    errors = []
    for path in specs:
        spec = check_duplicates(path, errors)
        if isinstance(spec, dict):
            check_security(path, spec, errors)
    if errors:
        sys.stderr.write("spec lint failed:\n")
        for err in errors:
            sys.stderr.write("  - %s\n" % err)
        return 1
    print("spec lint OK: %s" % ", ".join(specs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
