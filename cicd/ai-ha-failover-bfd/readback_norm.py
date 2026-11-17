#!/usr/bin/env python3
"""Normalise one node's configuration read-back so two nodes can be compared.

usage: readback_norm.py <kind> < raw.json > normalised.json

Fields dropped before the comparison are the ones that describe a node's
runtime state rather than what it was configured with. The list is explicit
and is printed in the scenario README:

  loadbalancer  endpoints[].counter   per-node traffic counter
                endpoints[].state     per-node health-probe result
                serviceArguments.id   a UUID each node mints for its own
                                      copy of the rule
                serviceArguments.fc_effective
                                      the gate's live state (in-flight units,
                                      reservation epoch, queue); compared
                                      separately and RECORDED, not asserted
  apikey        last_used_at          set by the node that served the key
"""
import json
import sys

kind = sys.argv[1]
doc = json.load(sys.stdin)

if kind == "loadbalancer":
    rules = doc.get("lbAttr") or []
    for r in rules:
        for ep in r.get("endpoints") or []:
            ep.pop("counter", None)
            ep.pop("state", None)
        (r.get("serviceArguments") or {}).pop("fc_effective", None)
        (r.get("serviceArguments") or {}).pop("id", None)
    rules.sort(key=lambda r: (r["serviceArguments"].get("port", 0),
                              r["serviceArguments"].get("model_name", "")))
    doc = rules
elif kind == "fc_effective":
    rules = doc.get("lbAttr") or []
    doc = {str(r["serviceArguments"].get("port")): r["serviceArguments"].get("fc_effective")
           for r in rules}
elif kind == "apikey":
    def strip(o):
        if isinstance(o, dict):
            o.pop("last_used_at", None)
            for v in o.values():
                strip(v)
        elif isinstance(o, list):
            for v in o:
                strip(v)
    strip(doc)

json.dump(doc, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
