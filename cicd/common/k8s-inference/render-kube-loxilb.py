#!/usr/bin/env python3
"""Rewrite kube-loxilb's shipped manifest for a testbed: image and args only.

Rendering from the manifest in the kube-loxilb checkout rather than keeping a
copy means RBAC or deployment-shape changes there are picked up instead of
drifting. Usage:

    KLB_IMAGE=... KLB_ARGS="--cidrPools=... --v=4" render-kube-loxilb.py <manifest.yaml>
"""
import os, sys, yaml

image = os.environ["KLB_IMAGE"]
args = os.environ["KLB_ARGS"].split()

docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
for doc in docs:
    if doc.get("kind") != "Deployment":
        continue
    c = doc["spec"]["template"]["spec"]["containers"][0]
    c["image"] = image
    c["imagePullPolicy"] = "IfNotPresent"
    c["args"] = args
yaml.safe_dump_all(docs, sys.stdout, default_flow_style=False, sort_keys=False)
