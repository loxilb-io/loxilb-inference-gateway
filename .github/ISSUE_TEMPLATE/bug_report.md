---
name: Bug report
about: Create a bug report to help us improve LoxiLB Inference Gateway
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**Feature area**
Which part is affected? [e.g. KV-cache-aware routing, P/D disaggregation, TTFT-adaptive LB, SGLang routing, API-key/rate-limit, model routing, MCP proxy, L4/L7 core, eBPF data path, REST API]

**To Reproduce**
Steps to reproduce the behavior (LB rule / REST config, or the `cicd/<scenario>` used):

**Expected behavior**
A clear and concise description of what you expected to happen.

**Logs / output**
If applicable, add loxilb logs, metrics, or scenario output to help explain the problem.

**Environment (please complete the following information):**
 - OS: [e.g. Ubuntu 22.04, Ubuntu 24.04, RedHat9]
 - Kernel Version: [e.g. 5.15.x, 6.8.x]
 - LoxiLB Inference Gateway version / image tag: [e.g. latest, v0.9.8.6-igw; or run: loxilb -v]
 - Serving engine + version: [e.g. vLLM 0.6.x, SGLang x.y — or "mock/echo backend"]
 - Deployment: [standalone / Kubernetes; cloud or on-prem]

**Additional context**
Add any other context or topology about the problem here.
