#!/usr/bin/env python3
"""Steady, GPU-safe live traffic for the demo, with per-rule client-side metrics.

Drives one or more gateway LB rules side by side (for example a KV-exact rule
and a plain round-robin rule) with the same workload shape, and exports what
the CLIENT experiences per rule on a Prometheus endpoint, so a dashboard can
compare routing strategies:

  demo_client_requests_total{rule,stream,status}
  demo_client_request_seconds_bucket{rule,stream,le}    end-to-end latency
  demo_client_ttft_seconds_bucket{rule,le}              streams: time to first token
  demo_client_inflight{rule}
  demo_client_tokens_total{rule,kind}                   kind = prompt | completion (engine usage)

The gateway's own AI and Tier-1.5 metrics carry no per-rule label, which is
why the per-rule view comes from the client.

Workload per rule: shared-prefix families (a few long system prompts reused
with different questions, so KV-aware routing has prefixes to reuse), ~40% SSE
streams, a few workers with jittered pacing. Each rule gets its own prompt
salt, so the two rules never share cached prefixes on the engines.

Standard library only. Knobs via environment:
  TARGETS      name=url,... (required), e.g.
               kv=http://gateway:8081/v1/chat/completions,rr=http://gateway:8090/v1/chat/completions
               (name = the gateway rule name, so a dashboard can join it with
               the gateway's per-rule families)
  GW_HOST      Host header when the rules sit behind a floating IP; default: the URL's host
  MODEL        default Qwen/Qwen3-32B-FP8
  WORKERS      workers PER RULE, default 3
  FAMILIES     shared-prefix prompt families PER RULE, default 12. Enough families
               (and some concurrency) that a load-based picker such as the EPP
               spreads first placements over all engines: with 4 families and 2
               workers every first pick was a tie, and the EPP's fixed tie-break
               plus prefix affinity left one engine unused.
  PACE_S       mean seconds between requests per worker, default 4
  DURATION_S   stop after this many seconds (0 = forever), default 0
  PROMPT_SALT  base tag mixed into every system prompt, default: start time.
               vLLM announces a KV block only when it first stores it, and a
               re-created gateway rule starts with an empty inventory; a fresh
               salt per run makes the families new blocks the gateway learns.
  METRICS_ADDR default 127.0.0.1    METRICS_PORT default 9105 (0 = no exporter)

Legacy mode turns thinking off with Qwen3's in-prompt "/no_think", NOT with
chat_template_kwargs: a strict KV-exact rule treats chat_template_kwargs, tools,
cache_salt, reasoning_effort, ... as excluded features and skips KV routing
(agent mode below sends the kwargs by default; that needs the gateway's
tools-aware path, LOXILB_KV_TOOLS_EXACT=1 on the attested profile).

Agent mode (MODE=agent) — the tools-aware KV-exact demo workload. N agents,
each with its own fixed, synthetic tool set (same shapes, names suffixed per
agent so the sets differ) and system prompt, each running multi-turn
conversations: user turn -> assistant tool_call -> tool result -> next turn,
8-12 requests per conversation, the model's own tool_calls replayed as history.
One new TCP connection per request (Connection: close), so the baseline
round-robins and the flag-on run can converge per agent. Every request is a
stream with usage, so TTFT is measured. The legacy workload above is untouched;
agent mode exports the same demo_client_* families with one extra label,
agent_id (bounded: agent index only), plus:

  demo_client_endpoint_requests_total{rule,agent_id,endpoint}  served endpoint, when known
  demo_client_turns_total{rule,agent_id,kind}                  kind = tool_call | answer
  demo_client_conversations_total{rule,agent_id,outcome}       outcome = ok | error

Agent-mode knobs:
  AGENTS           agents PER RULE, default 6
  AGENT_CONC       concurrent conversations per agent, default 1
  TOOLS_PER_AGENT  tools in each agent's set, default 67 (agent-style descriptions)
  TURNS_MIN/MAX    requests per conversation, default 8/12
  PRESET           agents12 (12 agents, 16-24 turns) | agents18 (18 agents, 16-24 turns);
                   explicit AGENTS/TURNS_* override the preset
  THINKING         kwargs (default: chat_template_kwargs enable_thinking=false,
                   preserve_thinking=true, the agent-harness shape) | prompt ("/no_think")
  SEED             tool sets, prompts and question order, default 20261105
                   (same seed for the flag-off and flag-on runs)
  AGENT_MAX_TOKENS default 160
  ENDPOINT_SOURCE  how the served endpoint is learned: header (a response header
                   named by ENDPOINT_HEADER, default X-Engine-Id; what a mock
                   engine sends), ct (the gateway's conntrack table at GW_API,
                   looked up while the stream is open) or none. Default header.
  GW_API           gateway REST base for ENDPOINT_SOURCE=ct, e.g. http://host:11111
  RECORD_CSV       per-request record file (ts, rule, agent, conv, turn, status,
                   ttft_s, total_s, endpoint, local_port, prompt/completion tokens)
  PACE_S / DURATION_S / PROMPT_SALT / METRICS_* as above.
"""
import csv
import hashlib
import http.client
import http.server
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# TARGETS: comma-separated <rule-label>=<chat completions URL>; required.
TARGETS = [tuple(t.split("=", 1)) for t in os.environ.get("TARGETS", "").split(",") if t.strip()]
if not TARGETS or any(len(t) != 2 for t in TARGETS):
    sys.exit("TARGETS must be <label>=<url>[,<label>=<url>...], e.g. kv=http://gateway:8081/v1/chat/completions")
GW_HOST = os.environ.get("GW_HOST", "")  # Host header; empty = the target URL's host
MODEL = os.environ.get("MODEL", "Qwen/Qwen3-32B-FP8")
WORKERS = int(os.environ.get("WORKERS", "3"))
FAMILIES = int(os.environ.get("FAMILIES", "12"))
PACE_S = float(os.environ.get("PACE_S", "4"))
DURATION_S = float(os.environ.get("DURATION_S", "0"))
PROMPT_SALT = os.environ.get("PROMPT_SALT", time.strftime("%Y%m%d-%H%M%S"))
METRICS_ADDR = os.environ.get("METRICS_ADDR", "127.0.0.1")
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9105"))
MODE = os.environ.get("MODE", "legacy").strip().lower()
# Presets bundle the agent-mode knobs for larger runs (explicit AGENTS/TURNS_* still win):
#   agents12: 12 agents, 16-24 turns   agents18: 18 agents, 16-24 turns
PRESETS = {"agents12": {"AGENTS": "12", "TURNS_MIN": "16", "TURNS_MAX": "24"},
           "agents18": {"AGENTS": "18", "TURNS_MIN": "16", "TURNS_MAX": "24"}}
PRESET = os.environ.get("PRESET", "").strip().lower()
if PRESET and PRESET not in PRESETS:
    sys.exit("PRESET must be one of %s (got %r)" % (", ".join(sorted(PRESETS)), PRESET))
_P = PRESETS.get(PRESET, {})
AGENTS = int(os.environ.get("AGENTS", _P.get("AGENTS", "6")))
AGENT_CONC = int(os.environ.get("AGENT_CONC", "1"))
TOOLS_PER_AGENT = int(os.environ.get("TOOLS_PER_AGENT", "67"))
TURNS_MIN = int(os.environ.get("TURNS_MIN", _P.get("TURNS_MIN", "8")))
TURNS_MAX = int(os.environ.get("TURNS_MAX", _P.get("TURNS_MAX", "12")))
# How thinking is turned off in agent mode: kwargs (chat_template_kwargs
# {"enable_thinking": false, "preserve_thinking": true}, what agent harnesses
# send; needs the gateway's tools-aware path) or prompt (Qwen3's "/no_think").
THINKING = os.environ.get("THINKING", "kwargs").strip().lower()
if THINKING not in ("kwargs", "prompt"):
    sys.exit("THINKING must be kwargs or prompt (got %r)" % THINKING)
SEED = int(os.environ.get("SEED", "20261105"))
AGENT_MAX_TOKENS = int(os.environ.get("AGENT_MAX_TOKENS", "160"))
ENDPOINT_SOURCE = os.environ.get("ENDPOINT_SOURCE", "header").strip().lower()
ENDPOINT_HEADER = os.environ.get("ENDPOINT_HEADER", "X-Engine-Id")
GW_API = os.environ.get("GW_API", "").rstrip("/")
RECORD_CSV = os.environ.get("RECORD_CSV", "")

TOPICS = {
    "k8s": "Kubernetes networking, Services, Gateway API, load balancing and eBPF datapaths",
    "llm": "large language model serving, prefill/decode disaggregation, KV caches and batching",
    "sre": "site reliability engineering, SLOs, alerting, capacity planning and incident response",
    "sec": "cloud-native security, mTLS, API keys, rate limiting and zero-trust networking",
}
QUESTIONS = [
    "Explain the core idea in three sentences.",
    "List three common mistakes and how to avoid them.",
    "Give a short checklist for a production rollout.",
    "What metric would you watch first, and why?",
    "Describe a realistic failure scenario and its mitigation.",
    "Summarize the trade-offs for a small team.",
    "Write a two-line haiku about it.",
    "Compare two popular approaches briefly.",
]


def system_prompt(topic, salt, variant):
    # ~1.5K tokens of stable text per family: long enough to span many KV blocks.
    desc = TOPICS[topic]
    para = (f"[session {salt} / family {variant}] You are a senior engineer and patient teacher specialising in {desc}. "
            "Answer precisely, prefer concrete examples, avoid marketing language, "
            "and keep answers short unless asked otherwise. ")
    ref = " ".join(f"Reference note {i}: {desc} — principle {i} concerns reliability, "
                   f"observability and cost at scale." for i in range(1, 40))
    return para + ref


# ---------------------------------------------------------------- metrics ----
LAT_BUCKETS = (0.25, 0.5, 1, 2, 3, 4, 6, 8, 10, 15, 20, 30, 60, 120)
TTFT_BUCKETS = (0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1, 1.5, 2, 3, 5, 10)


class Hist:
    def __init__(self, buckets):
        self.buckets, self.counts, self.sum, self.n = buckets, [0] * len(buckets), 0.0, 0

    def observe(self, v):
        self.sum += v
        self.n += 1
        for i, b in enumerate(self.buckets):
            if v <= b:
                self.counts[i] += 1


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = {}   # (rule, stream, status) -> n
        self.latency = {}    # (rule, stream) -> Hist
        self.ttft = {}       # rule -> Hist
        self.inflight = {}   # rule -> n
        self.tokens = {}     # (rule, kind) -> n

    def record(self, rule, stream, status, secs, ttft, usage):
        with self.lock:
            k = (rule, stream, str(status))
            self.requests[k] = self.requests.get(k, 0) + 1
            if status == 200:
                self.latency.setdefault((rule, stream), Hist(LAT_BUCKETS)).observe(secs)
                if ttft is not None:
                    self.ttft.setdefault(rule, Hist(TTFT_BUCKETS)).observe(ttft)
                if usage:
                    for kind, key in (("prompt", "prompt_tokens"), ("completion", "completion_tokens")):
                        self.tokens[(rule, kind)] = self.tokens.get((rule, kind), 0) + int(usage.get(key) or 0)

    def add_inflight(self, rule, d):
        with self.lock:
            self.inflight[rule] = self.inflight.get(rule, 0) + d

    def render(self):
        out = []

        def hist(name, help_, items):
            out.append(f"# HELP {name} {help_}\n# TYPE {name} histogram")
            for labels, h in items:
                acc = 0
                lab = ",".join(f'{k}="{v}"' for k, v in labels)
                for b, c in zip(h.buckets, h.counts):
                    out.append(f'{name}_bucket{{{lab},le="{b}"}} {c}')
                out.append(f'{name}_bucket{{{lab},le="+Inf"}} {h.n}')
                out.append(f"{name}_sum{{{lab}}} {h.sum}")
                out.append(f"{name}_count{{{lab}}} {h.n}")

        with self.lock:
            out.append("# HELP demo_client_requests_total Requests sent by the demo client, by gateway rule and HTTP status.")
            out.append("# TYPE demo_client_requests_total counter")
            for (r, s, st), n in sorted(self.requests.items()):
                out.append(f'demo_client_requests_total{{rule="{r}",stream="{s}",status="{st}"}} {n}')
            hist("demo_client_request_seconds", "End-to-end request latency seen by the demo client (successful requests).",
                 [((("rule", r), ("stream", s)), h) for (r, s), h in sorted(self.latency.items())])
            hist("demo_client_ttft_seconds", "Streamed requests: time to the first generated token seen by the demo client.",
                 [((("rule", r),), h) for r, h in sorted(self.ttft.items())])
            out.append("# HELP demo_client_inflight Requests the demo client has in flight, by gateway rule.")
            out.append("# TYPE demo_client_inflight gauge")
            for r in sorted({t[0] for t in TARGETS} | set(self.inflight)):
                out.append(f'demo_client_inflight{{rule="{r}"}} {self.inflight.get(r, 0)}')
            out.append("# HELP demo_client_tokens_total Tokens reported by the engine in the response usage, by rule and kind.")
            out.append("# TYPE demo_client_tokens_total counter")
            for (r, k), n in sorted(self.tokens.items()):
                out.append(f'demo_client_tokens_total{{rule="{r}",kind="{k}"}} {n}')
        return "\n".join(out) + "\n"


METRICS = Metrics()


class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] != "/metrics":
            self.send_error(404)
            return
        body = (AGENT_METRICS.render() if MODE == "agent" else METRICS.render()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------- traffic ----
def first_token_in(chunk):
    for c in chunk.get("choices") or []:
        d = c.get("delta") or {}
        if d.get("content") or d.get("reasoning_content") or d.get("reasoning"):
            return True
    return False


def one_request(rule, url, system, rng):
    stream = rng.random() < 0.4
    body = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system[rng.choice(list(system))]},
            {"role": "user", "content": rng.choice(QUESTIONS) + " /no_think"},
        ],
        "max_tokens": rng.choice([48, 96, 160, 256]),
        "stream": stream,
    }
    if stream:
        body["stream_options"] = {"include_usage": True}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Host": GW_HOST or urllib.parse.urlsplit(url).hostname,
                                          "Content-Type": "application/json"})
    t0, ttft, usage = time.time(), None, None
    METRICS.add_inflight(rule, 1)
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            if stream:
                for line in r:  # drain SSE so the stream stays open while generating
                    line = line.strip()
                    if not line.startswith(b"data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == b"[DONE]":
                        continue
                    try:
                        j = json.loads(payload)
                    except ValueError:
                        continue
                    if ttft is None and first_token_in(j):
                        ttft = time.time() - t0
                    if j.get("usage"):
                        usage = j["usage"]
            else:
                usage = json.load(r).get("usage")
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:  # network error, timeout
        status = f"exc_{type(e).__name__}"
    finally:
        METRICS.add_inflight(rule, -1)
    secs = time.time() - t0
    METRICS.record(rule, str(stream).lower(), status, secs, ttft, usage)
    if status != 200:
        print(f"{time.strftime('%H:%M:%S')} {rule} stream={stream} -> {status} ({secs:.1f}s)", flush=True)


def worker(rule, url, system, idx, stop_at):
    rng = random.Random(hash((rule, idx, time.time())))
    while not stop_at or time.time() < stop_at:
        one_request(rule, url, system, rng)
        time.sleep(rng.expovariate(1.0 / PACE_S))


# ------------------------------------------------------------- agent mode ----
# Synthetic, sanitized tool sets (the shapes of a coding-agent harness with
# MCP tools; no real tool names or descriptions). Deterministic per SEED and
# agent index, so the flag-off and flag-on runs send identical tool sets.
TOOL_VERBS = ["read", "write", "list", "search", "create", "update", "delete", "fetch",
              "run", "query", "describe", "diff", "move", "copy", "render", "summarize",
              "schedule", "cancel", "export", "import", "validate", "lint", "format",
              "open", "close", "watch", "unwatch", "tag", "untag", "pin", "unpin",
              "publish", "archive", "restore", "grep", "glob", "patch", "apply", "revert",
              "inspect", "measure", "trace", "profile", "deploy", "rollback", "scale",
              "notify", "send", "reply", "forward", "label", "assign", "resolve", "merge",
              "rebase", "checkout", "stash", "bisect", "blame", "annotate", "compile",
              "test", "benchmark", "package", "sign", "verify", "encrypt"]
TOOL_NOUNS = ["file", "page", "document", "issue", "pull_request", "branch", "commit",
              "note", "task", "event", "calendar", "message", "thread", "channel",
              "dashboard", "panel", "metric", "alert", "service", "deployment", "pod",
              "node", "secret", "config", "schema", "table", "row", "index", "snapshot",
              "artifact", "release", "workspace", "project", "ticket", "comment", "label",
              "user", "team", "role", "token", "webhook", "pipeline", "job", "log",
              "trace", "span", "report", "chart", "image", "video", "audio", "dataset",
              "model", "prompt", "template", "variable", "function", "module", "package",
              "dependency", "license", "vulnerability", "policy", "rule", "route", "cert"]
TOOL_SERVERS = ["gbrain", "repo", "calendar", "mail", "tracker", "k8s", "metrics", "docs",
                "browser", "fs", "shell", "db"]
TOOL_DESC = (
    "{Verb} a {noun} in the connected {server} workspace.\n\n"
    "Use this tool when the user asks to {verb} a {noun} or when a previous tool "
    "result references a {noun} identifier that must be followed up. Prefer this "
    "over shell access for {noun} operations because it validates arguments, "
    "respects the workspace's permission model and returns a structured result.\n\n"
    "Usage notes:\n"
    "- The `{noun}_id` must come from an earlier list/search call; never guess it.\n"
    "- Large results are truncated to {limit} items; pass `cursor` to continue.\n"
    "- Set `dry_run` to true to preview the change without applying it.\n"
    "- Errors are returned as `{{\"error\": {{\"code\": ..., \"message\": ...}}}}`; "
    "do not retry on `permission_denied`.\n\n"
    "Returns a JSON object with the {noun} fields and a `version` stamp."
)
TOOL_PARAM_NAMES = ["query", "limit", "cursor", "dry_run", "fields", "filter", "sort",
                    "include_archived", "format", "timeout_ms", "recursive", "pattern",
                    "path", "content", "title", "body", "assignee", "priority"]


def tool_params(rng, noun, n_props):
    props = {f"{noun}_id": {"type": "string", "description": f"Identifier of the {noun}."}}
    names = list(TOOL_PARAM_NAMES)
    rng.shuffle(names)
    for nm in names[: n_props - 1]:
        t = rng.choice(["string", "integer", "number", "boolean"])
        if nm in ("limit", "timeout_ms", "priority"):
            t = "integer"
        if nm in ("dry_run", "recursive", "include_archived"):
            t = "boolean"
        if nm == "fields":
            p = {"type": "array", "items": {"type": "string"}, "description": f"Subset of {noun} fields to return."}
        elif nm == "format":
            p = {"type": "string", "enum": ["json", "markdown", "text"], "description": "Output format."}
        else:
            p = {"type": t, "description": f"{nm.replace('_', ' ').capitalize()} for the {noun} operation."}
            if t == "string":
                p["description"] += " Must be UTF-8; leading/trailing whitespace is trimmed."
        props[nm] = p
    return {"type": "object", "properties": props, "required": [f"{noun}_id"], "additionalProperties": False}


def agent_tools(agent_idx, n):
    """n synthetic tools for one agent. The same (SEED, n) gives every agent the
    same shapes; the per-agent name suffix makes each agent's set distinct, so
    their rendered prefixes (and KV hash chains) differ."""
    rng = random.Random((SEED, "tools", n))
    tools, used = [], set()
    while len(tools) < n:
        verb, noun, server = rng.choice(TOOL_VERBS), rng.choice(TOOL_NOUNS), rng.choice(TOOL_SERVERS)
        base = f"mcp__{server}__{verb}_{noun}" if rng.random() < 0.7 else f"{verb}_{noun}"
        if base in used:
            continue
        used.add(base)
        desc = TOOL_DESC.format(Verb=verb.capitalize(), verb=verb, noun=noun, server=server,
                                limit=rng.choice([50, 100, 200]))
        tools.append({"type": "function", "function": {
            "name": f"{base}_a{agent_idx}", "description": desc,
            "parameters": tool_params(rng, noun, rng.randint(3, 7))}})
    return tools


def agent_system_prompt(agent_idx, salt):
    topic = list(TOPICS)[agent_idx % len(TOPICS)]
    return (f"[session {salt} / agent {agent_idx}] You are an autonomous engineering agent working on "
            f"{TOPICS[topic]}. Use the available tools to gather facts before answering; call one tool "
            "at a time, wait for its result, and keep final answers under three sentences. Never invent "
            "identifiers: obtain them from list or search tools first.")


AGENT_TASKS = [
    "Find the most recent failed pipeline run and summarize why it failed.",
    "List the open issues labelled 'regression' and pick the one to fix first.",
    "Check the current deployment's health and report anything unusual.",
    "Locate the config file that sets the request timeout and show its value.",
    "Search the docs for the rollout checklist and extract the pre-flight steps.",
    "Compare the last two releases and name the riskiest change.",
    "Look up who owns the alerting rules and draft a short message to them.",
    "Find the dashboard panel for error rate and read the current value.",
]


class AgentMetrics:
    """demo_client_* with an agent_id label (bounded: the agent index)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = {}       # (rule, agent, stream, status) -> n
        self.latency = {}        # (rule, agent, stream) -> Hist
        self.ttft = {}           # (rule, agent) -> Hist
        self.inflight = {}       # (rule, agent) -> n
        self.tokens = {}         # (rule, agent, kind) -> n
        self.endpoints = {}      # (rule, agent, endpoint) -> n
        self.turns = {}          # (rule, agent, kind) -> n
        self.conversations = {}  # (rule, agent, outcome) -> n

    def record(self, rule, agent, stream, status, secs, ttft, usage, endpoint, kind):
        with self.lock:
            k = (rule, agent, stream, str(status))
            self.requests[k] = self.requests.get(k, 0) + 1
            if status == 200:
                self.latency.setdefault((rule, agent, stream), Hist(LAT_BUCKETS)).observe(secs)
                if ttft is not None:
                    self.ttft.setdefault((rule, agent), Hist(TTFT_BUCKETS)).observe(ttft)
                if usage:
                    for kd, key in (("prompt", "prompt_tokens"), ("completion", "completion_tokens")):
                        self.tokens[(rule, agent, kd)] = self.tokens.get((rule, agent, kd), 0) + int(usage.get(key) or 0)
                e = (rule, agent, endpoint or "unknown")
                self.endpoints[e] = self.endpoints.get(e, 0) + 1
                if kind:
                    self.turns[(rule, agent, kind)] = self.turns.get((rule, agent, kind), 0) + 1

    def conversation(self, rule, agent, outcome):
        with self.lock:
            self.conversations[(rule, agent, outcome)] = self.conversations.get((rule, agent, outcome), 0) + 1

    def add_inflight(self, rule, agent, d):
        with self.lock:
            self.inflight[(rule, agent)] = self.inflight.get((rule, agent), 0) + d

    def render(self):
        out = []

        def hist(name, help_, items):
            out.append(f"# HELP {name} {help_}\n# TYPE {name} histogram")
            for labels, h in items:
                lab = ",".join(f'{k}="{v}"' for k, v in labels)
                for b, c in zip(h.buckets, h.counts):
                    out.append(f'{name}_bucket{{{lab},le="{b}"}} {c}')
                out.append(f'{name}_bucket{{{lab},le="+Inf"}} {h.n}')
                out.append(f"{name}_sum{{{lab}}} {h.sum}")
                out.append(f"{name}_count{{{lab}}} {h.n}")

        def counter(name, help_, items):
            out.append(f"# HELP {name} {help_}\n# TYPE {name} counter")
            for labels, n in items:
                lab = ",".join(f'{k}="{v}"' for k, v in labels)
                out.append(f"{name}{{{lab}}} {n}")

        with self.lock:
            counter("demo_client_requests_total", "Requests sent by the demo client, by gateway rule, agent and HTTP status.",
                    [((("rule", r), ("agent_id", a), ("stream", s), ("status", st)), n)
                     for (r, a, s, st), n in sorted(self.requests.items())])
            hist("demo_client_request_seconds", "End-to-end request latency seen by the demo client (successful requests).",
                 [((("rule", r), ("agent_id", a), ("stream", s)), h) for (r, a, s), h in sorted(self.latency.items())])
            hist("demo_client_ttft_seconds", "Streamed requests: time to the first generated token seen by the demo client.",
                 [((("rule", r), ("agent_id", a)), h) for (r, a), h in sorted(self.ttft.items())])
            out.append("# HELP demo_client_inflight Requests the demo client has in flight, by gateway rule and agent.")
            out.append("# TYPE demo_client_inflight gauge")
            for (r, a), n in sorted(self.inflight.items()):
                out.append(f'demo_client_inflight{{rule="{r}",agent_id="{a}"}} {n}')
            counter("demo_client_tokens_total", "Tokens reported by the engine in the response usage, by rule, agent and kind.",
                    [((("rule", r), ("agent_id", a), ("kind", k)), n) for (r, a, k), n in sorted(self.tokens.items())])
            counter("demo_client_endpoint_requests_total", "Successful requests by the engine endpoint that served them (unknown when not learned).",
                    [((("rule", r), ("agent_id", a), ("endpoint", e)), n) for (r, a, e), n in sorted(self.endpoints.items())])
            counter("demo_client_turns_total", "Assistant turns by kind: tool_call (the agent loop continues) or answer.",
                    [((("rule", r), ("agent_id", a), ("kind", k)), n) for (r, a, k), n in sorted(self.turns.items())])
            counter("demo_client_conversations_total", "Finished conversations by outcome.",
                    [((("rule", r), ("agent_id", a), ("outcome", o)), n) for (r, a, o), n in sorted(self.conversations.items())])
        return "\n".join(out) + "\n"


AGENT_METRICS = AgentMetrics()
RECORD_LOCK = threading.Lock()


def record_csv(row):
    if not RECORD_CSV:
        return
    with RECORD_LOCK:
        new = not os.path.exists(RECORD_CSV) or os.path.getsize(RECORD_CSV) == 0
        with open(RECORD_CSV, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["ts", "rule", "agent_id", "conv", "turn", "status", "ttft_s", "total_s",
                            "endpoint", "local_port", "prompt_tokens", "completion_tokens", "kind"])
            w.writerow(row)


def ct_endpoint(local_ip, local_port, rule_port):
    """Served endpoint from the gateway's conntrack table (best effort). A
    full-proxy connection's entry carries the backend leg in its action,
    "fp|<proxy ip:port>-><endpoint ip:port>|tcp"; only the endpoint ip:port
    is kept, so the label stays bounded by the rule's endpoint count."""
    if not GW_API:
        return ""
    try:
        with urllib.request.urlopen(GW_API + "/netlox/v1/config/conntrack/all", timeout=2) as r:
            cands = [e for e in json.load(r).get("ctAttr") or []
                     if e.get("sourcePort") == local_port and e.get("destinationPort") == rule_port]
        # Behind NAT the gateway sees another source IP: prefer an exact
        # source match, else accept the single entry with our port pair.
        exact = [e for e in cands if e.get("sourceIP") == local_ip]
        pick = exact[0] if exact else (cands[0] if len(cands) == 1 else None)
        if pick:
            act = pick.get("conntrackAct") or ""
            if "->" in act:
                return act.split("->", 1)[1].split("|", 1)[0]
    except Exception:
        pass
    return ""


def agent_request(rule, url, body, agent, conv, turn):
    """One streamed chat completion on a fresh connection. Returns
    (status, assistant_message or None, tool_calls, endpoint, ttft, secs, usage)."""
    u = urllib.parse.urlsplit(url)
    data = json.dumps(body).encode()
    t0, ttft, usage, endpoint, local_port, local_ip = time.time(), None, None, "", 0, ""
    content, tool_calls, status = [], {}, 0
    AGENT_METRICS.add_inflight(rule, agent, 1)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=180)
    try:
        conn.connect()
        local_ip, local_port = conn.sock.getsockname()[:2]
        conn.request("POST", u.path or "/", body=data, headers={
            "Host": GW_HOST or u.hostname, "Content-Type": "application/json", "Connection": "close",
            "Content-Length": str(len(data))})
        resp = conn.getresponse()
        status = resp.status
        if ENDPOINT_SOURCE == "header":
            endpoint = resp.getheader(ENDPOINT_HEADER) or ""
        if status != 200:
            resp.read()
        else:
            for raw in resp:
                line = raw.strip()
                if not line.startswith(b"data:"):
                    continue
                payload = line[5:].strip()
                if payload == b"[DONE]":
                    continue
                try:
                    j = json.loads(payload)
                except ValueError:
                    continue
                for c in j.get("choices") or []:
                    d = c.get("delta") or {}
                    if ttft is None and (d.get("content") or d.get("reasoning_content") or d.get("reasoning") or d.get("tool_calls")):
                        ttft = time.time() - t0
                        if ENDPOINT_SOURCE == "ct":
                            endpoint = ct_endpoint(local_ip, local_port, u.port or 80)
                    if d.get("content"):
                        content.append(d["content"])
                    for tc in d.get("tool_calls") or []:
                        slot = tool_calls.setdefault(tc.get("index", 0), {"id": "", "name": "", "arguments": ""})
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["arguments"] += fn["arguments"]
                if j.get("usage"):
                    usage = j["usage"]
    except http.client.HTTPException as e:
        status = f"exc_{type(e).__name__}"
    except Exception as e:  # network error, timeout
        status = f"exc_{type(e).__name__}"
    finally:
        conn.close()
        AGENT_METRICS.add_inflight(rule, agent, -1)
    secs = time.time() - t0
    calls = [tool_calls[i] for i in sorted(tool_calls)]
    kind = ("tool_call" if calls else "answer") if status == 200 else ""
    AGENT_METRICS.record(rule, agent, "true", status, secs, ttft, usage, endpoint, kind)
    record_csv([f"{t0:.3f}", rule, agent, conv, turn, status, "" if ttft is None else f"{ttft:.4f}", f"{secs:.3f}",
                endpoint, local_port, (usage or {}).get("prompt_tokens", ""), (usage or {}).get("completion_tokens", ""), kind])
    if status != 200:
        print(f"{time.strftime('%H:%M:%S')} {rule} agent={agent} conv={conv} turn={turn} -> {status} ({secs:.1f}s)", flush=True)
        return status, None, [], endpoint, ttft, secs, usage
    msg = {"role": "assistant", "content": "".join(content)}
    if calls:
        msg["tool_calls"] = [{"id": c["id"] or f"call_{agent}_{conv}_{turn}_{i}", "type": "function",
                              "function": {"name": c["name"], "arguments": c["arguments"] or "{}"}}
                             for i, c in enumerate(calls)]
    return status, msg, msg.get("tool_calls", []), endpoint, ttft, secs, usage


def tool_result(rng, call):
    """A short synthetic tool result for a replayed tool_call (string content)."""
    try:
        args = json.loads(call["function"]["arguments"] or "{}")
    except ValueError:
        args = {}
    ident = next((v for k, v in args.items() if k.endswith("_id")), None) or f"obj-{rng.randint(1000, 9999)}"
    return json.dumps({"ok": True, "id": ident, "version": rng.randint(1, 40),
                       "items": [{"id": f"{ident}-{i}", "status": rng.choice(["ok", "failed", "pending"])} for i in range(3)]})


def agent_conversation(rule, url, agent, conv, system, tools, rng):
    """user -> assistant (tool_call or answer) -> tool result -> ... for
    TURNS_MIN..TURNS_MAX requests. A new user turn follows an answer."""
    n_turns = rng.randint(TURNS_MIN, TURNS_MAX)
    suffix = " /no_think" if THINKING == "prompt" else ""
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": rng.choice(AGENT_TASKS) + suffix}]
    for turn in range(n_turns):
        body = {"model": MODEL, "messages": messages, "tools": tools, "max_tokens": AGENT_MAX_TOKENS,
                "stream": True, "stream_options": {"include_usage": True}}
        if THINKING == "kwargs":
            body["chat_template_kwargs"] = {"enable_thinking": False, "preserve_thinking": True}
        status, msg, calls, _ep, _ttft, _secs, _usage = agent_request(rule, url, body, agent, conv, turn)
        if status != 200:
            AGENT_METRICS.conversation(rule, agent, "error")
            return
        messages.append(msg)
        if calls:
            for c in calls:
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": tool_result(rng, c)})
        else:
            messages.append({"role": "user", "content": rng.choice(AGENT_TASKS) + suffix})
        time.sleep(rng.expovariate(1.0 / PACE_S) if PACE_S > 0 else 0)
    AGENT_METRICS.conversation(rule, agent, "ok")


def agent_worker(rule, url, agent, slot, system, tools, stop_at):
    conv = 0
    while not stop_at or time.time() < stop_at:
        rng = random.Random((SEED, rule, agent, slot, conv))
        agent_conversation(rule, url, agent, f"{slot}-{conv}", system, tools, rng)
        conv += 1


def agent_main():
    stop_at = time.time() + DURATION_S if DURATION_S > 0 else 0
    if METRICS_PORT:
        srv = http.server.ThreadingHTTPServer((METRICS_ADDR, METRICS_PORT), MetricsHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"metrics on http://{METRICS_ADDR}:{METRICS_PORT}/metrics", flush=True)
    for rule, url in TARGETS:
        salt = f"{PROMPT_SALT}-{rule}"
        for a in range(AGENTS):
            agent = f"a{a}"
            tools = agent_tools(a, TOOLS_PER_AGENT)
            system = agent_system_prompt(a, salt)
            size = len(json.dumps(tools))
            print(f"agent traffic: {rule}: agent {agent}: {len(tools)} tools ({size} B), {AGENT_CONC} conversation(s), "
                  f"{TURNS_MIN}-{TURNS_MAX} turns, pace {PACE_S}s -> {url} (Host {GW_HOST}, salt {salt}, seed {SEED})", flush=True)
            for slot in range(AGENT_CONC):
                threading.Thread(target=agent_worker, args=(rule, url, agent, slot, system, tools, stop_at), daemon=True).start()
    while not stop_at or time.time() < stop_at:
        time.sleep(30)
        with AGENT_METRICS.lock:
            tally, eps = {}, {}
            for (r, a, _s, st), n in AGENT_METRICS.requests.items():
                ok, err = tally.get(r, (0, 0))
                tally[r] = (ok + n, err) if st == "200" else (ok, err + n)
            for (r, a, e), n in AGENT_METRICS.endpoints.items():
                eps.setdefault((r, a), {})[e] = n
        line = " ".join(f"{r}: ok={o} err={e}" for r, (o, e) in sorted(tally.items()))
        dist = "; ".join(f"{r}/{a}: " + ",".join(f"{e}={n}" for e, n in sorted(d.items())) for (r, a), d in sorted(eps.items()))
        print(time.strftime("%H:%M:%S") + " " + line + (" | " + dist if dist else ""), flush=True)


def main():
    stop_at = time.time() + DURATION_S if DURATION_S > 0 else 0
    if METRICS_PORT:
        srv = http.server.ThreadingHTTPServer((METRICS_ADDR, METRICS_PORT), MetricsHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"metrics on http://{METRICS_ADDR}:{METRICS_PORT}/metrics", flush=True)
    for rule, url in TARGETS:
        salt = f"{PROMPT_SALT}-{rule}"
        topics = list(TOPICS)
        system = {f"{topics[i % len(topics)]}-{i}": system_prompt(topics[i % len(topics)], salt, i)
                  for i in range(FAMILIES)}
        print(f"traffic: {rule}: {WORKERS} workers, {FAMILIES} families, pace {PACE_S}s -> {url} "
              f"(Host {GW_HOST}, salt {salt})", flush=True)
        for i in range(WORKERS):
            threading.Thread(target=worker, args=(rule, url, system, i, stop_at), daemon=True).start()
    while not stop_at or time.time() < stop_at:
        time.sleep(60)
        with METRICS.lock:
            tally = {}
            for (r, _s, st), n in METRICS.requests.items():
                ok, err = tally.get(r, (0, 0))
                tally[r] = (ok + n, err) if st == "200" else (ok, err + n)
        print(time.strftime("%H:%M:%S") + " " + " ".join(f"{r}: ok={o} err={e}" for r, (o, e) in sorted(tally.items())),
              flush=True)


if __name__ == "__main__":
    try:
        if MODE == "agent":
            agent_main()
        elif MODE == "legacy":
            main()
        else:
            sys.exit("MODE must be legacy or agent (got %r)" % MODE)
    except KeyboardInterrupt:
        sys.exit(0)
