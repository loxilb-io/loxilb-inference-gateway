#!/bin/bash
# live-e2e.sh - On-demand E2E validation of the loxilb-mcp bridge against a
# LIVE loxilb-inference-gateway target (no docker testbed, no LLM required).
#
# Unlike validation.sh (which stands up a docker testbed), this drives the
# bridge over a single persistent stdio JSON-RPC session against an already-
# running loxilb REST endpoint, so you can point it at a real deployment on
# demand:
#
#     ./live-e2e.sh                                 # default target, read-only
#     TARGET=http://1.2.3.4:11111 ./live-e2e.sh     # any live target
#     ./live-e2e.sh --mutate                        # + control-plane round-trip
#
# Read-only mode (default) mutates NOTHING on the target. --mutate additionally
# runs an isolated lb_create -> lb_list -> confirm-token lb_delete round-trip on
# a TEST-NET-2 VIP (RFC 5737 198.51.100.0/24) that will not collide with real
# services, and cleans it up (including on failure). The two-step confirm-token
# flow is why the harness holds one session open: the token is in-memory,
# single-use, per process.
#
# Exit code 0 = all checks passed.
set -u

TARGET="${TARGET:-http://127.0.0.1:11111}"   # override with TARGET=http://<host>:11111
MUTATE=0
export VIP="${VIP:-198.51.100.7}"   # RFC 5737 TEST-NET-2, safe throwaway VIP
export VPORT="${VPORT:-19999}"
export VEP="${VEP:-198.51.100.8}"

for a in "$@"; do
    case "$a" in
        --mutate) MUTATE=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $a" >&2; exit 2 ;;
    esac
done

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
WORK=$(mktemp -d)
export BIN="$WORK/loxilb-mcp"      # built into the temp dir; nothing left behind
export AUDIT="$WORK/audit"
export TARGET MUTATE
trap 'rm -rf "$WORK"' EXIT

echo "=== loxilb-mcp live E2E ==="
echo "target : $TARGET"
echo "mode   : $([[ $MUTATE == 1 ]] && echo 'read-only + mutate round-trip' || echo 'read-only')"

echo "building loxilb-mcp"
if ! (cd "$root/mcp" && go build -o "$BIN" ./cmd/loxilb-mcp); then
    echo "=== live E2E [FAILED] (build) ==="; exit 1
fi

exec python3 - <<'PY'
import itertools, json, os, subprocess, sys, urllib.request

TARGET = os.environ["TARGET"]
BIN    = os.environ["BIN"]
AUDIT  = os.environ["AUDIT"]
MUTATE = os.environ.get("MUTATE") == "1"
VIP, VPORT, VEP = os.environ["VIP"], int(os.environ["VPORT"]), os.environ["VEP"]

code = 0
def ok(m):   print(f"  [OK] {m}")
def bad(m):
    global code; code = 1; print(f"  [FAILED] {m}")

class Session:
    """One persistent stdio JSON-RPC session against the bridge."""
    def __init__(self, role):
        self.p = subprocess.Popen(
            [BIN, "--target-url", TARGET, "--role", role, "--audit-dir", AUDIT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self.ids = itertools.count(1)
        self._rpc("initialize", params={
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "live-e2e", "version": "0"}})
        self._note("notifications/initialized")

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n"); self.p.stdin.flush()

    def _note(self, method, **kw):
        self._send({"jsonrpc": "2.0", "method": method, **kw})

    def _rpc(self, method, **kw):
        i = next(self.ids)
        self._send({"jsonrpc": "2.0", "id": i, "method": method, **kw})
        for line in self.p.stdout:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            if o.get("id") == i:
                return o
        return {}

    def list_tools(self):
        return self._rpc("tools/list").get("result", {}).get("tools", [])

    def call(self, tool, **args):
        r = self._rpc("tools/call", params={"name": tool, "arguments": args})
        if "error" in r:
            return True, r["error"], r
        res = r.get("result", {})
        c = res.get("content", [])
        t = c[0].get("text", "") if c else ""
        try:
            return res.get("isError") is True, json.loads(t), r
        except Exception:
            return res.get("isError") is True, t, r

    def close(self):
        try:
            self.p.stdin.close(); self.p.wait(timeout=5)
        except Exception:
            self.p.kill()

def rest_lb_count():
    try:
        with urllib.request.urlopen(TARGET + "/netlox/v1/config/loadbalancer/all", timeout=8) as r:
            return len(json.load(r).get("lbAttr", []))
    except Exception:
        return None

# ---------------- read-only checks (admin) ----------------
print("### read-only checks (admin role)")
s = Session("admin")
tools = s.list_tools()
(ok if len(tools) > 40 else bad)(f"tools/list -> {len(tools)} tools")

e, v, _ = s.call("version_get")
(ok if isinstance(v, dict) and v.get("version") else bad)(f"version_get -> {v.get('version') if isinstance(v, dict) else v}")

e, v, _ = s.call("health_overview")
reachable = isinstance(v, dict) and v.get("reachable") is True
(ok if reachable else bad)("health_overview reachable")
health_lb = v.get("lb_rule_count") if isinstance(v, dict) else None

e, v, _ = s.call("lb_list")
lblist = v.get("returned") if isinstance(v, dict) else None
rest = rest_lb_count()
if rest is not None:
    (ok if lblist == rest == health_lb else bad)(
        f"lb_list==REST==health ({rest} rules)" if lblist == rest == health_lb
        else f"lb count mismatch lb_list={lblist} health={health_lb} REST={rest}")
else:
    (ok if lblist == health_lb and lblist is not None else bad)(
        f"lb_list==health ({lblist} rules; REST cross-check unavailable)")

e, v, _ = s.call("metrics_snapshot", families=["loxilb_lb_rules"])
fam = v.get("family_count") if isinstance(v, dict) else 0
(ok if fam and fam >= 1 else bad)(f"metrics_snapshot family_count={fam}")

e, v, _ = s.call("targets_list")
(ok if isinstance(v, dict) and v.get("count", 0) >= 1 else bad)("targets_list non-empty")

e, v, _ = s.call("fleet_overview")
(ok if isinstance(v, dict) and v.get("reachable", 0) >= 1 else bad)("fleet_overview reachable")

e, v, _ = s.call("diagnose_l4_errors")
(ok if isinstance(v, dict) and "evidence" in v else bad)("diagnose_l4_errors evidence bundle")

e, v, _ = s.call("ai_traffic_report")
has_f12 = isinstance(v, dict) and any("F12" in c for c in v.get("caveats", []))
(ok if has_f12 else bad)("ai_traffic_report surfaces F12 caveat")

# ---------------- security guardrails ----------------
print("### security guardrails")
e, v, _ = s.call("lb_list", target=TARGET)      # URL as target name
(ok if e else bad)("URL-as-target rejected (anti-SSRF)")
e, v, _ = s.call("lb_list", target="no-such-target")
(ok if e else bad)("unknown target rejected")
e, v, r = s.call("does_not_exist")
(ok if "error" in r else bad)("unknown tool -> JSON-RPC error")
s.close()

# viewer role must not even see mutating tools
sv = Session("viewer")
vtools = [t["name"] for t in sv.list_tools()]
sv.close()
(ok if vtools and "lb_create" not in vtools else bad)(
    f"viewer role: no lb_create ({len(vtools)} read tools)")

# ---------------- optional mutation round-trip ----------------
if MUTATE:
    print(f"### mutation round-trip (VIP {VIP}:{VPORT} -> {VEP})")
    m = Session("admin")
    created = False
    try:
        e, v, _ = m.call("lb_create", external_ip=VIP, port=VPORT, protocol="tcp",
                         endpoints=[{"ip": VEP, "port": 80}])
        created = isinstance(v, dict) and v.get("action") == "executed"
        (ok if created else bad)("lb_create executed" if created else f"lb_create: {v}")

        e, v, _ = m.call("lb_list")
        present = isinstance(v, dict) and any(r.get("external_ip") == VIP for r in v.get("rules", []))
        (ok if present else bad)("new VIP present in lb_list")

        e, v, _ = m.call("lb_delete", external_ip=VIP, port=VPORT, protocol="tcp")
        tok = v.get("confirm_token") if isinstance(v, dict) else None
        (ok if isinstance(v, dict) and v.get("action") == "preview" and tok else bad)(
            "lb_delete preview returns confirm_token")

        e, v, _ = m.call("lb_list")
        still = isinstance(v, dict) and any(r.get("external_ip") == VIP for r in v.get("rules", []))
        (ok if still else bad)("VIP still present after preview (no mutation)")

        e, v, _ = m.call("lb_delete", external_ip=VIP, port=VPORT, protocol="tcp",
                         confirm_token=tok)
        done = isinstance(v, dict) and v.get("action") == "executed"
        (ok if done else bad)("lb_delete executed with token")
        created = created and not done

        e, v, _ = m.call("lb_list")
        gone = isinstance(v, dict) and not any(r.get("external_ip") == VIP for r in v.get("rules", []))
        (ok if gone else bad)("VIP gone after delete")

        try:
            with open(os.path.join(AUDIT, "audit.jsonl")) as f:
                a = f.read()
            (ok if '"tool":"lb_create"' in a and '"tool":"lb_delete"' in a else bad)(
                "audit.jsonl records create+delete")
        except FileNotFoundError:
            bad("no audit.jsonl written")
    finally:
        if created:
            print("  [cleanup] removing leftover VIP via --no-confirm")
            subprocess.run([BIN, "--target-url", TARGET, "--role", "admin",
                            "--no-confirm", "--audit-dir", AUDIT],
                           input=('{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
                                  '{"protocolVersion":"2025-06-18","capabilities":{},'
                                  '"clientInfo":{"name":"cleanup","version":"0"}}}\n'
                                  '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                                  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
                                  '{"name":"lb_delete","arguments":{"external_ip":"%s",'
                                  '"port":%d,"protocol":"tcp"}}}\n' % (VIP, VPORT)),
                           text=True, capture_output=True, timeout=15)
        m.close()

print()
print("=== live E2E [OK] ===" if code == 0 else "=== live E2E [FAILED] ===")
sys.exit(code)
PY
