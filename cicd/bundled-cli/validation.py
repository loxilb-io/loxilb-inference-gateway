#!/usr/bin/env python3
"""Exercise the image's bundled CLI, real Gateway and isolated mock engines."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from verify_bundled_cli import expected_identity, verify_identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--mock-binary", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    out = Path(args.evidence_dir).resolve()
    out.mkdir(parents=True, exist_ok=False)
    name = "bundled-cli-" + uuid.uuid4().hex[:12]
    created = False
    checks = []

    def run(cmd, check=True, timeout=30):
        started = time.time_ns()
        r = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        with (out / "commands.jsonl").open("a") as f:
            f.write(json.dumps(dict(started_ns=started, command=cmd, exit=r.returncode, stdout=r.stdout, stderr=r.stderr)) + "\n")
        if check and r.returncode:
            raise RuntimeError((cmd, r.returncode, r.stdout, r.stderr))
        return r

    def request(method, url, media="", body="", case=""):
        r = run(["docker", "exec", name, "/bundle-mock", "request", method, url, media, body, case])
        return json.loads(r.stdout)

    def state(reset=False):
        r = request("POST" if reset else "GET", "http://127.0.0.13:18081/" + ("reset" if reset else "records"))
        assert r["status"] == 200 and not r["error"], r
        return json.loads(r["body"])

    def cli(server, port, rest, check=True):
        return run(["docker", "exec", name, "/usr/local/sbin/loxicmd", "-s", server,
                    "-p", str(port), "-o", "json", *rest], check)

    def assert_case(label, predicate, detail):
        if not predicate:
            raise AssertionError((label, detail))
        checks.append(label)
        print("PASS:", label, flush=True)

    def entries():
        r = request("GET", "http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all")
        if r["status"] != 200:
            return []
        def walk(value):
            if isinstance(value, list):
                for item in value:
                    yield from walk(item)
            elif isinstance(value, dict):
                if "serviceArguments" in value:
                    yield value
                else:
                    for item in value.values():
                        yield from walk(item)
        return list(walk(json.loads(r["body"])))

    try:
        rev, version = expected_identity(args.dockerfile)
        result = run(["docker", "run", "--rm", "--network", "none", "--entrypoint",
                      "/usr/local/sbin/loxicmd", args.image, "version", "-o", "json"])
        (out / "cli-version.json").write_text(result.stdout)
        verify_identity(json.loads(result.stdout), rev, version)
        checks.append("bundled source revision and own version")
        command = "/bundle-mock & ulimit -l unlimited; mkdir -p /opt/loxilb/dp; mount -t bpf bpf /opt/loxilb/dp; exec /root/loxilb-io/loxilb/loxilb -p"
        run(["docker", "run", "-d", "--name", name, "--network", "none", "--privileged",
             "-v", str(Path(args.mock_binary).resolve()) + ":/bundle-mock:ro",
             "--entrypoint", "/bin/bash", args.image, "-ec", command])
        created = True
        for _ in range(90):
            r = request("GET", "http://127.0.0.1:11111/netlox/v1/version")
            if r["status"] == 200:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Gateway REST readiness timed out")
        run(["docker", "cp", name + ":/usr/local/sbin/loxicmd", str(out / "loxicmd")])
        (out / "cli-sha256.txt").write_text(hashlib.sha256((out / "loxicmd").read_bytes()).hexdigest() + "\n")
        for label, pd, mode, want in (("P/D off", False, "FailClose", 0),
                                     ("P/D FailOpen", True, "FailOpen", 0),
                                     ("P/D FailClose", True, "FailClose", 2),
                                     ("P/D omitted", True, None, 2)):
            state(True)
            flags = ["create", "lb", "192.0.2.87", "--tcp=2087:8080", "--mode=fullproxy",
                     "--epp-endpoint=127.0.0.20:9002", "--endpoints=198.51.100.1:1,198.51.100.2:1"]
            if pd:
                flags += ["--pd-disagg", "--ep-role=prefill,decode"]
            if mode:
                flags += ["--epp-failure-mode=" + mode]
            r = cli("127.0.0.14", 18082, flags, False)
            seen = state().get("wire") or []
            assert_case(label + " exit", r.returncode == want, (r.stdout, r.stderr))
            if want:
                assert_case(label + " zero HTTP", not seen, seen)
                assert_case(label + " actionable mode error", "requires --epp-failure-mode FailOpen" in r.stdout + r.stderr, (r.stdout, r.stderr))
            else:
                posts = [x for x in seen if x["method"] == "POST"]
                assert_case(label + " one POST", len(posts) == 1, seen)
                payload = json.loads(posts[0]["body"])
                service = payload["serviceArguments"]
                assert_case(label + " wire mode", bool(service.get("pd_disagg_mode")) == pd and service["eppFailureMode"] == mode, payload)
                if pd:
                    assert_case(label + " wire roles", [x["ep_role"] for x in payload["endpoints"]] == [1, 2], payload)
        for port, epp in ((20520, True), (20521, False)):
            flags = ["create", "lb", "127.0.0.22", f"--tcp={port}:18080", "--mode=fullproxy", "--pd-disagg",
                     "--endpoints=127.0.0.10:1,127.0.0.11:1,127.0.0.12:1", "--ep-role=prefill,decode,normal",
                     "--nixl-port=5600,5600,0"]
            if epp:
                flags += ["--epp-endpoint=127.0.0.20:9002", "--epp-failure-mode=FailOpen", "--epp-timeout-ms=50", "--epp-plaintext"]
            cli("127.0.0.1", 11111, flags)
            matches = [x for x in entries() if x["serviceArguments"]["port"] == port]
            assert_case(f"real Gateway {port} readback", len(matches) == 1 and matches[0]["serviceArguments"].get("pd_disagg_mode"), matches)
            if epp:
                assert_case("real Gateway EPP FailOpen readback", matches[0]["serviceArguments"]["eppFailureMode"] == "FailOpen", matches)
        def traffic(port, suffix):
            case = f"inference-{suffix}"
            body = json.dumps(dict(model="alias", prompt="hello pd", max_tokens=16))
            r = request("POST", f"http://127.0.0.22:{port}/v1/completions", "application/json", body, case)
            seen = [x for x in state().get("engine") or [] if x["case"] == case]
            assert_case(case + " response", r["status"] == 200 and not r["error"] and json.loads(r["body"]).get("served") == "decode", r)
            assert_case(case + " full P/D receipts", Counter(x["role"] for x in seen) == Counter(prefill=1, decode=1), seen)
            probe = json.loads(next(x["body"] for x in seen if x["role"] == "prefill"))
            decoded = json.loads(next(x["body"] for x in seen if x["role"] == "decode"))
            assert_case(case + " rewritten legs", probe["max_tokens"] == 1 and decoded["max_tokens"] == 16 and "kv_transfer_params" in decoded, seen)
        traffic(20520, "epp-down")
        traffic(20521, "native")
        r = request("GET", "http://127.0.0.22:20520/v1/models", case="bodyless")
        seen = [x for x in state().get("engine") or [] if x["case"] == "bodyless"]
        assert_case("bodyless decode response", r["status"] == 200 and json.loads(r["body"]).get("served") == "decode", r)
        assert_case("bodyless only decode receipt", Counter(x["role"] for x in seen) == Counter(decode=1), seen)
        r = request("POST", "http://127.0.0.22:20520/v1/completions", "application/octet-stream", "x" * 1024, "unsupported")
        assert_case("unsupported media full 415", r["status"] == 415 and not r["error"] and "pd_body_unsupported_media" in r["body"], r)
        assert_case("unsupported media zero receipts", not [x for x in state().get("engine") or [] if x["case"] == "unsupported"], state())
        # A config POST acknowledges running state; auto-persist is debounced.
        # Establish a durable checkpoint instead of racing the quiet period.
        persisted = request("POST", "http://127.0.0.1:11111/netlox/v1/config/persist")
        assert_case("durable checkpoint response", persisted["status"] == 200 and not persisted["error"], persisted)
        receipt = json.loads(persisted["body"])
        (out / "persist-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        run(["docker", "cp", name + ":/etc/loxilb/snapshot.json", str(out / "snapshot-before-restart.json")])
        saved = json.loads((out / "snapshot-before-restart.json").read_text())
        ports = {x["serviceArguments"]["port"] for x in saved["domains"]["loadbalancer"]}
        assert_case("durable checkpoint contains both rules",
                    ports >= {20520, 20521} and saved["generation"] >= receipt["generation"] > 0, saved)
        run(["docker", "restart", "--time", "15", name], timeout=30)
        for _ in range(90):
            if {x["serviceArguments"]["port"] for x in entries()} >= {20520, 20521}:
                break
            time.sleep(1)
        else:
            raise RuntimeError("persisted CLI rules did not replay")
        checks.append("restart restored both CLI-created rules")
        ready = request("GET", "http://127.0.0.1:11111/netlox/v1/status/ready")
        boot = json.loads(ready["body"])["boot"]
        assert_case("restart applied the saved snapshot", boot["snapshot_found"] and boot["succeeded"]
                    and boot["generation"] >= saved["generation"], ready)
        traffic(20520, "after-restart")
        for port in (20520, 20521):
            cli("127.0.0.1", 11111, ["delete", "lb", "127.0.0.22", f"--tcp={port}"])
            assert_case(f"CLI delete {port} readback", not [x for x in entries() if x["serviceArguments"]["port"] == port], entries())
        (out / "records.json").write_text(json.dumps(state(), indent=2) + "\n")
        (out / "result.json").write_text(json.dumps(dict(result="PASS", checks=checks, cliRevision=rev, cliVersion=version), indent=2) + "\n")
        print(f"PASS: {len(checks)} image CLI/REST/datapath/lifecycle assertions")
    finally:
        if created:
            try:
                diagnostics = dict(readiness=request("GET", "http://127.0.0.1:11111/netlox/v1/status/ready"),
                                   records=state())
                (out / "final-diagnostics.json").write_text(json.dumps(diagnostics, indent=2) + "\n")
            except (RuntimeError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
                (out / "diagnostics-error.txt").write_text(str(error) + "\n")
            log = run(["docker", "logs", "--timestamps", name], False)
            (out / "gateway.log").write_text(log.stdout + log.stderr)
            run(["docker", "stop", "--time", "15", name], False)
            run(["docker", "rm", name])


if __name__ == "__main__":
    main()
