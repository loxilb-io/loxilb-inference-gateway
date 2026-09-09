#!/usr/bin/env python3
"""HTTP admission oracles inside a suite-owned, network-isolated Gateway."""
import argparse
import copy
import json
import pathlib
import subprocess
import sys


def request(container, method, path, body=None):
    command = ["docker", "exec", "-i", container, "curl", "--silent", "--show-error",
               "--max-time", "10", "--request", method, "--write-out", "\n%{http_code}",
               "http://127.0.0.1:11111/netlox/v1" + path]
    if body is not None:
        command += ["--header", "Content-Type: application/json", "--data-binary", "@-"]
    result = subprocess.run(command, input=json.dumps(body) if body is not None else "",
                            text=True, capture_output=True, timeout=15, check=True)
    text, status = result.stdout.rsplit("\n", 1)
    return int(status), json.loads(text) if text else {}


def canonical_rules(value):
    # GET enumerates a Go map: top-level rule order is not a state change.
    # Preserve every field and all nested ordering; do not strip IDs/counters.
    result = copy.deepcopy(value)
    result["lbAttr"] = sorted(result["lbAttr"], key=lambda rule: json.dumps(rule, sort_keys=True))
    return result


def read_rules(container):
    status, value = request(container, "GET", "/config/loadbalancer/all")
    if (status != 200 or not isinstance(value, dict)
            or not isinstance(value.get("lbAttr"), list)):
        raise RuntimeError("rule readback unavailable; no product verdict")
    return value


def find_rule(value, external_ip, port, protocol):
    matches = [rule for rule in value["lbAttr"] if (
        rule.get("serviceArguments", {}).get("externalIP") == external_ip
        and rule.get("serviceArguments", {}).get("port") == port
        and rule.get("serviceArguments", {}).get("protocol") == protocol)]
    return matches[0] if len(matches) == 1 else None


def threshold_declarations(rule):
    service = rule.get("serviceArguments", {})
    # Go omits a stored zero declaration. Zero here means "use the effective
    # system default", not a literal zero-percent or zero-connection limit.
    return (service.get("pd_cache_threshold", 0),
            service.get("pd_balance_abs_threshold", 0))


def run_threshold_update_contract(container, evidence):
    """Exercise create and replace/PATCH declaration semantics on one L4 rule."""
    external_ip, port, protocol = "127.0.0.10", 19500, "tcp"
    path = (f"/config/loadbalancer/externalipaddress/{external_ip}"
            f"/port/{port}/protocol/{protocol}")
    body = {
        "serviceArguments": {
            "externalIP": external_ip,
            "port": port,
            "protocol": protocol,
            "mode": 0,
            "sel": 0,
            "name": "pd-threshold-contract",
            "pd_cache_threshold": 61,
            "pd_balance_abs_threshold": 8,
        },
        "endpoints": [
            {"endpointIP": "127.0.0.11", "targetPort": 8080, "weight": 1}
        ],
    }
    results = []

    def record(name, passed, status, response, before, after, sent):
        item = dict(case=name, passed=passed, request=sent, http_status=status,
                    response=response, before=before, after=after)
        (evidence / (name + ".json")).write_text(json.dumps(item, indent=2) + "\n")
        results.append(dict(case=name, passed=passed))
        print(f"{name}: {'PASS' if passed else 'FAIL'} (HTTP {status})", flush=True)

    before = read_rules(container)
    status, response = request(container, "POST", "/config/loadbalancer", body)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"]) + 1
              and rule is not None and threshold_declarations(rule) == (61, 8))
    record("threshold-create-positive", passed, status, response, before, after, body)
    if not passed:
        return results

    # Replace POST must preserve both declarations when their keys are absent.
    replace = copy.deepcopy(body)
    replace["serviceArguments"].pop("pd_cache_threshold")
    replace["serviceArguments"].pop("pd_balance_abs_threshold")
    replace["serviceArguments"]["name"] = "pd-threshold-omission-retained"
    before = after
    status, response = request(container, "POST", "/config/loadbalancer", replace)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"])
              and rule is not None and threshold_declarations(rule) == (61, 8))
    record("threshold-replace-omitted-retains", passed, status, response,
           before, after, replace)
    if not passed:
        return results

    replace_reset = copy.deepcopy(body)
    replace_reset["serviceArguments"].update(
        name="pd-threshold-replace-reset",
        pd_cache_threshold=0,
        pd_balance_abs_threshold=0,
    )
    before = after
    status, response = request(container, "POST", "/config/loadbalancer", replace_reset)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"])
              and rule is not None and threshold_declarations(rule) == (0, 0))
    record("threshold-replace-zero-resets", passed, status, response,
           before, after, replace_reset)
    if not passed:
        return results

    replace_positive = copy.deepcopy(body)
    replace_positive["serviceArguments"].update(
        name="pd-threshold-replace-positive",
        pd_cache_threshold=57,
        pd_balance_abs_threshold=7,
    )
    before = after
    status, response = request(container, "POST", "/config/loadbalancer", replace_positive)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"])
              and rule is not None and threshold_declarations(rule) == (57, 7))
    record("threshold-replace-positive-replaces", passed, status, response,
           before, after, replace_positive)
    if not passed:
        return results

    omitted = {"serviceArguments": {"name": "pd-threshold-patch-omitted"}}
    before = after
    status, response = request(container, "PATCH", path, omitted)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"])
              and rule is not None and threshold_declarations(rule) == (57, 7))
    record("threshold-patch-omitted-retains", passed, status, response,
           before, after, omitted)
    if not passed:
        return results

    positive = {"serviceArguments": {
        "pd_cache_threshold": 42, "pd_balance_abs_threshold": 5}}
    before = after
    status, response = request(container, "PATCH", path, positive)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"])
              and rule is not None and threshold_declarations(rule) == (42, 5))
    record("threshold-patch-positive-replaces", passed, status, response,
           before, after, positive)
    if not passed:
        return results

    reset = {"serviceArguments": {
        "pd_cache_threshold": 0, "pd_balance_abs_threshold": 0}}
    before = after
    status, response = request(container, "PATCH", path, reset)
    after = read_rules(container)
    rule = find_rule(after, external_ip, port, protocol)
    passed = (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"])
              and rule is not None and threshold_declarations(rule) == (0, 0))
    record("threshold-patch-zero-resets", passed, status, response,
           before, after, reset)
    if not passed:
        return results

    # Each numeric null must be rejected before any rule mutation.
    for field in ("pd_cache_threshold", "pd_balance_abs_threshold"):
        sent = {"serviceArguments": {field: None}}
        before = after
        status, response = request(container, "PATCH", path, sent)
        after = read_rules(container)
        passed = (status == 400 and field in json.dumps(response)
                  and canonical_rules(before) == canonical_rules(after))
        record("threshold-patch-null-" + field, passed, status, response,
               before, after, sent)
        if not passed:
            return results

    return results


def verdict(body, status, response, before, after, reason):
    """A rejection must name its cause and leave the entire rule set unchanged."""
    if reason is not None:
        return (status in (400, 422) and reason in json.dumps(response)
                and canonical_rules(before) == canonical_rules(after))
    # Count alone could pass if an unrelated rule was created instead.
    matches = [rule for rule in after["lbAttr"] if all(
        rule.get("serviceArguments", {}).get(key) == body["serviceArguments"][key]
        for key in ("externalIP", "port", "protocol", "mode"))]
    return (status == 200 and len(after["lbAttr"]) == len(before["lbAttr"]) + 1
            and len(matches) == 1
            # TTL zero is omitted by Go's JSON encoder. Compare declarations,
            # never substitute 300 here: effective expiry is proven by C tests.
            and matches[0]["serviceArguments"].get("pd_session_ttl_sec", 0)
                == body["serviceArguments"].get("pd_session_ttl_sec", 0)
            and all(matches[0]["serviceArguments"].get(key) == value
                    for key, value in body["serviceArguments"].items()
                    if key not in ("externalIP", "port", "protocol", "mode", "sel", "pd_session_ttl_sec"))
            and all(
                any(all(ep.get(key) == value for key, value in expected.items())
                    for ep in matches[0].get("endpoints", []))
                for expected in body["endpoints"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("container")
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args()
    inspected = json.loads(subprocess.check_output(["docker", "inspect", args.container]))[0]
    if (inspected["Config"].get("Labels", {}).get("io.loxilb.cicd") != "ai-multitier-contract"
            or inspected["HostConfig"]["NetworkMode"] != "none"
            or inspected["HostConfig"]["Privileged"] or inspected["Mounts"]):
        raise RuntimeError("refusing to mutate a container outside the isolated suite")
    base = {"serviceArguments": {"externalIP": "127.0.0.1", "port": 19100,
            "protocol": "tcp", "mode": 4, "sel": 0},
            "endpoints": [{"endpointIP": "127.0.0.2", "targetPort": 8080, "weight": 1}]}
    cases = [
        ("control", None, None, None, None),
        ("cache-null", "serviceArguments", "pd_cache_threshold", None, "pd_cache_threshold"),
        ("balance-null", "serviceArguments", "pd_balance_abs_threshold", None, "pd_balance_abs_threshold"),
        ("balance-overflow", "serviceArguments", "pd_balance_abs_threshold", 256, "pd_balance_abs_threshold"),
        ("block-overflow", "serviceArguments", "kvBlockSize", 1 << 32, "kvBlockSize"),
        ("warmup-overflow", "serviceArguments", "kvWarmupSec", 1 << 32, "kvWarmupSec"),
        ("role-negative", "endpoint", "ep_role", -1, "ep_role"),
        ("role-unknown", "endpoint", "ep_role", 3, "ep_role"),
        ("nixl-negative", "endpoint", "nixl_port", -1, "nixl_port"),
        ("nixl-overflow", "endpoint", "nixl_port", 65536, "nixl_port"),
        ("reserved-vllm", "serviceArguments", "kvEngineType", "vllm", "reserved"),
        ("reserved-sglang", "serviceArguments", "kvEngineType", "sglang", "reserved"),
        ("ttl-negative", "serviceArguments", "pd_session_ttl_sec", -1, "pd_session_ttl_sec"),
        ("ttl-overflow", "serviceArguments", "pd_session_ttl_sec", 1 << 31, "pd_session_ttl_sec"),
    ]
    for ttl in (0, 1, 300, 600, (1 << 31) - 1):
        cases.append((f"ttl-control-{ttl}", "serviceArguments", "pd_session_ttl_sec", ttl, None))
    fixed_c_strings = (
        ("host", 255),
        ("path_prefix", 255),
        ("session_header_name", 127),
        ("model_name", 127),
    )
    for field, limit in fixed_c_strings:
        cases.extend((
            (f"{field}-boundary", "serviceArguments", field, "a" * limit, None),
            (f"{field}-overflow", "serviceArguments", field, "a" * (limit + 1), field),
            (f"{field}-nul", "serviceArguments", field, "safe\x00shadow", field),
        ))
    # Prove limits are UTF-8 byte limits, not character-count limits. Each
    # U+00E9 is two bytes in UTF-8; the trailing ASCII byte lands exactly on
    # the accepted boundary.
    for field, limit in fixed_c_strings:
        exact = "é" * (limit // 2) + ("a" if limit % 2 else "")
        overflow = exact + ("é" if limit % 2 else "a")
        cases.extend((
            (f"{field}-utf8-boundary", "serviceArguments", field, exact, None),
            (f"{field}-utf8-overflow", "serviceArguments", field, overflow, field),
        ))
    cases.extend((
        ("composite-boundary", "serviceArguments", "__composite__", {
            "host": "h" * 255, "path_prefix": "p" * 127, "model_name": "m" * 127,
        }, None),
        ("composite-overflow", "serviceArguments", "__composite__", {
            "host": "h" * 255, "path_prefix": "p" * 128, "model_name": "m" * 127,
        }, "composite"),
    ))
    for engine in ("default", "vllm", "trtllm", "llamacpp"):
        for ranks in (2, 8):
            cases.append((f"rank-{engine}-{ranks}", "serviceArguments", "kvDpRankCount", ranks, "rank"))
    for engine, ranks in (("vllm", 1), ("sglang", 1), ("sglang", 2), ("sglang", 8)):
        cases.append((f"rank-control-{engine}-{ranks}", "serviceArguments", "kvDpRankCount", ranks, None))
    results = []
    for index, (name, scope, key, value, reason) in enumerate(cases):
        body = copy.deepcopy(base)
        body["serviceArguments"]["port"] += index
        if scope:
            target = body["endpoints"][0] if scope == "endpoint" else body[scope]
            if key == "__composite__":
                target.update(value)
            else:
                target[key] = value
        if name.startswith("reserved-"):
            body["serviceArguments"].update(kvExactMode=2, model_name="model-a")
        if name.startswith("rank-"):
            engine = name.split("-")[-2]
            if engine != "default":
                body["serviceArguments"]["kvEngineType"] = engine
        before = read_rules(args.container)
        status, response = request(args.container, "POST", "/config/loadbalancer", body)
        after = read_rules(args.container)
        passed = verdict(body, status, response, before, after, reason)
        if name in ("cache-null", "balance-null"):
            passed = passed and status == 400
        record = dict(case=name, passed=passed, request=body, http_status=status,
                      response=response, before=before, after=after)
        (args.evidence / (name + ".json")).write_text(json.dumps(record, indent=2) + "\n")
        results.append(dict(case=name, passed=passed))
        print(f"{name}: {'PASS' if passed else 'FAIL'} (HTTP {status})", flush=True)
        if reason is None and not passed:
            raise RuntimeError("positive control failed; negative verdicts would be invalid")
    results.extend(run_threshold_update_contract(args.container, args.evidence))
    (args.evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
