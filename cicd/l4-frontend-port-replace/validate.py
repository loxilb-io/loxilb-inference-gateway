#!/usr/bin/env python3
"""Check same-name frontend recreation on a configured Docker L4 test pair."""

import argparse
import json
import subprocess
import time
from ipaddress import IPv4Address


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def node_exec(node, *args):
    return run("docker", "exec", node, *args)


def api(node, endpoint):
    return json.loads(node_exec(node, "curl", "-fsS", "--max-time", "2",
                                "http://127.0.0.1:11111/netlox/v1" + endpoint))


def link(node, address):
    addresses = json.loads(node_exec(node, "ip", "-j", "-4", "addr", "show"))
    return next(item for item in addresses if any(
        row["local"] == address for row in item["addr_info"]))


def port(node, name):
    return next(item for item in api(node, "/config/port/all")["portAttr"]
                if item["portName"] == name)


def tx_ifindex(node, port_number):
    key = [f"{byte:02x}" for byte in port_number.to_bytes(4, "little")]
    item = json.loads(node_exec(node, "bpftool", "-j", "map", "lookup", "pinned",
                               "/opt/loxilb/dp/bpf/tx_intf_map", "key", "hex", *key))
    return int.from_bytes(bytes(int(byte, 16) for byte in item["value"]), "little")


def healthy(node, vip):
    role = next(row["state"] for row in api(node, "/config/cistate/all")["Attr"]
                if row["instance"] == "llb-inst0")
    bfd = api(node, "/config/bfd/all")["Attr"]
    has_vip = any(vip + "/" in line for line in node_exec(node, "ip", "-o", "-4", "addr", "show").splitlines())
    return role == "MASTER" and bool(bfd) and all(row["state"] == "BFDUp" for row in bfd) and has_vip


def serves(probe):
    return subprocess.run(probe, check=False, stdout=subprocess.DEVNULL, timeout=5).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, help="the active test L4 container")
    parser.add_argument("--network", required=True, help="its separately attached Docker frontend network")
    parser.add_argument("--address", required=True, type=IPv4Address)
    parser.add_argument("--vip", required=True, type=IPv4Address)
    parser.add_argument("probe", nargs=argparse.REMAINDER, help="command returning success only for valid VIP traffic")
    args = parser.parse_args()
    probe = args.probe[1:] if args.probe[:1] == ["--"] else args.probe
    if not probe:
        parser.error("a VIP probe command is required")
    node, network, address, vip = args.node, args.network, str(args.address), str(args.vip)
    attached = json.loads(run("docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", node))
    if attached.get(network, {}).get("IPAddress") != address or len(attached) < 2:
        raise SystemExit("test frontend must be a separate attached network with the specified address")
    before = link(node, address)
    name, old_idx = before["ifname"], before["ifindex"]
    initial = port(node, name)
    number = initial["portNo"]
    if not (healthy(node, vip) and serves(probe) and tx_ifindex(node, number) == old_idx):
        raise SystemExit("the active test node, VIP probe, or initial transmit mapping is unhealthy")

    run("docker", "network", "disconnect", network, node)
    run("docker", "network", "connect", "--ip", address, network, node)
    after = link(node, address)
    if after["ifname"] != name or after["ifindex"] == old_idx:
        raise SystemExit("test did not produce a same-name interface with a different ifindex")
    new_idx = after["ifindex"]

    start = time.monotonic()
    mapping_ready = None
    error = None
    # The existing VIP sweep advertises the new MAC every 30 seconds.
    # Confirm the map promptly, then allow one advertisement interval for
    # the client's cached neighbor entry to move.
    while time.monotonic() - start < 40:
        try:
            current = port(node, name)
            if (current["portSoftwareInformation"]["osId"] == new_idx
                    and tx_ifindex(node, current["portNo"]) == new_idx):
                if mapping_ready is None:
                    mapping_ready = time.monotonic() - start
                    print(f"mapped {name} ifindex {old_idx} -> {new_idx} in {mapping_ready:.3f}s", flush=True)
                    if mapping_ready > 5:
                        raise SystemExit("replacement datapath mapping was not ready within five seconds")
                if healthy(node, vip) and serves(probe):
                    print(f"PASS {name}: VIP traffic restored after {time.monotonic() - start:.3f}s")
                    return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, StopIteration, TypeError) as err:
            error = err
        time.sleep(0.25)
    raise SystemExit(f"FAIL {name} ifindex {old_idx} -> {new_idx}: VIP or datapath mapping did not recover: {error}")


if __name__ == "__main__":
    main()
