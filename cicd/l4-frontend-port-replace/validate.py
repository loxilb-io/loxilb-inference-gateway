#!/usr/bin/env python3
"""Check same-name frontend recreation on a configured Docker L4 test pair."""

import argparse
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile
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


def response_frames(capture, since):
    pattern = re.compile(
        r"^(\d+\.\d+) ([\da-f:]+) > .*? > [\d.]+\.(\d+): "
        r"Flags \[([^]]*)\].* length (\d+)$"
    )
    for line in capture.read_text().splitlines():
        match = pattern.match(line)
        if match:
            stamp, source, client_port, flags, length = match.groups()
            if float(stamp) >= since:
                yield float(stamp), source, int(client_port), flags, int(length)


def check_replacement(args, probe, stream_probe, capture):
    node, network, address, vip = args.node, args.network, str(args.address), str(args.vip)
    before = link(node, address)
    name, old_idx = before["ifname"], before["ifindex"]
    old_mac = json.loads(node_exec(node, "ip", "-j", "link", "show", "dev", name))[0]["address"]
    number = port(node, name)["portNo"]
    if not (healthy(node, vip) and serves(probe) and tx_ifindex(node, number) == old_idx):
        raise SystemExit("the active node, VIP probe, or initial transmit mapping is unhealthy")

    stream_start = time.time()
    with subprocess.Popen(stream_probe, stdout=subprocess.DEVNULL) as stream:
        try:
            for _ in range(30):
                if any(mac == old_mac and client == args.stream_client_port and size > 0
                       for _, mac, client, _, size in response_frames(capture, stream_start)):
                    break
                if stream.poll() is not None:
                    raise SystemExit("the existing stream exited before the cut")
                time.sleep(0.1)
            else:
                raise SystemExit("no payload from the pre-replacement stream was captured")

            start, cut = time.monotonic(), time.time()
            run("docker", "network", "disconnect", network, node)
            run("docker", "network", "connect", "--ip", address, network, node)
            after = link(node, address)
            if after["ifname"] != name or after["ifindex"] == old_idx:
                raise SystemExit("test did not produce a same-name link with a new ifindex")
            new_idx = after["ifindex"]
            new_mac = json.loads(node_exec(node, "ip", "-j", "link", "show", "dev", name))[0]["address"]
            if new_mac == old_mac:
                raise SystemExit("test did not produce a different frontend MAC")

            mapping_ready = None
            first_new_syn = first_new_stream = None
            client_ready = False
            error = None
            while time.monotonic() - start < 8:
                try:
                    current = port(node, name)
                    if mapping_ready is None and current["portSoftwareInformation"]["osId"] == new_idx:
                        if tx_ifindex(node, current["portNo"]) == new_idx:
                            mapping_ready = time.monotonic() - start
                            if mapping_ready > 5:
                                raise SystemExit("replacement datapath mapping was not ready within 5 s")
                    if mapping_ready is not None and healthy(node, vip):
                        client_ready = serves(probe)
                        for stamp, source, client, flags, size in response_frames(capture, cut):
                            if source == new_mac and stamp - cut <= 8:
                                if client != args.stream_client_port and flags == "S.":
                                    first_new_syn = first_new_syn or stamp
                                if client == args.stream_client_port and size > 0:
                                    first_new_stream = first_new_stream or stamp
                        if client_ready and first_new_syn is not None and first_new_stream is not None:
                            break
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, StopIteration, TypeError) as err:
                    error = err
                time.sleep(0.25)
            else:
                raise SystemExit(f"FAIL {name} ifindex {old_idx} -> {new_idx}: "
                                 f"map={mapping_ready}, client={client_ready}, "
                                 f"fresh SYN-ACK={first_new_syn}, stream payload={first_new_stream}: {error}")

            if stream.wait(timeout=25) != 0:
                raise SystemExit("the pre-existing stream did not finish successfully")
            if not (healthy(node, vip) and serves(probe)):
                raise SystemExit("VIP service or BFD role regressed after the stream")
            time.sleep(0.1)  # Flush the line-buffered capture of the final probe.
            if any(source != new_mac for _, source, _, _, _ in
                   response_frames(capture, min(first_new_syn, first_new_stream))):
                raise SystemExit("a response used a stale source MAC after forwarding resumed")
            print(f"PASS {name}: map {mapping_ready:.3f}s; fresh SYN-ACK "
                  f"{first_new_syn - cut:.3f}s; existing stream {first_new_stream - cut:.3f}s; "
                  f"both use {new_mac}")
        finally:
            if stream.poll() is None:
                stream.terminate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, help="the active test L4 container")
    parser.add_argument("--network", required=True, help="its separately attached Docker frontend network")
    parser.add_argument("--address", required=True, type=IPv4Address)
    parser.add_argument("--vip", required=True, type=IPv4Address)
    parser.add_argument("--tcp-port", required=True, type=int, help="VIP TCP service port")
    parser.add_argument("--stream-client-port", required=True, type=int,
                        help="fixed local TCP port used by the existing flow")
    parser.add_argument("--stream-probe", required=True,
                        help="quoted command opening a successful stream lasting at least 12 s")
    parser.add_argument("--capture", type=Path, help="save the Ethernet capture to this file")
    parser.add_argument("probe", nargs=argparse.REMAINDER, help="command returning success only for valid VIP traffic")
    args = parser.parse_args()
    probe = args.probe[1:] if args.probe[:1] == ["--"] else args.probe
    if not probe:
        parser.error("a VIP probe command is required")
    stream_probe = shlex.split(args.stream_probe)
    if not stream_probe:
        parser.error("a stream probe command is required")
    node, network, address = args.node, args.network, str(args.address)
    attached = json.loads(run("docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", node))
    if attached.get(network, {}).get("IPAddress") != address or len(attached) < 2:
        raise SystemExit("test frontend must be a separate attached network with the specified address")
    frontend = json.loads(run("docker", "network", "inspect", network))[0]
    if frontend["Driver"] != "bridge":
        raise SystemExit("this case requires a Docker bridge frontend")
    bridge = frontend["Options"].get("com.docker.network.bridge.name", f"br-{frontend['Id'][:12]}")
    with tempfile.TemporaryDirectory() as temp:
        capture = args.capture or Path(temp) / "frontend.log"
        with capture.open("wb") as output, subprocess.Popen(
                ["tcpdump", "-e", "-n", "-l", "-tt", "-i", bridge,
                 f"tcp and src host {args.vip} and src port {args.tcp_port}"],
                stdout=output, stderr=subprocess.STDOUT) as tcpdump:
            try:
                for _ in range(20):
                    if "listening on" in capture.read_text():
                        break
                    if tcpdump.poll() is not None:
                        raise SystemExit(capture.read_text())
                    time.sleep(0.1)
                else:
                    raise SystemExit("tcpdump did not start")
                check_replacement(args, probe, stream_probe, capture)
            finally:
                if tcpdump.poll() is None:
                    tcpdump.send_signal(signal.SIGINT)


if __name__ == "__main__":
    main()
