#!/usr/bin/env python3
"""Exercise a BACKUP-first L2 BFD upgrade and maintenance rollback."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid


BINARY = "/root/loxilb-io/loxilb/loxilb"
CONFIG = "/etc/loxilb"
BACK, FRONT = "172.29.176", "172.29.177"
VIP, PORT = FRONT + ".253", 9443
LABEL = "org.loxilb.ha-mixed-fixture"


def run(*args, payload=None, timeout=30):
    return subprocess.run(args, input=payload, check=True, capture_output=True,
                          text=True, timeout=timeout).stdout.strip()


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def wait_for(description, predicate, seconds=90):
    end = time.monotonic() + seconds
    problem = None
    while time.monotonic() < end:
        try:
            value = predicate()
            if value:
                return value
        except (subprocess.SubprocessError, ValueError, KeyError) as exc:
            problem = exc
        time.sleep(0.2)
    raise RuntimeError(f"{description} timed out: {problem}")


class Trial:
    def __init__(self, out, old, new, backend):
        self.out = out
        self.name = f"ha-mixed-{uuid.uuid4().hex[:10]}"
        self.label = f"{LABEL}={self.name}"
        self.front = self.name + "-front"
        self.back = self.name + "-back"
        self.nodes = (1, 2)
        self.images = {ref: docker("image", "inspect", "-f", "{{.Id}}", ref)
                       for ref in (old, new, backend)}
        if old == new or self.images[old] == self.images[new]:
            raise RuntimeError("legacy and candidate resolve to the same image")
        self.old, self.new, self.backend = old, new, backend
        self.containers, self.networks, self.volumes = {}, {}, {}
        # Keep FullNAT return traffic on the VIP segment. Crossing two Docker
        # bridges puts backend replies through the runner's host firewall.
        self.endpoints = {f"echo-{i}": f"{FRONT}.{30+i}" for i in (1, 2, 3)}
        self.log = (out / "timeline.jsonl").open("x", encoding="utf-8")

    def record(self, event, **fields):
        line = json.dumps({"event": event, "t": time.monotonic(), **fields})
        print(line, flush=True)
        print(line, file=self.log, flush=True)

    def create_network(self, name, subnet):
        self.networks[name] = docker("network", "create", "--label", self.label,
                                     "--subnet", subnet + ".0/24", name)

    def create_node(self, node, ref, *, rollback=False):
        if node in self.containers:
            raise RuntimeError(f"node {node} already exists")
        config = "rollback" if rollback else "config"
        volume_key = (node, config)
        if volume_key not in self.volumes:
            self.volumes[volume_key] = docker("volume", "create", "--label", self.label,
                                              f"{self.name}-{config}-{node}")
        local, peer = f"{BACK}.{10+node}", f"{BACK}.{13-node}"
        launch = ("set -e; mkdir -p /opt/loxilb/dp; mount -t bpf bpf /opt/loxilb/dp; "
                  f"exec {BINARY} --cluster={peer} --self={node-1} --ka={peer}:{local} "
                  "--config-auto-persist=on --loglevel=info")
        self.containers[node] = docker(
            "create", "--pull=never", "--privileged", "--name", f"{self.name}-l4-{node}", "--label", self.label,
            "--network", self.back, "--ip", local, "--mount",
            f"type=volume,src={self.volumes[volume_key]},dst={CONFIG},volume-nocopy",
            "--entrypoint", "/bin/bash", self.images[ref], "-c", launch)
        docker("network", "connect", "--ip", f"{FRONT}.{10+node}", self.front, self.containers[node])

    def remove_node(self, node, stage):
        container = self.containers[node]
        result = subprocess.run(["docker", "logs", container], capture_output=True, text=True, timeout=15)
        (self.out / f"{stage}-node-{node}.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        docker("rm", "-fv", container)
        del self.containers[node]

    def cli(self, node, *args, **kwargs):
        return docker("exec", "-i", self.containers[node], *args, **kwargs)

    def api(self, node, path, data=None):
        args = ["curl", "-fsS", "--max-time", "2", "http://127.0.0.1:11111/netlox/v1" + path]
        if data is not None:
            args += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
        return json.loads(self.cli(node, *args, payload=json.dumps(data) if data is not None else None))

    def role(self, node):
        return next((row["state"] for row in self.api(node, "/config/cistate/all")["Attr"]
                     if row["instance"] == "llb-inst0"), None)

    def bfd_up(self, node):
        peers = self.api(node, "/config/bfd/all").get("Attr")
        return bool(peers) and all(row["state"] == "BFDUp" for row in peers)

    def holds_vip(self, node):
        return self.container_has_vip(self.containers[node])

    @staticmethod
    def container_has_vip(container):
        result = docker("inspect", "-f", "{{.State.Running}}", container)
        if result == "false":
            return False
        output = docker("exec", container, "ip", "-o", "-4", "addr", "show")
        return any(f" {VIP}/" in line for line in output.splitlines())

    def node_identity(self, node, ref):
        container = self.containers[node]
        actual = docker("inspect", "-f", "{{.Image}}", container)
        if actual != self.images[ref]:
            raise RuntimeError(f"node {node} image {actual} differs from expected {self.images[ref]}")
        checksum = self.cli(node, "sha256sum", BINARY).split()[0]
        self.record("node-image", node=node, requested=ref, image=actual, binary_sha256=checksum)
        return checksum

    def program(self, node):
        result = self.api(node, "/config/loadbalancer", {
            "serviceArguments": {"externalIP": VIP, "port": PORT, "protocol": "tcp", "mode": 2,
                                 "sel": 1, "name": "ha-mixed-hash", "inactiveTimeOut": 60},
            "endpoints": [{"endpointIP": ip, "targetPort": 80, "weight": 1}
                          for ip in self.endpoints.values()],
        })
        if result.get("result") != "Success":
            raise RuntimeError(f"initial rule creation failed on node {node}: {result}")

    def has_rule(self, node):
        for rule in self.api(node, "/config/loadbalancer/all").get("lbAttr") or []:
            args = rule["serviceArguments"]
            if (args.get("externalIP"), args.get("port"), args.get("mode"), args.get("sel")) == (VIP, PORT, 2, 1):
                return {ep["endpointIP"] for ep in rule["endpoints"]} == set(self.endpoints.values())
        return False

    def persist(self, node):
        result = json.loads(self.cli(node, "curl", "-fsS", "--max-time", "5", "-X", "POST",
                                     "http://127.0.0.1:11111/netlox/v1/config/persist"))
        if result.get("result") != "ok" or not result.get("checksum"):
            raise RuntimeError(f"node {node} did not persist the running rule")
        self.record("snapshot", node=node, checksum=result["checksum"], schema=result.get("schema_version"))

    def archive_config(self, node):
        return subprocess.run(["docker", "cp", f"{self.containers[node]}:{CONFIG}/.", "-"],
                              check=True, capture_output=True, timeout=30).stdout

    def restore_config(self, node, archive):
        subprocess.run(["docker", "cp", "-", f"{self.containers[node]}:{CONFIG}"],
                       input=archive, check=True, capture_output=True, timeout=30)

    def probe(self, address=VIP, port=PORT):
        try:
            first = run("curl", "--noproxy", "*", "-fsS", "--connect-timeout", "0.5", "--max-time",
                        "1", f"http://{address}:{port}/echo", timeout=3).splitlines()
        except subprocess.SubprocessError:
            return None
        return next((name for name in self.endpoints if first and first[0] == "X-Echo-Backend: " + name), None)

    def stable_service(self):
        def sample():
            for _ in range(5):
                if self.probe() is None:
                    return False
                time.sleep(0.2)
            return True
        wait_for("stable client HTTP", sample, 55)

    def pair_master(self):
        states = {node: self.role(node) for node in self.nodes}
        if sorted(str(role) for role in states.values()) != ["BACKUP", "MASTER"]:
            return None
        master = next(node for node in self.nodes if states[node] == "MASTER")
        return master if all(self.bfd_up(node) for node in self.nodes) else None

    def sole_owner(self, master):
        return self.pair_master() == master and self.holds_vip(master) and not self.holds_vip(3-master)

    @contextmanager
    def watch_incumbent(self, stage, master):
        done = threading.Event()
        first_sample = threading.Event()
        samples = []

        def watch():
            while not done.is_set():
                start = time.monotonic()
                name = self.probe()
                try:
                    retained = self.role(master) == "MASTER" and self.holds_vip(master)
                except (subprocess.SubprocessError, ValueError, KeyError):
                    retained = False
                other = self.containers.get(3-master)
                duplicate = False
                if other is not None:
                    try:
                        duplicate = self.container_has_vip(other)
                    except subprocess.CalledProcessError as exc:
                        # Removal can race either inspect or exec on this peer.
                        peer_gone = (
                            f"No such object: {other}",
                            f"No such container: {other}",
                            f"container {other} is not running",
                        )
                        if not any(message in (exc.stderr or "") for message in peer_gone):
                            raise
                samples.append({"t": start, "backend": name, "incumbent_kept_vip": retained,
                                "other_holds_vip": duplicate})
                first_sample.set()
                done.wait(0.2)

        with ThreadPoolExecutor(max_workers=1) as executor:
            observer = executor.submit(watch)
            try:
                if not first_sample.wait(8):
                    raise RuntimeError("the client observer did not start")
                yield
            finally:
                done.set()
                try:
                    observer.result()
                finally:
                    (self.out / f"{stage}.json").write_text(json.dumps(samples), encoding="utf-8")
        if len(samples) < 3 or any(not row["backend"] or not row["incumbent_kept_vip"]
                                   or row["other_holds_vip"] for row in samples):
            raise RuntimeError(f"{stage}: traffic or incumbent VIP ownership was interrupted")
        self.record(stage, incumbent=master, samples=len(samples), http_failures=0)

    def return_node(self, node, ref, incumbent, stage):
        with self.watch_incumbent(stage, incumbent):
            self.remove_node(node, stage)
            self.create_node(node, ref)
            docker("start", self.containers[node])
            checksum = self.node_identity(node, ref)
            wait_for("restored rule and non-preemptive BACKUP",
                     lambda: self.has_rule(node) and self.sole_owner(incumbent))
            self.stable_service()
        return checksum

    def clean_withdrawal(self, master):
        bridge = "br-" + self.networks[self.back][:12]
        capture = self.out / "sigterm-bfd.txt"
        with capture.open("wb") as output:
            # Bound the capture inside sudo so cleanup does not depend on
            # how the runner's sudo process forwards signals to tcpdump.
            monitor = subprocess.Popen(
                ["sudo", "-n", "timeout", "--signal=INT", "--kill-after=2s", "12s",
                 "tcpdump", "-nnvv", "-tt", "-l", "-i", bridge, "udp", "dst", "port", "3784"],
                stdout=output, stderr=subprocess.STDOUT,
            )
            try:
                wait_for("BFD packet capture ready", lambda: "listening on" in capture.read_text(), 5)
                start = time.time()
                docker("kill", "--signal=TERM", self.containers[master])
                wait_for("peer inherits the VIP", lambda: self.role(3-master) == "MASTER"
                         and self.holds_vip(3-master) and not self.holds_vip(master), 12)
                wait_for("clean process exit",
                         lambda: docker("inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}",
                                        self.containers[master]) == "exited 0", 20)
                self.stable_service()
            finally:
                monitor.wait(timeout=17)
        packets = re.split(r"(?m)^(?=\d+\.\d+ IP )", capture.read_text())[1:]
        if not any(float(packet.split()[0]) >= start
                   and f"{BACK}.{10+master}." in packet
                   and f"> {BACK}.{13-master}.3784:" in packet
                   and "My Discriminator: 0x00000001," in packet for packet in packets):
            raise RuntimeError("clean shutdown did not send the BFD withdrawal rank")
        self.record("candidate-sigterm", old_owner=master, new_owner=3-master, withdrawal_rank=1)

    def execute(self):
        self.record("images", legacy=self.old, candidate=self.new, resolved=self.images)
        self.create_network(self.back, BACK)
        self.create_network(self.front, FRONT)
        for name, ip in self.endpoints.items():
            self.containers[name] = docker(
                "run", "-d", "--pull=never", "--label", self.label, "--name", f"{self.name}-{name}",
                "--network", self.front, "--ip", ip, "-e", f"ECHO_NAME={name}", self.images[self.backend])
            wait_for(f"{name} ready", lambda: self.probe(ip, 80) == name, 15)
        for node in self.nodes:
            self.create_node(node, self.old)
        docker("start", *(self.containers[node] for node in self.nodes))
        incumbent = wait_for("legacy BFD pair", self.pair_master)
        old_checksums = set()
        for node in self.nodes:
            old_checksums.add(self.node_identity(node, self.old))
            self.program(node)
            self.persist(node)
        wait_for("legacy VIP", lambda: self.sole_owner(incumbent))
        self.stable_service()
        archives = {node: self.archive_config(node) for node in self.nodes}
        self.record("legacy-baseline", owner=incumbent)

        standby = 3-incumbent
        new_checksum = self.return_node(standby, self.new, incumbent, "backup-first")
        if len(old_checksums) != 1 or new_checksum in old_checksums:
            raise RuntimeError("old and new gateway binary identities are not distinct")
        cut = time.monotonic()
        docker("stop", "--time", "20", self.containers[incumbent])
        wait_for("mixed-version takeover",
                 lambda: self.role(standby) == "MASTER" and self.holds_vip(standby)
                 and not self.holds_vip(incumbent), 12)
        self.stable_service()
        self.record("planned-takeover", new_owner=standby, stable_http_confirmed_s=time.monotonic() - cut)
        if self.return_node(incumbent, self.new, standby, "second-upgrade") != new_checksum:
            raise RuntimeError("the two candidate binaries differ")

        self.clean_withdrawal(standby)
        self.return_node(standby, self.new, incumbent, "candidate-rejoin")
        for node in self.nodes:
            self.persist(node)
        cut = time.monotonic()
        docker("kill", *(self.containers[node] for node in self.nodes))
        if any(self.holds_vip(node) for node in self.nodes) or self.probe() is not None:
            raise RuntimeError("VIP still served after stopping both candidate nodes")
        for node in self.nodes:
            self.remove_node(node, "before-rollback")
            self.create_node(node, self.old, rollback=True)
            self.restore_config(node, archives[node])
        docker("start", *(self.containers[node] for node in self.nodes))
        rolled_back = wait_for("rollback legacy pair", self.pair_master)
        for node in self.nodes:
            if self.node_identity(node, self.old) not in old_checksums:
                raise RuntimeError("rollback binary differs from the original release")
            wait_for("pre-upgrade snapshot restored by legacy binary", lambda: self.has_rule(node))
        wait_for("single VIP after rollback", lambda: self.sole_owner(rolled_back))
        self.stable_service()
        self.record("maintenance-rollback", owner=rolled_back, stable_http_confirmed_s=time.monotonic() - cut)

    def close(self):
        errors = []
        for node, container in list(self.containers.items()):
            try:
                if node in self.nodes:
                    self.remove_node(node, "final")
                else:
                    docker("rm", "-fv", container)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        for kind, resources in (("network", self.networks), ("volume", self.volumes)):
            for target in resources.values():
                try:
                    docker(kind, "rm", target)
                except (OSError, subprocess.SubprocessError) as exc:
                    errors.append(str(exc))
        self.record("cleanup", errors=errors)
        self.log.close()
        if errors:
            raise RuntimeError(f"fixture cleanup failed: {errors}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
    pinned = Path(__file__).with_name("old-image.txt").read_text().strip()
    trial = Trial(args.out, os.environ.get("HA_L2_OLD_IMAGE") or pinned,
                  os.environ["LOXILB_DOCKER_IMAGE"],
                  os.environ.get("HA_L2_BACKEND_IMAGE", "ghcr.io/loxilb-io/reflect-echo:latest"))
    try:
        trial.execute()
        trial.record("PASS")
    finally:
        trial.close()


if __name__ == "__main__":
    main()
