"""Bounded LB deletion checks against an independent GoBGP peer RIB."""

from pathlib import Path
import argparse, ipaddress, json, subprocess, time, uuid

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument(
    "--image",
    required=True,
    help="Locally built gateway image containing gobgp/gobgpd and loxicmd",
)
ap.add_argument(
    "--output",
    required=True,
    type=Path,
    help="Directory for retained command/RIB/process evidence",
)
ap.add_argument(
    "--proxy-only",
    action="store_true",
    help="Control-plane diagnostic only; excludes eBPF/dataplane acceptance",
)
ap.add_argument(
    "--active-observer",
    action="store_true",
    help="Use active/active BGP instead of the default passive observer",
)
args = ap.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
case = args.output.resolve() / ("bgp-withdraw-" + uuid.uuid4().hex[:8])
case.mkdir(mode=0o700)
created = {}
network = None
records = []
image = args.image
absent_prefixes = set()
scope = (
    "proxy-only BGP control-plane diagnostic"
    if args.proxy_only
    else "eBPF-enabled BGP deletion"
)


def run(cmd, check=True, timeout=35):
    r = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    with (case / "commands.jsonl").open("a") as f:
        f.write(
            json.dumps(
                {
                    "at_ns": time.time_ns(),
                    "command": cmd,
                    "exit": r.returncode,
                    "stdout": r.stdout,
                    "stderr": r.stderr,
                }
            )
            + "\n"
        )
    if check and r.returncode:
        raise RuntimeError((cmd, r.returncode, r.stdout, r.stderr))
    return r


def inspect(name):
    return json.loads(run(["docker", "inspect", name]).stdout)[0]


def alive():
    info = inspect(gw)
    if not info["State"]["Running"]:
        raise RuntimeError(
            "gateway process stopped; withdrawal cannot PASS: "
            + json.dumps(info["State"])
        )


def api(path, body=None):
    cmd = [
        "docker",
        "exec",
        gw,
        "curl",
        "--noproxy",
        "*",
        "-sS",
        "--max-time",
        "4",
        "-w",
        "\nSTATUS:%{http_code}",
    ]
    if body is not None:
        cmd += [
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            json.dumps(body),
        ]
    r = run(cmd + ["http://127.0.0.1:11111/netlox/v1" + path], False)
    raw, _, code = r.stdout.rpartition("\nSTATUS:")
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw
    return int(code) if code.isdigit() else 0, value


def success(result):
    assert (
        result[0] == 200
        and isinstance(result[1], dict)
        and result[1].get("result") == "Success"
    ), result


def neighbor_ready():
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        alive()
        r = run(
            [
                "docker",
                "exec",
                peer,
                "/usr/sbin/gobgp",
                "-p",
                "50052",
                "neighbor",
                "-j",
            ],
            False,
        )
        if r.returncode == 0:
            v = json.loads(r.stdout)
            if any(x.get("state", {}).get("session_state") == 6 for x in v):
                return
        time.sleep(1)
    raise AssertionError("independent observer never Established")


def rib(prefix, present, tag, hold=0):
    deadline = time.monotonic() + 20
    stable = None
    index = 0
    while time.monotonic() < deadline:
        alive()
        family = "ipv4" if ipaddress.ip_network(prefix).version == 4 else "ipv6"
        raw = run(
            [
                "docker",
                "exec",
                peer,
                "/usr/sbin/gobgp",
                "-p",
                "50052",
                "global",
                "rib",
                "-a",
                family,
                "-j",
            ]
        ).stdout
        (case / (tag + "-" + str(index) + ".json")).write_text(raw)
        index += 1
        value = json.loads(raw)
        found = any(
            ipaddress.ip_network(k, strict=False) == ipaddress.ip_network(prefix)
            and paths
            for k, paths in value.items()
        )
        if bool(found) == present:
            if stable is None:
                stable = time.monotonic()
            if time.monotonic() - stable >= hold:
                if not present:
                    absent_prefixes.add(prefix)
                return
        else:
            stable = None
        time.sleep(0.5)
    raise AssertionError((tag, prefix, present, value))


def add(vip, port, proto="tcp", bgp=True, secondary=None):
    rule = {
        "serviceArguments": {
            "externalIP": vip,
            "port": port,
            "protocol": proto,
            "bgp": bgp,
        },
        "endpoints": [
            {
                "endpointIP": "127.0.0.2"
                if ipaddress.ip_address(vip).version == 4
                else "::1",
                "targetPort": 18081,
                "weight": 1,
            }
        ],
    }
    if secondary:
        rule["secondaryIPs"] = [{"secondaryIP": s} for s in secondary]
    success(api("/config/loadbalancer", rule))
    time.sleep(0.5)
    alive()


def delete(vip, port, proto="tcp", force_bgp=False):
    cmd = [
        "docker",
        "exec",
        gw,
        "/usr/local/sbin/loxicmd",
        "delete",
        "lb",
        vip,
        "--" + proto + "=" + str(port),
    ]
    if force_bgp:
        cmd += ["--bgp"]
    r = run(cmd, False)
    time.sleep(0.75)
    alive()
    assert r.returncode == 0 and "Success" in r.stdout, (
        r.returncode,
        r.stdout,
        r.stderr,
    )
    assert_rule_absent(vip, port, proto)


def assert_rule_absent(vip, port, proto="tcp"):
    status, rules = api("/config/loadbalancer/all")
    assert status == 200, (status, rules)

    def members(v):
        if isinstance(v, list):
            for x in v:
                yield from members(x)
        elif isinstance(v, dict):
            if "serviceArguments" in v:
                yield v["serviceArguments"]
            else:
                for x in v.values():
                    yield from members(x)

    assert not any(
        ipaddress.ip_address(s["externalIP"]) == ipaddress.ip_address(vip)
        and s["port"] == port
        and s["protocol"] == proto
        for s in members(rules)
    ), rules


try:
    existing = []
    for route in json.loads(run(["ip", "-j", "route", "show", "table", "all"]).stdout):
        try:
            existing.append(ipaddress.ip_network(route.get("dst", ""), strict=False))
        except ValueError:
            pass
    for n in run(["docker", "network", "ls", "-q"]).stdout.split():
        for c in (
            json.loads(run(["docker", "network", "inspect", n]).stdout)[0]
            .get("IPAM", {})
            .get("Config")
            or []
        ):
            if c.get("Subnet"):
                existing.append(ipaddress.ip_network(c["Subnet"]))
    subnet = next(
        c
        for c in ipaddress.ip_network("198.18.0.0/15").subnets(new_prefix=29)
        if not any(c.version == e.version and c.overlaps(e) for e in existing)
    )
    network = run(
        [
            "docker",
            "network",
            "create",
            "--internal",
            "--subnet",
            str(subnet),
            "--label",
            "reproduction=bgp-withdraw",
            "bgp-withdraw-" + uuid.uuid4().hex[:8],
        ]
    ).stdout.strip()
    (case / "network.json").write_text(
        run(["docker", "network", "inspect", network]).stdout
    )
    gwip = str(subnet.network_address + 2)
    peerip = str(subnet.network_address + 3)
    gw = "bgp-withdraw-gw-" + uuid.uuid4().hex[:8]
    peer = "bgp-withdraw-peer-" + uuid.uuid4().hex[:8]
    for name, asn, rid, neighbor, peer_as, ip in [
        (gw, 65122, "192.0.2.22", peerip, 65123, gwip),
        (peer, 65123, "192.0.2.23", gwip, 65122, peerip),
    ]:
        folder = case / name
        folder.mkdir()
        (folder / "config").mkdir()
        (folder / "gobgp").mkdir()
        (folder / "gobgp/gobgp_loxilb.yaml").write_text(
            f'global:\n  config:\n    as: {asn}\n    router-id: "{rid}"\n    port: 1179\nneighbors:\n  - config:\n      neighbor-address: "{neighbor}"\n      peer-as: {peer_as}\n    transport:\n      config:\n        remote-port: 1179\n        passive-mode: {str(name == peer and not args.active_observer).lower()}\n    afi-safis:\n      - config:\n          afi-safi-name: ipv4-unicast\n      - config:\n          afi-safi-name: ipv6-unicast\n'
        )
        cmd = [
            "docker",
            "create",
            "--name",
            name,
            "--label",
            "reproduction=bgp-withdraw",
            "--network",
            network,
            "--ip",
            ip,
            "-v",
            str(folder / "gobgp") + ":/etc/gobgp:ro",
        ]
        if name == gw:
            cmd += [
                "--privileged",
                "-v",
                str(folder / "config") + ":/etc/loxilb",
                "--entrypoint",
                "/bin/bash",
                image,
                "-ec",
                "ulimit -l unlimited; mkdir -p /opt/loxilb/dp; mount -t bpf bpf /opt/loxilb/dp; exec /root/loxilb-io/loxilb/loxilb -b --loglevel=debug"
                + (" --proxyonlymode" if args.proxy_only else ""),
            ]
        else:
            cmd += [
                "--entrypoint",
                "/usr/sbin/gobgpd",
                image,
                "-t",
                "yaml",
                "-f",
                "/etc/gobgp/gobgp_loxilb.yaml",
                "--api-hosts=127.0.0.1:50052",
            ]
        created[name] = run(cmd).stdout.strip()
        run(["docker", "start", name])
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        alive()
        status, v = api("/status/ready")
        if status == 200 and not v.get("boot", {}).get("degraded"):
            break
        time.sleep(1)
    else:
        raise AssertionError(("boot not ready", status, v))
    (case / "boot-ready.json").write_text(json.dumps(v, indent=2))
    neighbor_ready()
    (case / "image-inspect.json").write_text(
        run(["docker", "image", "inspect", image]).stdout
    )
    for name, cmd in [
        ("cli-help", ["/usr/local/sbin/loxicmd", "--help"]),
        ("cli-version", ["/usr/local/sbin/loxicmd", "version"]),
        (
            "artifact-hashes",
            [
                "sha256sum",
                "/usr/local/sbin/loxicmd",
                "/root/loxilb-io/loxilb/loxilb",
                "/usr/sbin/gobgp",
                "/usr/sbin/gobgpd",
            ],
        ),
        ("kernel", ["uname", "-a"]),
    ]:
        r = run(["docker", "exec", gw, *cmd], False)
        (case / (name + ".txt")).write_text(r.stdout + r.stderr)

    def sample(label, fn):
        try:
            fn()
            records.append({"case": label, "result": "PASS"})
        except BaseException as e:
            records.append({"case": label, "result": "RED", "error": repr(e)})
            raise
        finally:
            (case / "results.json").write_text(json.dumps(records, indent=2))

    def single(vip, port, proto="tcp", secondary=None):
        add(vip, port, proto, secondary=secondary)
        prefixes = [
            str(ipaddress.ip_network(s, strict=False))
            for s in [vip] + (secondary or [])
        ]
        for i, prefix in enumerate(prefixes):
            rib(prefix, True, f"{port}-initial-{i}")
        delete(vip, port, proto)
        for i, prefix in enumerate(prefixes):
            rib(prefix, False, f"{port}-withdraw-{i}", hold=2)

    def shared(vip, port, alternate=None):
        prefix = str(ipaddress.ip_network(vip, strict=False))
        add(vip, port)
        add(vip, port + 1)
        rib(prefix, True, f"{port}-shared-initial")
        delete(alternate or vip, port)
        rib(prefix, True, f"{port}-retained", hold=2)
        delete(vip, port + 1)
        rib(prefix, False, f"{port}-last-withdraw", hold=2)

    def update_rule(vip, port, bgp=True, oper=0, target=18082, rejected=False):
        payload = {
            "serviceArguments": {
                "externalIP": vip,
                "port": port,
                "protocol": "tcp",
                "oper": oper,
            },
            "endpoints": [
                {"endpointIP": "127.0.0.2", "targetPort": target, "weight": 1}
            ],
        }
        if bgp is not None:
            payload["serviceArguments"]["bgp"] = bgp
        result = api("/config/loadbalancer", payload)
        if rejected:
            assert result[0] == 400 and "bgp flag cannot be changed" in str(
                result[1]
            ), result
        else:
            success(result)
        alive()

    def updated_owner(flag):
        vip = "192.0.2.120" if flag else "192.0.2.121"
        port = 21545 if flag else 21546
        add(vip, port)
        rib(vip + "/32", True, f"{port}-update-initial")
        update_rule(vip, port, bgp=True if flag else False, rejected=not flag)
        rib(vip + "/32", True, f"{port}-update-retained")
        delete(vip, port)
        rib(vip + "/32", False, f"{port}-update-final-withdraw", hold=2)

    def updated_nonowner():
        vip = "192.0.2.122"
        port = 21547
        add(vip, port, bgp=False)
        rib(vip + "/32", False, "update-nonowner-initial")
        update_rule(vip, port, bgp=True, rejected=True)
        rib(vip + "/32", False, "update-nonowner-stored-intent", hold=2)
        delete(vip, port)
        rib(vip + "/32", False, "update-nonowner-deleted")

    def detach_owner():
        vip = "192.0.2.123"
        port = 21548
        add(vip, port)
        rib(vip + "/32", True, "detach-initial")
        update_rule(vip, port, oper=2, target=18081)
        assert_rule_absent(vip, port)
        rib(vip + "/32", False, "detach-last-owner-withdraw", hold=2)

    def shared_secondary(vip1, vip2, secondary, port):
        prefixes = [
            str(ipaddress.ip_network(ip, strict=False))
            for ip in [vip1, vip2, secondary]
        ]
        add(vip1, port, "sctp", secondary=[secondary])
        add(vip2, port + 1, "sctp", secondary=[secondary])
        for i, prefix in enumerate(prefixes):
            rib(prefix, True, f"{port}-shared-secondary-initial-{i}")
        delete(vip1, port, "sctp")
        rib(prefixes[0], False, f"{port}-first-primary-withdraw")
        rib(prefixes[2], True, f"{port}-secondary-retained", hold=2)
        delete(vip2, port + 1, "sctp")
        for i, prefix in enumerate(prefixes[1:]):
            rib(prefix, False, f"{port}-last-secondary-withdraw-{i}", hold=2)

    sample("ipv4-single", lambda: single("192.0.2.101", 21525))
    sample("ipv4-shared", lambda: shared("192.0.2.102", 21526))

    def mixed():
        vip = "192.0.2.103"
        add(vip, 21528)
        add(vip, 21529, bgp=False)
        rib(vip + "/32", True, "mixed-initial")
        delete(vip, 21529, force_bgp=True)
        rib(vip + "/32", True, "nonowner-retains", hold=2)
        delete(vip, 21528)
        rib(vip + "/32", False, "owner-withdraw", hold=2)

    sample("delete-nonowner-cannot-withdraw", mixed)
    sample(
        "ipv4-sctp-secondary",
        lambda: single("192.0.2.104", 21530, "sctp", ["192.0.2.105"]),
    )
    sample("ipv6-single", lambda: single("2001:db8::101", 21531))
    sample("ipv6-shared", lambda: shared("2001:db8::102", 21532))
    sample(
        "ipv6-sctp-secondary",
        lambda: single("2001:db8::104", 21534, "sctp", ["2001:db8::105"]),
    )
    sample(
        "ipv6-alternate-delete-shared",
        lambda: shared(
            "2001:0db8:0000:0000:0000:0000:0000:0106", 21535, "2001:db8::106"
        ),
    )
    sample("ipv4-updated-owner-delete", lambda: updated_owner(True))
    sample("ipv4-update-disable-bgp-rejected", lambda: updated_owner(False))
    sample("ipv4-update-enable-bgp-rejected", updated_nonowner)
    sample("ipv4-detach-last-endpoint", detach_owner)
    sample(
        "ipv4-shared-secondary",
        lambda: shared_secondary("192.0.2.124", "192.0.2.125", "192.0.2.126", 21550),
    )
    sample(
        "ipv6-shared-secondary",
        lambda: shared_secondary(
            "2001:db8::124", "2001:db8::125", "2001:db8::126", 21552
        ),
    )

    def no_resurrection(tag):
        rib("192.0.2.110/32", True, tag + "-canary-live")
        for prefix in sorted(absent_prefixes):
            rib(
                prefix,
                False,
                tag + "-absent-" + prefix.replace(":", "-").replace("/", "_"),
                hold=1,
            )

    def reconnect():
        add("192.0.2.110", 21540)
        rib("192.0.2.110/32", True, "reconnect-canary-initial")
        run(["docker", "restart", peer])
        neighbor_ready()
        no_resurrection("observer-reconnect")

    sample("observer-reconnect-no-resurrection", reconnect)

    def speaker_reconnect():
        find_daemon = 'for d in /proc/[0-9]*; do if read -r name < "$d/comm" 2>/dev/null && [ "$name" = gobgpd ]; then printf "%s\\n" "${d##*/}"; fi; done'
        pids = run(
            ["docker", "exec", gw, "/bin/bash", "-ec", find_daemon]
        ).stdout.split()
        assert len(pids) == 1 and pids[0].isdigit(), pids
        run(["docker", "exec", gw, "/bin/kill", "-TERM", pids[0]])
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            alive()
            current = run(
                ["docker", "exec", gw, "/bin/bash", "-ec", find_daemon]
            ).stdout.split()
            if len(current) == 1 and current != pids:
                break
            time.sleep(1)
        else:
            raise AssertionError("gateway did not respawn its BGP daemon")
        neighbor_ready()
        no_resurrection("speaker-reconnect")

    sample("speaker-reconnect-no-resurrection", speaker_reconnect)

finally:
    for name, cid in reversed(list(created.items())):
        info = inspect(name)
        assert (
            info["Id"] == cid
            and info["Config"]["Labels"]["reproduction"] == "bgp-withdraw"
        )
        folder = case / name
        (folder / "final-inspect.json").write_text(json.dumps(info, indent=2))
        log = run(["docker", "logs", "--timestamps", name], False)
        (folder / "process.log").write_text(log.stdout + log.stderr)
        if info["State"]["Running"]:
            run(["docker", "stop", "--time", "10", name], False)
        run(["docker", "rm", name])
    if network:
        run(["docker", "network", "rm", network])
    (case / "cleanup-complete.txt").write_text(
        "Removed exact owned containers and network only.\n"
    )
    print(
        json.dumps(
            {
                "evidence": str(case),
                "scope": scope,
                "observer_mode": "active" if args.active_observer else "passive",
                "results": records,
            }
        ),
        flush=True,
    )
