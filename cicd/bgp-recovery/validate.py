"""API BGP recovery with an independent peer RIB and external VIP requests."""
import argparse
import concurrent.futures
import ipaddress
import json
from pathlib import Path
import subprocess
import time
import uuid
import shutil
import re

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', required=True)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--yaml-preservation', action='store_true', help='Preserve unadopted YAML-only timers through auto-persist/crash/restart, then adopt explicitly')
p.add_argument('--expect-loss', action='store_true', help='Require the unfixed completed-state failure')
p.add_argument('--keep-on-failure', action='store_true', help='Retain labeled test resources for diagnosis')
p.add_argument('--role-managed', action='store_true')
p.add_argument('--static-baseline', action='store_true', help='Adopt YAML, then delete its peer through the API')
a = p.parse_args()
if a.yaml_preservation:
    a.static_baseline = True
go_binary = shutil.which("go") or "/usr/local/go/bin/go"
out = a.output.resolve() / ('bgp-recovery-' + uuid.uuid4().hex[:8])
out.mkdir(parents=True, mode=0o700)
created = {}
network = None
started = time.monotonic()
results = []
deleted_items = False
label = 'reproduction=bgp-recovery'


def run(cmd, check=True, timeout=45):
    r = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    with (out / 'commands.jsonl').open('a') as f:
        f.write(json.dumps(dict(at=time.time(), command=cmd, exit=r.returncode, stdout=r.stdout, stderr=r.stderr)) + '\n')
    if check and r.returncode:
        raise AssertionError((cmd, r.returncode, r.stdout[-2000:], r.stderr[-2000:]))
    return r


def api(path, body=None, method=None):
    cmd = ['docker', 'exec', gw, 'curl', '--noproxy', '*', '-sS', '--max-time', '40', '-w', '\nSTATUS:%{http_code}']
    if body is not None:
        cmd += ['-H', 'Content-Type: application/json', '--data-binary', json.dumps(body)]
    if method:
        cmd += ['-X', method]
    r = run(cmd + ['http://127.0.0.1:11111/netlox/v1' + path], False)
    raw, _, code = r.stdout.rpartition('\nSTATUS:')
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw
    return int(code) if code.isdigit() else 0, value


def success(r):
    assert r[0] == 200 and r[1].get('result') == 'Success', r


def wait(fn, seconds=85):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
            if last:
                return last
        except (AssertionError, ValueError) as e:
            last = repr(e)
        time.sleep(.7)
    raise AssertionError(('wait timeout', last))


def actual(container, *args):
    r = run(['docker', 'exec', container, '/usr/sbin/gobgp', '-p', '50052', *args, '-j'], False)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]


def established():
    v = actual(peer, 'neighbor')
    return v and any(n.get('state', {}).get('session_state') == 6 for n in v)


def rib(present=True):
    v = actual(peer, 'global', 'rib')
    return v is not None and bool(v.get(vip + '/32')) == present


def save_state(tag):
    for name, container in [('gw', gw), ('peer', peer)]:
        for key, cmd in [('global', ('global',)), ('neighbors', ('neighbor',)), ('rib', ('global', 'rib')), ('policies', ('policy',)), ('assignments', ('global', 'policy')), ('prefix-sets', ('policy', 'prefix'))]:
            (out / f'{tag}-{name}-{key}.json').write_text(json.dumps(actual(container, *cmd), indent=2))
    (out / f'{tag}-status.json').write_text(json.dumps(api('/status/ready'), indent=2))


def receipt(tag):
    # GoBGP is a RIB observer. Explicitly install its observed next hop in
    # this isolated client's FIB; do not claim automatic FIB integration.
    assert rib(), 'no independent BGP route before external traffic'
    run(['docker', 'exec', peer, 'ip', 'route', 'replace', vip + '/32', 'via', gwip])
    token = tag + '-' + uuid.uuid4().hex
    r = run(['docker', 'exec', peer, 'curl', '--noproxy', '*', '-sS', '--max-time', '6', f'http://{vip}:18080/{token}'])
    assert token in r.stdout, r.stdout
    logs = run(['docker', 'logs', backend]).stdout
    assert token in logs, ('backend receipt missing', token, logs)
    (out / (tag + '-receipt.txt')).write_text(r.stdout)


def checkpoint(name, fn):
    fn()
    results.append(dict(case=name, result='PASS'))
    (out / 'results.json').write_text(json.dumps(results, indent=2))
    print(name + ': PASS', flush=True)


def crash():
    before = run(['docker', 'exec', gw, 'pidof', 'gobgpd']).stdout.strip()
    run(['docker', 'exec', gw, 'pkill', '-KILL', '-x', 'gobgpd'])
    wait(lambda: (r := run(['docker', 'exec', gw, 'pidof', 'gobgpd'], False)).returncode == 0 and r.stdout.strip() != before)


def recovered(tag):
    wait(lambda: actual(gw, 'global') and actual(gw, 'global').get('asn') == 65122)
    global_state = actual(gw, 'global')
    assert global_state['router_id'] == '192.0.2.22' and global_state['listen_port'] == 1179, global_state
    wait(lambda: (neighbors := actual(gw, 'neighbor')) and len(neighbors) == 1 and neighbors[0]['conf']['neighbor_address'] == peerip)
    wait(established)
    wait(rib)
    observed = actual(peer, 'global', 'rib')[vip + '/32']
    assert any(65122 in segment.get('asns', []) for path in observed for attr in path['attrs'] if attr.get('type') == 2 for segment in attr.get('as_paths', [])), observed
    assignments = actual(gw, 'global', 'policy')
    assert any(x.get('direction') == 2 and x.get('default_action') == 2 and any(p['name'] == 'export-canary' for p in x.get('policies', [])) for x in assignments), assignments
    assert any(x.get('type') == 4 and x.get('metric') == 77 for path in observed for x in path['attrs']), observed
    ready = wait(lambda: (r := api('/status/ready'))[0] == 200)
    assert ready
    policies = actual(gw, 'policy')
    assert policies is not None and 'export-canary' in json.dumps(policies), policies
    if deleted_items:
        assert 'delete-canary' not in json.dumps(actual(gw, 'policy')), 'deleted policy resurrected'
        assert 'delete-canary' not in json.dumps(actual(gw, 'global', 'policy')), 'deleted assignment resurrected'
        assert 'delete-set' not in json.dumps(actual(gw, 'policy', 'prefix')), 'deleted set resurrected'
    save_state(tag)
    receipt(tag)


try:
    # Avoid overlapping any host route or pre-existing Docker network.
    existing = []
    for route in json.loads(run(['ip', '-j', 'route', 'show', 'table', 'all']).stdout):
        try:
            existing.append(ipaddress.ip_network(route.get('dst', ''), strict=False))
        except ValueError:
            pass
    for nid in run(['docker', 'network', 'ls', '-q']).stdout.split():
        for cfg in json.loads(run(['docker', 'network', 'inspect', nid]).stdout)[0].get('IPAM', {}).get('Config') or []:
            if cfg.get('Subnet'):
                existing.append(ipaddress.ip_network(cfg['Subnet']))
    subnet = next(n for n in ipaddress.ip_network('198.18.0.0/15').subnets(new_prefix=29) if not any(n.version == x.version and n.overlaps(x) for x in existing))
    name = 'bgp-recovery-' + uuid.uuid4().hex[:8]
    network = run(['docker', 'network', 'create', '--internal', '--subnet', str(subnet), '--label', label, name]).stdout.strip()
    gwip, peerip, backendip = [str(subnet.network_address + i) for i in (2, 3, 4)]
    vip = '203.0.113.149'
    (out / 'image-inspect.json').write_text(run(['docker', 'image', 'inspect', a.image]).stdout)
    (out / 'options.json').write_text(json.dumps(vars(a), default=str, indent=2))
    (out / 'config').mkdir()
    (out / 'gobgp').mkdir()
    observer = out / 'observer.yaml'
    observer.write_text(f'global:\n  config:\n    as: 65123\n    router-id: "192.0.2.23"\n    port: 1179\nneighbors:\n  - config:\n      neighbor-address: "{gwip}"\n      peer-as: 65122\n    transport:\n      config:\n        remote-port: 1179\n        passive-mode: true\n')
    if a.static_baseline:
        (out / 'gobgp/gobgp_loxilb.yaml').write_text(f'global:\n  config:\n    as: 65122\n    router-id: "192.0.2.22"\n    port: 1179\nneighbors:\n  - config:\n      neighbor-address: "{peerip}"\n      peer-as: 65123\n    transport:\n      config:\n        remote-port: 1179\n')
    if a.yaml_preservation:
        yaml_file = out / 'gobgp/gobgp_loxilb.yaml'
        yaml_file.write_text(yaml_file.read_text() + '    timers:\n      config:\n        hold-time: 27\n        keepalive-interval: 9\n')
    source = out / 'backend.go'
    source.write_text('package main\nimport("fmt";"net/http")\nfunc main(){http.HandleFunc("/",func(w http.ResponseWriter,r *http.Request){fmt.Println(r.URL.Path);fmt.Fprintln(w,r.URL.Path)});panic(http.ListenAndServe(":18081",nil))}\n')
    run([go_binary, 'build', '-o', str(out / 'backend'), str(source)])
    for role, ip, flags, command in [
        ('backend', backendip, ['--cap-add', 'NET_ADMIN', '-v', str(out / 'backend') + ':/backend:ro'], ['/backend']),
        ('peer', peerip, ['--cap-add', 'NET_ADMIN', '-v', str(observer) + ':/peer.yaml:ro'], ['/usr/sbin/gobgpd', '-f', '/peer.yaml', '--api-hosts=127.0.0.1:50052']),
        ('gw', gwip, ['--privileged', '-v', str(out / 'config') + ':/etc/loxilb', '-v', str(out / 'gobgp') + ':/etc/gobgp:ro'], ['/bin/bash', '-ec', 'ulimit -l unlimited; mkdir -p /opt/loxilb/dp; mount -t bpf bpf /opt/loxilb/dp; exec /root/loxilb-io/loxilb/loxilb -b -p --loglevel=debug']),
    ]:
        cid = run(['docker', 'create', '--name', name + '-' + role, '--label', label, '--network', network, '--ip', ip, *flags, '--entrypoint', command[0], a.image, *command[1:]]).stdout.strip()
        created[role] = cid
        run(['docker', 'start', cid])
    gw, peer, backend = [created[k] for k in ('gw', 'peer', 'backend')]
    run(['docker', 'exec', backend, 'ip', 'route', 'replace', vip + '/32', 'via', gwip])
    (out / 'artifact-hashes.txt').write_text(run(['docker', 'exec', gw, 'sha256sum', '/root/loxilb-io/loxilb/loxilb', '/usr/sbin/gobgp', '/usr/sbin/gobgpd']).stdout)
    (out / 'kernel.txt').write_text(run(['docker', 'exec', gw, 'uname', '-a']).stdout)
    (out / 'network.json').write_text(run(['docker', 'network', 'inspect', network]).stdout)
    wait(lambda: api('/status/ready')[0] == 200)
    wait(lambda: actual(gw, 'global') is not None)
    if a.yaml_preservation:
        extra_yaml_peer = str(subnet.network_address + 5)
        yaml_extra_added = False
        def saved_marker(expected):
            r = run(['docker', 'exec', gw, 'cat', '/etc/loxilb/snapshot.json'], False)
            if r.returncode != 0:
                return False
            return json.loads(r.stdout).get('bgp_api_adopted', False) == expected

        def yaml_healthy(tag, retained):
            wait(lambda: actual(gw, 'global') and actual(gw, 'global').get('asn') == 65122)
            wait(established)
            wait(rib)
            wait(lambda: api('/status/ready')[0] == 200)
            peers = actual(gw, 'neighbor')
            primary = next(n for n in peers if n['conf']['neighbor_address'] == peerip)
            hold = primary['timers']['config']['hold_time']
            if yaml_extra_added:
                assert any(n['conf']['neighbor_address'] == extra_yaml_peer for n in peers), peers
            assert (hold == 27) == retained, peers
            save_state(tag)
            receipt(tag)

        # No BGP REST call precedes this unrelated mutation. Auto-persist is on.
        success(api('/config/loadbalancer', dict(serviceArguments=dict(externalIP=vip, port=18080, protocol='tcp', mode=2, bgp=True), endpoints=[dict(endpointIP=backendip, targetPort=18081, weight=1)])))
        time.sleep(7)
        wait(lambda: saved_marker(False))
        checkpoint('yaml-unrelated-auto-persist-not-adoption', lambda: yaml_healthy('yaml-initial', True))
        crash()
        checkpoint('yaml-timer-survives-daemon-crash', lambda: yaml_healthy('yaml-crash', True))
        # The persisted BGP projection still has one peer. Edit the mounted
        # YAML after that persist, without any BGP API mutation/adoption.
        yaml_file.write_text(yaml_file.read_text() + f'  - config:\n      neighbor-address: "{extra_yaml_peer}"\n      peer-as: 65125\n    transport:\n      config:\n        remote-port: 1179\n')
        disk = json.loads(run(['docker', 'exec', gw, 'cat', '/etc/loxilb/snapshot.json']).stdout)
        assert extra_yaml_peer not in json.dumps(disk['domains']['bgp']), 'test snapshot already contains YAML edit'
        yaml_extra_added = True
        run(['docker', 'restart', '-t', '15', gw], timeout=55)
        checkpoint('yaml-edits-and-timer-survive-unmarked-snapshot-boot', lambda: yaml_healthy('yaml-container', True))
        assert saved_marker(False), 'boot or persist silently adopted YAML'
        success(api('/config/bgp/global', dict(localAs=65122, routerId='192.0.2.22', listenPort=1179)))
        wait(lambda: saved_marker(True))
        def adoption_warning():
            code, metrics = api('/metrics')
            match = re.search(r'^loxilb_bgp_adoption_dropped_attributes ([-+.0-9eE]+)$', metrics, re.M)
            assert code == 200 and match and float(match.group(1)) >= 2, metrics[-1000:]
            logs = run(['docker', 'logs', gw]).stdout
            assert 'BGP adoption peer=' + peerip in logs and 'timers.hold_time' in logs and 'timers.keepalive_interval' in logs, logs[-1000:]
            (out / 'adoption-metrics.txt').write_text(metrics)
        checkpoint('yaml-adoption-warns-and-exposes-dropped-attributes', adoption_warning)
        crash()
        checkpoint('explicit-bgp-api-adopts-supported-projection', lambda: yaml_healthy('yaml-adopted', False))
        assert saved_marker(True)
        run(['docker', 'restart', '-t', '15', gw], timeout=55)
        checkpoint('yaml-adoption-marker-survives-container-restart', lambda: yaml_healthy('yaml-adopted-container', False))
        assert saved_marker(True)
    else:
        success(api('/config/bgp/global', dict(localAs=65122, routerId='192.0.2.22', listenPort=1179)))
        if not a.static_baseline:
            success(api('/config/bgp/neigh', dict(ipAddress=peerip, remoteAs=65123, remotePort=1179)))
        # One assigned policy changes the externally observed MED. A second
        # definition/set is later deleted to detect stale intent resurrection.
        for policy in ['export-canary', 'delete-canary']:
            success(api('/config/bgp/policy/definitions', dict(name=policy, statements=[dict(name=policy + '-stmt', conditions={}, actions=dict(routeDisposition='accept-route', bgpActions=dict(setMed='77')))])))
        success(api('/config/bgp/policy/definedsets/prefix', dict(name='delete-set', prefixList=[dict(ipPrefix='192.0.2.0/24', masklengthRange='24..32')])))
        success(api('/config/bgp/policy/apply', dict(ipAddress='global', policyType='export', policies=['export-canary'], routeAction='reject')))
        success(api('/config/bgp/policy/apply', dict(ipAddress='global', policyType='import', policies=['delete-canary'], routeAction='accept')))
        if a.role_managed:
            success(api('/config/cistate', dict(instance='llb-inst0', state='NOT_DEFINED', vip='0.0.0.0')))
        success(api('/config/loadbalancer', dict(serviceArguments=dict(externalIP=vip, port=18080, protocol='tcp', mode=2, bgp=True), endpoints=[dict(endpointIP=backendip, targetPort=18081, weight=1)])))
        if a.role_managed:
            wait(established)
            assert rib(False), 'role gate leaked VIP before MASTER'
            success(api('/config/cistate', dict(instance='llb-inst0', state='MASTER', vip='0.0.0.0')))
        time.sleep(7)  # allow native interface discovery/attachment to settle
        checkpoint('initial-api-config-rib-and-traffic', lambda: recovered('initial'))
        def out_of_band_capture():
            extra_ip = str(subnet.network_address + 5)
            run(['docker', 'exec', gw, '/usr/sbin/gobgp', '-p', '50052', 'neighbor', 'add', extra_ip, 'as', '65125'])
            response = api('/config/persist', {}, 'POST')
            assert response[0] == 200, response
            disk = json.loads(run(['docker', 'exec', gw, 'cat', '/etc/loxilb/snapshot.json']).stdout)
            assert any(extra_ip in n.values() for n in disk['domains']['bgp']['neighbors']), disk['domains']['bgp']
            run(['docker', 'exec', gw, '/usr/sbin/gobgp', '-p', '50052', 'neighbor', 'del', extra_ip])
            assert api('/config/persist', {}, 'POST')[0] == 200
        checkpoint('healthy-out-of-band-neighbor-persists', out_of_band_capture)
        persisted = api('/config/persist', {}, 'POST')
        assert persisted[0] == 200, persisted
        crash()
        if a.expect_loss:
            time.sleep(12)
            save_state('completed-crash-loss')
            assert actual(gw, 'global') == {} and actual(gw, 'neighbor') == [], 'expected baseline loss missing'
            assert rib(False), 'baseline external route unexpectedly survived'
            checkpoint('reproduced-completed-state-loss', lambda: None)
        else:
            checkpoint('completed-state-crash', lambda: recovered('crash-1'))
            crash()
            checkpoint('repeated-daemon-crash', lambda: recovered('crash-2'))
            if a.role_managed:
                success(api('/config/cistate', dict(instance='llb-inst0', state='NOT_DEFINED', vip='0.0.0.0')))
                crash()
                wait(lambda: api('/status/ready')[0] == 200)
                wait(lambda: rib(False))
                time.sleep(2)
                assert rib(False), 'replacement advertised before a valid HA role'
                success(api('/config/cistate', dict(instance='llb-inst0', state='MASTER', vip='0.0.0.0')))
                checkpoint('daemon-recovery-preserves-role-barrier', lambda: recovered('role-recovery'))
            success(api('/config/bgp/policy/apply', dict(ipAddress='global', policyType='import', policies=['delete-canary'], routeAction='accept'), 'DELETE'))
            success(api('/config/bgp/policy/definitions/delete-canary', method='DELETE'))
            success(api('/config/bgp/policy/definedsets/prefix/delete-set', method='DELETE'))
            success(api('/config/bgp/neigh/' + peerip + '?remoteAs=65123', method='DELETE'))
            deleted_items = True
            # Crash immediately after the successful delete, before the normal
            # debounce has to publish it, while explicit persist races recovery.
            with concurrent.futures.ThreadPoolExecutor() as pool:
                persist = pool.submit(api, '/config/persist', {}, 'POST')
                crash()
                assert persist.result()[0] == 200
            wait(lambda: actual(gw, 'global') and actual(gw, 'global').get('asn') == 65122)
            wait(lambda: api('/status/ready')[0] == 200)
            assert actual(gw, 'neighbor') == [], 'deleted neighbor resurrected'
            assert 'delete-canary' not in json.dumps(actual(gw, 'policy')), 'deleted policy resurrected'
            assert 'delete-canary' not in json.dumps(actual(gw, 'global', 'policy')), 'deleted assignment resurrected'
            assert 'delete-set' not in json.dumps(actual(gw, 'policy', 'prefix')), 'deleted set resurrected'
            assert rib(False), 'deleted neighbor route survived'
            save_state('deleted-restart')
            checkpoint('delete-persist-crash-no-resurrection', lambda: None)
            status, replacement = api('/config/snapshot')
            assert status == 200, (status, replacement)
            success(api('/config/bgp/neigh', dict(ipAddress=peerip, remoteAs=65123, remotePort=1179)))
            checkpoint('current-neighbor-readded', lambda: recovered('readded'))
            crash()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                replaced = pool.submit(api, '/config/restore?mode=commit', replacement)
                persisted = pool.submit(api, '/config/persist', {}, 'POST')
                rr, pr = replaced.result(), persisted.result()
            assert pr[0] in (200, 409), pr
            if rr[0] == 409:
                rr = api('/config/restore?mode=commit', replacement)
            assert rr[0] == 200 and rr[1].get('result') == 'ok', rr
            wait(lambda: actual(gw, 'neighbor') == [])
            wait(lambda: rib(False))
            time.sleep(4)
            assert actual(gw, 'neighbor') == [], 'obsolete retry overrode replacement'
            checkpoint('full-replacement-races-recovery-and-persist', lambda: None)
            success(api('/config/bgp/neigh', dict(ipAddress=peerip, remoteAs=65123, remotePort=1179)))
            recovered('replacement-readded')
            assert api('/config/persist', {}, 'POST')[0] == 200
            run(['docker', 'restart', '-t', '15', gw], timeout=55)
            checkpoint('durable-container-restart', lambda: recovered('container'))
            assert 'delete-canary' not in json.dumps(actual(gw, 'policy'))
            # Freeze the initial daemon before saved BGP boot replay completes,
            # observe the real pending group, then kill only that stopped daemon.
            run(['docker', 'stop', '-t', '15', gw], timeout=45)
            run(['docker', 'start', gw])
            run(['docker', 'exec', gw, 'bash', '-ec', 'for n in {1..400}; do p=$(pidof gobgpd || true); if [ -n "$p" ]; then kill -STOP $p; exit 0; fi; sleep .02; done; exit 1'])
            pending = wait(lambda: (r := api('/status/ready'))[0] == 503 and 'bgp_domain_pending' in json.dumps(r), seconds=35)
            assert pending
            run(['docker', 'exec', gw, 'pkill', '-KILL', '-x', 'gobgpd'])
            checkpoint('pending-state-daemon-crash', lambda: recovered('pending'))
except BaseException as e:
    results.append(dict(case='failure', result='FAIL', error=repr(e)))
    raise
finally:
    for role, cid in created.items():
        r = run(['docker', 'logs', '--timestamps', cid], False)
        (out / (role + '-logs.txt')).write_text(r.stdout + r.stderr)
        info = json.loads(run(['docker', 'inspect', cid]).stdout)[0]
        (out / (role + '-inspect.json')).write_text(json.dumps(info, indent=2))
        assert info['Id'] == cid and info['Config']['Labels'].get('reproduction') == 'bgp-recovery'
        if not (a.keep_on_failure and any(r['result'] == 'FAIL' for r in results)):
            run(['docker', 'rm', '-f', cid])
    if network and not (a.keep_on_failure and any(r['result'] == 'FAIL' for r in results)):
        run(['docker', 'network', 'rm', network])
    (out / 'results.json').write_text(json.dumps(results, indent=2))
    (out / 'runtime-seconds.txt').write_text(str(time.monotonic() - started))
    print(out, flush=True)
