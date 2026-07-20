# pkg-smoke

Functional smoke test for the native `.deb` / `.rpm` packages. Unlike the
container-based scenarios, this one drives a loxilb instance installed
**natively on the host** from a package and managed by systemd — it
validates exactly the delta the packages introduce (file layout, unit
lifecycle, configuration persistence across restart) plus one thin
end-to-end datapath check.

Flow:

1. `config.sh` — starts `loxilb.service`, builds a small netns topology
   (one client, two HTTP endpoints), creates one TCP load-balancer rule via
   the REST API, and persists the running configuration
   (`POST /netlox/v1/config/persist` → `/etc/loxilb/snapshot.json`).
2. `validation.sh` — curls through the VIP from the client namespace
   (both endpoints must serve), checks the REST API, then runs
   `systemctl restart loxilb` and asserts the service comes back healthy
   with the persisted rule reloaded and traffic flowing again.
3. `rmconfig.sh` — tears down the topology, stops the service, and removes
   the drill's persisted snapshot.

Prerequisites: the loxilb-inference-gateway package must already be
installed (`apt install ./loxilb-inference-gateway_*.deb` or
`dnf install ./loxilb-inference-gateway-*.rpm`), and the host needs an
eBPF-capable kernel, `python3`, and `curl`. Run as a normal user with sudo
rights (the scripts call `sudo` internally):

```sh
cd cicd/pkg-smoke
./config.sh
./validation.sh
./rmconfig.sh
```

Package removal itself is exercised by the workflow
(`package-sanity.yml`), not by this scenario.
