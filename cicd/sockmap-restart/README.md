# sockmap restart check

A gateway started with `--sockmapsupport` must come back after a restart of
the **same** container (`docker restart`, or stop and start), not only in a
new container from the same image.

The two differ in one way: a restarted container keeps its writable layer but
gets a fresh mount namespace. The cgroup2 hierarchy the sockmap bootstrap
joins (`/opt/loxilb/cgroup`) is a mount, so it is gone, while the directory
the previous boot created is still there. A boot that reads the directory as
the mount skips the mount and aborts inside the data path init:

```
(cgroup.c:59: errno: No such file or directory) Opening Cgroup Procs: /opt/loxilb/cgroup/cgroup.procs
sockmap: cgroup join failed for ''
ebpf: fatal: llb_setup_kern_sockmap failed during init - aborting
```

The fix mounts by mount state on every boot and refuses to start, with one
line naming the cause, when the hierarchy is still not there (see
[`docs/sockmap-acceleration.md`](../../docs/sockmap-acceleration.md),
*Requirements*). `--localsockpolicy` uses the same bootstrap.

## What `validation.sh` does

1. `docker run --privileged` the image with `--sockmapsupport`, the daemon as
   the container's PID 1. The shared testbed in `cicd/sockmap-fullproxy/`
   starts the daemon under `--entrypoint /bin/bash`, which does **not**
   reproduce the defect: `docker restart` must recreate the mount namespace
   of the daemon's own container.
2. Wait for `GET /netlox/v1/status/ready` to answer 200 (90 s).
3. Create one load-balancer rule and read it back.
4. `docker restart` the container twice. After each restart: ready 200 within
   90 s, and the rule reads back (auto-persist writes it through to the
   snapshot before the restart).

An exited container fails the step at once, with its exit code and the
`cgroup` / `fatal` lines of its log in `artifacts/summary.txt`; the full log of
the failing boot is kept next to it.

```bash
LOXILB_IMAGE=ghcr.io/loxilb-io/loxilb-inference-gateway:main ./validation.sh
```

| variable | default | meaning |
|---|---|---|
| `LOXILB_IMAGE` | `ghcr.io/loxilb-io/loxilb-inference-gateway:main` | image under test |
| `RESTARTS` | `2` | restarts driven |
| `READY_TIMEOUT` | `90` | seconds allowed for ready after each boot |
| `OUT_DIR` | `./artifacts` | evidence directory |

It runs in CI as the `sockmap-restart-sanity` job of
`.github/workflows/ai-gateway-sanity.yml`. The host needs Docker with
privileged containers, a cgroup v2 host and a kernel of 5.7 or later.
