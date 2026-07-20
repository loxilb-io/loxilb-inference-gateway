# Log rotation & disk-usage protection

> Motivation: every log file the gateway wrote previously grew **unbounded**
> (with `--loglevel debug` as the default), which starves the disk on any long-lived
> production deployment.

## What writes logs, and how each is rotated now

| Producer | File(s) | Rotation mechanism |
|---|---|---|
| `tk.LogIt` (loxilib classic logger) | `/var/log/loxilb<HOSTNAME>.log` | in-process `pkg/logrotate.Writer` — loxilib opens a plain append file, so all level writers are re-pointed at the rotating writer at startup (`pkg/loxinet/loxinet.go`) |
| eBPF data-plane C library | `/var/log/loxilbdp.log` | copy-truncate sweeper (`logrotate.StartSweeper`, 1-min interval) — the C side holds its own `FILE*` for the process lifetime, so the file is copied to a backup and truncated in place; the C writer keeps appending unaffected (`O_APPEND` semantics). Lines written in the copy→truncate window are lost — the standard copytruncate trade-off |
| `pkg/loxilog` structured logs (CP+DP, json+text) | `/var/log/loxilb/loxilb-audit.json.log`, `loxilb<HOST>.log`, `loxilb-dp-audit.json.log`, `loxilb-dp<HOST>.log` | `logrotate.Writer` underneath the zerolog/diode pipeline |
| loxilb-mcp bridge audit trail | `<audit_dir>/audit.jsonl` | `logrotate.Writer`, fixed policy: 20 MB / 8 backups / 90 days / gzip (long forensic window, bounded disk) |
| process stdout (`LogTTY`) | container runtime log | **not rotated by loxilb** — see "Container deployments" below |

Rotated files are named `<base>-<UTC-timestamp>.log[.gz]` in the same directory,
e.g. `loxilb75e60c4d3de0-20260719-215610.875.log.gz`.

## Tuning knobs (loxilb)

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--log-max-size` | `LOXILB_LOG_MAX_SIZE` | `50` | rotate when a file exceeds this many MB; `0` disables rotation |
| `--log-max-backups` | `LOXILB_LOG_MAX_BACKUPS` | `4` | rotated files kept per log, oldest deleted first (`0` = keep all until age limit) |
| `--log-max-age` | `LOXILB_LOG_MAX_AGE` | `28` | days to retain rotated files (`0` = keep forever) |
| `--log-no-compress` | `LOXILB_LOG_NO_COMPRESS` | off | disable gzip of rotated files |

Worst-case disk budget per log file ≈ `max-size × (1 + max-backups)` uncompressed —
with defaults, 250 MB per file *before* compression (gzip typically shrinks the
backups >10×; the live drill compressed 1 MB of debug logs to 44 KB).

## REST API interaction

- `GET /netlox/v1/log-archives` lists active + rotated logs from **both**
  `/var/log/` and `/var/log/loxilb/` (the structured-log directory was previously
  invisible to this API). Filter: name starts `loxilb`, ends `.log` / `.log.gz`.
- `GET /netlox/v1/log-archives/{filename}` downloads from either directory
  (path-traversal guarded).
- The MCP bridge exposes the same via `log_archives_list` / `log_archive_get`.

## Container deployments (important)

`tk.LogIt` also mirrors every line to **stdout** (`LogTTY=true`). When loxilb is
the container entrypoint, the container runtime captures that stream and its
growth is outside loxilb's control — configure the runtime side too:

- Docker: `--log-opt max-size=50m --log-opt max-file=4` (or daemon.json defaults).
- Kubernetes: kubelet `containerLogMaxSize` / `containerLogMaxFiles`.

In the cicd testbed loxilb is started via `docker exec`, so its stdout bypasses
the container log — production images that exec loxilb as PID 1 must set the
runtime limits above.

## Validation

- `pkg/logrotate` unit tests (`-race`): rotation trigger, gzip integrity,
  backup-count and age pruning, copytruncate sweep with a live foreign
  `O_APPEND` handle, disabled-config passthrough, concurrent writers.
- End-to-end on a running gateway (`--log-max-size=1`): 1 MB of debug logs →
  timestamped `.log.gz` backup, active file reset mid-stream with zero process
  disruption; `GET /log-archives` listed it, and the download passed `gunzip -t`.

## Known limits / follow-ups

- The copytruncate window can drop a few DP log lines per rotation.
- goBGP (`-b` mode) runs as a separate process with its own logging — not
  covered here; bound it via the container runtime limits.
- Stale per-hostname files from *previous* container identities (e.g. a
  `loxilb<oldhost>.log` baked into an image layer) are not auto-deleted; the
  age-based pruning only manages backups of the current process's logs.
