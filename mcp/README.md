# loxilb-mcp

Standalone **MCP (Model Context Protocol) bridge** for loxilb-inference-gateway.
It lets MCP clients — **Claude Desktop**, **Claude Code**, MCP Inspector, or any
custom agent — observe, manage, and diagnose loxilb through guarded tools
instead of raw REST.

- Single **static binary**, no runtime dependencies (cgo-free).
- Runs on **macOS, Windows, and Linux** (Ubuntu, Rocky, Alma, Debian, Alpine, …)
  on **amd64 and arm64** — the same Linux binary works on every distro because
  it is statically linked (no glibc dependency).
- Talks to the loxilb REST API (`:11111 /netlox/v1`), optionally Prometheus/Alertmanager.

For the full operations reference (roles, tools, confirm-token flow, security
posture) see [`../docs/MCP-OPERATIONS.md`](../docs/MCP-OPERATIONS.md).

---

## Install

Pick one. `X.Y.Z` = the release version; the download assets are named
`loxilb-mcp_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) and are attached to
each [GitHub Release](https://github.com/loxilb-io/loxilb-inference-gateway/releases)
under the `mcp/vX.Y.Z` tags, alongside `SHA256SUMS`.

To verify a download, fetch `SHA256SUMS` into the same directory and run:
```sh
shasum -a 256 -c SHA256SUMS --ignore-missing     # macOS/Linux
# → loxilb-mcp_X.Y.Z_darwin_arm64.tar.gz: OK
```

### macOS

**Homebrew (recommended):**
```sh
brew install --cask loxilb-io/tap/loxilb-mcp
loxilb-mcp --version
```
The tap ships a cask, so it is macOS-only; on Linux use the tarball, the
container image, or `go install`.

**Or download the binary** (Apple Silicon = `arm64`, Intel = `amd64`):
```sh
curl -L -o loxilb-mcp.tar.gz \
  https://github.com/loxilb-io/loxilb-inference-gateway/releases/download/mcp/vX.Y.Z/loxilb-mcp_X.Y.Z_darwin_arm64.tar.gz
tar xzf loxilb-mcp.tar.gz
sudo mv loxilb-mcp /usr/local/bin/          # or anywhere on PATH
xattr -d com.apple.quarantine /usr/local/bin/loxilb-mcp 2>/dev/null || true
loxilb-mcp --version
```

### Windows

Download `loxilb-mcp_X.Y.Z_windows_amd64.zip` (or `arm64`) from the Releases
page, extract `loxilb-mcp.exe`, and note its full path (e.g.
`C:\Tools\loxilb-mcp.exe`). Verify in PowerShell:
```powershell
C:\Tools\loxilb-mcp.exe --version
```

### Linux (Ubuntu, Rocky, and any distro)

```sh
curl -L -o loxilb-mcp.tar.gz \
  https://github.com/loxilb-io/loxilb-inference-gateway/releases/download/mcp/vX.Y.Z/loxilb-mcp_X.Y.Z_linux_amd64.tar.gz
tar xzf loxilb-mcp.tar.gz
sudo install -m 0755 loxilb-mcp /usr/local/bin/
loxilb-mcp --version
```
The same `linux_amd64` binary runs on Ubuntu **and** Rocky/Alma/RHEL — it is
statically linked, so there is no "works on Ubuntu but not Rocky" glibc issue.
Use `linux_arm64` on ARM hosts.

### With the Go toolchain (any OS)

```sh
go install github.com/loxilb-io/loxilb-inference-gateway/mcp/cmd/loxilb-mcp@latest
# binary lands in $(go env GOPATH)/bin
```

### Docker (any OS, no local install)

```sh
docker pull ghcr.io/loxilb-io/loxilb-mcp:latest
docker run -i --rm ghcr.io/loxilb-io/loxilb-mcp --target-url http://YOUR_LOXILB_HOST:11111
```
The `-i` flag is required — the stdio MCP transport needs stdin kept open.

The image is multi-arch (`linux/amd64` + `linux/arm64`); Docker picks the right
one. `:latest` tracks the newest **stable** release — a pre-release publishes
only its own `:X.Y.Z-rc.N` tag and never moves `:latest`, so pin the version tag
if you want to try one.

---

## Integrate with Claude Desktop

Claude Desktop reads a JSON config file. Add a `loxilb` entry under
`mcpServers`, pointing at wherever you installed the binary (or at Docker).

**Config file location:**

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

**Binary install** (macOS/Linux example):
```json
{
  "mcpServers": {
    "loxilb": {
      "command": "/usr/local/bin/loxilb-mcp",
      "args": ["--target-url", "http://YOUR_LOXILB_HOST:11111", "--read-only"]
    }
  }
}
```

**Windows** (note the doubled backslashes in JSON):
```json
{
  "mcpServers": {
    "loxilb": {
      "command": "C:\\Tools\\loxilb-mcp.exe",
      "args": ["--target-url", "http://YOUR_LOXILB_HOST:11111", "--read-only"]
    }
  }
}
```

**Docker** (any OS):
```json
{
  "mcpServers": {
    "loxilb": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/loxilb-io/loxilb-mcp:latest",
               "--target-url", "http://YOUR_LOXILB_HOST:11111", "--read-only"]
    }
  }
}
```

Then **fully quit and reopen Claude Desktop** (⌘Q on macOS / Quit from the tray
on Windows — closing the window is not enough; the config only reloads on a full
restart). The `loxilb` tools then appear under the tools/connector icon near the
message box. Ask *"check current loxilb LB rules"* to exercise it.

> `--read-only` is recommended for a desktop chat: it registers only the
> observe/diagnose tools and no mutations. Drop it (default role is admin) if you
> want the guarded management/AI-gateway tools too — destructive actions still
> require the two-step confirm-token flow. See `../docs/MCP-OPERATIONS.md`.

## Integrate with Claude Code

```sh
claude mcp add loxilb -- /usr/local/bin/loxilb-mcp --target-url http://YOUR_LOXILB_HOST:11111
# verify:
claude mcp list        # or /mcp inside a session
```

---

## Releasing (maintainers)

Releases are fully automated by [`../.github/workflows/mcp-release.yml`](../.github/workflows/mcp-release.yml)
and are **independent** of the datapath's `vX.Y.Z-igw.N` releases. To cut one:

```sh
git tag mcp/v1.0.0
git push origin mcp/v1.0.0        # mcp/v1.0.0-rc.1 → published as a pre-release
```

That single tag triggers the workflow to build all six binaries, write
`SHA256SUMS`, publish a GitHub Release on the `mcp/vX.Y.Z` tag, push the
`ghcr.io/loxilb-io/loxilb-mcp` multi-arch image, and update the Homebrew cask.
A tag carrying a pre-release suffix publishes its own image tag but does **not**
move `:latest`, which stays on the last stable release.

Two implementation notes, since GoReleaser OSS has no monorepo support: the
workflow runs it from `mcp/` and passes the prefix-stripped version via
`GORELEASER_CURRENT_TAG`, and GoReleaser's own release pipe is disabled — it
would derive a bare `vX.Y.Z` tag and mint it inside the datapath's tag
namespace, so the workflow creates the Release with `gh release create` on the
real tag instead.

**One-time prerequisites:** the repo is public (or GHCR/tap are otherwise
reachable), the `loxilb-io/homebrew-tap` repository exists, and the
`HOMEBREW_TAP_TOKEN` secret (a PAT with `contents:write` on the tap) is set.
GHCR uses the built-in `GITHUB_TOKEN`. Every PR touching `mcp/**` is gated by
[`mcp-ci.yml`](../.github/workflows/mcp-ci.yml) (vet, race tests, the full
cross-compile matrix, and a GoReleaser snapshot).
