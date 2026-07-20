# Packaging

In-repo [nfpm](https://nfpm.goreleaser.com/) packaging that produces the
`.deb`, `.rpm`, and binary-tarball release artifacts for
loxilb-inference-gateway. `release.yml` runs this on every release tag;
`package-sanity.yml` validates the output before anything is published.

## Files

| File | Purpose |
|------|---------|
| `nfpm.yaml` | Package definition (contents, scripts, dependencies) for both deb and rpm |
| `Dockerfile.build` | Ubuntu 20.04 build container that produces the package payload |
| `build-pkgs.sh` | Driver: stage artifacts → nfpm → tarball → checksums |
| `loxilb.service` | systemd unit installed by the packages |
| `loxilb-wrapper.sh` | `/usr/sbin/loxilb` launcher (sets the private library path) |
| `mkllb-bpffs.sh` | bpf filesystem mount helper (`ExecStartPre`) |
| `scripts/` | Package maintainer scripts (postinstall / preremove / postremove) |

## Design notes

- **Ubuntu 20.04 build base.** glibc 2.31 is the floor of the supported
  install matrix (Ubuntu 20.04/22.04/24.04, RHEL/Rocky/Alma 9 ≥ 2.34), so a
  binary built on 20.04 runs everywhere in the matrix. The container images
  keep their own Dockerfiles; this builder exists only for package payloads.
- **Private library directory.** The binary needs a kTLS-enabled OpenSSL and
  a libbpf newer than most target distributions ship. They install under
  `/usr/lib/loxilb/` and are picked up only through the `/usr/sbin/loxilb`
  launcher, so system libraries are never shadowed.
- **`/etc/loxilb` survives upgrades and removals.** The package owns the
  directory but not the files created in it at runtime (`snapshot.json` from
  configuration persistence), so package operations never touch them.
- **Service lifecycle.** postinstall enables but does not start the service
  (fresh installs only). preremove stops it on removal, never on upgrade.
- **Kernel baseline.** Packages are a convenience install, not a
  compatibility guarantee: the host kernel must still meet the eBPF baseline
  documented in the README.

## Local build

```sh
# amd64 packages + tarball + checksums, building the payload in Docker
packaging/build-pkgs.sh --version v0.9.8.6-igw.1 --arch amd64 --from-docker --checksums

# arm64 cross-build (QEMU) from an amd64 host
packaging/build-pkgs.sh --version v0.9.8.6-igw.1 --arch arm64 --from-docker
```

Output lands in `dist/`. Version mapping: `v0.9.8.6-igw.1-rc.1` →
package version `0.9.8.6`, revision `igw.1~rc.1` (the `~` sorts release
candidates before the final package in both dpkg and rpm).
