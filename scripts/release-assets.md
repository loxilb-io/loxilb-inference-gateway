# Pinned build downloads

`fetch-release-asset.sh` is shared by native CI setup and Docker builds. It
requires Bash, curl and sha256sum, and accepts only the named assets in its
case table. Both release-asset API and browser-download responses must match
the pinned SHA-256 before the output is atomically replaced. Public downloads
need no credentials. Do not pass GitHub tokens as Docker build arguments.

Each request has a 10-second connection limit and 60-second total limit. There
are at most three attempts across two routes, with two/four-second backoff.
A verified existing output is reused; an invalid response is never installed.

Pin provenance (version, asset ID and digest must be updated together):

| Asset | Version | Digest source |
|---|---|---|
| libtokenizers Linux amd64/arm64 | v1.27.0 | Official release-asset API SHA-256 fields, verified against downloaded archives |
| OpenSSL source | 3.4.1 | Official `openssl-3.4.1.tar.gz.sha256` release asset |
| bpftool/libbpf source | v7.2.0 | SHA-256 of official source asset 106403783 retrieved through the authenticated release API; this release provides no separate source-archive checksum |
| Gitleaks Linux x64 | v8.24.3 | Official `gitleaks_8.24.3_checksums.txt` release asset |

The bpftool content pin is an integrity baseline, not a publisher signature.
Versions, architectures, CGO settings and build flags are unchanged by the
download route. Unsupported asset names fail before any network access.

Run `python3 scripts/test_fetch_release_asset.py` for the local HTTP/error and
checksum controls. The Gitleaks workflow runs these before installing its scanner.
