#!/usr/bin/env bash
# Fetch only pinned build dependencies. CI may authenticate API requests; Docker
# builds accept the token only through a BuildKit secret, never a build argument.
set -euo pipefail

verify_asset() {
    printf '%s  %s\n' "$1" "$2" | sha256sum -c - >/dev/null 2>&1
}

fetch_verified() (
    set -euo pipefail
    local api_url=$1 browser_url=$2 digest=$3 output=$4 partial attempt url
    local token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
    if [ -z "$token" ] && [ -r /run/secrets/github_token ]; then
        token=$(cat /run/secrets/github_token)
    fi
    local -a headers=()
    if [ -f "$output" ] && verify_asset "$digest" "$output"; then
        return 0
    fi
    partial=$(mktemp "${output}.part.XXXXXX")
    trap 'rm -f "$partial" "$partial.headers"' EXIT
    for attempt in 1 2 3; do
        for url in "$api_url" "$browser_url"; do
            headers=(-H 'Accept: application/octet-stream')
            if [[ "$url" == https://api.github.com/* ]] && [ -n "$token" ]; then
                headers+=(-H "Authorization: Bearer $token")
            fi
            printf 'release asset: attempt %s: %s\n' "$attempt" "$url" >&2
            # An explicit file, HTTP error handling and a deadline avoid empty
            # tar streams, quiet wget exit 4 and unbounded network waits.
            if curl --fail --show-error --silent --location \
                --connect-timeout 10 --max-time 60 \
                "${headers[@]}" \
                --dump-header "$partial.headers" "$url" -o "$partial"; then
                if verify_asset "$digest" "$partial"; then
                    mv -f "$partial" "$output"
                    return 0
                fi
                printf 'release asset: SHA-256 mismatch from %s\n' "$url" >&2
            fi
            # Preserve useful status/rate-limit diagnostics, never redirect URLs
            # or request/authorization headers.
            awk 'tolower($0) ~ /^(http\/|x-ratelimit-|retry-after:)/ {print}' \
                "$partial.headers" >&2
        done
        if [ "$attempt" -lt 3 ]; then sleep "$((attempt * 2))"; fi
    done
    printf 'release asset: failed to download and verify %s\n' "$output" >&2
    return 1
)

main() {
    if [ "$#" -ne 2 ]; then
        echo 'usage: fetch-release-asset.sh <pinned-asset> <output>' >&2
        return 2
    fi
    local repo tag name id digest
    case "$1" in
        tokenizers-linux-amd64)
            repo=daulet/tokenizers; tag=v1.27.0; name=libtokenizers.linux-amd64.tar.gz
            id=384896938; digest=72556cdca798dd4ea7cdaba308e5f0d68a8cb93b67c96edf485b7a0edd7b07f4 ;;
        tokenizers-linux-arm64)
            repo=daulet/tokenizers; tag=v1.27.0; name=libtokenizers.linux-arm64.tar.gz
            id=384896945; digest=e96545ad05930c26f51f63d932ee6d3bbd32bbed149e102c5290d587a2293067 ;;
        openssl-3.4.1)
            repo=openssl/openssl; tag=openssl-3.4.1; name=openssl-3.4.1.tar.gz
            id=228199386; digest=002a2d6b30b58bf4bea46c43bdd96365aaf8daa6c428782aa4feee06da197df3 ;;
        bpftool-7.2.0)
            repo=libbpf/bpftool; tag=v7.2.0; name=bpftool-libbpf-v7.2.0-sources.tar.gz
            id=106403783; digest=baa1e1c2a79c06a1f3112be3e47a6b4e00df0dc07a1e9117f2213a96fb37bf8a ;;
        gitleaks-linux-x64)
            repo=gitleaks/gitleaks; tag=v8.24.3; name=gitleaks_8.24.3_linux_x64.tar.gz
            id=245568496; digest=9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c ;;
        *) echo "unsupported pinned release asset: $1" >&2; return 2 ;;
    esac
    fetch_verified "https://api.github.com/repos/$repo/releases/assets/$id" \
        "https://github.com/$repo/releases/download/$tag/$name" "$digest" "$2"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
