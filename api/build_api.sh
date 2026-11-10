#!/usr/bin/env bash
set -euo pipefail

api_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(dirname -- "$api_dir")"
cd "$api_dir"
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$repo_dir:/src" -w /src/api \
    quay.io/goswagger/swagger:0.30.3 generate server
# Preserve zero-valued constraints lost by the pinned generator's OrigSpec clone.
# This only synchronizes the original embedded contract, not flattened schemas.
go run ./cmd/sync-swagger -spec swagger.yml -generated restapi/embedded_spec.go
go run ./cmd/sync-model-validators -generated models/end_point_host_state.go
sed -i 's/s\.hasScheme(schemeHTTPS)/s\.hasScheme(schemeHTTPS) \&\& options\.Opts\.TLS/gi' restapi/server.go
sed -i'' -r -e '/import/a\\t\"github.com/loxilb-io/loxilb/options\"' restapi/server.go
