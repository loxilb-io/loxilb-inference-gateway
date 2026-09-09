#!/usr/bin/env bash
set -euo pipefail

sudo docker run --rm -i  --user $(id -u):$(id -g) -e GOPATH=$(go env GOPATH):/go -v $HOME:$HOME -w $(pwd) quay.io/goswagger/swagger:0.30.3 generate server
# Preserve zero-valued constraints lost by the pinned generator's OrigSpec clone.
# This only synchronizes the original embedded contract, not flattened schemas.
go run ./cmd/sync-swagger -spec swagger.yml -generated restapi/embedded_spec.go
sed -i 's/s\.hasScheme(schemeHTTPS)/s\.hasScheme(schemeHTTPS) \&\& options\.Opts\.TLS/gi' restapi/server.go
sed -i'' -r -e '/import/a\\t\"github.com/loxilb-io/loxilb/options\"' restapi/server.go
