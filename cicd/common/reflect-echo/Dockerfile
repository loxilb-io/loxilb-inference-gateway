# Dockerfile — header-reflecting HTTP echo backend for the L7 / KV-cache CICD scenarios.
#
# Multi-stage Go build. loxilb forwards an h2c (cleartext HTTP/2 prior-knowledge) client request to
# the backend AS HTTP/2 in transit mode (no h2->h1 downgrade), so the backend MUST speak h2c on the
# cleartext port or it resets the transit leg and the H2 asserts get empty bodies. This Go server
# serves BOTH HTTP/1.1 and h2c on one plaintext port via golang.org/x/net/http2/h2c. Deps are
# VENDORED (reflect-echo/vendor/) so the build needs NO network.
#
# Built via cicd/common/reflect-echo/docker-build.sh as `ghcr.io/loxilb-io/reflect-echo:latest` and
# spawned via the `reflect-echo` dock-type in cicd/common.sh. Listens on :80; behaviour driven
# entirely by env vars (ECHO_NAME / HEALTHZ_CODE / SLOW_MS / LISTEN_PORT) set per-container.

FROM golang:1.25-alpine AS build
WORKDIR /src
# Copy module + vendored deps first (cache-friendly), then the source.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY server.go ./
# CGO off + vendored deps + no network: fully reproducible static binary.
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -o /reflect-echo ./...

FROM alpine:3.20
COPY --from=build /reflect-echo /reflect-echo
EXPOSE 80
# Unbuffered stderr "reflect-echo up" line reaches `docker logs` immediately (Go writes unbuffered).
ENTRYPOINT ["/reflect-echo"]
