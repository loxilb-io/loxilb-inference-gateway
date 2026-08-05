# Minimal image for loxilb-mcp. GoReleaser builds the static binaries first and
# drops them into the build context, so this just wraps one in distroless — it
# is not meant to be built standalone with `docker build`. To produce it
# locally: cd mcp && goreleaser release --snapshot --clean.
FROM gcr.io/distroless/static:nonroot
# GoReleaser lays the context out as <goos>/<goarch>/loxilb-mcp, and buildx
# fills in TARGETPLATFORM per platform of the multi-arch build.
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/loxilb-mcp /usr/local/bin/loxilb-mcp
# stdio MCP server by default; pass --target-url / --config at runtime.
# Run with -i to keep stdin open: docker run -i --rm <image> --target-url http://host:11111
ENTRYPOINT ["/usr/local/bin/loxilb-mcp"]
