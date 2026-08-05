# Minimal image for loxilb-mcp. GoReleaser builds the static binary first and
# drops it into the build context, so this just wraps it in distroless.
# For a from-source build instead, see the `docker build` note in README.md.
FROM gcr.io/distroless/static:nonroot
COPY loxilb-mcp /usr/local/bin/loxilb-mcp
# stdio MCP server by default; pass --target-url / --config at runtime.
# Run with -i to keep stdin open: docker run -i --rm <image> --target-url http://host:11111
ENTRYPOINT ["/usr/local/bin/loxilb-mcp"]
