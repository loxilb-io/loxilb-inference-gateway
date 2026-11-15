# Local loxilib maintenance

Source: github.com/loxilb-io/loxilib, exact version
`v0.8.9-0.20241218081253-760c19357603` (commit `760c19357603`).
The root module replaces that dependency with this directory so the logging
reader and writer share synchronization. All original source files except logger.go are byte-for-byte copies of that
version. LICENSE and AUTHORS are retained. Module metadata follows the root
repository's centralized Go/x/net pins and is included in the pin checker's managed module inventory.

Changes: synchronized first default publication and replacement, construction
without publication, configuration accessors, and concurrency/negative tests.
Exported fields remain compatible for construction; direct writes after
publication are unsupported. Use SwapDefaultLogger, LogItSetLevel,
LogItGetLevel and LogItSetTTY. Standard log.Logger.SetOutput remains safe.
A custom output writer must not reenter logger replacement or configuration.

Run `go test -race -count=1 ./...` in this directory as well as the root package
race suite. Replace this local copy with a released upstream version only after
it contains these APIs and passes the same regressions. The effective root dependency versions and native gitlink are unchanged.
