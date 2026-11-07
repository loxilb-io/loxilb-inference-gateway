# Bundled CLI image regression

This fixture tests the CLI extracted from a freshly built image against its
Dockerfile's explicit source revision and version. It runs a real Gateway
in an isolated privileged container with no external network, plus synthetic
HTTP/1 prefill, decode and sidecar engines and a separate REST recorder.

```sh
CGO_ENABLED=0 go build -o /tmp/bundled-cli-mock ./cicd/bundled-cli/mock
python3 cicd/bundled-cli/validation.py \
  --image <locally-built-image> --dockerfile Dockerfile \
  --mock-binary /tmp/bundled-cli-mock --evidence-dir <new-evidence-directory>
```

The four CLI wire cases cover P/D off, explicit FailOpen, FailClose and an
omitted failure mode. Refused combinations must exit 2 without any HTTP call.
Accepted payloads preserve P/D mode and endpoint roles. The real Gateway
cases exercise EPP-down FailOpen, native P/D without EPP, independent receipts
for both P/D legs, bodyless decode, a complete 415 with no engine receipts,
an explicit durable persist checkpoint, restart/replay and CLI deletion/readback.

The fixture stops on its first unexpected result and retains command results,
client responses, backend records, binary identity and stdout/stderr logs.
It cleans up only its own container. Use a new evidence directory per run;
failed evidence is never overwritten.

These are mock HTTP/1 routing tests. They do not establish real engine KV
reuse, HTTP/2 P/D support or HA behavior. Build-Check-CI runs the fixture on
its candidate Dockerfile.buildcheck image; this is not full release-image
matrix coverage.
