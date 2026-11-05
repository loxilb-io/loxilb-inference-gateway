# OpenAI JSON parser regression

This Linux Docker scenario runs the JSON boundary requests against an explicit
Gateway image. The mock backend serves HTTP/1.1 and h2c and records headers and
complete request bodies by request ID. Its Go dependencies reuse the vendored
reflect-echo module.

## Run

Use a source-built Gateway image containing the desired eBPF pin.

~~~bash
bash cicd/ai-json-parser/validation.sh IMAGE /absolute/path/to/new-evidence
~~~

The image defaults to LOXILB_DOCKER_IMAGE, then
ghcr.io/loxilb-io/loxilb-inference-gateway:latest. The evidence directory must
be new. Docker, Git, Python 3 and curl with HTTP/2 support are required on the
Linux host. The mock image builds from Dockerfile.mock. Set
JSON_PARSER_MOCK_IMAGE to reuse an already-built mock image.

The runner creates an internal Docker network and two uniquely named containers.
The Gateway runs in proxy-only mode with NET_ADMIN. The host drives the
container addresses directly, so run this scenario on a native Linux Docker
host. The exit trap saves evidence and removes this invocation's containers,
network and mock image, including on failure. An explicitly supplied mock image
is retained.

## Matrix

| Cases | Requests | Expected |
| --- | --- | --- |
| 2,047 / 2,048 / 2,049 items, including model-last at 2,048 | 12 | 200 and SSE DONE |
| 3,586 items, model first and last | 6 | 200 and SSE DONE |
| 8,192 items, model first and last | 6 | 200 and SSE DONE |
| 8,193 items, model first and last | 6 | 413 and json_structure_limit_exceeded |
| Content-Type value starts at byte 2032 / 2033 | 6 | 200 and SSE DONE |
| Split name, value and Content-Length, mixed case and parameters | 2 | 200 and SSE DONE |
| Header-name/media suffix decoys and a real form body | 3 | Correct streaming/buffering and 200 |
| Five requests on one keep-alive connection | 5 | Four successes, then one 413 |
| Required authentication with an unconfigured policy store | 2 | Existing 503 policy_store_unavailable |
| Sixteen 3,586-item requests with eight workers | 16 | 200 and SSE DONE |
| h2c at 3,586 / 8,192 / 8,193, model first and last | 6 | Four successes, two 413 |
| Total | 70 | Every declared request executes |

JSON bodies remain 106,206 bytes. The 3,586-item fixture hashes are checked by
test_oracle.py against the original reproduction. Structural items are JSMN
tokens, including object keys and containers.

A success must have one backend receipt and one data.ai.complete event.
A refusal must have zero backend receipts and one sec.ai.deny event carrying
the same HTTP status and error code. The oracle fails duplicated denials,
completion/denial mixtures, missing terminal records, unexpected backend
receipts and an incomplete matrix.

## Evidence and CI

The evidence includes source and binary identity, fixture image identity,
request hashes, expected.json, receipts.json, active/sealed/compressed audit
segments, merged audit.jsonl, request-results.json,
summary.json, logs, cleanup.txt and SHA256SUMS.

AI-Gateway-Sanity-CI runs this scenario in ai-admission using the Gateway
built by ai-sanity-setup and uploads its evidence on every run.
DP-Unit-Gate-CI runs the JSON extraction tests, production header callback
split tests, local-refusal audit tests and the harness oracle tests.

~~~bash
python3 -m unittest discover -s cicd/ai-json-parser -p 'test_*.py'
make -C loxilb-ebpf/common test_usage test_admit test_backend_failure_audit
~~~
