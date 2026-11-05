# OpenAI JSON parser regression

This Linux Docker scenario runs reproducible JSON boundary requests against an
explicit Gateway image. The mock serves HTTP/1.1 and h2c and records request
headers separately from **complete request bodies**, indexed by request ID.
Its Go dependencies reuse the vendored reflect-echo module.

## Contract

Routing, model authorization and user/session extraction use a fixed-storage,
allocation-free top-level scanner. JSON escapes are decoded when comparing keys
and model values. More than one decoded top-level `model` key is rejected with
HTTP 400 `duplicate_model_field`, including `mod\u0065l`. Nested `model` keys
are not routing operands. Duplicate Content-Type headers are rejected with
HTTP 400 `duplicate_content_type`, even when their values agree.

The 8,192 JSMN-token budget applies only to optional prefix/KV hashing. Exceeding
it, or failing the expanded token allocation, skips that hash and preserves the
routing model. It does not introduce a structural 413 or bypass allowed_models.
The scanner also replaces the old 64-token user extractor. Deep nesting does not
consume recursive stack frames. Buffered requests share the scanner result
between admission, model routing and prefix extraction. Optional parsing of
bodies over 64KiB counts tokens first, avoiding an initial failed 2,048-token pass.

H1 Content-Length bodies above the existing 768KiB inspection cap and chunked
JSON bodies keep streaming. One incremental scanner state follows decoded body
chunks, independent of the receive buffer, and the backend leg cannot enter
sockmap relay while that guard is active. One trailing byte for Content-Length,
or a five-byte suffix for chunked framing, is withheld until the JSON scan and
HTTP framing complete. The zero-chunk callback validates JSON before any trailer
can complete the backend request. A late duplicate resets/closes the backend
leg without reuse, cancels any unused token reservation without a settlement,
answers 400 and records exactly one sec.ai.deny. The terminal refusal remains
latched until teardown, including queued readable events.

A streamed refusal can therefore expose headers and a **partial** body to the
backend. Its complete-body receipt must remain zero. The mock waits for complete
framing before acknowledging receipt, matching the backend contract assumed by
this guard. H2 retains its existing bounded body buffering and uses the same
metadata scanner. No additional 16MiB H1 collection buffer is allocated.
Oversized H1 routing still requires the first model to be discovered within the
existing 64KiB routing window; this change extends duplicate detection through
the end of that streamed body, rather than extending the routing window.

## Run

Use a source-built Gateway image containing the desired eBPF pin.

~~~bash
bash cicd/ai-json-parser/validation.sh IMAGE /absolute/path/to/new-evidence
~~~

The image defaults to LOXILB_DOCKER_IMAGE, then
ghcr.io/loxilb-io/loxilb-inference-gateway:latest. The evidence directory must
be new. Docker, Git, Python 3 and curl with HTTP/2 support are required on the
native Linux Docker host. Set JSON_PARSER_MOCK_IMAGE to reuse a mock image.

The runner creates one internal network and three uniquely named containers:
a proxy-only Gateway with NET_ADMIN, a mock backend and PostgreSQL 18.6. The
policy database is bootstrapped from scripts/aigw-db-bootstrap.sql and uses
synthetic credentials and disposable storage. Two real fixture API keys have
opposing allowed_models lists. Readiness includes the asynchronous policy store.
Raw API keys are not written to auth-fixtures.json. The exit trap preserves
evidence and removes this invocation's containers, volumes, network and built
mock image, including after failures. A supplied mock image is retained.

## Matrix

| Coverage | Requests | Expected |
| --- | --- | --- |
| 2,047 / 2,048 / 2,049 / 3,586 / 8,192 / 8,193 structural items, model first/last | 30 | 200 and SSE DONE |
| JSON array relay with a routing header | 1 | 200 |
| Content-Type value at byte 2032 / 2033 | 6 | 200 |
| Split header name/value/length, mixed case and parameters | 2 | 200 |
| Header/media decoys and real form body | 3 | Existing streaming/buffering and 200 |
| Five requests on one keep-alive connection | 5 | 200, including 8,193 items |
| Required authentication without an API key | 2 | 401 invalid_api_key |
| 3,586 items with eight concurrent workers | 16 | 200 |
| h2c at 3,586 / 8,192 / 8,193 items, model first/last | 6 | 200 |
| Normal 800KiB and 2MiB, H1 and H2 | 4 | 200, one complete backend receipt |
| Duplicate model at front, 800KiB tail and escaped tail, H1 and H2 | 6 | 400, zero complete receipts |
| Chunked normal 2MiB and 800KiB with trailers | 2 | 200 |
| Chunked duplicate front/tail/escaped tail | 3 | 400, zero complete receipts |
| Depth 12,000, H1 and H2 | 2 | 200 |
| Equal/conflicting duplicate Content-Type, H1 and H2 | 4 | 400, zero complete receipts |
| Real allowed/denied API keys at 106,206 bytes and 800KiB, H1 and H2 | 8 | 200 / 403 model_not_allowed |
| Allowed key with escaped duplicate model at 800KiB tail, H1 and H2 | 2 | 400, zero complete receipts |
| Non-string model and duplicate after a non-string first value, authenticated H1/H2 | 4 | 400, zero complete receipts |
| **Total** | **106** | **81 successes, 19 metadata refusals, 6 policy refusals** |

The original 106,206-byte, 3,586-item fixture hashes are pinned by test_oracle.py.
Structural items mean JSMN tokens, including object keys and containers, rather
than model tokenizer tokens. Large H1 normal and late-duplicate cases pause the
upload after 64KiB and assert one backend header receipt but zero complete-body
receipts. This proves streaming is active. Chunked completion is split across
writes, and escaped metadata is tested across every scanner split in C units.

A success requires one backend receipt and one data.ai.complete. A refusal
requires zero complete receipts and exactly one sec.ai.deny with the same status
and error code. Duplicate-key/type refusals must use the framing stage. The
oracle fails duplicate denials, completion/denial mixtures, settlement after a
refusal, missing events, unexpected backend receipts and an incomplete matrix.

## Evidence and CI

Evidence includes source and binary identity, fixture image identity, fixture key
IDs/policies, request hashes, responses, latency samples, backend observations,
active/sealed/compressed audit segments, joined request-results.json,
summary.json, logs, cleanup.txt and SHA256SUMS. Local review evidence belongs in
artifacts/ (Git-ignored) so it is accessible from this workspace.

AI-Gateway-Sanity-CI runs the complete scenario in ai-admission against the image
built by ai-sanity-setup and uploads evidence on every run for 14 days.
DP-Unit-Gate-CI runs extraction/allocator-failure units, production header split
callbacks, refusal audit units and all 15 oracle/fixture tests. The full scenario
also exercises actual callback registration and dispatch, which the isolated
header-callback compilation alone cannot cover. The eBPF C-Unit-Gates workflow
runs its own scanner/extraction and refusal targets before the Gateway pin moves.

~~~bash
python3 -m unittest discover -s cicd/ai-json-parser -p 'test_*.py'
make -C loxilb-ebpf/common test_usage test_aiident test_admit test_stream test_backend_failure_audit test_kv
go test -count=1 -run TestTokenQuota ./pkg/loxinet
~~~

## Publication order

The earlier local eBPF commit c5e75a29 and its predecessors were not advertised
by the eBPF remote refs during review. Local validation can use Git bundles;
GitHub submodule checkout requires a remotely reachable revision. Publish and
review the eBPF branch first, merge it, then update the Gateway gitlink to that
reachable merged revision before publishing/merging the Gateway PR. A local
candidate gitlink is not proof that hosted CI can check it out.
