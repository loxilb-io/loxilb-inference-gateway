# vLLM 0.31.0 empty terminal output fix

An initial output with no text, no token IDs and `finish_reason="error"` was
filtered as an unfinished prefill chunk. This skipped `_raise_if_error` and
could emit an empty successful stream. Skip only outputs whose finish reason
is still unset; terminal errors, stop and length metadata reach existing handling.
Normal empty in-progress chunks remain filtered. No NIXL, allocator or model
settings change.

The Dockerfile derives a separate candidate from the pinned stock image. It
checks the installed distribution and exact original/patched source SHA256,
then applies only the reviewed gate change. The stock image stays available
for rollback. It fails on version drift or repeat application.

Run `python3 test_patch.py /path/to/original/serving.py` before building to
execute the actual AST predicate with six before/after controls. Build with
`docker build --pull=false -t vllm031-empty-terminal-error .` after caching the
pinned base. Record the resulting image ID and actual installed source hash;
use that immutable ID for native GPU validation. CPU controls do not establish
native inference or fail-over qualification. Deployment and rollback must use
separate owned containers and retain the original image and model assets.
