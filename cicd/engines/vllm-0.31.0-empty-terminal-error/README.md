# vLLM 0.31.0 empty terminal error — testbed recipe

This is an opt-in CICD/support reproduction artifact, **not a customer engine
distribution or a requirement to replace stock engines**. It preserves the stock
image and applies only to the pinned vLLM 0.31.0 source SHA.

The first empty output could be skipped even when it carried a terminal error.
Skip only empty in-progress prefill chunks (`finish_reason is None`), allowing
existing terminal/error handling to run. No allocator, NIXL, lease or transport
policy changes are included.

## Upstream disposition

Upstream already merged [return streaming errors before the first token,
#40986](https://github.com/vllm-project/vllm/pull/40986). Its current chat path
also filters an empty chunk only when `output.finish_reason is None`; this was
verified at revision `03ee2e134d6cc60c4cc84096c8492fcc971f0526`. A duplicate patch
against current main would add no fix, so none is submitted. The official
v0.31.0 serving.py SHA matches this recipe's pinned original file. This recipe
reproduces the older release behavior while an upgrade/backport is reviewed.

## Validation and the remaining RED

`SOURCE.json` records completed finite native replay and the SHA256 of its
private internal review record. That record preserves all four actual worker
image IDs, installed source hashes, raw evidence references and retained REDs;
it is delivered to internal reviewers separately. It does not claim all-green
native qualification. Historical images retain their original pre-build
metadata; changing recipe metadata creates different future image IDs.
Always record the immutable ID and installed source SHA of each actual run.

The healthy-Decode availability difference remains unresolved and is tracked
as `F12-review-availability` in the private review package. Both environments'
failures selected an unavailable Decode worker and failed before content.
Matched repeated fault/recovery runs are required to distinguish selection /
readiness timing from an engine effect. No causal engine regression or
availability equivalence is claimed. **Keep this PR draft until that follow-up
is resolved or its disposition is accepted by the reviewers.** The public
issue containing internal measurements awaits disclosure authorization.

## Controlled use

Run `python3 test_patch.py /path/to/original/serving.py` for six controls on the
actual source predicate. CPU controls do not establish native inference.
After caching the pinned base, build with
`docker build --pull=false -t vllm031-empty-terminal-error .` and record the
immutable resulting ID and actual installed source SHA. Version/source drift
and repeat application fail. Use only separately owned test containers and
preserve the original engine image/model for rollback. The stock customer
engine remains the default.
