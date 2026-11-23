# radix-h2: non-P/D prefix routing on HTTP/2

The HTTP/2 counterpart of `cicd/radix-h1`. It sources `../radix-h1/lib.sh`,
so the isolation, gateway start, rules, counters and host check are the same:
- every container runs with `--network none`, `--cgroupns private`, resource
  limits and no restart policy;
- links between container namespaces are wired with nsenter;
- only the gateway container is privileged;
- `hostcheck.sh` compares the host before and after the run.

What differs:

| | radix-h1 | radix-h2 |
|---|---|---|
| Mocks | HTTP/1.1 (`mock_backend.py`) | h2c, HTTP/2 prior knowledge (`h2_mock.py`, admin on HTTP/1.1 `:8001`) |
| Client | `client.py` | `h2_client.py`, which builds the same bodies with radix-h1's `client.py` |
| Mock image | python3 | python3 and python3-h2 from the distribution, on the same pinned base (`mock.Dockerfile`) |
| Containers | `rx4-*` | `rx6-*` |

Usage: `RX_IMG_GW=<gateway image built with -DHAVE_RADIX_TEST_SWITCH>
RX_IMG_MOCK=<mock.Dockerfile image> RX_RUN_DIR=<run folder> ./run.sh`

## Legs

| Leg | Checks |
|---|---|
| E1a | the switch-on arm answers every request of the plan as the switch-off arm (status, SSE) |
| E1b | the switch creates radix state for every pool; none without it |
| E2 | turn 2 of a conversation goes to turn 1's endpoint (fresh connections) |
| MUX | two conversations learned on two endpoints; four streams sent on ONE connection before any answer, each with its own stream id, each routed to its own conversation's endpoint |
| RST | three held streams on one connection; the client resets the second only; the other two are answered, and no underflow or `notify-pin-FAIL` line appears |
| E3-conv | a stream with `x-conversation-id` is pinned: counted `pinned`, never scanned |
| E4 | short body and miss, each counted under its own name |
| NOT-CHAT | `/v1/completions` counts `not_chat`; a `text/plain` body counts `no_body`; neither is scanned |
| E5 | a 500 is not learned; an SSE answer is learned |
| E6 | CHWBL pool, streams on kept connections and one reset stream: no underflow line |
| E6-move | CHWBL pool that admits one request per endpoint. A radix HIT off the CHWBL pick moves the stream's bounded-load unit; an admission move after a HIT is counted `moved`. In-flight is back to 0. |
| STICKY | a persistence pool is never overridden: counted `pinned`, not scanned |
| E8 | a body above 768 KiB is answered and counted `inspect_size`, not scanned |
| TOKENS | a body above 8,192 JSON tokens is scanned and routed by radix |
| GUARD-FALLBACK | four streams of a prefix held on its endpoint, each a HIT; the fifth counts `spread` |
| GUARD-RULES-APART | four streams held on Y; a prefix learned on idle X is a HIT on X |
| QUIESCE | admission in-flight back to 0 on every pool used; no underflow or `notify-pin-FAIL` line in the run |
| E9 | a marker string in a request is absent from the gateway log at debug level |
| COOKIE | not driven (INFO). The cookie pin needs an L7 policy with `HTTP_COOKIE` persistence; covered by `test_radix_wiring`. |

Not carried over from radix-h1:
- **KA, E2-KA, KA-session and PIPE:** HTTP/1.1 keep-alive and pipelining rules.
- **E3-session:** the session overlay is an HTTP/1.1 selection path.
- **E3-cb/E7, the purge:** it is pool state and protocol-independent; radix-h1 covers it.
- **M1, the latency report:** step-5 E11 measures HTTP/2 cost separately.
