#!/usr/bin/env python3
"""A P/D backend that fails in one chosen, named way.

This scenario drives the `loxilb_pd_*` failure-path counters. Every one of
them is an eager scalar: it is present at zero in every scrape, so it looks
alive whether or not anything can ever move it. Presence is not evidence for these families --
only a driven delta with a control arm is. This stub is the drive half.

Modes, each matched to ONE datapath trigger read out of the source:

  zerobyte   accept, read the whole request, then close having written NOTHING.
             This is the exact shape sockproxy_http.c:4925-4938 names: "decode
             backend EOF with ZERO response bytes". It increments BOTH
             pd_decode_ep_died and pd_decode_zero_byte_eof, and the client gets
             a 502 {"error":"pd_decode_backend_died"} -- a receipt, not just a
             counter.

  refuse     do not listen at all (the port is closed, connect() gets ECONNREFUSED).
             Feeds the connect-retry / failover paths in sockproxy_ep.c.

  hang       accept and never reply, never close. Holds the client in its
             prefill/decode phase without producing an EOF, so it separates
             "backend died" from "backend is slow" -- two different counters.

  ok         a normal 200 with a usage object. This is the CONTROL: the same
             topology, the same swap mechanism, the same request, and every
             fault counter must stay flat. An arm without this control cannot
             tell "the fault fired" from "the counter moves on its own".

  slowok     accept, read the whole request, write NOTHING for --delay seconds,
             then answer exactly as `ok` does. This is `ok` with a guaranteed
             silent window, and it exists for ONE reason: the SGLang pair-retry
             gate (sockproxy_pd_sglang.c:633) requires pd_sg_decode_untouched(),
             i.e. the decode leg must not have produced a single byte when the
             drain leg dies. A dual dispatch hands the SAME request to both
             legs at once, so with a normal decode backend whether the retry
             fires at all is a RACE between the decode's reply and the prefill's
             close. An arm that silently loses that race reports a flat counter
             and reads as "the family cannot be driven". The stall removes the
             race by construction rather than by luck. Keep --delay well under
             pd_prefill_timeout_sec (default 30s, sockproxy.h:604) or the
             rendezvous-wedge abort fires instead and moves a DIFFERENT family.

  reject     answer a chosen 4xx/5xx status with a MARKER body, headers and body
             in a SINGLE write. Two gate terms of the SGLang prefill-reject
             relay (sockproxy_pd_sglang.c:312-331) need exactly this: the status
             must be < 500, and it must arrive on the FIRST chunk fed to the
             drain leg's parser (`first_feed`, :274) -- a response split across
             two writes is detected too late to have a verbatim prefix to hand
             over, and takes the abort path instead. The marker is what proves
             the relay was VERBATIM: the client's body must carry the origin's
             own bytes, not a gateway-synthesised error.

Usage: pd-fault-backend.py --mode zerobyte --port 8099
       pd-fault-backend.py --mode slowok --port 8099 --delay 6
       pd-fault-backend.py --mode reject --port 8099 --status 400
"""
import argparse
import json
import time
import socket
import socketserver
import sys
import threading

ARGS = None


def read_request(c):
    """Read headers + body so the gateway has genuinely SENT the request.

    A close before the request is read is a different defect shape (the
    datapath may classify it as a connect failure rather than a dead backend),
    so the fault must land AFTER the request is on the wire.
    """
    c.settimeout(20)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = c.recv(65536)
            if not chunk:
                return buf
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    clen = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    clen = 0
        while len(rest) < clen:
            chunk = c.recv(65536)
            if not chunk:
                break
            rest += chunk
    except (socket.timeout, OSError):
        pass
    return buf


OK_BODY = json.dumps({
    "id": "chatcmpl-pd-fault-control",
    "object": "chat.completion",
    "created": 0,
    "model": "control",
    "choices": [{"index": 0, "finish_reason": "stop",
                 "message": {"role": "assistant", "content": "ok"}}],
    "usage": {"prompt_tokens": 30, "completion_tokens": 20, "total_tokens": 50},
}).encode()


# ---- TRT-LLM context-leg bodies -------------------------------------------
#
# pd_trt_ctx_early_exit_check (sockproxy_pd.c:896) reads choices[0].finish_reason
# out of the buffered CONTEXT response and skips the generation leg unless the
# value is "length" or "not_finished". These two bodies differ in EXACTLY that
# one JSON string and in nothing else -- same status (200, which the gate also
# requires), same id, same length class, same framing. That is what makes the
# control a control: any other difference and a flat counter could be explained
# by something other than the finish_reason.
#
# The shared TRT_MARKER id is deliberate. The early-exit relay hands the
# CONTEXT response to the client VERBATIM, so a client that sees the marker was
# served by the prefill leg; a client that does not was served by the decode
# leg. Giving the two modes different markers would have made the control's
# receipt ambiguous -- it would prove "not this mode" rather than "the decode
# leg ran".
TRT_MARKER = "trtctx-early-exit-marker"

# The prefill-reject relay hands the origin's 4xx to the client VERBATIM, so a
# marker in this body is the response-path oracle for "verbatim": if the client
# sees it, the bytes came from the backend and not from the gateway's own error
# synthesiser. Keep it a literal the receipt grep in pd-burst.sh will not
# confuse with an "error" token -- it is read separately.
REJECT_MARKER = "pdsg-origin-reject-marker"


def trt_body(finish_reason):
    return json.dumps({
        "id": TRT_MARKER,
        "object": "chat.completion",
        "created": 0,
        "model": "trt-ctx",
        "choices": [{"index": 0, "finish_reason": finish_reason,
                     "message": {"role": "assistant", "content": "ctx"}}],
        "usage": {"prompt_tokens": 30, "completion_tokens": 1,
                  "total_tokens": 31},
    }).encode()


SSE_CUT_CHUNKS = 2


def sse_chunk(i):
    """One OpenAI-shaped SSE delta frame. Deliberately NOT the terminator.

    The stream this mode produces is CUT, so it must never contain
    "data: [DONE]": that terminator is exactly what makes the gateway leave
    PD_PHASE_DECODE_STREAMING through the SSE scanner instead of through the
    mid-stream EOF branch under test (sockproxy_http.c:4980-4996).
    """
    d = json.dumps({"id": "chatcmpl-ssecut", "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"content": f"tok{i} "},
                                 "finish_reason": None}]})
    return b"data: " + d.encode() + b"\n\n"


TRT_STOP_BODY = trt_body("stop")
TRT_LEN_BODY = trt_body("length")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        mode = ARGS.mode
        read_request(c)

        if mode == "zerobyte":
            # The whole point: close with zero bytes written. SO_LINGER off so
            # this is a clean FIN (an RST would be a different event again).
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            c.close()
            return

        if mode == "hang":
            # Never answer, never close. The caller kills the stub to end it.
            #
            # 🚨 CLEAR THE READ TIMEOUT FIRST. read_request() sets
            # settimeout(20) and it STAYS on the socket. socket.timeout is an
            # OSError subclass, so without this the recv below raises at 20s,
            # the handler returns, and socketserver CLOSES the connection --
            # turning "hangs forever" into "closes with zero bytes after 20s".
            # That silently becomes a DIFFERENT arm: any gateway timeout longer
            # than 20s (the P/D decode first-byte wedge is 30s) can never fire,
            # and its counter reads as undrivable when the stub was the one
            # that gave up. Measured on 2026-09-15: every wedge request died at
            # T+20s to this line, not to the product.
            c.settimeout(None)
            try:
                while True:
                    if not c.recv(65536):
                        return
            except OSError:
                return

        if mode in ("trtstop", "trtlen"):
            payload = TRT_STOP_BODY if mode == "trtstop" else TRT_LEN_BODY
            out = (b"HTTP/1.1 200 OK\r\n"
                   b"Content-Type: application/json\r\n"
                   b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                   b"Connection: keep-alive\r\n\r\n" + payload)
            try:
                c.sendall(out)
            except OSError:
                pass
            return

        if mode == "reject":
            # ONE write: status line, headers and body together, so the status
            # lands on the drain leg's first_feed.
            payload = json.dumps({
                "error": {"message": "origin rejected the request",
                          "type": "invalid_request_error",
                          "marker": REJECT_MARKER},
            }).encode()
            out = (b"HTTP/1.1 " + str(ARGS.status).encode() + b" Rejected\r\n"
                   b"Content-Type: application/json\r\n"
                   b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                   b"Connection: close\r\n\r\n" + payload)
            try:
                c.sendall(out)
            except OSError:
                pass
            return

        if mode == "ssecut":
            # Site B of pd_sg_decode_close_drain: the decode leg must first
            # REACH PD_PHASE_DECODE_STREAMING and only then be cut.
            #
            # Reaching it is not automatic. sockproxy_http.c:1660-1690 makes the
            # DECODE_SENDING -> DECODE_STREAMING transition only when the rule
            # carries sse_mode=1 AND this response's head carries
            # "Content-Type: text/event-stream" within its first 2048 bytes.
            # The header is therefore load-bearing: without it the same abrupt
            # close lands on the ZERO-BYTE branch (site A) instead, and the arm
            # would score site A twice while reporting it had covered both.
            #
            # No Content-Length, on purpose. An SSE body is close-framed; a
            # length would let the parser read the FIN as a COMPLETE message
            # rather than a cut stream, which is the opposite of the event
            # under test.
            head = (b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/event-stream\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"Connection: keep-alive\r\n\r\n")
            try:
                c.sendall(head)
                # Flushed as its own segment so the activation scan sees the
                # content-type on a read of its own, exactly as a real worker's
                # header flush arrives.
                time.sleep(0.05)
                for i in range(SSE_CUT_CHUNKS):
                    c.sendall(sse_chunk(i))
                    time.sleep(0.05)
            except OSError:
                pass
            # THE CUT: a clean FIN with no terminator ever sent.
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            c.close()
            return

        if mode == "slowok":
            # Silent for --delay, THEN the ok response. The silence is the
            # whole point; see the module docstring.
            time.sleep(ARGS.delay)

        if mode in ("ok", "slowok"):
            out = (b"HTTP/1.1 200 OK\r\n"
                   b"Content-Type: application/json\r\n"
                   b"Content-Length: " + str(len(OK_BODY)).encode() + b"\r\n"
                   b"Connection: keep-alive\r\n\r\n" + OK_BODY)
            try:
                c.sendall(out)
            except OSError:
                pass
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=["zerobyte", "refuse", "hang", "ok", "slowok",
                             "reject", "trtstop", "trtlen", "ssecut"])
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--delay", type=float, default=6.0,
                    help="slowok: seconds of silence before the 200")
    ap.add_argument("--status", type=int, default=400,
                    help="reject: the HTTP status to answer with")
    ARGS = ap.parse_args()

    if ARGS.mode == "refuse":
        # Refusing means NOT listening. Staying alive as a process keeps the
        # swap script's pidfile contract identical across modes, so teardown
        # is the same code path for every arm.
        print(f"pd-fault-backend: mode=refuse, NOT listening on {ARGS.port} "
              f"(connect() will get ECONNREFUSED)", flush=True)
        threading.Event().wait()
        return

    srv = Server(("0.0.0.0", ARGS.port), Handler)
    print(f"pd-fault-backend: mode={ARGS.mode} on 0.0.0.0:{ARGS.port}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
