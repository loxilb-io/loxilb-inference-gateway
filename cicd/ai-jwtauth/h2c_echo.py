#!/usr/bin/env python3
"""h2c (HTTP/2 prior-knowledge, no TLS) echo backend for the H2 gate legs.

The hdr_echo.py pools speak HTTP/1.1, which makes them useless as ADMISSION
oracles for HTTP/2: the gateway forwards h2 frames upstream, an H/1.1 server
cannot parse them, and the client-side reset looks identical to a refusal.
This backend completes the h2 exchange, so "admitted" and "refused" finally
produce different client-visible outcomes over HTTP/2.

Behaviour mirrors hdr_echo.py where it matters to the legs:
  POST *            -> 200 JSON carrying the label, header-presence markers
                       (authorization / x-api-key / x-auth-tenant / x-auth-user)
                       and a usage object (feeds the H2 settle path);
                       an x-test-nonce header is counted as a receipt.
  GET /__receipts/N -> the count for nonce N, as a decimal body.

A third argument of "no-usage" suppresses the usage object, mirroring
hdr_echo.py's mode of the same name. usage is optional in the response shape,
and the HTTP/2 settle path reads it out of the stream's own tail window, so
this is the only way to drive "an H2 response completed and no dialect could
read usage from it" — the shape the missing-usage accounting leg needs.

An X-Test-Delay-Ms request header holds the response for that many
milliseconds, the same per-request knob hdr_echo.py carries and for the same
reason: the interval between admission and settlement is the only window in
which an H2 stream has a live reservation to reset, abandon or GOAWAY out
from under, and unheld it is microseconds long. A delayed request is answered
from its OWN thread, so several delayed streams can be in flight on one
connection at once — which is the whole point for the GOAWAY case, and is why
the delay could not simply be a sleep in the connection loop. The receipt is
recorded and the body drained BEFORE the delay, so a delayed request still
counts as having arrived.

Usage: h2c_echo.py <label> <port> [no-usage]
"""

import json
import socket
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events

LABEL = sys.argv[1] if len(sys.argv) > 1 else "server-h2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8090
MODE = sys.argv[3] if len(sys.argv) > 3 else ""
EMIT_USAGE = MODE != "no-usage"
# "error-500": the OpenAI-compatible error shape over HTTP/2. Indistinguishable
# from the no-usage case to anything that only asks whether usage came back,
# which is exactly why the settle path separates them on status.
ERROR_STATUS = 500 if MODE == "error-500" else 0
if ERROR_STATUS:
    EMIT_USAGE = False

receipts = {}
receipts_lock = threading.Lock()


class Peer:
    """One client connection: the h2 state machine, its socket, and the one
    lock that owns both.

    h2.connection.H2Connection is not thread-safe and neither is interleaving
    two sendall() calls on one socket, so every touch of either — from the
    receive loop and from each delayed responder thread — goes through this
    lock. Without it the delay knob would corrupt the frame stream instead of
    widening a window.
    """

    def __init__(self, sock, conn):
        self.sock = sock
        self.conn = conn
        self.lock = threading.Lock()

    def flush_locked(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)


def respond(peer, stream_id, status, body):
    with peer.lock:
        try:
            peer.conn.send_headers(stream_id, [
                (":status", str(status)),
                ("content-type", "application/json"),
                ("content-length", str(len(body))),
            ])
            peer.conn.send_data(stream_id, body, end_stream=True)
            peer.flush_locked()
        except Exception:      # noqa: BLE001
            # The client reset this stream or dropped the connection while we
            # held it. That is the case under test on several legs, not an
            # error here: the stream is gone, there is nothing to answer, and
            # raising would take the other streams on this connection with it.
            pass


def handle_request(peer, stream_id, headers, body):
    hdr = {}
    for name, value in headers:
        if isinstance(name, bytes):
            name = name.decode("utf8", "replace")
        if isinstance(value, bytes):
            value = value.decode("utf8", "replace")
        hdr[name.lower()] = value

    method = hdr.get(":method", "")
    path = hdr.get(":path", "/")

    if method == "GET" and path.startswith("/__receipts/"):
        nonce = path[len("/__receipts/"):]
        with receipts_lock:
            count = receipts.get(nonce, 0)
        respond(peer, stream_id, 200, str(count).encode())
        return

    nonce = hdr.get("x-test-nonce", "")
    if nonce:
        with receipts_lock:
            receipts[nonce] = receipts.get(nonce, 0) + 1

    # After the receipt, before the answer — see the module docstring.
    delay_ms = hdr.get("x-test-delay-ms")
    if delay_ms:
        try:
            time.sleep(min(max(int(delay_ms), 0), 30000) / 1000.0)
        except ValueError:
            pass

    if ERROR_STATUS:
        # Label retained so the leg can prove it reached THIS pool.
        respond(peer, stream_id, ERROR_STATUS, json.dumps({
            "label": LABEL,
            "error": {"message": "upstream failure", "type": "server_error"},
        }).encode())
        return

    reply = {
        "label": LABEL,
        "object": "chat.completion",
        "authorization": "yes" if "authorization" in hdr else "no",
        "apikey": "yes" if "x-api-key" in hdr else "no",
        "x_auth_tenant": hdr.get("x-auth-tenant", ""),
        "x_auth_user": hdr.get("x-auth-user", ""),
        "body_len": len(body),
    }
    if EMIT_USAGE:
        reply["usage"] = {"prompt_tokens": 5, "completion_tokens": 7,
                          "total_tokens": 12}
    respond(peer, stream_id, 200, json.dumps(reply).encode())


def dispatch(peer, stream_id, headers, body):
    """Answer inline, or on a thread when the request asked to be held.

    Inline is the default on purpose: every leg that existed before the delay
    knob keeps its exact ordering, and the suite does not pay a thread per
    request. Only a request carrying X-Test-Delay-Ms — which is asking for a
    window in which other streams must stay live — is moved off the receive
    loop.
    """
    for name, value in headers:
        if isinstance(name, bytes):
            name = name.decode("utf8", "replace")
        if name.lower() == "x-test-delay-ms":
            threading.Thread(target=handle_request,
                             args=(peer, stream_id, headers, body),
                             daemon=True).start()
            return
    handle_request(peer, stream_id, headers, body)


def handle_conn(sock):
    config = h2.config.H2Configuration(client_side=False,
                                       header_encoding=None)
    conn = h2.connection.H2Connection(config=config)
    peer = Peer(sock, conn)
    with peer.lock:
        conn.initiate_connection()
        peer.flush_locked()

    streams = {}  # stream_id -> {"headers": [...], "body": bytearray}
    # Long enough to outlive the widest delay a leg may ask for (30s), plus
    # room to answer it. A shorter timeout would close the connection out from
    # under a held stream and hand the case a teardown it did not drive.
    sock.settimeout(45)
    try:
        while True:
            data = sock.recv(65535)
            if not data:
                break
            ready = []
            with peer.lock:
                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        streams[event.stream_id] = {
                            "headers": event.headers, "body": bytearray()}
                        if event.stream_ended:
                            ready.append((event.stream_id,
                                          streams.pop(event.stream_id)))
                    elif isinstance(event, h2.events.DataReceived):
                        st = streams.get(event.stream_id)
                        if st is not None:
                            st["body"] += event.data
                        conn.acknowledge_received_data(
                            len(event.data), event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        st = streams.pop(event.stream_id, None)
                        if st is not None:
                            ready.append((event.stream_id, st))
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return
                peer.flush_locked()
            # Dispatched with the lock RELEASED: an inline answer takes it
            # again inside respond(), and a held one must not be holding it
            # while it sleeps — that would stall every other stream on the
            # connection and quietly turn the multi-stream cases into
            # one-at-a-time ones.
            for stream_id, st in ready:
                dispatch(peer, stream_id, st["headers"], bytes(st["body"]))
    except (socket.timeout, OSError):
        pass
    finally:
        sock.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(16)
    print(f"h2c_echo '{LABEL}' listening on :{PORT}", flush=True)
    while True:
        sock, _ = server.accept()
        threading.Thread(target=handle_conn, args=(sock,),
                         daemon=True).start()


if __name__ == "__main__":
    main()
