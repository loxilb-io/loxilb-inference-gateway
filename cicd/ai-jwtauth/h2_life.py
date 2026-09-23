#!/usr/bin/env python3
"""HTTP/2 lifecycle driver — the teardown shapes curl cannot produce.

curl always finishes or abandons a request; it never sends RST_STREAM on a
stream it opened, never sends GOAWAY, and never leaves several streams in
flight on one connection while doing either. Those three shapes ARE the
HTTP/2 lifecycle cases, so they need a client that can drive them
deliberately and then say what it drove.

Every mode prints ONE JSON object per line and a final "summary" line, so the
caller can bind each verdict to the stream that produced it. The drive shape
is reported rather than assumed: a case that meant to abort a stream the
gateway had already answered is measuring an ordinary served response, and
the summary line is what lets the scenario refuse it.

Modes (all take <host> <port>):

  rst       one stream, held at the backend, then RST_STREAM(CANCEL) from the
            client while it is still in flight. The stream closes; the
            CONNECTION stays up and is closed cleanly afterwards, so the
            gateway settles through the per-stream close and NOT through the
            connection-teardown sweep. This is the only mode that isolates
            that path.
  kill      k streams held at the backend, then the TCP connection is torn
            down with RST (SO_LINGER 0) — no GOAWAY, no stream close. The
            gateway settles through the connection-teardown sweep.
  goaway    k streams held at the backend, then GOAWAY, then close. Every
            stream was live when the session was told to end.
  hdrkill   one stream, NOT held: the socket is destroyed the instant the
            response :status arrives, so the response has reached the gateway
            (its usage is in the stream's tail window) while the client is
            gone before the exchange finishes. The per-stream close and the
            teardown sweep race here, which is the point: the result must be
            the same either way.
  hold      k streams held at the backend, then the responses are read
            normally. Nothing is aborted — it exists so the caller can do
            something to the gateway (delete a rule, break a backend) while
            real streams are in flight.
  denyrst   k streams on ONE connection, each DENIED by the gateway and each
            RST_STREAM'd the instant its :status arrives — so the error body
            the gateway queued is never drained. Repeats to make an
            accumulating allocation visible.
  control   one long-lived connection: a full request, then `--churn` short
            connections opened and closed against the same service, then a
            SECOND full request on the FIRST connection. Detects a
            recycled/closed backend descriptor being reused under a live
            session.
  pin       k full requests IN SEQUENCE on ONE connection, each carrying the
            same `--system` prompt so every stream hashes to the same
            endpoint, then a clean close. Reports which backend label
            answered each stream. On a bounded-load (CHWBL) pool the label
            set is the verdict: a stream that spills to another endpoint
            with only ONE stream ever in flight was pushed off its hash by
            load that nobody holds.

Options: --token <file> | --model <name> | --nonce <n> (repeatable, one per
stream) | --delay-ms <n> | --wait-ms <n> | --streams <k> | --churn <n> |
--system <prompt> (a system message ahead of the user message; "" = none)
"""

import argparse
import json
import socket
import struct
import sys
import time

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.settings


def new_conn(host, port, timeout=20):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True,
                                         header_encoding=None))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    return sock, conn


def hard_close(sock):
    """Destroy the connection without a FIN: SO_LINGER 0 makes close() send a
    TCP RST. A FIN would be an orderly shutdown the gateway can drain, which
    is a different case from the client vanishing."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def send_request(conn, sock, host, port, args, nonce):
    sid = conn.get_next_available_stream_id()
    messages = []
    if getattr(args, "system", ""):
        messages.append({"role": "system", "content": args.system})
    messages.append({"role": "user", "content": nonce})
    body = json.dumps({
        "model": args.model,
        "max_tokens": args.max_tokens,
        "messages": messages,
    }).encode()
    headers = [
        (":method", "POST"),
        (":path", "/v1/chat/completions"),
        (":scheme", "http"),
        (":authority", "%s:%d" % (host, port)),
        ("content-type", "application/json"),
        ("content-length", str(len(body))),
        ("x-test-nonce", nonce),
    ]
    if args.delay_ms:
        headers.append(("x-test-delay-ms", str(args.delay_ms)))
    if args.token:
        headers.append(("authorization", "Bearer " + args.token))
    conn.send_headers(sid, headers)
    conn.send_data(sid, body, end_stream=True)
    sock.sendall(conn.data_to_send())
    return sid


def pump(conn, sock, streams, deadline):
    """Read events until the deadline or until every stream is done.

    Returns True if it stopped because everything finished."""
    while time.monotonic() < deadline:
        if streams and all(st["done"] for st in streams.values()):
            return True
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            data = sock.recv(65535)
        except (socket.timeout, OSError):
            return False
        if not data:
            return False
        for event in conn.receive_data(data):
            st = streams.get(getattr(event, "stream_id", None))
            if isinstance(event, h2.events.ResponseReceived):
                if st is not None:
                    for name, value in event.headers:
                        if isinstance(name, bytes):
                            name = name.decode("utf8", "replace")
                        if isinstance(value, bytes):
                            value = value.decode("utf8", "replace")
                        if name == ":status":
                            st["status"] = value
                    st["headers_at"] = time.monotonic()
            elif isinstance(event, h2.events.DataReceived):
                if st is not None:
                    st["body"] += event.data
                try:
                    conn.acknowledge_received_data(len(event.data),
                                                   event.stream_id)
                except Exception:      # noqa: BLE001 — stream already gone
                    pass
            elif isinstance(event, h2.events.StreamEnded):
                if st is not None:
                    st["done"] = True
            elif isinstance(event, h2.events.StreamReset):
                if st is not None:
                    st["status"] = st["status"] or "RST"
                    st["done"] = True
            elif isinstance(event, h2.events.ConnectionTerminated):
                return False
        try:
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
        except OSError:
            return False
    return False


def blank(nonce):
    return {"nonce": nonce, "status": "", "body": bytearray(), "done": False,
            "headers_at": 0.0}


def emit(sts, mode, **extra):
    # Named `sts`, not `streams`: three modes want a "streams" COUNT in their
    # summary, and a positional parameter of that name silently turns into a
    # TypeError at the one moment the case needs a summary to read.
    for sid in sorted(sts):
        st = sts[sid]
        print(json.dumps({
            "stream": sid, "nonce": st["nonce"],
            "status": st["status"] or "NONE",
            "body": bytes(st["body"]).decode("utf8", "replace")[:400],
        }), flush=True)
    summary = {"summary": mode}
    summary.update(extra)
    print(json.dumps(summary), flush=True)


def nonces_for(args, n):
    if args.nonce:
        if len(args.nonce) < n:
            sys.stderr.write("need %d --nonce values, got %d\n"
                             % (n, len(args.nonce)))
            sys.exit(2)
        return args.nonce[:n]
    return ["h2life-%d" % i for i in range(n)]


def mode_rst(host, port, args):
    """Cancel a stream that is still in flight, keeping the connection."""
    sock, conn = new_conn(host, port)
    nonce = nonces_for(args, 1)[0]
    sid = send_request(conn, sock, host, port, args, nonce)
    streams = {sid: blank(nonce)}
    # Let the request reach the backend before cancelling it. Without this the
    # case can cancel a stream the gateway has not dispatched, which tests the
    # admission path and not the settle path.
    deadline = time.monotonic() + args.wait_ms / 1000.0
    finished = pump(conn, sock, streams, deadline)
    answered = bool(streams[sid]["status"])
    reset_sent = False
    if not finished:
        # Anything raised here — the stream already closed under us, the
        # socket gone — must still leave a summary line behind. A mode that
        # dies without one gives the scenario nothing to read, and "no
        # summary" would otherwise be indistinguishable from "the drive shape
        # was wrong".
        try:
            conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            reset_sent = True
        except Exception:      # noqa: BLE001
            pass
    # The connection outlives the stream on purpose: this mode exists to
    # isolate the per-stream close from the connection-teardown sweep, and a
    # socket dropped here would run both.
    time.sleep(args.linger_ms / 1000.0)
    try:
        conn.close_connection()
        sock.sendall(conn.data_to_send())
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
    emit(streams, "rst", reset=reset_sent, answered_before_reset=answered)
    return 0 if reset_sent else 3


def mode_kill(host, port, args):
    sock, conn = new_conn(host, port)
    ns = nonces_for(args, args.streams)
    streams = {}
    for nonce in ns:
        streams[send_request(conn, sock, host, port, args, nonce)] = blank(nonce)
    deadline = time.monotonic() + args.wait_ms / 1000.0
    finished = pump(conn, sock, streams, deadline)
    answered = sum(1 for st in streams.values() if st["status"])
    hard_close(sock)
    emit(streams, "kill", killed=not finished, answered_before_kill=answered,
         streams=len(streams))
    return 0 if not finished else 3


def mode_goaway(host, port, args):
    sock, conn = new_conn(host, port)
    ns = nonces_for(args, args.streams)
    streams = {}
    for nonce in ns:
        streams[send_request(conn, sock, host, port, args, nonce)] = blank(nonce)
    deadline = time.monotonic() + args.wait_ms / 1000.0
    finished = pump(conn, sock, streams, deadline)
    answered = sum(1 for st in streams.values() if st["status"])
    goaway_sent = False
    if not finished:
        # last_stream_id 0: every stream this connection opened is being
        # abandoned, which is the multi-stream fatal teardown under test.
        try:
            conn.close_connection(error_code=h2.errors.ErrorCodes.NO_ERROR,
                                  last_stream_id=0)
            sock.sendall(conn.data_to_send())
            goaway_sent = True
        except Exception:      # noqa: BLE001
            pass
    time.sleep(args.linger_ms / 1000.0)
    try:
        sock.close()
    except OSError:
        pass
    emit(streams, "goaway", sent=goaway_sent, answered_before_goaway=answered,
         streams=len(streams))
    return 0 if goaway_sent else 3


def mode_hdrkill(host, port, args):
    sock, conn = new_conn(host, port)
    nonce = nonces_for(args, 1)[0]
    sid = send_request(conn, sock, host, port, args, nonce)
    streams = {sid: blank(nonce)}
    deadline = time.monotonic() + args.wait_ms / 1000.0
    saw_headers = False
    while time.monotonic() < deadline and not saw_headers:
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            data = sock.recv(65535)
        except (socket.timeout, OSError):
            break
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, h2.events.ResponseReceived):
                st = streams.get(event.stream_id)
                if st is not None:
                    for name, value in event.headers:
                        if isinstance(name, bytes):
                            name = name.decode("utf8", "replace")
                        if isinstance(value, bytes):
                            value = value.decode("utf8", "replace")
                        if name == ":status":
                            st["status"] = value
                saw_headers = True
    # Stop reading, but do not die yet. The usage object rides the response
    # BODY, and this client is killing itself the moment the headers land: if
    # the socket went away now, whether the gateway had already read the
    # backend's DATA would be a race, and the token assertion would be
    # measuring scheduling. The gateway reads its backend regardless of this
    # client, so a short pause makes the usage's arrival certain while the
    # client is still the one that vanishes.
    time.sleep(args.linger_ms / 1000.0)
    hard_close(sock)
    emit(streams, "hdrkill", saw_headers=saw_headers)
    return 0 if saw_headers else 3


def mode_denyrst(host, port, args):
    """Cancel each denied stream before its error body is drained.

    The gateway answers an H2 denial itself, with HEADERS plus a DATA body
    read out of a per-stream provider. Resetting the stream the instant the
    headers arrive leaves that provider holding a body nghttp2 will now never
    read — the allocation whose release is under test. One connection, many
    streams, so what accumulates is per-STREAM state and not per-connection
    state.
    """
    # SETTINGS_INITIAL_WINDOW_SIZE = 0 BEFORE the first request. Without it
    # this mode cannot drive its own case: the gateway answers a denial with
    # HEADERS + DATA + END_STREAM in a single burst, so by the time the client
    # has seen the status the stream is already closed and RST_STREAM raises
    # instead of being sent. With the window shut the body cannot leave the
    # gateway at all -- it stays in the per-stream provider, which is exactly
    # the "reset before the deny body is drained" shape.
    sock, conn = new_conn(host, port, timeout=20)
    conn.update_settings(
        {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
    sock.sendall(conn.data_to_send())
    denied = 0
    reset = 0
    undrained = 0
    statuses = set()
    for i in range(args.streams):
        sid = send_request(conn, sock, host, port, args, "h2life-deny-%d" % i)
        deadline = time.monotonic() + 5.0
        got = False
        ended = False
        while time.monotonic() < deadline and not got:
            try:
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                data = sock.recv(65535)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    if event.stream_id == sid:
                        for name, value in event.headers:
                            if isinstance(name, bytes):
                                name = name.decode("utf8", "replace")
                            if isinstance(value, bytes):
                                value = value.decode("utf8", "replace")
                            if name == ":status":
                                statuses.add(value)
                        got = True
                elif isinstance(event, h2.events.StreamEnded):
                    # The body was delivered after all, so this stream is NOT
                    # the shape under test. Counted rather than ignored: a run
                    # where every stream ended is a run that tested nothing,
                    # and the scenario must be able to see that.
                    if event.stream_id == sid:
                        ended = True
                elif isinstance(event, h2.events.ConnectionTerminated):
                    print(json.dumps({"summary": "denyrst", "denied": denied,
                                      "reset": reset, "undrained": undrained,
                                      "asked": args.streams,
                                      "statuses": sorted(statuses),
                                      "terminated_at": i}), flush=True)
                    return 3
        if not got:
            break
        denied += 1
        if not ended:
            undrained += 1
        try:
            conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
            sock.sendall(conn.data_to_send())
            reset += 1
        except Exception:      # noqa: BLE001
            break
    try:
        conn.close_connection()
        sock.sendall(conn.data_to_send())
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
    print(json.dumps({"summary": "denyrst", "denied": denied, "reset": reset,
                      "undrained": undrained, "asked": args.streams,
                      "statuses": sorted(statuses)}), flush=True)
    return 0 if denied == args.streams else 3


def mode_hold(host, port, args):
    sock, conn = new_conn(host, port, timeout=max(30, args.wait_ms // 1000 + 10))
    ns = nonces_for(args, args.streams)
    streams = {}
    for nonce in ns:
        streams[send_request(conn, sock, host, port, args, nonce)] = blank(nonce)
    print(json.dumps({"sent": len(streams)}), flush=True)
    deadline = time.monotonic() + args.wait_ms / 1000.0
    finished = pump(conn, sock, streams, deadline)
    try:
        sock.close()
    except OSError:
        pass
    emit(streams, "hold", finished=finished, streams=len(streams))
    return 0


def one_full_request(sock, conn, host, port, args, nonce, timeout):
    sid = send_request(conn, sock, host, port, args, nonce)
    streams = {sid: blank(nonce)}
    pump(conn, sock, streams, time.monotonic() + timeout)
    return sid, streams[sid]


def mode_control(host, port, args):
    """A long-lived connection must survive other connections being recycled."""
    sock, conn = new_conn(host, port, timeout=30)
    ns = nonces_for(args, 2)
    sid1, st1 = one_full_request(sock, conn, host, port, args, ns[0], 15)

    churn_fail = 0
    for _ in range(args.churn):
        try:
            csock, cconn = new_conn(host, port, timeout=10)
            cargs = argparse.Namespace(**vars(args))
            cargs.delay_ms = 0
            # The churn is about connections, not quota: a full-size claim
            # sixty times over would exhaust whatever bucket the service
            # sits behind and the second control request would be refused
            # for a reason that has nothing to do with the descriptor under
            # test.
            cargs.max_tokens = 1
            csid = send_request(cconn, csock, host, port, cargs, "h2life-churn")
            pump(cconn, csock, {csid: blank("h2life-churn")},
                 time.monotonic() + 10)
            hard_close(csock)
        except OSError:
            churn_fail += 1

    sid2, st2 = one_full_request(sock, conn, host, port, args, ns[1], 15)
    try:
        conn.close_connection()
        sock.sendall(conn.data_to_send())
        sock.close()
    except OSError:
        pass
    emit({sid1: st1, sid2: st2}, "control", churn=args.churn,
         churn_failures=churn_fail)
    return 0


def label_of(st):
    """The backend label out of an echo reply, "" when the body is not one."""
    try:
        return str(json.loads(bytes(st["body"]).decode("utf8", "replace"))
                   .get("label", ""))
    except (ValueError, AttributeError):
        return ""


def mode_pin(host, port, args):
    """k sequential streams on one connection: which endpoint answered each?

    Sequential on purpose. A bounded-load selector is ALLOWED to spill when
    several streams of one hash are in flight at once; with one stream in
    flight at a time the hashed endpoint's load is at most 1, so any spill
    can only come from units that were never handed back.
    """
    sock, conn = new_conn(host, port, timeout=20)
    sts = {}
    labels = {}
    completed = 0
    for i in range(args.streams):
        nonce = "h2life-pin-%d" % i
        try:
            sid, st = one_full_request(sock, conn, host, port, args, nonce, 10)
        except OSError:
            break
        sts[sid] = st
        if st["done"] and st["status"] == "200":
            completed += 1
        label = label_of(st) or ("status-%s" % (st["status"] or "NONE"))
        labels[label] = labels.get(label, 0) + 1
        if not st["done"]:
            break
    try:
        conn.close_connection()
        sock.sendall(conn.data_to_send())
        sock.close()
    except OSError:
        pass
    emit(sts, "pin", asked=args.streams, completed=completed, labels=labels)
    return 0 if completed == args.streams else 3


MODES = {"rst": mode_rst, "kill": mode_kill, "goaway": mode_goaway,
         "hdrkill": mode_hdrkill, "hold": mode_hold, "control": mode_control,
         "denyrst": mode_denyrst, "pin": mode_pin}


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("mode", choices=sorted(MODES))
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--token", default="")
    ap.add_argument("--token-file", default="")
    ap.add_argument("--model", default="llama-70b")
    ap.add_argument("--max-tokens", type=int, default=600)
    ap.add_argument("--nonce", action="append", default=[])
    ap.add_argument("--delay-ms", type=int, default=0)
    ap.add_argument("--wait-ms", type=int, default=1500)
    ap.add_argument("--linger-ms", type=int, default=300)
    ap.add_argument("--streams", type=int, default=1)
    ap.add_argument("--churn", type=int, default=50)
    ap.add_argument("--system", default="")
    args = ap.parse_args()
    if args.token_file:
        with open(args.token_file) as f:
            args.token = f.read().strip()
    try:
        return MODES[args.mode](args.host, args.port, args)
    except Exception as exc:      # noqa: BLE001
        # Broad on purpose: the scenario reads the summary line to decide
        # whether the shape it asked for was driven, and a traceback with no
        # summary reads the same as a shape that silently degraded.
        print(json.dumps({"summary": args.mode, "error": "%s: %s"
                          % (type(exc).__name__, exc)}), flush=True)
        return 4


if __name__ == "__main__":
    sys.exit(main())
