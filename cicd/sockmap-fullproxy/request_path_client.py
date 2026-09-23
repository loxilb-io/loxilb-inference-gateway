#!/usr/bin/env python3
"""request_path_client.py - raw HTTP/1.1 client for validation_request_path.sh.

Each mode drives one request shape through the proxy against
request_path_server.js, which answers with the path, length and sha256 of the
body it received. A mode prints one line starting with OK or FAIL and exits 0
on OK.

  split     <host> <port> <conns>   first request headers and body in separate
                                    writes, ending with a 1 byte tail; then a
                                    second request whose header block ends in a
                                    separate 2 byte write
  stream    <host> <port> <mb>      streamed upload (application/octet-stream,
                                    above the 64KB streaming threshold) sent
                                    without pauses, then a second request on the
                                    same connection
  pipeline  <host> <port>           three requests in one write, then two more
                                    right behind them
  halfclose <host> <port>           request, then shutdown(SHUT_WR); expects an answer
  halfslow  <host> <port> [ms]      same, against a backend that holds the response
                                    back ms (default 500); expects an answer
  halfsplit <host> <port> [ms]      same, against a backend that sends the opening
                                    bytes at once and the rest ms later; expects
                                    the WHOLE body, not just the opening bytes
  halfmid   <host> <port> [ms]      the same split response, but the client waits
                                    for the opening bytes BEFORE shutdown(SHUT_WR);
                                    expects the whole body
  halfinflight <host> <port>        half-closes while the rest of a 256KB answer is
                                    still in the pipeline; expects the whole body
  halfprefix <host> <port>          the same, but passes on ANY length as long as
                                    what arrived is a correct prefix of the pattern:
                                    a hole or reordering fails, a clean cut does not
  halfpartial <host> <port>         half a request, then shutdown(SHUT_WR); the
                                    connection goes away and the service keeps
                                    serving a fresh one
  keepalive <host> <port> <secs> <interval_ms>
                                    one request per interval on one connection
  echo      <host> <port>           one connection, a fixed request sequence
                                    (bodies of 0/100/65535/65536/70000 bytes);
                                    prints one JSON record per request for the
                                    equivalence diff instead of a verdict
  chunked   <host> <port>           Transfer-Encoding: chunked request body
  sizes     <host> <port>           responses of 1/65535/65536/307200/1048576
                                    bytes, verified against the backend pattern
  special   <host> <port>           204, 304 and HEAD on one connection
  abort     <host> <port> [n]       backend promises 2N bytes, sends N, then FIN;
                                    repeated n times (the race is intermittent)
  idle      <host> <port> <secs>    connect, wait secs sending nothing, then use
                                    the connection (it was never accelerated)
  volume    <host> <port> [hold]    one connection, the echo sequence then the
                                    sizes sequence: a fixed byte volume in both
                                    directions for the counter comparison. With
                                    hold, prints DONE and keeps the connection
                                    open for hold seconds before closing it

The echo mode is the only one that prints records rather than OK/FAIL: the
equivalence suite diffs its output across acceleration modes.
"""
import hashlib
import json
import socket
import sys
import time

TIMEOUT = 10


def connect(host, port):
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


class Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''
        self.head = None   # the last response head split off; None until then

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError('connection closed')
        self.buf += chunk

    def response_full(self, no_body=False):
        """Returns (status, headers dict, body). no_body is for HEAD, where
        Content-Length describes the body a GET would have carried."""
        self.head = None
        while b'\r\n\r\n' not in self.buf:
            self._fill()
        head, self.buf = self.buf.split(b'\r\n\r\n', 1)
        self.head = head
        lines = head.decode('latin-1').split('\r\n')
        status = int(lines[0].split()[1])
        headers = {}
        length = 0
        for line in lines[1:]:
            k, _, v = line.partition(':')
            k = k.strip().lower()
            if not k:
                continue
            headers[k] = v.strip()
            if k == 'content-length':
                length = int(v.strip())
        if no_body:
            length = 0
        while len(self.buf) < length:
            self._fill()
        body, self.buf = self.buf[:length], self.buf[length:]
        return status, headers, body

    def response(self):
        status, _, body = self.response_full()
        return status, body

    def drain(self):
        """Reads whatever is left until EOF. Returns the bytes received."""
        try:
            while True:
                self._fill()
        except (EOFError, ConnectionResetError):
            pass
        out, self.buf = self.buf, b''
        return out


def request(method, path, host, body=b'', ctype='text/plain'):
    head = '%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (
        method, path, host, ctype, len(body))
    return head.encode(), body


# The backend fills ?bytes= responses with this 64 byte block repeated, so a body
# of any length is verifiable without shipping an expected copy.
PATTERN = hashlib.sha256(b'sockmap-pattern').hexdigest().encode()


def pattern(n):
    return (PATTERN * (-(-n // len(PATTERN))))[:n]


def first_diff(got, want):
    for i in range(min(len(got), len(want))):
        if got[i] != want[i]:
            return i
    return min(len(got), len(want))


def check(status, body, path, payload=b''):
    if status != 200:
        return 'status %d on %s' % (status, path)
    try:
        got = json.loads(body)
    except ValueError:
        return 'unparseable body on %s: %r' % (path, body[:80])
    if got.get('path') != path:
        return 'wrong response: expected %s, got %s' % (path, got.get('path'))
    if got.get('len') != len(payload) or got.get('sha256') != hashlib.sha256(payload).hexdigest():
        return 'body mismatch on %s: sent %d bytes, backend got %s' % (path, len(payload), got.get('len'))
    return None


def mode_split(host, port, conns):
    for c in range(conns):
        s = connect(host, port)
        r = Reader(s)
        payload = (b'split-%d-' % c) * 2000
        head, body = request('POST', '/split1', host, payload)
        s.sendall(head)
        time.sleep(0.01)
        s.sendall(body[:-1])
        time.sleep(0.02)
        s.sendall(body[-1:])
        err = check(*r.response(), '/split1', payload)
        if err:
            return 'FAIL conn %d: %s' % (c, err)
        head, _ = request('GET', '/split2', host)
        s.sendall(head[:-2])
        time.sleep(0.02)
        s.sendall(head[-2:])
        err = check(*r.response(), '/split2')
        if err:
            return 'FAIL conn %d: %s' % (c, err)
        s.close()
    return 'OK %d connections' % conns


def mode_stream(host, port, mb):
    s = connect(host, port)
    r = Reader(s)
    payload = hashlib.sha256(b'seed').digest() * (mb * 1024 * 1024 // 32)
    head, body = request('POST', '/stream', host, payload, 'application/octet-stream')
    s.sendall(head)
    for off in range(0, len(body), 65536):
        s.sendall(body[off:off + 65536])
    err = check(*r.response(), '/stream', payload)
    if err:
        return 'FAIL ' + err
    for i in range(3):
        head, _ = request('GET', '/after%d' % i, host)
        s.sendall(head)
        err = check(*r.response(), '/after%d' % i)
        if err:
            return 'FAIL ' + err
    s.close()
    return 'OK %d bytes' % len(payload)


def mode_pipeline(host, port):
    s = connect(host, port)
    r = Reader(s)
    paths = ['/p1', '/p2', '/p3', '/p4', '/p5']
    bodies = [b'a' * 1000, b'', b'c' * 3000, b'', b'e' * 10]
    reqs = [b''.join(request('POST', p, host, b)) for p, b in zip(paths, bodies)]
    s.sendall(reqs[0] + reqs[1] + reqs[2])
    time.sleep(0.001)
    s.sendall(reqs[3])
    s.sendall(reqs[4])
    for p, b in zip(paths, bodies):
        err = check(*r.response(), p, b)
        if err:
            return 'FAIL ' + err
    s.close()
    return 'OK 5 pipelined requests in order'


def mode_halfclose(host, port):
    s = connect(host, port)
    r = Reader(s)
    head, _ = request('GET', '/halfclose', host)
    s.sendall(head)
    s.shutdown(socket.SHUT_WR)
    err = check(*r.response(), '/halfclose')
    s.close()
    return 'FAIL ' + err if err else 'OK'


def mode_halfslow(host, port, ms=500):
    """halfclose against a slow backend. An immediate backend cannot tell whether
    the proxy waits for the response: it answers inside the proxy's deferred-close
    bound either way. Holding the response past that bound is what distinguishes
    "the response leg is kept open" from "the pair is torn down on a timer".

    Only meaningful through the proxy. Pointed straight at request_path_server.js
    this fails on the backend rather than the proxy: Node's HTTP server destroys a
    connection whose peer half-closes (httpAllowHalfOpen defaults to false). The
    proxy does not propagate the client's FIN to the backend, so the backend never
    sees the half-close on the path under test."""
    s = connect(host, port)
    r = Reader(s)
    path = '/halfslow?rdelay=%d' % ms
    head, _ = request('GET', path, host)
    s.sendall(head)
    s.shutdown(socket.SHUT_WR)
    err = check(*r.response(), path)
    s.close()
    return 'FAIL ' + err if err else 'OK answered after %dms' % ms


def mode_halfsplit(host, port, ms=500):
    """A half-closed client whose answer has already started.

    halfslow holds the whole response back, so a proxy that gives up mid-wait
    always yields a clean EOF and the case cannot tell "nothing was sent" from
    "what was sent got cut". Here the opening bytes arrive at once under a
    promised Content-Length and the rest follows ms later, so a proxy that
    delivers the opening and drops the remainder is a FAIL rather than a pass.
    That is the shape of real inference traffic, and the reason this case exists
    alongside halfslow rather than replacing it.

    Kept small on purpose: an unpatched kernel duplicates bytes on an accelerated
    response at multi-megabyte sizes, which would make the length check meaningless.

    Only meaningful through the proxy, for the reason in mode_halfslow."""
    return _split_case(host, port, ms, '/halfsplit', wait_for_opening=False)


def mode_halfmid(host, port, ms=500):
    """halfsplit, but the client half-closes with the answer already in flight.

    Every other half-* mode shuts its write side down before a single response
    byte exists, so none of them produces the order where the FIN lands on top of
    a response the proxy has already begun. Two things ride on that order:

      - It is the only case that shows layer 1 truncating a stream rather than
        losing it whole: off and request deliver the opening bytes and then drop
        the remainder, where halfsplit has them deliver nothing at all.
      - It is the worst order for a fix that responds to the FIN by dropping the
        connection's acceleration, because the kernel may already hold response
        bytes taken for redirect and no userspace queue can see them.

    Keep it even if that fix is not the one taken: the first point stands on its
    own. Only meaningful through the proxy, for the reason in mode_halfslow."""
    return _split_case(host, port, ms, '/halfmid', wait_for_opening=True)


def mode_halfinflight(host, port):
    """A half-close that lands while the answer is still moving.

    halfmid waits for the opening bytes and the backend then stays silent, so by
    the time the FIN goes out the kernel has delivered everything it was given
    and nothing is in flight. That is the same queue state as halfsplit; what
    halfmid varies is the connection's state, not the kernel's.

    Here the remainder follows the opening immediately and is far larger than one
    buffer hop, so when the client reads its 4096 bytes and half-closes, the rest
    is provably still in the pipeline. It is the order that matters to any fix
    which responds to the FIN by dropping the connection's acceleration: the
    unpair then happens on top of bytes the kernel has taken for redirect and no
    userspace queue can see.

    256KB is under the largest size measured intact on an unpatched kernel
    (300KB); above that an accelerated response duplicates bytes and the length
    check stops meaning anything.

    Expect this to PASS on the arms where it passes today and keep passing: it is
    a regression guard for that fix, not a defect case of its own."""
    return _split_case(host, port, 0, '/halfinflight', wait_for_opening=True,
                       total=262144)


def mode_halfprefix(host, port):
    """halfinflight's shape with a different question.

    halfinflight asked for the whole body, and its answer turned on whether
    256KB beat the proxy's deferred-close bound - which depends on the load in
    front of it, so it was withdrawn. This asks only that whatever DID arrive is
    the pattern's correct prefix: bytes 0..N-1, contiguous. A response cut short
    by the bound still passes, because it is only late. A response with a hole,
    or with a later chunk delivered before an earlier one, fails at the offset.

    That is exactly the split the withdrawn case could not make, and it is the
    failure a fix that drops the connection's acceleration on the FIN could
    introduce: the kernel may still hold response bytes taken for redirect at
    that moment, and if userspace then relays bytes that arrive after them, the
    two orders race to the client. Passes on all four arms today, on purpose -
    it is a guard, and it is registered as nothing."""
    return _split_case(host, port, 0, '/halfprefix', wait_for_opening=True,
                       total=262144, prefix_only=True)


def _prefix_verdict(body, total):
    """None if body is the pattern's correct prefix, else the failing offset."""
    want = pattern(min(len(body), total))
    if body[:len(want)] == want:
        return None
    return first_diff(body, want)


def _split_case(host, port, ms, path_base, wait_for_opening, total=65536,
                prefix_only=False):
    first = 4096
    s = connect(host, port)
    r = Reader(s)
    path = '%s?bytes=%d&split=%d&rdelay=%d' % (path_base, total, first, ms)
    head, _ = request('GET', path, host)
    s.sendall(head)
    if wait_for_opening:
        try:
            while b'\r\n\r\n' not in r.buf or \
                    len(r.buf.split(b'\r\n\r\n', 1)[1]) < first:
                r._fill()
        except (OSError, EOFError) as e:
            return 'FAIL the opening bytes never arrived (%s)' % e
    s.shutdown(socket.SHUT_WR)
    try:
        status, headers, body = r.response_full()
    except (OSError, EOFError) as e:
        if r.head is None:
            return 'FAIL cut before the headers completed (%s)' % e
        got = r.buf
        bad = _prefix_verdict(got, total)
        if bad is not None:
            return 'FAIL body differs at offset %d of %d received (%s)' % (bad, len(got), e)
        if prefix_only:
            return 'OK %d of %d bytes, a correct prefix (cut: %s)' % (len(got), total, e)
        return 'FAIL cut after %d bytes, a correct prefix (%s)' % (len(got), e)
    if status != 200:
        return 'FAIL status %d' % status
    if headers.get('content-length') != str(total):
        return 'FAIL promised %s bytes, expected %d' % (headers.get('content-length'), total)
    if len(body) != total:
        return 'FAIL truncated: promised %d, got %d' % (total, len(body))
    want = pattern(total)
    if body != want:
        return 'FAIL body differs at offset %d' % first_diff(body, want)
    if prefix_only:
        return 'OK %d bytes, the whole body' % total
    return 'OK %d bytes, opening %d then the rest after %dms' % (total, first, ms)


def mode_keepalive(host, port, secs, interval_ms):
    s = connect(host, port)
    r = Reader(s)
    end = time.time() + secs
    ok = 0
    while time.time() < end:
        path = '/ka%d' % ok
        head, _ = request('GET', path, host)
        try:
            s.sendall(head)
            err = check(*r.response(), path)
        except (OSError, EOFError) as e:
            err = str(e)
        if err:
            return 'FAIL after %d requests: %s' % (ok, err)
        ok += 1
        time.sleep(interval_ms / 1000.0)
    s.close()
    return 'OK %d requests' % ok


# One connection, a fixed sequence that crosses the 64KB streaming threshold.
# Request 1 is served by userspace on every mode; requests 2+ are the ones the
# kernel carries once the request direction is active, which is where a skipped
# header rewrite would show up.
ECHO_SEQ = [('GET', '/e1', 0), ('POST', '/e2', 100), ('POST', '/e3', 65535),
            ('POST', '/e4', 65536), ('POST', '/e5', 70000), ('GET', '/e6', 0)]


def mode_echo(host, port):
    s = connect(host, port)
    r = Reader(s)
    out = []
    for i, (method, path, blen) in enumerate(ECHO_SEQ):
        payload = pattern(blen)
        head, body = request(method, path, host, payload)
        s.sendall(head + body)
        status, hdrs, rbody = r.response_full()
        try:
            backend = json.loads(rbody)
        except ValueError:
            backend = {'unparseable': rbody[:120].decode('latin-1')}
        out.append(json.dumps({'i': i, 'req': '%s %s' % (method, path),
                               'sent': blen, 'status': status,
                               'rhdr': hdrs, 'backend': backend},
                              sort_keys=True))
    s.close()
    return '\n'.join(out)


def mode_chunked(host, port):
    s = connect(host, port)
    r = Reader(s)
    payload = pattern(30000)
    head = ('POST /chunked HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\n'
            'Transfer-Encoding: chunked\r\n\r\n' % host).encode()
    s.sendall(head)
    for off in range(0, len(payload), 4096):
        chunk = payload[off:off + 4096]
        s.sendall(b'%x\r\n' % len(chunk) + chunk + b'\r\n')
    s.sendall(b'0\r\n\r\n')
    err = check(*r.response(), '/chunked', payload)
    if err:
        return 'FAIL ' + err
    head, _ = request('GET', '/afterchunked', host)
    s.sendall(head)
    err = check(*r.response(), '/afterchunked')
    s.close()
    return 'FAIL ' + err if err else 'OK %d bytes chunked, connection reusable' % len(payload)


SIZES = [1, 65535, 65536, 307200, 1048576]


def mode_sizes(host, port):
    s = connect(host, port)
    r = Reader(s)
    for n in SIZES:
        head, _ = request('GET', '/size?bytes=%d' % n, host)
        s.sendall(head)
        status, _, body = r.response_full()
        if status != 200:
            return 'FAIL status %d at bytes=%d' % (status, n)
        if len(body) != n:
            return 'FAIL bytes=%d: received %d bytes' % (n, len(body))
        want = pattern(n)
        if body != want:
            return 'FAIL bytes=%d: content differs at offset %d' % (n, first_diff(body, want))
    s.close()
    return 'OK sizes %s' % ','.join(str(n) for n in SIZES)


def mode_volume(host, port, hold=0):
    s = connect(host, port)
    r = Reader(s)
    n = 0
    for method, path, blen in ECHO_SEQ:
        payload = pattern(blen)
        head, body = request(method, path, host, payload)
        s.sendall(head + body)
        status, _, _ = r.response_full()
        if status != 200:
            return 'FAIL status %d at %s' % (status, path)
        n += 1
    for size in SIZES:
        head, _ = request('GET', '/size?bytes=%d' % size, host)
        s.sendall(head)
        status, _, body = r.response_full()
        if status != 200 or len(body) != size:
            return 'FAIL bytes=%d: status %d, received %d' % (size, status, len(body))
        n += 1
    if hold:
        print('DONE %d requests' % n, flush=True)
        time.sleep(hold)
    s.close()
    return 'OK %d requests' % n


def mode_special(host, port):
    s = connect(host, port)
    r = Reader(s)
    for code in (204, 304):
        head, _ = request('GET', '/special?status=%d' % code, host)
        s.sendall(head)
        status, _, body = r.response_full()
        if status != code or body:
            return 'FAIL status=%d answered %d with %d body bytes' % (code, status, len(body))
    s.sendall(('HEAD /head?bytes=1000 HTTP/1.1\r\nHost: %s\r\n\r\n' % host).encode())
    status, hdrs, body = r.response_full(no_body=True)
    if status != 200 or body:
        return 'FAIL HEAD answered %d with %d body bytes' % (status, len(body))
    if hdrs.get('content-length') != '1000':
        return 'FAIL HEAD content-length %r' % hdrs.get('content-length')
    head, _ = request('GET', '/afterspecial', host)
    s.sendall(head)
    err = check(*r.response(), '/afterspecial')
    s.close()
    return 'FAIL ' + err if err else 'OK 204/304/HEAD, connection reusable'


ABORT_N = 50000


def mode_abort(host, port, n=1, delay=0):
    """Repeated on purpose. When the response direction is accelerated the
    backend's FIN can beat its own redirected bytes to the client, and that race
    is lost only some of the time — a single attempt reports a defect present as
    a pass most runs, which is worse than not testing it."""
    bad = []
    for i in range(n):
        err = _abort_once(host, port, delay)
        if err:
            bad.append(err)
    # The count is always reported, in a fixed shape the suite parses, so a rate
    # that grows is visible even where the case does not fail on it.
    if bad:
        return 'FAIL %d/%d early: %s' % (len(bad), n, bad[0])
    return 'OK 0/%d early' % n


def _abort_once(host, port, delay=0):
    """Returns None when the truncation looked as it does without acceleration,
    or a description of how it differed."""
    s = connect(host, port)
    r = Reader(s)
    head, _ = request('GET', '/abort?abort=%d&delay=%d' % (ABORT_N, delay), host)
    s.sendall(head)
    try:
        while b'\r\n\r\n' not in r.buf:
            r._fill()
    except (EOFError, ConnectionResetError) as e:
        s.close()
        return 'closed before the response headers arrived (%s)' % type(e).__name__
    hdr, r.buf = r.buf.split(b'\r\n\r\n', 1)
    lines = hdr.decode('latin-1').split('\r\n')
    status = int(lines[0].split()[1])
    promised = 0
    for line in lines[1:]:
        k, _, v = line.partition(':')
        if k.strip().lower() == 'content-length':
            promised = int(v.strip())
    body = r.drain()
    s.close()
    if status != 200 or promised != ABORT_N * 2:
        return 'status=%d content-length=%d' % (status, promised)
    if len(body) != ABORT_N:
        return 'delivered %d of the %d bytes the backend sent' % (len(body), ABORT_N)
    if body != pattern(ABORT_N):
        return 'content differs at offset %d' % first_diff(body, pattern(ABORT_N))
    return None


def mode_halfpartial(host, port):
    """A request that stops half way and then half-closes can never complete, so
    the connection must end — either with no answer at all or with a 4xx. What it
    must NOT do is hang, and it must not disturb the service."""
    s = connect(host, port)
    r = Reader(s)
    head, _ = request('GET', '/halfpartial', host)
    s.sendall(head[:len(head) // 2])
    s.shutdown(socket.SHUT_WR)
    got = r.drain()
    s.close()
    answer = 'none'
    if got:
        first = got.split(b'\r\n', 1)[0].decode('latin-1')
        if not first.startswith('HTTP/1.'):
            return 'FAIL a partial request drew a non-HTTP answer: %r' % got[:80]
        code = first.split()[1] if len(first.split()) > 1 else '?'
        if not code.startswith('4'):
            return 'FAIL a partial request was answered %s' % first
        answer = code
    s2 = connect(host, port)
    r2 = Reader(s2)
    head, _ = request('GET', '/afterpartial', host)
    s2.sendall(head)
    err = check(*r2.response(), '/afterpartial')
    s2.close()
    if err:
        return 'FAIL ' + err
    return 'OK partial request closed (answer: %s), service intact' % answer


def mode_idle(host, port, secs):
    """Connects, sends nothing for secs, then uses the connection. A connection
    that has not sent a request has no socket pair, so it is NOT accelerated: an
    admin teardown of the rule's accelerated connections must leave it alone."""
    s = connect(host, port)
    r = Reader(s)
    time.sleep(secs)
    head, _ = request('GET', '/idle', host)
    s.sendall(head)
    err = check(*r.response(), '/idle')
    s.close()
    return 'FAIL ' + err if err else 'OK idle connection usable after %ss' % secs


# Modes that print records for the equivalence diff instead of a verdict.
RECORD_MODES = {'echo'}

MODES = {'split': mode_split, 'stream': mode_stream, 'pipeline': mode_pipeline,
         'halfclose': mode_halfclose, 'halfslow': mode_halfslow,
         'halfsplit': mode_halfsplit, 'halfmid': mode_halfmid,
         'halfinflight': mode_halfinflight, 'halfprefix': mode_halfprefix,
         'halfpartial': mode_halfpartial,
         'keepalive': mode_keepalive, 'echo': mode_echo, 'chunked': mode_chunked,
         'sizes': mode_sizes, 'special': mode_special, 'abort': mode_abort,
         'idle': mode_idle, 'volume': mode_volume}


def main():
    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    args = [int(a) if a.lstrip('-').isdigit() else a for a in sys.argv[4:]]
    failed = False
    try:
        out = MODES[mode](host, port, *args)
    except (OSError, EOFError, ValueError) as e:
        out = 'FAIL %s: %s' % (type(e).__name__, e)
        failed = True
    print(out)
    if mode in RECORD_MODES:
        sys.exit(1 if failed else 0)
    sys.exit(0 if out.startswith('OK') else 1)


if __name__ == '__main__':
    main()
