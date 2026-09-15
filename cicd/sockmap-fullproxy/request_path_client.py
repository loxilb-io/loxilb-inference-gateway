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
  keepalive <host> <port> <secs> <interval_ms>
                                    one request per interval on one connection
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

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError('connection closed')
        self.buf += chunk

    def response(self):
        while b'\r\n\r\n' not in self.buf:
            self._fill()
        head, self.buf = self.buf.split(b'\r\n\r\n', 1)
        lines = head.decode('latin-1').split('\r\n')
        status = int(lines[0].split()[1])
        length = 0
        for line in lines[1:]:
            k, _, v = line.partition(':')
            if k.strip().lower() == 'content-length':
                length = int(v.strip())
        while len(self.buf) < length:
            self._fill()
        body, self.buf = self.buf[:length], self.buf[length:]
        return status, body


def request(method, path, host, body=b'', ctype='text/plain'):
    head = '%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (
        method, path, host, ctype, len(body))
    return head.encode(), body


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


def main():
    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    args = [int(a) for a in sys.argv[4:]]
    fn = {'split': mode_split, 'stream': mode_stream, 'pipeline': mode_pipeline,
          'halfclose': mode_halfclose, 'keepalive': mode_keepalive}[mode]
    try:
        out = fn(host, port, *args)
    except (OSError, EOFError, ValueError) as e:
        out = 'FAIL %s: %s' % (type(e).__name__, e)
    print(out)
    sys.exit(0 if out.startswith('OK') else 1)


if __name__ == '__main__':
    main()
