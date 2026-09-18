// request_path_server.js - HTTP/1.1 backend for the sockmap request-path and
// equivalence scenarios.
//
// Answers every request with what it received, so the client can tell whether
// the proxy delivered the request intact, in order and UNMODIFIED:
//   {"name","method","path","len","sha256","headers"}
// headers is every request header the backend saw (Node lowercases the names),
// which is what makes header injection or removal by the proxy visible to the
// client. len/sha256 cover the request body.
//
// Query knobs, for the response shapes the equivalence suite compares:
//   ?bytes=N   respond with N bytes of PATTERN instead of the JSON echo
//   ?status=N  respond with status N (204/304 carry no body)
//   ?abort=N   write N bytes, promise 2N, then FIN mid-response
// A HEAD request gets the GET headers and no body.
//
// PATTERN is sha256("sockmap-pattern") in hex, repeated — the client derives the
// same 64 bytes, so a body of any length is verifiable without transferring an
// expected copy.
//
//   node request_path_server.js <name> <port>
var http = require('http');
var crypto = require('crypto');

var name = process.argv[2] || 'server';
var port = parseInt(process.argv[3] || '8080', 10);

var PATTERN = crypto.createHash('sha256').update('sockmap-pattern').digest('hex');

function pattern(n) {
  var out = Buffer.alloc(n);
  for (var off = 0; off < n; off += PATTERN.length) {
    out.write(PATTERN, off, Math.min(PATTERN.length, n - off), 'latin1');
  }
  return out;
}

function query(url, key) {
  var m = url.match(new RegExp('[?&]' + key + '=([0-9]+)'));
  return m ? parseInt(m[1], 10) : null;
}

var server = http.createServer(function (req, res) {
  var hash = crypto.createHash('sha256');
  var len = 0;
  req.on('data', function (chunk) {
    hash.update(chunk);
    len += chunk.length;
  });
  req.on('end', function () {
    var abort = query(req.url, 'abort');
    if (abort !== null) {
      // ?delay=ms holds the FIN back after the short write. It isolates a race:
      // if a truncation only loses bytes when the FIN follows immediately, the
      // bytes were still in flight when the connection was torn down.
      var delay = query(req.url, 'delay');
      // Headers promise more than is sent, then the socket dies: the client must
      // see the same truncation with and without acceleration.
      res.writeHead(200, { 'Content-Type': 'application/octet-stream',
                           'Content-Length': String(abort * 2) });
      res.write(pattern(abort));
      // FIN, not RST: a reset can make the client's stack discard the bytes it
      // already buffered, which would make the truncation length flaky.
      if (delay) {
        setTimeout(function () { res.socket.end(); }, delay);
      } else {
        res.socket.end();
      }
      return;
    }

    var status = query(req.url, 'status');
    if (status !== null) {
      // 204 and 304 are body-less by definition; Node enforces that.
      res.writeHead(status);
      res.end();
      return;
    }

    var bytes = query(req.url, 'bytes');
    if (bytes !== null) {
      var body = pattern(bytes);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream',
                           'Content-Length': String(body.length) });
      if (req.method === 'HEAD') {
        res.end();
      } else {
        res.end(body);
      }
      return;
    }

    var headers = {};
    Object.keys(req.headers).sort().forEach(function (k) {
      headers[k] = req.headers[k];
    });
    var json = JSON.stringify({ name: name, method: req.method, path: req.url,
                                len: len, sha256: hash.digest('hex'),
                                headers: headers });
    res.writeHead(200, { 'Content-Type': 'application/json',
                         'Content-Length': Buffer.byteLength(json) });
    if (req.method === 'HEAD') {
      res.end();
    } else {
      res.end(json);
    }
  });
});
server.keepAliveTimeout = 30000;
server.listen(port);
