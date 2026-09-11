// perf_server.js - backend HTTP server for sockmap-fullproxy performance comparison.
//
//   node perf_server.js <name> <port> [defaultBytes]
//
// GET /?bytes=N lets the client choose the response body size (defaultBytes if
// omitted). <name> is stamped at the start of the body so the backend is identifiable.
// keep-alive is on. The same code serves both ports (9080/9090) to keep the on/off
// comparison fair.

const http = require('http');
const url = require('url');

const name = process.argv[2] || 'server';
const port = parseInt(process.argv[3] || '9080', 10);
const defaultBytes = parseInt(process.argv[4] || '256', 10);

const MAX_BYTES = 4 * 1024 * 1024;
const bigBuf = Buffer.alloc(MAX_BYTES, 'x');
Buffer.from(name + ':').copy(bigBuf, 0); // leading identifier

const server = http.createServer((req, res) => {
  const q = url.parse(req.url, true).query;
  let n = parseInt(q.bytes, 10);
  if (!Number.isInteger(n) || n < 0 || n > MAX_BYTES) n = defaultBytes;
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': n,
  });
  res.end(bigBuf.subarray(0, n));
});

// keep-alive must be held long enough for sockmap splice to engage on the connection.
server.keepAliveTimeout = 120000;
server.headersTimeout = 125000;
server.maxRequestsPerSocket = 0; // unlimited

server.listen(port, () => {
  console.log(`${name} perf_server listening on :${port} (default ${defaultBytes}B)`);
});
