// perf_client.js - closed-loop load generator for sockmap-fullproxy comparison.
//
//   node perf_client.js <host> <port> <concurrency> <durMs> <bytes> <warmMs> [upBytes]
//
// Holds <concurrency> keep-alive connections and fires GET /?bytes=<bytes> back to
// back. keep-alive is required: sockmap splice only engages on a connection after its
// first request. The first warmMs is excluded from measurement; throughput and latency
// over the following durMs are aggregated and printed on the last line in an easily
// parsed form:
//
//   PERFLINE <requests> <errors> <rps> <mbps> <lat_mean_ms> <lat_p50_ms> <lat_p99_ms>
//
// With upBytes > 0 every request is instead a POST carrying a body of that many bytes,
// under Content-Length. That is the request-heavy shape: it loads the request
// direction, which a GET load never does, and is what lets the CPU comparison say how
// much of the gain each direction is worth on its own. mbps then counts both
// directions, since that is the volume the proxy moved.

const http = require('http');

const host = process.argv[2] || '127.0.0.1';
const port = parseInt(process.argv[3] || '80', 10);
const conc = parseInt(process.argv[4] || '16', 10);
const durMs = parseInt(process.argv[5] || '6000', 10);
const bytes = parseInt(process.argv[6] || '256', 10);
const warmMs = parseInt(process.argv[7] || '1500', 10);
const upBytes = parseInt(process.argv[8] || '0', 10);

const path = `/?bytes=${bytes}`;
const upBody = upBytes > 0 ? Buffer.alloc(upBytes, 'u') : null;
const method = upBody ? 'POST' : 'GET';
const headers = upBody ? { 'Content-Type': 'application/octet-stream',
                           'Content-Length': upBytes } : {};
const agent = new http.Agent({ keepAlive: true, maxSockets: conc, maxFreeSockets: conc });

let measuring = false;
let done = false;
let count = 0;
let errors = 0;
let totBytes = 0;
const lats = [];
let measureStart = 0;

function fire() {
  if (done) return;
  const t0 = process.hrtime.bigint();
  const req = http.request({ host, port, path, method, headers, agent }, (res) => {
    let b = 0;
    res.on('data', (d) => { b += d.length; });
    res.on('end', () => {
      if (measuring) {
        count++;
        totBytes += b + upBytes;
        lats.push(Number(process.hrtime.bigint() - t0) / 1e6);
      }
      fire();
    });
    res.on('error', () => { if (measuring) errors++; fire(); });
  });
  req.on('error', () => {
    if (measuring) errors++;
    setTimeout(fire, 5);
  });
  if (upBody) {
    req.end(upBody);
  } else {
    req.end();
  }
}

for (let i = 0; i < conc; i++) fire();

setTimeout(() => { measuring = true; measureStart = Date.now(); }, warmMs);

setTimeout(() => {
  done = true;
  const elapsed = (Date.now() - measureStart) / 1000;
  lats.sort((a, b) => a - b);
  const pct = (q) => (lats.length ? lats[Math.min(lats.length - 1, Math.floor(q * lats.length))] : 0);
  const mean = lats.length ? lats.reduce((s, x) => s + x, 0) / lats.length : 0;
  const rps = elapsed > 0 ? count / elapsed : 0;
  const mbps = elapsed > 0 ? (totBytes / elapsed) / 1048576 : 0;
  console.log(
    `PERFLINE ${count} ${errors} ${rps.toFixed(1)} ${mbps.toFixed(2)} ` +
    `${mean.toFixed(3)} ${pct(0.5).toFixed(3)} ${pct(0.99).toFixed(3)}`
  );
  process.exit(0);
}, warmMs + durMs);
