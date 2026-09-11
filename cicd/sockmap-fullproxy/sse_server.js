// sse_server.js - mock OpenAI-compatible Server-Sent Events (chat completions) backend.
//
//   node sse_server.js <name> <port> [defaultTokens] [defaultRate]
//
// POST /v1/chat/completions  (body: {"model":..,"messages":[..],"stream":true,"max_tokens":N})
//   Response: text/event-stream + chunked, in the same chunk shape real OpenAI streams use
//     data: {"id":..,"object":"chat.completion.chunk","choices":[{"delta":{"content":".."}}]}\n\n
//   It finishes with a finish_reason=stop chunk and data: [DONE].
//
// Benchmark parameters (the query string takes precedence over the body):
//   ?tokens=N   number of tokens (chunks) to emit   default defaultTokens
//   ?rate=R     tokens/s per stream, 0 = as fast as possible   default defaultRate
//   ?tok=C      content length of one token in chars   default 8
//
// Design intent: this is the backend of an experiment that measures *proxy* CPU. If
// the backend burns CPU itself it pollutes the host_cores signal, so per-token cost is
// kept minimal:
//   1) one chunk Buffer is built per stream and reused for every token, so there is no
//      repeated JSON.stringify
//   2) streams are advanced by a single global ticker rather than a setTimeout each,
//      which avoids running hundreds of timers at hundreds of streams
//   3) the ticker stops when no stream is active, so idle CPU is zero

const http = require('http');

const name = process.argv[2] || 'sse';
const port = parseInt(process.argv[3] || '9081', 10);
const defTokens = parseInt(process.argv[4] || '200', 10);
const defRate = parseFloat(process.argv[5] || '25');   // tokens/s per stream, 0 = unpaced
const TICK_MS = parseInt(process.env.TICK_MS || '20', 10);
const MODEL = process.env.MODEL || 'gpt-4o-mini';
const MAX_TOKENS = 100000;

// -- diagnostic mode (?seq=1) ------------------------------------------------
// To tell whether the framing corruption is loss, reordering or duplication, every
// token carries a monotonically increasing sequence number in its content.
//
// Building JSON (or allocating a Buffer) per token would make the backend the
// bottleneck long before the byte rate that reproduces the defect, around 240 MB/s.
// So at startup SEQ_POOL fixed-width chunks are pre-rendered into one large Buffer and
// each token writes a subarray view of it - no copy. With zero allocation per token
// the throughput matches normal mode.
//
// Every chunk has the same length and differs only in the fixed-width seq field, so
// the client can check continuity by reading digits at a fixed offset instead of
// parsing JSON.
const SEQ_POOL = 10000;          // seq cycles 0..SEQ_POOL-1 (same constant on the client)
const seqPools = new Map();      // tokChars -> { buf, chunkLen }

function seqPool(tokChars) {
  let pool = seqPools.get(tokChars);
  if (pool) return pool;

  const width = Math.max(String(SEQ_POOL - 1).length, tokChars);
  const render = (n) => {
    const chunk = {
      id: `chatcmpl-${name}-seq`, object: 'chat.completion.chunk',
      created: 1700000000, model: MODEL,
      choices: [{ index: 0, delta: { content: String(n).padStart(width, '0') },
                  logprobs: null, finish_reason: null }],
    };
    return Buffer.from('data: ' + JSON.stringify(chunk) + '\n\n');
  };

  const first = render(0);
  const chunkLen = first.length;
  const buf = Buffer.allocUnsafe(chunkLen * SEQ_POOL);
  first.copy(buf, 0);
  for (let n = 1; n < SEQ_POOL; n++) {
    const b = render(n);
    // Fixed width is what makes the subarray offset arithmetic valid.
    if (b.length !== chunkLen) throw new Error('seq chunk length not fixed');
    b.copy(buf, n * chunkLen);
  }
  pool = { buf, chunkLen };
  seqPools.set(tokChars, pool);
  return pool;
}

let seq = 0;
const active = new Set();
let ticker = null;

function startTicker() {
  if (ticker) return;
  ticker = setInterval(tick, TICK_MS);
  if (ticker.unref) ticker.unref();
}
function stopTicker() {
  if (!ticker) return;
  clearInterval(ticker);
  ticker = null;
}

// Advances paced streams. The rate can be slower than one token per TICK, so a
// fractional accumulator (acc) carries the remainder.
function tick() {
  if (active.size === 0) { stopTicker(); return; }
  for (const s of active) {
    s.acc += s.perTick;
    while (s.acc >= 1 && s.remaining > 0) {
      s.acc -= 1;
      s.remaining--;
      s.res.write(nextChunk(s));
    }
    if (s.remaining <= 0) finish(s);
  }
}

// In diagnostic mode return a view of the next seq chunk from the pool, otherwise the
// stream's shared buffer.
function nextChunk(s) {
  if (!s.pool) return s.buf;
  const k = s.seq % SEQ_POOL;
  s.seq++;
  return s.pool.buf.subarray(k * s.pool.chunkLen, (k + 1) * s.pool.chunkLen);
}

function finish(s) {
  if (s.done) return;
  s.done = true;
  active.delete(s);
  s.res.write(s.tailBuf);
  s.res.end();
}

// unpaced: push as fast as possible, respecting only backpressure (drain).
function pump(s) {
  while (s.remaining > 0) {
    s.remaining--;
    if (!s.res.write(nextChunk(s))) {
      s.res.once('drain', () => { if (!s.done) pump(s); });
      return;
    }
  }
  finish(s);
}

function intParam(q, body, key, def, max) {
  let v = parseInt(q[key], 10);
  if (!Number.isInteger(v)) v = parseInt(body && body[key], 10);
  if (!Number.isInteger(v) || v < 0 || v > max) v = def;
  return v;
}

const server = http.createServer((req, res) => {
  // url.parse() is deprecated and constructing a WHATWG URL per request is costly.
  // The benchmark parameters are plain key=value, so the query string is split by hand
  // to keep the mock server's CPU down.
  const q = {};
  const qs = req.url.indexOf('?');
  if (qs !== -1) {
    for (const kv of req.url.slice(qs + 1).split('&')) {
      const eq = kv.indexOf('=');
      if (eq > 0) q[kv.slice(0, eq)] = kv.slice(eq + 1);
    }
  }

  if (req.method === 'GET') {
    // Health check, used to confirm the backend is ready.
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': name.length });
    res.end(name);
    return;
  }

  // The POST body flows client->proxy->backend like a real prompt, but only its length
  // is counted and the content dropped - this is a mock server, so parsing it would
  // just cost CPU. Streaming starts once the body has been received.
  let blen = 0;
  req.on('data', (d) => { blen += d.length; });
  req.on('end', () => {
    const tokens = intParam(q, null, 'tokens', defTokens, MAX_TOKENS);
    let rate = parseFloat(q.rate);
    if (!Number.isFinite(rate) || rate < 0) rate = defRate;
    const tokChars = intParam(q, null, 'tok', 8, 4096);

    const id = `chatcmpl-${name}-${(seq++).toString(36)}`;
    const created = Math.floor(Date.now() / 1000);
    const content = 'x'.repeat(tokChars);

    // One chunk reused by every token, in the same schema as a real OpenAI chunk.
    const chunk = {
      id, object: 'chat.completion.chunk', created, model: MODEL,
      choices: [{ index: 0, delta: { content }, logprobs: null, finish_reason: null }],
    };
    const buf = Buffer.from('data: ' + JSON.stringify(chunk) + '\n\n');

    // role chunk (first event) + terminating chunk + [DONE].
    const roleChunk = {
      id, object: 'chat.completion.chunk', created, model: MODEL,
      choices: [{ index: 0, delta: { role: 'assistant', content: '' }, logprobs: null, finish_reason: null }],
    };
    const stopChunk = {
      id, object: 'chat.completion.chunk', created, model: MODEL,
      choices: [{ index: 0, delta: {}, logprobs: null, finish_reason: 'stop' }],
    };
    const headBuf = Buffer.from('data: ' + JSON.stringify(roleChunk) + '\n\n');
    const tailBuf = Buffer.from('data: ' + JSON.stringify(stopChunk) + '\n\ndata: [DONE]\n\n');

    // keep-alive by default, which is how streaming normally behaves. ?close=1 closes
    // the socket once the response ends so a client can read to EOF and count received
    // bytes exactly - for diagnostics.
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': q.close === '1' ? 'close' : 'keep-alive',
      'X-Backend': name,
    });
    res.write(headBuf);

    const s = { res, buf, tailBuf, remaining: tokens, acc: 0, perTick: 0, done: false,
                pool: q.seq === '1' ? seqPool(tokChars) : null, seq: 0 };

    res.on('close', () => { s.done = true; active.delete(s); });

    if (tokens === 0) { finish(s); return; }

    if (rate <= 0) {
      pump(s);                       // unpaced (burst): as fast as possible
    } else {
      s.perTick = rate * TICK_MS / 1000;
      active.add(s);
      startTicker();
    }
  });
});

server.keepAliveTimeout = 300000;   // long streams must not be timed out
server.headersTimeout = 305000;
server.requestTimeout = 0;
server.maxRequestsPerSocket = 0;

server.listen(port, () => {
  console.log(`${name} sse_server listening on :${port} (tokens=${defTokens} rate=${defRate}/s tick=${TICK_MS}ms)`);
});
