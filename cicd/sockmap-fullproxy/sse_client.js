// sse_client.js - OpenAI-compatible SSE load generator, for sockmap on/off comparison.
//
//   node sse_client.js <host> <port> <conc> <durMs> <bytesPrompt> <warmMs> <tokens> <rate> [tokChars] [keepalive]
//
// Closed loop: keeps <conc> streams in flight and starts the next one as soon as one
// finishes. Each stream is a POST /v1/chat/completions with stream:true, answered as
// text/event-stream.
//
// Why these metrics and not RPS
// -----------------------------
// The cost of SSE/LLM traffic attaches to the number of tokens pushed while a stream
// is held open, not to the number of requests. One token is a small 200-300 B write,
// and the userspace relay pays epoll wakeup -> recv() -> copy -> send() for each one.
// So the metrics are:
//   - tokens/s, streams/s  (throughput)
//   - TTFT, time to first token  (the primary user-visible number)
//   - ITL, inter-token latency  (streaming quality, p99 jitter in particular)
// The shell script combines these with CPU to normalize into CPU per token.
//
// Final line, meant to be parsed:
//   SSELINE <streams> <errors> <events> <tokens> <bytes> <streams_ps> <tokens_ps> <MBps>
//           <ttft_mean> <ttft_p50> <ttft_p99> <itl_mean> <itl_p50> <itl_p99>

const http = require('http');

const host = process.argv[2] || '127.0.0.1';
const port = parseInt(process.argv[3] || '80', 10);
const conc = parseInt(process.argv[4] || '16', 10);
const durMs = parseInt(process.argv[5] || '20000', 10);
const promptBytes = parseInt(process.argv[6] || '512', 10);
const warmMs = parseInt(process.argv[7] || '4000', 10);
const tokens = parseInt(process.argv[8] || '200', 10);
const rate = parseFloat(process.argv[9] || '25');
const tokChars = parseInt(process.argv[10] || '8', 10);
const keepalive = (process.argv[11] || '1') !== '0';
// SSE_DEBUG_ERR=1 writes error kinds to stderr for classification. The default is to
// count them silently.
const debugErr = process.env.SSE_DEBUG_ERR === '1';
const errKinds = new Map();
function noteErr(kind) {
  errKinds.set(kind, (errKinds.get(kind) || 0) + 1);
  if (debugErr && errKinds.get(kind) === 1) console.error(`ERRKIND ${kind}`);
}

// -- diagnostic mode (SSE_SEQ_CHECK=1) ---------------------------------------
// Checks the monotonic seq the server stamped into every token to classify what kind
// of framing corruption occurred:
//   seq jumps forward -> data loss
//   seq goes backward -> reordering (duplication if it is the immediately previous value)
// It does not parse JSON, only the digits after '"content":"'. A chunk can straddle a
// TCP boundary, so each stream carries an unfinished tail and joins it to the next
// chunk. If SSE_DUMP_DIR is set, the raw byte tail at the point of a parse failure
// (HPE_*) is written to a file.
const seqCheck = process.env.SSE_SEQ_CHECK === '1';
const dumpDir = process.env.SSE_DUMP_DIR || '';
const SEQ_POOL = 10000;                        // same constant as the server
const MARK = Buffer.from('"content":"');
const QUOTE = 0x22;
const EMPTY = Buffer.alloc(0);
const fs = dumpDir ? require('fs') : null;
let dumpCount = 0;

const seqStats = { gapEvents: 0, gapTokens: 0, dupEvents: 0, reorderEvents: 0,
                   okTokens: 0, streamsChecked: 0 };

function classify(st, g) {
  if (st.expect < 0) { st.expect = (g + 1) % SEQ_POOL; seqStats.okTokens++; return; }
  if (g === st.expect) { st.expect = (g + 1) % SEQ_POOL; seqStats.okTokens++; return; }
  const fwd = (g - st.expect + SEQ_POOL) % SEQ_POOL;
  if (fwd > 0 && fwd < SEQ_POOL / 2) {
    seqStats.gapEvents++; seqStats.gapTokens += fwd;      // fwd tokens went missing
    st.expect = (g + 1) % SEQ_POOL;
  } else {
    const back = (st.expect - g + SEQ_POOL) % SEQ_POOL;
    if (back === 1) seqStats.dupEvents++; else seqStats.reorderEvents++;
  }
}

function scanSeq(st, chunkBuf) {
  const b = st.pending.length ? Buffer.concat([st.pending, chunkBuf]) : chunkBuf;
  let idx = 0, consumed = 0;
  for (;;) {
    const m = b.indexOf(MARK, idx);
    if (m === -1) { consumed = Math.max(consumed, Math.max(0, b.length - MARK.length)); break; }
    const vs = m + MARK.length;
    const q = b.indexOf(QUOTE, vs);
    if (q === -1) { consumed = m; break; }          // value has not arrived yet
    const val = b.toString('latin1', vs, q);
    idx = q + 1; consumed = idx;
    if (val.length === 0) continue;                 // role chunk
    const g = parseInt(val, 10);
    if (Number.isInteger(g)) classify(st, g);
  }
  st.pending = consumed >= b.length ? EMPTY : b.subarray(consumed);
  if (st.pending.length > 65536) st.pending = st.pending.subarray(st.pending.length - 4096);
}

const path = `/v1/chat/completions?tokens=${tokens}&rate=${rate}&tok=${tokChars}` +
             (seqCheck ? '&seq=1' : '');
const agent = new http.Agent({ keepAlive: keepalive, maxSockets: conc, maxFreeSockets: conc });

// The request body is built once and reused, to save client CPU. Prompt size is an
// argument.
const reqBody = Buffer.from(JSON.stringify({
  model: 'gpt-4o-mini',
  messages: [{ role: 'user', content: 'p'.repeat(Math.max(1, promptBytes)) }],
  stream: true,
  max_tokens: tokens,
}));
const headers = {
  'Content-Type': 'application/json',
  'Content-Length': reqBody.length,
  'Accept': 'text/event-stream',
};

const NL2 = Buffer.from('\n\n');

let measuring = false;
let done = false;
let measureStart = 0;

let streams = 0;      // streams completed within the measurement window
let errors = 0;
let events = 0;       // SSE events received within the measurement window
let totBytes = 0;
const ttfts = [];
const itls = [];

// Counts SSE event delimiters ('\n\n') within one chunk. Buffer.indexOf is native and
// far cheaper than a byte loop; only a '\n'+'\n' pair straddling the chunk boundary is
// handled separately, via prevLast.
function countEvents(buf, prevLast) {
  let n = 0;
  let start = 0;
  if (prevLast === 10 && buf.length > 0 && buf[0] === 10) { n++; start = 1; }
  let idx = start;
  while ((idx = buf.indexOf(NL2, idx)) !== -1) { n++; idx += 2; }
  return n;
}

function fire() {
  if (done) return;
  const t0 = process.hrtime.bigint();
  const startedMeasuring = measuring;
  let first = true;
  let prevLast = 0;
  let lastEvT = 0n;
  const st = seqCheck ? { expect: -1, pending: EMPTY, tail: EMPTY } : null;

  const req = http.request({ host, port, path, method: 'POST', agent, headers }, (res) => {
    if (res.statusCode !== 200) {
      if (measuring) { errors++; noteErr(`status:${res.statusCode}`); }
      res.resume();
      res.on('end', fire);
      return;
    }
    res.on('data', (d) => {
      const now = process.hrtime.bigint();
      if (first) {
        first = false;
        if (startedMeasuring && measuring) ttfts.push(Number(now - t0) / 1e6);
        lastEvT = now;
      } else if (measuring) {
        itls.push(Number(now - lastEvT) / 1e6);
        lastEvT = now;
      } else {
        lastEvT = now;
      }
      if (measuring) {
        totBytes += d.length;
        events += countEvents(d, prevLast);
      }
      if (st) {
        if (measuring) scanSeq(st, d);
        if (fs) {
          st.tail = st.tail.length ? Buffer.concat([st.tail, d]) : d;
          if (st.tail.length > 4096) st.tail = st.tail.subarray(st.tail.length - 4096);
        }
      }
      prevLast = d.length ? d[d.length - 1] : prevLast;
    });
    res.on('end', () => {
      if (measuring) streams++;
      fire();
    });
    res.on('error', (e) => { if (measuring) { errors++; noteErr(`res:${e.code || e.message}`); } fire(); });
  });
  req.on('error', (e) => {
    if (measuring) { errors++; noteErr(`req:${e.code || e.message}`); }
    if (fs && st && st.tail.length && dumpCount < 20) {
      try {
        fs.writeFileSync(`${dumpDir}/dump_${process.pid}_${dumpCount++}_${e.code || 'err'}.bin`, st.tail);
      } catch (_) { /* diagnostics only - keep generating load even if this fails */ }
    }
    setTimeout(fire, 5);
  });
  req.end(reqBody);
}

for (let i = 0; i < conc; i++) fire();

setTimeout(() => { measuring = true; measureStart = Date.now(); }, warmMs);

setTimeout(() => {
  done = true;
  const elapsed = (Date.now() - measureStart) / 1000;
  const q = (arr, p) => (arr.length ? arr[Math.min(arr.length - 1, Math.floor(p * arr.length))] : 0);
  const mean = (arr) => (arr.length ? arr.reduce((s, x) => s + x, 0) / arr.length : 0);
  ttfts.sort((a, b) => a - b);
  itls.sort((a, b) => a - b);

  // events = role(1) + tokens(N) + stop(1) + [DONE](1), so subtract the 3 non-token
  // events per completed stream.
  const tok = Math.max(0, events - 3 * streams);
  const sps = elapsed > 0 ? streams / elapsed : 0;
  const tps = elapsed > 0 ? tok / elapsed : 0;
  const mbps = elapsed > 0 ? (totBytes / elapsed) / 1048576 : 0;

  if (seqCheck) {
    console.error(`SEQSUM ok=${seqStats.okTokens} gap_events=${seqStats.gapEvents} ` +
                  `gap_tokens=${seqStats.gapTokens} dup=${seqStats.dupEvents} ` +
                  `reorder=${seqStats.reorderEvents}`);
  }
  if (debugErr && errKinds.size) {
    for (const [k, v] of errKinds) console.error(`ERRSUM ${k} ${v}`);
  }
  console.log(
    `SSELINE ${streams} ${errors} ${events} ${tok} ${totBytes} ` +
    `${sps.toFixed(2)} ${tps.toFixed(1)} ${mbps.toFixed(3)} ` +
    `${mean(ttfts).toFixed(3)} ${q(ttfts, 0.5).toFixed(3)} ${q(ttfts, 0.99).toFixed(3)} ` +
    `${mean(itls).toFixed(3)} ${q(itls, 0.5).toFixed(3)} ${q(itls, 0.99).toFixed(3)}`
  );
  process.exit(0);
}, warmMs + durMs);
