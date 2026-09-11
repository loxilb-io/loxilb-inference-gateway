// sse_raw_probe.js - wire-level classifier for the framing corruption.
//
//   node sse_raw_probe.js <host> <port> <conc> <durMs> <tokens> [maxReports]
//
// Why this exists: sse_client.js uses Node's HTTP parser, so what reaches a callback
// is body that has already been de-chunked. Only bytes after the framing broke are
// visible, which makes it impossible to tell what happened on the wire - bytes lost,
// inserted, or reordered.
//
// This probe sends the request over a raw TCP socket, takes the response bytes without
// parsing them, and interprets HTTP/1.1 chunked framing strictly by itself:
//     <hex-size>\r\n <size bytes> \r\n ...
// It then checks the de-chunked body against the deterministic sequence the server must
// have sent (in ?seq=1 mode the body is fully predictable: role chunk + tokens 0..N-1 +
// stop + [DONE]).
//
// At the first anomaly it reports:
//   - the wire offset and the kind of anomaly (bad chunk header / body mismatch)
//   - the raw bytes around that point, in hex and printable form
// That is what separates loss from insertion from reordering.

const net = require('net');

const host = process.argv[2] || '127.0.0.1';
const port = parseInt(process.argv[3] || '80', 10);
const conc = parseInt(process.argv[4] || '32', 10);
const durMs = parseInt(process.argv[5] || '20000', 10);
const tokens = parseInt(process.argv[6] || '4000', 10);
const maxReports = parseInt(process.argv[7] || '5', 10);
// Fixing the number of streams means none are left half-finished when the timer fires,
// so the verdict counter and received bytes compare exactly (0 keeps running for durMs).
const streamLimit = parseInt(process.argv[8] || '0', 10);
// SLOW_READ_MS: pause reading the socket for this long every SLOW_READ_EVERY bytes.
// This deliberately backs up the destination (client) socket to provoke a partial send
// on the redirect path. If that reproduces the defect without concurrency, the verdict
// byte counter and received bytes can be compared exactly, per stream.
const slowMs = parseInt(process.env.SLOW_READ_MS || '0', 10);
const slowEvery = parseInt(process.env.SLOW_READ_EVERY || '65536', 10);

const TOKCHARS = 8;
const body = Buffer.from(JSON.stringify({
  model: 'gpt-4o-mini', messages: [{ role: 'user', content: 'p'.repeat(512) }],
  stream: true, max_tokens: tokens,
}));
const reqHead = Buffer.from(
  `POST /v1/chat/completions?tokens=${tokens}&rate=0&tok=${TOKCHARS}&seq=1 HTTP/1.1\r\n` +
  `Host: ${host}:${port}\r\nContent-Type: application/json\r\n` +
  `Accept: text/event-stream\r\nConnection: close\r\n` +
  `Content-Length: ${body.length}\r\n\r\n`);

// The token lines the server sends are fully deterministic - build the expected form.
const SEQ_POOL = 10000;
function tokenLine(n, name) {
  const chunk = {
    id: `chatcmpl-${name}-seq`, object: 'chat.completion.chunk',
    created: 1700000000, model: 'gpt-4o-mini',
    choices: [{ index: 0, delta: { content: String(n).padStart(TOKCHARS, '0') },
                logprobs: null, finish_reason: null }],
  };
  return 'data: ' + JSON.stringify(chunk) + '\n\n';
}

let done = false, reports = 0, streams = 0, clean = 0, rxBytes = 0, active = 0;
const kinds = new Map();
const lossSamples = [];
function note(k) { kinds.set(k, (kinds.get(k) || 0) + 1); }

function hexdump(buf, mark) {
  const out = [];
  for (let i = 0; i < buf.length; i += 16) {
    const s = buf.subarray(i, i + 16);
    const hex = [...s].map((v) => v.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const txt = [...s].map((v) => (v >= 32 && v < 127 ? String.fromCharCode(v) : '.')).join('');
    out.push(`    ${String(i).padStart(5)} ${hex} |${txt}|` + (mark !== undefined && i <= mark && mark < i + 16 ? '  <== here' : ''));
  }
  return out.join('\n');
}

// Accumulates wire bytes and interprets the chunked framing strictly.
function makeState(name) {
  return { name, raw: Buffer.alloc(0), off: 0, phase: 'head', need: 0,
           mode: 'sync', syncBuf: '', firstLine: null, exp: null, expIdx: 0, complete: false,
           tokenNo: 0, reported: false };
}

function analyze(st) {
  // skip past the response headers
  if (st.phase === 'head') {
    const e = st.raw.indexOf('\r\n\r\n');
    if (e === -1) return;
    st.off = e + 4;
    st.phase = 'size';
  }
  for (;;) {
    if (st.phase === 'size') {
      const nl = st.raw.indexOf('\r\n', st.off);
      if (nl === -1) return;
      const line = st.raw.toString('latin1', st.off, nl);
      const n = parseInt(line, 16);
      if (!/^[0-9a-fA-F]+$/.test(line.trim()) || Number.isNaN(n)) {
        report(st, st.off, `bad chunk-size line: ${JSON.stringify(line.slice(0, 24))}`);
        return;
      }
      st.need = n; st.off = nl + 2;
      if (n === 0) { st.phase = 'trailer'; st.complete = true; return; }
      st.phase = 'data';
      continue;
    }
    if (st.phase === 'data') {
      if (st.raw.length < st.off + st.need + 2) return;
      const payload = st.raw.subarray(st.off, st.off + st.need);
      const crlf = st.raw.subarray(st.off + st.need, st.off + st.need + 2);
      if (crlf[0] !== 0x0d || crlf[1] !== 0x0a) {
        report(st, st.off + st.need, `missing CRLF at end of chunk (size=${st.need})`);
        return;
      }
      checkBody(st, payload, st.off);
      st.off += st.need + 2; st.phase = 'size';
      continue;
    }
    return; // trailer
  }
}

// Compares the de-chunked body against the expected sequence as it accumulates.
// The role chunk's created field is the request time and cannot be predicted, so the
// comparison synchronizes on the first token line (seq 00000000) and then matches byte
// for byte from the next token onward. The stop and [DONE] chunks after the last token
// are excluded.
function checkBody(st, payload, wireOff) {
  for (let i = 0; i < payload.length; i++) {
    const c = payload[i];

    if (st.mode === 'done') return;

    if (st.mode === 'sync') {
      st.syncBuf += String.fromCharCode(c);
      if (st.syncBuf.length > 8192) st.syncBuf = st.syncBuf.slice(-2048);
      if (st.syncBuf.endsWith(st.firstLine)) {
        st.mode = 'verify';
        st.tokenNo = 1;
        st.exp = Buffer.from(tokenLine(1, st.name));
        st.expIdx = 0;
        st.syncBuf = '';
      }
      continue;
    }

    if (c !== st.exp[st.expIdx]) {
      report(st, wireOff + i,
        `body mismatch: token #${st.tokenNo} at offset ${st.expIdx}, ` +
        `expected ${JSON.stringify(String.fromCharCode(st.exp[st.expIdx]))} ` +
        `got ${JSON.stringify(String.fromCharCode(c))}`);
      return;
    }
    st.expIdx++;
    if (st.expIdx === st.exp.length) {
      st.tokenNo++;
      if (st.tokenNo >= tokens) { st.mode = 'done'; return; }
      st.exp = Buffer.from(tokenLine(st.tokenNo % SEQ_POOL, st.name));
      st.expIdx = 0;
    }
  }
}

// Finds where the stream returns to valid framing after the anomaly, and derives how
// many bytes went missing and how many tokens were skipped. This is what settles loss
// versus insertion, and by how much.
function resync(st, wireOff) {
  const marker = Buffer.from(`\r\ndata: {"id":"chatcmpl-${st.name}-seq"`);
  const hit = st.raw.indexOf(marker, wireOff);
  if (hit === -1) return null;
  const lineStart = hit + 2;
  const cm = /"content":"(\d{8})"/.exec(st.raw.toString('latin1', lineStart, lineStart + 260));
  if (!cm) return null;
  const foundSeq = parseInt(cm[1], 10);
  // st.tokenNo is the last token received cleanly, and st.expIdx bytes of it arrived.
  const lineLen = st.exp ? st.exp.length : 0;
  // Signed delta: positive means a forward jump (loss), negative means going backward
  // (retransmission / rewind).
  const delta = foundSeq - st.tokenNo;
  const truncAt = st.expIdx;
  return { foundSeq, expected: st.tokenNo, delta, truncAt, lineLen,
           resyncOff: hit, gapOnWire: hit - wireOff };
}

function report(st, wireOff, msg) {
  if (st.reported) return;
  st.reported = true;
  note(msg.split(':')[0]);
  const rs = resync(st, wireOff);
  if (rs) {
    note(rs.delta < 0 ? 'resync: seq went backward (retransmission/rewind)'
                      : rs.delta > 0 ? 'resync: seq jumped forward (loss)'
                                     : 'resync: same seq');
    lossSamples.push(rs);
  } else {
    note('resync failed (stream never recovered)');
  }
  if (reports >= maxReports) return;
  reports++;
  // Dump the whole raw stream for an anomalous connection, so it can be checked offline
  // whether the stream rewound after the retransmission (1913, 1914, ...) or resumed at
  // its original position (1919, ...).
  if (process.env.RAW_DUMP_DIR) {
    try { require('fs').writeFileSync(`${process.env.RAW_DUMP_DIR}/raw_${process.pid}_${reports}.bin`, st.raw); } catch (_) {}
  }
  const from = Math.max(0, wireOff - 160), to = Math.min(st.raw.length, wireOff + 160);
  console.log(`\n### anomaly #${reports} - wire offset ${wireOff} (${st.raw.length} B received)`);
  console.log(`    ${msg}`);
  if (rs) {
    console.log(`    resync: token #${rs.expected} truncated at ${rs.truncAt}/${rs.lineLen} B -> ` +
                `next clean token seq=${rs.foundSeq} (delta ${rs.delta >= 0 ? '+' : ''}${rs.delta}), ` +
                `rewound bytes ~ ${Math.abs(rs.delta) * (rs.lineLen + 6)}`);
  }
  console.log(hexdump(st.raw.subarray(from, to), wireOff - from));
}

function fire() {
  if (done) return;
  if (streamLimit && streams + active >= streamLimit) return;
  active++;
  const sock = net.connect(port, host);
  const st = makeState(null);
  sock.on('connect', () => sock.write(Buffer.concat([reqHead, body])));
  sock.on('data', (d) => {
    if (st.name === null) {
      const m = /chatcmpl-([^-]+)-seq/.exec(d.toString('latin1', 0, Math.min(d.length, 2048)));
      if (m) { st.name = m[1]; st.firstLine = tokenLine(0, st.name); }
    }
    rxBytes += d.length;
    // Bound memory: stop accumulating once a stream has been reported.
    if (!st.reported) st.raw = Buffer.concat([st.raw, d]);
    if (st.name !== null && !st.reported) analyze(st);
    if (st.complete) { finish(); return; }
    if (!st.doneSeen && d.indexOf('data: [DONE]') !== -1) {
      st.doneSeen = true;
      setTimeout(() => finish(), 300);
    }
    if (slowMs > 0) {
      st.sincePause = (st.sincePause || 0) + d.length;
      if (st.sincePause >= slowEvery) {
        st.sincePause = 0;
        sock.pause();
        setTimeout(() => { if (!finished) sock.resume(); }, slowMs);
      }
    }
    // The server forces Connection: keep-alive in the response header, so the socket
    // never emits 'end'. Finish the stream when the terminating chunk is seen.
  });
  // Finish only at EOF (the server closes when close=1). That way every received byte
  // is accounted for, corrupted streams included, and the verdict counter compares
  // exactly.
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    streams++; if (!st.reported) clean++;
    active--;
    sock.destroy();
    if (streamLimit && streams >= streamLimit) done = true;
    if (!done) fire();
    if (done && active === 0) summarize();
  };
  sock.on('end', finish);
  sock.on('close', finish);
  sock.on('error', finish);
  sock.setTimeout(30000, finish);
}

for (let i = 0; i < conc; i++) fire();
let summarized = false;
function summarize() {
  if (summarized) return;
  summarized = true;
  console.log(`\n======== summary ========`);
  console.log(`  streams=${streams} clean=${clean} anomalous=${streams - clean}`);
  console.log(`  RXBYTES ${rxBytes}`);
  for (const [k, v] of kinds) console.log(`  ${v.toString().padStart(5)}  ${k}`);
  if (lossSamples.length) {
    const d = lossSamples.map((x) => x.delta).sort((a, b) => a - b);
    const t = lossSamples.map((x) => x.truncAt).sort((a, b) => a - b);
    const q = (a, p) => a[Math.min(a.length - 1, Math.floor(p * a.length))];
    const back = lossSamples.filter((x) => x.delta < 0).length;
    const fwd = lossSamples.filter((x) => x.delta > 0).length;
    console.log(`  ---- resync delta distribution (n=${lossSamples.length}) ----`);
    console.log(`  backward (retransmit): ${back}   forward (loss): ${fwd}   same: ${lossSamples.length - back - fwd}`);
    console.log(`  delta (tokens): min=${d[0]} p50=${q(d, 0.5)} p90=${q(d, 0.9)} max=${d[d.length - 1]}`);
    console.log(`  truncation offset (B): min=${t[0]} p50=${q(t, 0.5)} max=${t[t.length - 1]} (of a ${lossSamples[0].lineLen}B line)`);
  }
  process.exit(0);
}
setTimeout(() => { done = true; summarize(); }, durMs);
