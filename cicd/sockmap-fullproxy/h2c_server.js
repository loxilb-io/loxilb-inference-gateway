// h2c_server.js - plaintext HTTP/2 (prior knowledge) backend for validation_request_path.sh.
//
//   node h2c_server.js <name> <port>
// Responds 200 with "<name>:" padded to ?bytes=N (default 64).
var http2 = require('http2');

var name = process.argv[2] || 'h2';
var port = parseInt(process.argv[3] || '8080', 10);

http2.createServer(function (req, res) {
  var m = (req.url || '').match(/bytes=(\d+)/);
  var n = m ? parseInt(m[1], 10) : 64;
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(name + ':' + 'x'.repeat(Math.max(0, n - name.length - 1)));
}).listen(port);
