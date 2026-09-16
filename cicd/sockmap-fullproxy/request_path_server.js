// request_path_server.js - HTTP/1.1 backend for validation_request_path.sh.
//
// Answers every request with what it received, so the client can tell whether
// the proxy delivered the request intact and in order:
//   {"name", "path", "len", "sha256"}   (len/sha256 cover the request body)
//
//   node request_path_server.js <name> <port>
var http = require('http');
var crypto = require('crypto');

var name = process.argv[2] || 'server';
var port = parseInt(process.argv[3] || '8080', 10);

var server = http.createServer(function (req, res) {
  var hash = crypto.createHash('sha256');
  var len = 0;
  req.on('data', function (chunk) {
    hash.update(chunk);
    len += chunk.length;
  });
  req.on('end', function () {
    var body = JSON.stringify({ name: name, path: req.url, len: len, sha256: hash.digest('hex') });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  });
});
server.keepAliveTimeout = 30000;
server.listen(port);
