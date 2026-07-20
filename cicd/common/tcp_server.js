var http = require('http');
var port = 8080
if (process.argv[3]) {
  port = 2020
}
http.createServer(function (req, res) {
  res.writeHead(200, {'Content-Type': 'text/html'});
  var name = process.argv[2];
  var url = req.url || '/';
  // Path-based responses for P6 LPM (prefix) routing tests — mirror the
  // common/http2 servers. Root and non-/v1 paths keep returning the bare
  // name so the non-prefix scenarios are unaffected.
  if (url.indexOf('/v1/users') === 0) {
    res.end(name + ':users');
  } else if (url.indexOf('/v1/orders') === 0) {
    res.end(name + ':orders');
  } else if (url.indexOf('/v1/') === 0) {
    res.end(name + ':v1');
  } else {
    res.end(name);
  }
}).listen(port);
