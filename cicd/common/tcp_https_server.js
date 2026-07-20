// tcp_https_server.js

var certdir = "./"
if (process.argv[3]) {
  certdir = process.argv[3]
}
const https = require('https');
const fs = require('fs');

https.createServer({
    cert: fs.readFileSync(certdir + '/server.crt'),
    key: fs.readFileSync(certdir + '/server.key')
}, (req, res) => {
    res.writeHead(200);
    const name = process.argv[2];
    const url = req.url || '/';
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
}).listen(8080);
console.log("Server listening on https://localhost:8080/");
