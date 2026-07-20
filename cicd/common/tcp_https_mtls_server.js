// tcp_https_mtls_server.js
// HTTPS server with mutual TLS (mTLS) support
// Requires client certificate verification

const https = require('https');
const fs = require('fs');

// Command line arguments
const serverName = process.argv[2] || 'server';
const port = process.argv[3] || 8443;
const certPath = process.argv[4] || '/tmp/server.crt';
const keyPath = process.argv[5] || '/tmp/server.key';
const clientCaPath = process.argv[6] || '/tmp/client_ca.crt';

console.log(`Starting mTLS HTTPS server: ${serverName} on port ${port}`);
console.log(`Server cert: ${certPath}`);
console.log(`Server key: ${keyPath}`);
console.log(`Client CA: ${clientCaPath}`);

// Create HTTPS server with mTLS configuration
const options = {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
    ca: fs.readFileSync(clientCaPath),
    requestCert: true,        // Request client certificate
    rejectUnauthorized: true  // Reject clients without valid certificate
};

https.createServer(options, (req, res) => {
    // Log client certificate info if present
    if (req.socket.authorized) {
        const cert = req.socket.getPeerCertificate();
        console.log(`Authorized client: ${cert.subject.CN || 'unknown'}`);
    } else {
        console.log(`Unauthorized client: ${req.socket.authorizationError}`);
    }

    // Handle different endpoints
    if (req.url === '/v1/users') {
        res.writeHead(200);
        res.end(serverName + ':users');
    } else if (req.url === '/v1/orders') {
        res.writeHead(200);
        res.end(serverName + ':orders');
    } else {
        res.writeHead(200);
        res.end(serverName);
    }
}).listen(port, () => {
    console.log(`mTLS HTTPS server ${serverName} listening on https://0.0.0.0:${port}/`);
});
