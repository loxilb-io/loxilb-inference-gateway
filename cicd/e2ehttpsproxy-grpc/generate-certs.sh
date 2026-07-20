#!/bin/bash

# Script to generate test certificates for gRPC TLS testing
# Usage: $0 <server-ip> [hostname] [existing-ca-cert] [existing-ca-key]
# When ca-cert and ca-key are provided, they are reused instead of generating a new CA.
# This ensures all certs share a single trusted CA (required for e2ehttps fullproxy verification).

# Check if IP address is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <server-ip> [hostname] [existing-ca-cert] [existing-ca-key]"
    echo "Example: $0 31.31.31.1 server1"
    echo "Example (reuse CA): $0 31.31.31.1 server1 ./10.10.10.254/certs/ca.crt ./10.10.10.254/certs/ca.key"
    exit 1
fi

SERVER_IP=$1
SERVER_HOSTNAME=${2:-"server"}
EXISTING_CA_CERT=${3:-""}
EXISTING_CA_KEY=${4:-""}

CERT_DIR="./${SERVER_HOSTNAME}/certs"
mkdir -p $CERT_DIR

echo "Generating certificates in $CERT_DIR for IP: $SERVER_IP, Hostname: $SERVER_HOSTNAME..."

if [ -n "$EXISTING_CA_CERT" ] && [ -n "$EXISTING_CA_KEY" ]; then
    # Reuse provided CA so all certs are signed by the same root
    echo "Reusing existing CA: $EXISTING_CA_CERT"
    cp "$EXISTING_CA_CERT" $CERT_DIR/ca.crt
    cp "$EXISTING_CA_KEY"  $CERT_DIR/ca.key
else
    # Generate a new CA private key and certificate
    openssl genrsa -out $CERT_DIR/ca.key 4096
    openssl req -new -x509 -key $CERT_DIR/ca.key -sha256 -subj "/C=US/ST=CA/O=Test/CN=Test CA" -days 365 -out $CERT_DIR/ca.crt
fi

# Generate server private key
openssl genrsa -out $CERT_DIR/server.key 4096

# Generate server certificate signing request (CSR)
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr -config <(
cat <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C=US
ST=CA
O=Test
CN=$SERVER_HOSTNAME

[v3_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_HOSTNAME
DNS.2 = localhost
IP.1 = $SERVER_IP
IP.2 = 127.0.0.1
IP.3 = ::1
EOF
)

# Sign server certificate with CA
openssl x509 -req -in $CERT_DIR/server.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial -out $CERT_DIR/server.crt -days 365 -sha256 -extensions v3_ext -extfile <(
cat <<EOF
[v3_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_HOSTNAME
DNS.2 = localhost
IP.1 = $SERVER_IP
IP.2 = 127.0.0.1
IP.3 = ::1
EOF
)

# Generate client private key (optional, for mutual TLS)
openssl genrsa -out $CERT_DIR/client.key 4096

# Generate client certificate signing request (CSR)
openssl req -new -key $CERT_DIR/client.key -out $CERT_DIR/client.csr -subj "/C=US/ST=CA/O=Test/CN=Test Client"

# Sign client certificate with CA
openssl x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial -out $CERT_DIR/client.crt -days 365 -sha256

# Clean up CSR files
rm $CERT_DIR/*.csr

echo "Certificates generated successfully!"
echo ""
echo "Generated files:"
echo "  CA certificate: $CERT_DIR/ca.crt"
echo "  Server certificate: $CERT_DIR/server.crt (for IP: $SERVER_IP, Hostname: $SERVER_HOSTNAME)"
echo "  Server key: $CERT_DIR/server.key"
echo "  Client certificate: $CERT_DIR/client.crt (for mutual TLS)"
echo "  Client key: $CERT_DIR/client.key (for mutual TLS)"
echo ""
echo "Server certificate is valid for:"
echo "  - IP: $SERVER_IP"
echo "  - Hostname: $SERVER_HOSTNAME"
echo "  - IP: 127.0.0.1"
echo "  - Hostname: localhost"
