#!/bin/bash

# Test script for MCP server with HTTPS locally

cd "$(dirname "$0")"

echo "========================================="
echo "Testing MCP Server HTTPS Locally"
echo "========================================="
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed"
    exit 1
fi

echo "✓ pip3 found"

# Create a virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv test-venv

# Activate virtual environment
source test-venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q fastmcp uvicorn[standard]

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo "❌ openssl not found"
    exit 1
fi

echo "✓ Using openssl for certificate generation"

# Generate test certificates
echo ""
echo "Generating test certificates with openssl..."
mkdir -p test-certs/localhost

# Generate private key
openssl genrsa -out test-certs/localhost/key.pem 2048 2>/dev/null

# Generate self-signed certificate
openssl req -new -x509 -key test-certs/localhost/key.pem \
    -out test-certs/localhost/cert.pem -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost" 2>/dev/null

# Create a CA cert copy (same as cert for self-signed)
cp test-certs/localhost/cert.pem test-certs/minica.pem

if [ ! -f "test-certs/localhost/cert.pem" ]; then
    echo "❌ Certificate generation failed"
    exit 1
fi

echo "✓ Certificates generated"

# Test 1: HTTP server (no SSL)
echo ""
echo "========================================="
echo "Test 1: HTTP Server (Port 8080)"
echo "========================================="

python3 mcp-server/mcp-server.py test-server 8080 > test-http.log 2>&1 &
HTTP_PID=$!
echo "Started HTTP server (PID: $HTTP_PID)"

sleep 3

# Check if server is running
if ! ps -p $HTTP_PID > /dev/null; then
    echo "❌ HTTP server failed to start"
    cat test-http.log
    kill $HTTP_PID 2>/dev/null
    deactivate
    exit 1
fi

# Test HTTP connection
echo "Testing HTTP connection..."
HTTP_RESULT=$(curl -s http://localhost:8080/ 2>&1)

if [ $? -eq 0 ]; then
    echo "✓ HTTP server is responding"
else
    echo "❌ HTTP connection failed"
    cat test-http.log
fi

# Stop HTTP server
kill $HTTP_PID 2>/dev/null
sleep 1

# Test 2: HTTPS server with SSL
echo ""
echo "========================================="
echo "Test 2: HTTPS Server (Port 8443)"
echo "========================================="

python3 mcp-server/mcp-server.py test-server 8443 \
    --ssl-certfile test-certs/localhost/cert.pem \
    --ssl-keyfile test-certs/localhost/key.pem \
    > test-https.log 2>&1 &
HTTPS_PID=$!
echo "Started HTTPS server (PID: $HTTPS_PID)"

sleep 3

# Check if server is running
if ! ps -p $HTTPS_PID > /dev/null; then
    echo "❌ HTTPS server failed to start"
    echo ""
    echo "Server logs:"
    cat test-https.log
    kill $HTTPS_PID 2>/dev/null
    deactivate
    exit 1
fi

# Test HTTPS connection
echo "Testing HTTPS connection (insecure)..."
HTTPS_RESULT=$(curl -k -s https://localhost:8443/ 2>&1)

if [ $? -eq 0 ]; then
    echo "✓ HTTPS server is responding"
else
    echo "❌ HTTPS connection failed"
    echo ""
    echo "Server logs:"
    cat test-https.log
fi

# Test with CA certificate
echo "Testing HTTPS connection (with CA cert)..."
CA_RESULT=$(curl --cacert test-certs/minica.pem -s https://localhost:8443/ 2>&1)

if [ $? -eq 0 ]; then
    echo "✓ HTTPS with CA certificate works"
else
    echo "❌ HTTPS with CA certificate failed"
fi

# Stop HTTPS server
kill $HTTPS_PID 2>/dev/null

# Cleanup
echo ""
echo "Cleaning up..."
deactivate
rm -rf test-venv test-certs test-http.log test-https.log minica 2>/dev/null

echo ""
echo "========================================="
echo "Test Complete"
echo "========================================="
