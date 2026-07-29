#!/bin/bash
# minica (github.com/jsha/minica) is fetched on demand — no binary is committed.
MINICA="$(command -v minica || echo "$(go env GOPATH)/bin/minica")"
[ -x "$MINICA" ] || { go install github.com/jsha/minica@latest; MINICA="$(go env GOPATH)/bin/minica"; }


source ../common.sh

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1 
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2
spawn_docker_host --dock-type host --dock-name l3ep3

echo "#########################################"
echo "Connecting and configuring  hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1
connect_docker_hosts l3ep3 llb1

sleep 5

docker exec llb1 bash -c "apt update && apt install -y curl"

#L3 config
config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254
config_docker_host --host1 l3ep3 --host2 llb1 --ptype phy --addr 33.33.33.1/24 --gw 33.33.33.254
config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24
config_docker_host --host1 llb1 --host2 l3ep3 --ptype phy --addr 33.33.33.254/24

$dexec llb1 ip addr add 10.10.10.3/32 dev lo

echo "#########################################"
echo "Generating certificates for end-to-end mTLS"
echo "#########################################"

chmod +x "$MINICA" 2>/dev/null || true

# Generate root CA using minica
"$MINICA" -ip-addresses 10.10.10.254
sleep 10

# Generate client certificates for frontend mTLS
# Client 1: Valid client with correct CN pattern
"$MINICA" -domains client1.internal.corp.com -ip-addresses 10.10.10.1
sleep 10

# Client 2: Invalid client (wrong CN pattern) - for negative testing
"$MINICA" -domains client2.external.com -ip-addresses 10.10.10.1
sleep 10

# Generate backend server certificates with proper IP SANs
"$MINICA" -ip-addresses 31.31.31.1
sleep 10
"$MINICA" -ip-addresses 32.32.32.1
sleep 10
"$MINICA" -ip-addresses 33.33.33.1
sleep 10

# Generate loxilb's client certificate for backend mTLS (when loxilb connects to backends)
"$MINICA" -domains loxilb.internal.loadbalancer.com -ip-addresses 10.10.10.254
sleep 10

# Generate security test certificates (Tests 7-9)
# These require openssl; each block is guarded and will log SKIP if unavailable.

# Test 7: Expired client cert — signed by minica CA but notAfter in the past
mkdir -p client-expired
if command -v openssl &>/dev/null && [ -f minica-key.pem ]; then
    openssl genrsa -out client-expired/key.pem 2048 2>/dev/null
    openssl req -new -key client-expired/key.pem \
        -out client-expired/client.csr \
        -subj "/CN=client1.internal.corp.com" 2>/dev/null
    openssl x509 -req -in client-expired/client.csr \
        -CA minica.pem -CAkey minica-key.pem -CAcreateserial \
        -out client-expired/cert.pem -days -1 2>/dev/null
    echo "Generated expired client cert for Test 7 (notAfter in past)"
else
    echo "SKIP: openssl or minica-key.pem not available — Test 7 will be skipped"
fi

# Test 8: Client cert signed by a rogue (untrusted) CA — CN matches allowed pattern
mkdir -p rogue-ca rogue-client
if command -v openssl &>/dev/null; then
    openssl req -x509 -newkey rsa:2048 -keyout rogue-ca/ca-key.pem -out rogue-ca/ca.pem \
        -days 365 -nodes -subj "/CN=Rogue CA" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout rogue-client/key.pem \
        -out rogue-client/client.csr \
        -subj "/CN=client1.internal.corp.com" 2>/dev/null
    openssl x509 -req -in rogue-client/client.csr \
        -CA rogue-ca/ca.pem -CAkey rogue-ca/ca-key.pem -CAcreateserial \
        -out rogue-client/cert.pem -days 365 2>/dev/null
    echo "Generated rogue CA client cert for Test 8 (untrusted CA)"
else
    echo "SKIP: openssl not available — Test 8 will be skipped"
fi

# Test 9: SAN-only cert — trusted CA signature but empty CN field
mkdir -p san-only
if command -v openssl &>/dev/null && [ -f minica-key.pem ]; then
    openssl req -newkey rsa:2048 -nodes -keyout san-only/key.pem \
        -out san-only/client.csr \
        -subj "/CN= " 2>/dev/null
    openssl x509 -req -in san-only/client.csr \
        -CA minica.pem -CAkey minica-key.pem -CAcreateserial \
        -out san-only/cert.pem -days 365 \
        -extfile <(echo "subjectAltName=DNS:client.external.com") 2>/dev/null
    echo "Generated SAN-only cert (empty CN) for Test 9"
else
    echo "SKIP: openssl or minica-key.pem not available — Test 9 will be skipped"
fi

echo "#########################################"
echo "Installing certificates"
echo "#########################################"

# Install frontend TLS certificates on loxilb (for client-facing connections)
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem llb1:/opt/loxilb/cert/server.key

# Install client CA bundle on loxilb (for verifying frontend client certificates)
docker cp minica.pem llb1:/opt/loxilb/cert/client_ca.crt

# Install backend CA bundle on loxilb (for verifying backend server certificates)
docker cp minica.pem llb1:/opt/loxilb/cert/backend_ca.crt

# Install loxilb's client certificate for backend mTLS (presented to backends)
docker cp loxilb.internal.loadbalancer.com/cert.pem llb1:/opt/loxilb/cert/backend_client.crt
docker cp loxilb.internal.loadbalancer.com/key.pem llb1:/opt/loxilb/cert/backend_client.key

# Copy CA cert to l3h1 for curl validation
docker cp minica.pem l3h1:/tmp/minica.pem

# Copy backend server certificates to endpoints for HTTPS servers
docker cp 31.31.31.1/cert.pem l3ep1:/tmp/server.crt
docker cp 31.31.31.1/key.pem l3ep1:/tmp/server.key
docker cp minica.pem l3ep1:/tmp/ca.crt

docker cp 32.32.32.1/cert.pem l3ep2:/tmp/server.crt
docker cp 32.32.32.1/key.pem l3ep2:/tmp/server.key
docker cp minica.pem l3ep2:/tmp/ca.crt

docker cp 33.33.33.1/cert.pem l3ep3:/tmp/server.crt
docker cp 33.33.33.1/key.pem l3ep3:/tmp/server.key
docker cp minica.pem l3ep3:/tmp/ca.crt

# Copy loxilb CA to backend endpoints for verifying loxilb's client cert (backend mTLS)
docker cp minica.pem l3ep1:/tmp/client_ca.crt
docker cp minica.pem l3ep2:/tmp/client_ca.crt
docker cp minica.pem l3ep3:/tmp/client_ca.crt

echo "#########################################"
echo "Registering SNI certificate for VIP"
echo "#########################################"

# D-5 config path: drive the inference-gateway loxicmd as the load-bearing config
# path when present (subject-under-test); fall back to raw REST for old/absent CLI.
cli_preflight llb1 && USE_CLI=1 || USE_CLI=0

# SNI certificates live in loxilb's GLOBAL SNI store and are NOT auto-created
# by a security=2 LB rule — they must be registered explicitly via
# POST /sni/certificates. validate_api.sh API-T3 asserts at least one entry
# exists for the VIP. certPath is the directory holding server.crt/server.key
# (installed above at /opt/loxilb/cert).
if [[ "$USE_CLI" == "1" ]]; then
  $dexec llb1 loxicmd create sni --hostname=10.10.10.254 --cert-path=/opt/loxilb/cert
else
docker exec llb1 curl -s -X POST http://localhost:11111/netlox/v1/sni/certificates \
  -H "Content-Type: application/json" \
  -d '{"hostname":"10.10.10.254","certPath":"/opt/loxilb/cert"}'
echo
fi

echo "#########################################"
echo "Creating end-to-end mTLS load balancer rules"
echo "#########################################"

sleep 5

# Test 1: Full end-to-end mTLS with required frontend client cert + backend mTLS verification
# Frontend: Client must present valid cert with CN matching "*.internal.corp.com"
# Backend: Verify backend server certificates and present loxilb client cert
if [[ "$USE_CLI" == "1" ]]; then
  create_lb_rule llb1 10.10.10.254 --tcp=2020:8443 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --security=e2ehttps --name=e2e-mtls-required-service --host=10.10.10.254 --mtls-client-cert-mode=required --mtls-client-ca-path=/opt/loxilb/cert/client_ca.crt --mtls-require-client-cn --mtls-client-cn-pattern='*.internal.corp.com' --mtls-backend-ca-path=/opt/loxilb/cert/backend_ca.crt --mtls-backend-cert-path=/opt/loxilb/cert/backend_client.crt --mtls-backend-key-path=/opt/loxilb/cert/backend_client.key --mtls-backend-verify-server
else
docker exec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2020,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "name": "e2e-mtls-required-service",
    "host": "10.10.10.254",
    "mtls_frontend": {
      "client_cert_mode": "required",
      "client_ca_path": "/opt/loxilb/cert/client_ca.crt",
      "require_client_cn": true,
      "client_cn_pattern": "*.internal.corp.com"
    },
    "mtls_backend": {
      "backend_ca_path": "/opt/loxilb/cert/backend_ca.crt",
      "client_cert_path": "/opt/loxilb/cert/backend_client.crt",
      "client_key_path": "/opt/loxilb/cert/backend_client.key",
      "verify_server_cert": true
    }
  },
  "endpoints": [
    {
      "endpointIP": "31.31.31.1",
      "targetPort": 8443,
      "weight": 1
    },
    {
      "endpointIP": "32.32.32.1",
      "targetPort": 8443,
      "weight": 1
    },
    {
      "endpointIP": "33.33.33.1",
      "targetPort": 8443,
      "weight": 1
    }
  ]
}'
fi

# Test 2: Frontend mTLS optional + Backend mTLS verification
if [[ "$USE_CLI" == "1" ]]; then
  create_lb_rule llb1 10.10.10.254 --tcp=2021:8443 --endpoints=31.31.31.1:1,32.32.32.1:1,33.33.33.1:1 --mode=fullproxy --security=e2ehttps --name=e2e-mtls-optional-service --host=10.10.10.254 --mtls-client-cert-mode=optional --mtls-client-ca-path=/opt/loxilb/cert/client_ca.crt --mtls-backend-ca-path=/opt/loxilb/cert/backend_ca.crt --mtls-backend-cert-path=/opt/loxilb/cert/backend_client.crt --mtls-backend-key-path=/opt/loxilb/cert/backend_client.key --mtls-backend-verify-server
else
docker exec llb1 curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer \
  -H "Content-Type: application/json" \
  -d '{
  "serviceArguments": {
    "externalIP": "10.10.10.254",
    "port": 2021,
    "protocol": "tcp",
    "security": 2,
    "mode": 4,
    "name": "e2e-mtls-optional-service",
    "host": "10.10.10.254",
    "mtls_frontend": {
      "client_cert_mode": "optional",
      "client_ca_path": "/opt/loxilb/cert/client_ca.crt"
    },
    "mtls_backend": {
      "backend_ca_path": "/opt/loxilb/cert/backend_ca.crt",
      "client_cert_path": "/opt/loxilb/cert/backend_client.crt",
      "client_key_path": "/opt/loxilb/cert/backend_client.key",
      "verify_server_cert": true
    }
  },
  "endpoints": [
    {
      "endpointIP": "31.31.31.1",
      "targetPort": 8443,
      "weight": 1
    },
    {
      "endpointIP": "32.32.32.1",
      "targetPort": 8443,
      "weight": 1
    },
    {
      "endpointIP": "33.33.33.1",
      "targetPort": 8443,
      "weight": 1
    }
  ]
}'
fi

echo "#########################################"
echo "End-to-end mTLS configuration complete"
echo "#########################################"