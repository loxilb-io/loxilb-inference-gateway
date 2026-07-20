# End-to-End mTLS Load Balancer Test

This test validates complete end-to-end mutual TLS (mTLS) functionality in loxilb's full proxy mode.

## Test Topology

```
[Client]                 [LoxiLB]                  [Backend Servers]
(l3h1)                   (llb1)                    (l3ep1/2/3)
10.10.10.1               10.10.10.254              31.31.31.1/32.32.32.1/33.33.33.1

  │                          │                          │
  │  Frontend mTLS (HTTPS)   │   Backend mTLS (HTTPS)   │
  │  ────────────────────>   │   ────────────────────>  │
  │                          │                          │
  │  Client cert required    │   Server cert verified   │
  │  CN pattern matching     │   Client cert presented  │
```

## mTLS Configuration

### Frontend mTLS (Client → LoxiLB)
- **Server certificate**: loxilb presents TLS certificate to clients
- **Client authentication**: 
  - **Required mode**: Client must present valid certificate with CN matching pattern `*.internal.corp.com`
  - **Optional mode**: Client certificate is optional (backward compatibility)
- **CN pattern validation**: Uses fnmatch wildcards for flexible matching

### Backend mTLS (LoxiLB → Backend Servers)
- **Server verification**: loxilb verifies backend server certificates against CA
- **Client presentation**: loxilb presents its own client certificate to backend servers
- **Mutual authentication**: Backend servers require and verify loxilb's client certificate

## Test Scenarios

### Test 1: E2E mTLS Required - Valid Frontend Client Certificate
- Client presents valid certificate (CN: `client1.internal.corp.com`)
- Frontend: Certificate accepted (CN matches `*.internal.corp.com`)
- Backend: loxilb presents client cert, verifies server certs
- **Expected**: Connection succeeds, load balanced across backends

### Test 2: E2E mTLS Required - Invalid Frontend Client Certificate
- Client presents certificate with wrong CN (CN: `client2.external.com`)
- Frontend: Certificate rejected (CN doesn't match `*.internal.corp.com`)
- **Expected**: TLS alert, connection rejected at frontend

### Test 3: E2E mTLS Required - No Frontend Client Certificate
- Client doesn't present certificate
- Frontend: Connection rejected (client cert required)
- **Expected**: TLS alert, connection rejected at frontend

### Test 4: E2E mTLS Optional - With Frontend Client Certificate
- Client presents valid certificate
- Frontend: Certificate accepted (optional mode)
- Backend: mTLS enforced (loxilb verifies backends)
- **Expected**: Connection succeeds, load balanced across backends

### Test 5: E2E mTLS Optional - Without Frontend Client Certificate
- Client doesn't present certificate
- Frontend: Connection accepted (optional mode)
- Backend: mTLS enforced (loxilb verifies backends)
- **Expected**: Connection succeeds, load balanced across backends

### Test 6: Backend mTLS Verification
- Validates that loxilb properly verifies backend server certificates
- Validates that backends accept loxilb's client certificate
- **Expected**: All backend connections use mTLS successfully

## Certificate Hierarchy

```
Root CA (minica)
  ├── Frontend Server Cert (10.10.10.254) - Presented by loxilb to clients
  ├── Client Cert 1 (client1.internal.corp.com) - Valid client
  ├── Client Cert 2 (client2.external.com) - Invalid client (wrong CN)
  ├── Backend Server Cert 1 (31.31.31.1) - Backend ep1
  ├── Backend Server Cert 2 (32.32.32.1) - Backend ep2
  ├── Backend Server Cert 3 (33.33.33.1) - Backend ep3
  └── LoxiLB Client Cert (loxilb.internal.loadbalancer.com) - Presented to backends
```

## Load Balancer Configuration

### Port 2020: Required Frontend mTLS + Backend mTLS
```json
{
  "security": 5,
  "mode": 4,
  "mtls_frontend": {
    "client_cert_mode": "required",
    "client_ca_path": "/opt/loxilb/cert/client_ca.crt",
    "require_client_cn": true,
    "client_cn_pattern": "*.internal.corp.com"
  },
  "mtls_backend": {
    "ca_path": "/opt/loxilb/cert/backend_ca.crt",
    "cert_path": "/opt/loxilb/cert/backend_client.crt",
    "key_path": "/opt/loxilb/cert/backend_client.key",
    "verify_server": true,
    "server_name_pattern": "*"
  }
}
```

### Port 2021: Optional Frontend mTLS + Backend mTLS
```json
{
  "security": 5,
  "mode": 4,
  "mtls_frontend": {
    "client_cert_mode": "optional",
    "client_ca_path": "/opt/loxilb/cert/client_ca.crt"
  },
  "mtls_backend": {
    "ca_path": "/opt/loxilb/cert/backend_ca.crt",
    "cert_path": "/opt/loxilb/cert/backend_client.crt",
    "key_path": "/opt/loxilb/cert/backend_client.key",
    "verify_server": true,
    "server_name_pattern": "*"
  }
}
```

## Certificate Management

### Initial Certificate Setup

The `config.sh` script automatically generates all necessary certificates using `minica`:

- **Root CA**: `minica.pem` (used to sign all certificates)
- **Frontend Server Certificate**: `10.10.10.254/` (presented by loxilb to clients)
- **Client Certificates**: `client1.internal.corp.com/`, `client2.external.com/`
- **Backend Server Certificates**: `31.31.31.1/`, `32.32.32.1/`, `33.33.33.1/`
- **LoxiLB Backend Client Certificate**: `loxilb.internal.loadbalancer.com/`

### Adding New Client Certificates After Initial Setup

After running `config.sh`, you can add additional client certificates without restarting the entire environment:

#### Step 1: Generate New Client Certificate

```bash
# Generate a new client certificate with a CN that matches the pattern *.internal.corp.com
./minica -domains client3.internal.corp.com -ip-addresses 10.10.10.1

# Or for a different client
./minica -domains admin.internal.corp.com -ip-addresses 10.10.10.1
```

#### Step 2: Update Client CA Bundle on LoxiLB

Since all certificates are signed by the same root CA (`minica.pem`), the CA bundle is already up-to-date. **No update needed** if using the same root CA.

If you need to add a **different CA** (e.g., for certificates signed by another authority):

```bash
# Append the new CA certificate to the existing CA bundle
cat new_ca.pem >> minica.pem

# Update the CA bundle on loxilb
docker cp minica.pem llb1:/opt/loxilb/cert/client_ca.crt

# Restart loxilb to reload the CA bundle (if hot-reload is not supported)
docker restart llb1
```

#### Step 3: Use New Client Certificate

```bash
# Copy the new client certificate to the client host
docker cp client3.internal.corp.com/cert.pem l3h1:/tmp/client3.crt
docker cp client3.internal.corp.com/key.pem l3h1:/tmp/client3.key

# Test with curl
$dexec l3h1 curl -v --cacert /tmp/minica.pem \
  --cert /tmp/client3.crt \
  --key /tmp/client3.key \
  https://10.10.10.254:2020
```

### Adding Backend Server Certificates

To add new backend servers with mTLS:

#### Step 1: Generate Backend Server Certificate

```bash
# Generate certificate for new backend IP
./minica -ip-addresses 34.34.34.1
```

#### Step 2: Deploy Certificate to Backend Server

```bash
# Copy server certificate to the new backend
docker cp 34.34.34.1/cert.pem l3ep4:/tmp/server.crt
docker cp 34.34.34.1/key.pem l3ep4:/tmp/server.key
docker cp minica.pem l3ep4:/tmp/ca.crt
docker cp minica.pem l3ep4:/tmp/client_ca.crt
```

#### Step 3: Update Load Balancer Configuration

```bash
# Add the new endpoint to the existing load balancer
curl -X POST http://localhost:11111/netlox/v1/config/loadbalancer/e2e-mtls-required-service/endpoint \
  -H "Content-Type: application/json" \
  -d '{
    "endpointIP": "34.34.34.1",
    "targetPort": 8443,
    "weight": 1
  }'
```

### Certificate Rotation and Renewal

#### Rotating Client Certificates

```bash
# 1. Generate new certificate with the same CN
./minica -domains client1.internal.corp.com -ip-addresses 10.10.10.1

# 2. Deploy to client host (overwrites old certificate)
docker cp client1.internal.corp.com/cert.pem l3h1:/tmp/client1.crt
docker cp client1.internal.corp.com/key.pem l3h1:/tmp/client1.key

# 3. Old certificate is automatically invalidated (same CN, new serial)
```

#### Rotating LoxiLB Server Certificate (Frontend)

```bash
# 1. Generate new server certificate
./minica -ip-addresses 10.10.10.254

# 2. Update certificate on loxilb
docker cp 10.10.10.254/cert.pem llb1:/opt/loxilb/cert/server.crt
docker cp 10.10.10.254/key.pem llb1:/opt/loxilb/cert/server.key

# 3. Restart loxilb or trigger hot-reload (if supported)
docker restart llb1
```

#### Rotating LoxiLB Backend Client Certificate

```bash
# 1. Generate new client certificate for loxilb
./minica -domains loxilb.internal.loadbalancer.com -ip-addresses 10.10.10.254

# 2. Update on loxilb
docker cp loxilb.internal.loadbalancer.com/cert.pem llb1:/opt/loxilb/cert/backend_client.crt
docker cp loxilb.internal.loadbalancer.com/key.pem llb1:/opt/loxilb/cert/backend_client.key

# 3. Restart loxilb
docker restart llb1
```

### Certificate Validation and Testing

#### Verify Certificate Details

```bash
# View certificate information
openssl x509 -in client1.internal.corp.com/cert.pem -text -noout

# Check certificate CN
openssl x509 -in client1.internal.corp.com/cert.pem -noout -subject

# Check certificate expiration
openssl x509 -in client1.internal.corp.com/cert.pem -noout -dates

# Verify certificate against CA
openssl verify -CAfile minica.pem client1.internal.corp.com/cert.pem
```

#### Test Client Certificate Authentication

```bash
# Test with valid client certificate (should succeed)
$dexec l3h1 curl -v --cacert /tmp/minica.pem \
  --cert /tmp/client1.crt \
  --key /tmp/client1.key \
  https://10.10.10.254:2020

# Test without client certificate (should fail on required mode)
$dexec l3h1 curl -v --cacert /tmp/minica.pem \
  https://10.10.10.254:2020

# Test with invalid CN (should fail)
$dexec l3h1 curl -v --cacert /tmp/minica.pem \
  --cert /tmp/client2.crt \
  --key /tmp/client2.key \
  https://10.10.10.254:2020
```

### Certificate Storage Locations

| Component | Certificate Type | LoxiLB Path | Purpose |
|-----------|-----------------|-------------|---------|
| Frontend TLS | Server Cert | `/opt/loxilb/cert/server.crt` | Presented to clients |
| Frontend TLS | Server Key | `/opt/loxilb/cert/server.key` | Private key for server cert |
| Frontend mTLS | Client CA Bundle | `/opt/loxilb/cert/client_ca.crt` | Verifies client certificates |
| Backend mTLS | Backend CA Bundle | `/opt/loxilb/cert/backend_ca.crt` | Verifies backend server certs |
| Backend mTLS | Client Cert | `/opt/loxilb/cert/backend_client.crt` | Presented to backends |
| Backend mTLS | Client Key | `/opt/loxilb/cert/backend_client.key` | Private key for backend client |

### Best Practices

1. **Certificate Expiration**: Monitor certificate expiration dates and renew before expiry
   ```bash
   # Check all certificates
   for cert in $(find . -name "cert.pem"); do
     echo "Certificate: $cert"
     openssl x509 -in "$cert" -noout -dates
     echo ""
   done
   ```

2. **CA Bundle Management**: Keep CA bundles updated when adding new certificate authorities

3. **CN Pattern Matching**: Ensure client certificate CNs match the configured pattern (`*.internal.corp.com`)

4. **Certificate Revocation**: To revoke a client certificate, remove it from the CA bundle or implement CRL/OCSP

5. **Backup Certificates**: Keep secure backups of private keys and CA certificates

6. **Separate CAs**: Consider using separate CAs for client and server certificates in production

7. **Key Security**: Never share private keys between systems; generate unique keys for each component

## Running the Tests

```bash
# Setup test environment
cd /path/to/cicd/e2ehttpsproxy-mtls
./config.sh

# Run validation tests
./validation.sh

# Cleanup
./rmconfig.sh
```

## Security Features Validated

1. **Frontend mTLS**:
   - ✅ Client certificate validation
   - ✅ CN pattern matching with wildcards
   - ✅ Required vs optional client certificates
   - ✅ Certificate rejection for invalid CNs

2. **Backend mTLS**:
   - ✅ Backend server certificate verification
   - ✅ loxilb client certificate presentation
   - ✅ Mutual authentication between loxilb and backends

3. **End-to-End Security**:
   - ✅ Complete TLS encryption from client to backend
   - ✅ Certificate validation at both frontend and backend
   - ✅ No plaintext communication in the entire chain

## References

- Frontend mTLS tests: `../httpsproxy-mtls/`
- HTTPS proxy tests: `../e2ehttpsproxy/`
- Common test utilities: `../common/`
