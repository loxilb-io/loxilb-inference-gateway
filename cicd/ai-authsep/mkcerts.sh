#!/bin/bash
# Mint the certificate material the TLS legs need (DP-16, DP-17).
#
# Four artefacts, and the differences between them are the test:
#
#   ca.crt/ca.key          the CA the gateway is told to trust
#   server.crt/server.key  the store's certificate, SAN = DNS:aikey-store ONLY.
#                          No IP SAN, deliberately: connecting to the same
#                          server by its address is then a hostname mismatch
#                          and nothing else, which is what DP-17 needs.
#   client.crt/client.key  CN=aigwuser, so pg_hba's `cert` method authenticates
#                          the gateway by its certificate. If the client
#                          keypair were ignored the connection would simply
#                          fail, so the positive leg proves it is load-bearing.
#   rogue-ca.crt           an unrelated CA. Handed to the gateway in place of
#                          ca.crt it must produce an unknown-authority failure
#                          and no connection at all.
#
# openssl rather than minica: it is present on every runner and in the loxilb
# image, and the SAN sets here have to be exact.
set -euo pipefail

OUT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs}"
STORE_DNS="${AIKEY_STORE_DNS:-aikey-store}"

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca.key -out ca.crt -subj "/CN=ai-authsep-store-ca" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout rogue-ca.key -out rogue-ca.crt -subj "/CN=ai-authsep-rogue-ca" >/dev/null 2>&1

# Server certificate: DNS SAN only.
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=${STORE_DNS}" >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 3650 \
    -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$STORE_DNS") \
    >/dev/null 2>&1

# Client certificate: CN must equal the database role for pg_hba `cert`.
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
    -subj "/CN=aigwuser" >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 3650 \
    -extfile <(printf 'extendedKeyUsage=clientAuth\n') >/dev/null 2>&1

rm -f server.csr client.csr

# PostgreSQL refuses a key file that is group- or world-readable. Owned by
# root it accepts 0640; the container's postgres user reads it through the
# bind mount.
chmod 0640 server.key ca.key rogue-ca.key
chmod 0644 ca.crt rogue-ca.crt server.crt client.crt
# The gateway reads the client key as root inside its own container.
chmod 0600 client.key

echo "certs minted in $OUT (server SAN = DNS:${STORE_DNS}, client CN = aigwuser)"
