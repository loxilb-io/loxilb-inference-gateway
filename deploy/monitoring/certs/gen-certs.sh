#!/usr/bin/env bash
# OPTIONAL tooling — only for the transport-encryption scrape path
# (docs/MONITORING-DESIGN.md §2 "Optional"). The default monitoring deployment
# uses a same-host, network-isolated plaintext scrape and needs NO certs. TLS on
# the loxilb API listener is transport encryption, not scraper authentication
# (finding F11); the client cert below is transport hardening only.
#
# Generate a self-signed CA plus the loxilb API server cert and a Prometheus
# scraper client cert.
#
# Usage:   ./gen-certs.sh <IP-or-DNS SAN> [more SANs...]
# Example: ./gen-certs.sh 172.17.0.2 10.10.10.254 llb1
#
# Outputs (in this directory):
#   rootCA.crt / rootCA.key   private CA (keep rootCA.key offline in production)
#   server.crt / server.key   install into the loxilb container at /opt/loxilb/cert/
#   client.crt / client.key   mounted into the Prometheus container (tls_config)
#
# loxilb side: run loxilb with `--tls` and env TLS_CA_CERTIFICATE=/opt/loxilb/cert/rootCA.crt
# (the --tls-ca flag is only known to the API sub-parser; the env var works everywhere).
set -euo pipefail
cd "$(dirname "$0")"

[ $# -ge 1 ] || { echo "usage: $0 <IP-or-DNS SAN> [more SANs...]" >&2; exit 1; }

DAYS_CA=3650
DAYS_LEAF=825

san_list="DNS:localhost,IP:127.0.0.1"
for s in "$@"; do
  if [[ "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san_list+=",IP:$s"
  else
    san_list+=",DNS:$s"
  fi
done

if [ ! -f rootCA.key ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS_CA" -nodes \
    -keyout rootCA.key -out rootCA.crt -subj "/CN=loxilb-monitoring-ca"
  echo "new CA created"
fi

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=loxilb"
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -days "$DAYS_LEAF" -sha256 -out server.crt \
  -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n" "$san_list")

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=prometheus-scraper"
openssl x509 -req -in client.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -days "$DAYS_LEAF" -sha256 -out client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n")

rm -f server.csr client.csr
chmod 600 ./*.key
echo "OK: rootCA / server / client certs generated (SANs: $san_list)"
