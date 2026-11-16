#!/usr/bin/env bash
# Invoked by validation.sh while the verified HTTPS backends are running.
source ../common.sh

validate_frontend_mtls_sni() (
    set -euo pipefail
    local vip=$1
    local hostname=frontend-mtls-ci.test
    local port=2022
    local api=http://localhost:11111/netlox/v1
    local tmp response status
    tmp=$(mktemp -d)
    trap 'rm -rf -- "$tmp"' EXIT

    # A distinct DNS-only leaf makes server hostname verification proof that
    # the SNI callback selected the uploaded certificate.
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$hostname" \
        -keyout "$tmp/server.key" -out "$tmp/server.csr" 2>"$tmp/openssl.log"
    printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$hostname" >"$tmp/extensions"
    openssl x509 -req -days 2 -CA minica.pem -CAkey minica-key.pem \
        -CAserial "$tmp/ca.srl" -CAcreateserial -extfile "$tmp/extensions" \
        -in "$tmp/server.csr" -out "$tmp/server.crt" 2>>"$tmp/openssl.log"

    python3 - "$tmp" > "$tmp/cert.json" <<'PY'
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
print(json.dumps({
    "certId": "e2e-frontend-mtls-sni",
    "certPem": (directory / "server.crt").read_text(),
    "keyPem": (directory / "server.key").read_text(),
}))
PY
    status=$($dexec llb1 curl --silent --show-error --max-time 10 \
        -X POST -H 'Content-Type: application/json' --data-binary @- \
        -o /dev/null -w '%{http_code}' "$api/config/cert" < "$tmp/cert.json")
    if [[ $status != 201 ]]; then
        echo "Frontend mTLS SNI certificate upload returned HTTP $status, expected 201" >&2
        exit 1
    fi

    # Set only inline client CA. Keep backend identity and verification from
    # the other security=2 rules in this scenario.
    python3 - "$vip" "$port" > "$tmp/rule.json" <<'PY'
import base64
import json
import pathlib
import sys

vip, port = sys.argv[1:]
print(json.dumps({
    "serviceArguments": {
        "externalIP": vip, "port": int(port), "protocol": "tcp", "mode": 4, "security": 2,
        "name": "e2e-mtls-inline-required", "host": vip,
        "mtls_frontend": {
            "client_cert_mode": "required",
            "client_ca_cert_data": base64.standard_b64encode(pathlib.Path("minica.pem").read_bytes()).decode("ascii"),
        },
        "mtls_backend": {"verify_server_cert": True},
        "backend_ca_cert_id": "e2e-backend-ca",
        "backend_client_cert_id": "e2e-backend-client",
    },
    "endpoints": [{"endpointIP": "31.31.31.1", "targetPort": 8443, "weight": 1}],
}))
PY
    if ! $dexec llb1 curl --fail-with-body --silent --show-error --max-time 10 \
        -X POST -H 'Content-Type: application/json' --data-binary @- "$api/config/loadbalancer" \
        < "$tmp/rule.json" > "$tmp/rule-response.json"; then
        cat "$tmp/rule-response.json" >&2
        exit 1
    fi
    python3 - "$tmp/rule-response.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as stream:
    response = json.load(stream)
if response.get("result") != "Success":
    raise SystemExit(f"Inline required-mTLS rule creation failed: {response}")
PY

    local -a client=(curl --fail --silent --show-error --max-time 10 --noproxy '*'
                     --tlsv1.2 --tls-max 1.2 --cacert minica.pem)
    local -a valid=(--cert client1.internal.corp.com/cert.pem --key client1.internal.corp.com/key.pem)
    local -a sni=(--resolve "$hostname:$port:$vip" -H "Host: $vip")
    response=$($hexec l3h1 "${client[@]}" "${valid[@]}" "https://$vip:$port")
    if [[ $response != server1 ]]; then
        echo "Inline CA without SNI: unexpected backend response '$response'" >&2
        exit 1
    fi
    echo "Required inline CA, valid client without SNI [OK]"

    response=$($hexec l3h1 "${client[@]}" "${valid[@]}" "${sni[@]}" "https://$hostname:$port")
    if [[ $response != server1 ]]; then
        echo "Inline CA with SNI: unexpected backend response '$response'" >&2
        exit 1
    fi
    echo "Required inline CA, SNI server certificate and valid client [OK]"

    if response=$($hexec l3h1 "${client[@]}" "${sni[@]}" \
        --cert rogue-client/cert.pem --key rogue-client/key.pem "https://$hostname:$port" 2>&1); then
        echo "Inline CA with SNI accepted a wrong-CA client" >&2
        exit 1
    fi
    if ! grep -qiE 'alert .*unknown ca' <<<"$response"; then
        echo "Inline CA with SNI: expected unknown-CA TLS alert, got '$response'" >&2
        exit 1
    fi
    echo "Required inline CA, SNI rejects wrong-CA client with TLS unknown_ca [OK]"
)

validate_frontend_mtls_sni "$1"
