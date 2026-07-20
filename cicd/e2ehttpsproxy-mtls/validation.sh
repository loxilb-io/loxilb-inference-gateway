#!/bin/bash
source ../common.sh
echo SCENARIO-e2e-mtls-fullproxy

# Start backend HTTPS servers with mTLS support
# These servers will verify loxilb's client certificate
$hexec l3ep1 node ../common/tcp_https_mtls_server.js server1 8443 31.31.31.1/cert.pem 31.31.31.1/key.pem minica.pem &
$hexec l3ep2 node ../common/tcp_https_mtls_server.js server2 8443 32.32.32.1/cert.pem 32.32.32.1/key.pem minica.pem &
$hexec l3ep3 node ../common/tcp_https_mtls_server.js server3 8443 33.33.33.1/cert.pem 33.33.33.1/key.pem minica.pem &

sleep 5
code=0
servIP="10.10.10.254"
servArr=( "server1" "server2" "server3" )

echo "#########################################"
echo "Test 1: E2E mTLS Required - Valid Frontend Client Certificate"
echo "#########################################"

# Test with valid client certificate (CN matches pattern: client1.internal.corp.com)
# Backend mTLS: loxilb presents client cert to backends and verifies their server certs
# 2×3=6 requests (up from 3) to improve load-distribution confidence
lcode=0
declare -A t1_backends
for i in {1..2}
do
for j in {0..2}
do
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert client1.internal.corp.com/cert.pem \
        --key client1.internal.corp.com/key.pem \
        -s https://${servIP}:2020)
    echo "E2E mTLS valid client cert response: $res"
    # Check if response is one of the valid backend servers (order doesn't matter)
    if [[ $res != "server1" && $res != "server2" && $res != "server3" ]]
    then
        lcode=1
    else
        t1_backends[$res]=1
    fi
    sleep 1
done
done
t1_unique=${#t1_backends[@]}
echo "  Test 1: $t1_unique unique backend(s) responded"

if [[ $lcode == 0 ]]
then
    echo "Test 1: E2E mTLS with valid frontend client cert [OK]"
else
    echo "Test 1: E2E mTLS with valid frontend client cert [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 2: E2E mTLS Required - Invalid Frontend Client Certificate (Wrong CN)"
echo "#########################################"

# Test with invalid client certificate (CN doesn't match pattern: client2.external.com)
# This should FAIL at frontend - connection rejected before reaching backend
res=$($hexec l3h1 curl --max-time 10 \
    --cacert minica.pem \
    --cert client2.external.com/cert.pem \
    --key client2.external.com/key.pem \
    --fail --silent --show-error \
    https://${servIP}:2020 2>&1)
curl_exit=$?

# Check if connection was rejected via TLS exit code (not empty response which could be a timeout)
# Exit 35 = CURLE_SSL_CONNECT_ERROR, 60 = CURLE_SSL_CACERT — genuine TLS rejection
# Exit 28 = CURLE_OPERATION_TIMEDOUT — must NOT be treated as rejection (false-positive guard)
if [[ $curl_exit -eq 35 || $curl_exit -eq 60 ]]; then
    echo "Test 2: E2E mTLS rejected invalid frontend CN pattern (exit=$curl_exit) [OK]"
elif [[ $curl_exit -eq 28 ]]; then
    echo "Test 2: TIMEOUT — backend may be unreachable, not TLS rejection [FAILED]"
    code=1
elif [[ $curl_exit -eq 0 ]]; then
    echo "Test 2: connection SUCCEEDED — mTLS is NOT enforcing CN check [FAILED]"
    code=1
else
    if [[ "$res" =~ "SSL" || "$res" =~ "alert" || "$res" =~ "handshake" ]]; then
        echo "Test 2: E2E mTLS rejected invalid frontend CN pattern (exit=$curl_exit) [OK]"
    else
        echo "Test 2: ambiguous curl exit=$curl_exit, no SSL keywords in: $res [FAILED]"
        code=1
    fi
fi

echo "#########################################"
echo "Test 3: E2E mTLS Required - No Frontend Client Certificate"
echo "#########################################"

# Test without client certificate
# This should FAIL at frontend - connection rejected
res=$($hexec l3h1 curl --max-time 10 \
    --cacert minica.pem \
    --fail --silent --show-error \
    https://${servIP}:2020 2>&1)
curl_exit=$?

# Check if connection was rejected via TLS exit code (not empty response which could be a timeout)
# Exit 35 = CURLE_SSL_CONNECT_ERROR, 60 = CURLE_SSL_CACERT — genuine TLS rejection
# Exit 28 = CURLE_OPERATION_TIMEDOUT — must NOT be treated as rejection (false-positive guard)
if [[ $curl_exit -eq 35 || $curl_exit -eq 60 ]]; then
    echo "Test 3: E2E mTLS rejected missing frontend client cert (exit=$curl_exit) [OK]"
elif [[ $curl_exit -eq 28 ]]; then
    echo "Test 3: TIMEOUT — backend may be unreachable, not TLS rejection [FAILED]"
    code=1
elif [[ $curl_exit -eq 0 ]]; then
    echo "Test 3: connection SUCCEEDED — mTLS is NOT requiring client cert [FAILED]"
    code=1
else
    if [[ "$res" =~ "SSL" || "$res" =~ "alert" || "$res" =~ "handshake" ]]; then
        echo "Test 3: E2E mTLS rejected missing frontend client cert (exit=$curl_exit) [OK]"
    else
        echo "Test 3: ambiguous curl exit=$curl_exit, no SSL keywords in: $res [FAILED]"
        code=1
    fi
fi

echo "#########################################"
echo "Test 4: E2E mTLS Optional - With Valid Frontend Client Certificate"
echo "#########################################"

# Test optional mode with valid client certificate
# Backend mTLS still enforced (loxilb verifies backend certs)
# 2×3=6 requests to improve load-distribution confidence
lcode=0
declare -A t4_backends
for i in {1..2}
do
for j in {0..2}
do
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert client1.internal.corp.com/cert.pem \
        --key client1.internal.corp.com/key.pem \
        -s https://${servIP}:2021)
    echo "E2E mTLS optional with frontend cert response: $res"
    # Check if response is one of the valid backend servers (order doesn't matter)
    if [[ $res != "server1" && $res != "server2" && $res != "server3" ]]
    then
        lcode=1
    else
        t4_backends[$res]=1
    fi
    sleep 1
done
done
t4_unique=${#t4_backends[@]}
echo "  Test 4: $t4_unique unique backend(s) responded"

if [[ $lcode == 0 ]]
then
    echo "Test 4: E2E mTLS optional with frontend client cert [OK]"
else
    echo "Test 4: E2E mTLS optional with frontend client cert [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 5: E2E mTLS Optional - Without Frontend Client Certificate"
echo "#########################################"

# Test optional mode without client certificate (should work)
# Backend mTLS still enforced (loxilb verifies backend certs and presents its own cert)
# 2×3=6 requests to improve load-distribution confidence
lcode=0
declare -A t5_backends
for i in {1..2}
do
for j in {0..2}
do
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        -s https://${servIP}:2021)
    echo "E2E mTLS optional without frontend cert response: $res"
    # Check if response is one of the valid backend servers (order doesn't matter)
    if [[ $res != "server1" && $res != "server2" && $res != "server3" ]]
    then
        lcode=1
    else
        t5_backends[$res]=1
    fi
    sleep 1
done
done
t5_unique=${#t5_backends[@]}
echo "  Test 5: $t5_unique unique backend(s) responded"

if [[ $lcode == 0 ]]
then
    echo "Test 5: E2E mTLS optional without frontend client cert [OK]"
else
    echo "Test 5: E2E mTLS optional without frontend client cert [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 6: Backend mTLS Verification - Backend Server Certificate Validation"
echo "#########################################"

# The old unconditional echo [OK] was a tautology — it never actually
# tested anything. The correct behavior is to detect a rogue backend (self-signed
# cert not in the minica CA) and confirm loxilb rejects it.
# Until a rogue-backend fixture is added to config.sh, mark this as an explicit
# SKIP so its absence is visible in CI logs rather than silently passing.
echo "Test 6: [SKIP] rogue-backend cert rejection test requires a 4th backend"
echo "        with a self-signed cert outside the minica CA (not yet provisioned)"
echo "        Add a rogue backend in config.sh and assert loxilb returns 5xx here"

echo "#########################################"
echo "Test 7: Expired Client Certificate → Server Must Reject"
echo "#########################################"

# Test 7: Client presents a certificate that has expired (notAfter in the past).
# Generated in config.sh via openssl with -days -1, signed by the minica CA so the
# CA signature is valid — rejection must come from cert validity check, not CA check.
# A silent SKIP hides the fact that these test fixtures are missing.
# Change to FAILED so the test suite alerts when cert generation was incomplete.
if [ -f client-expired/cert.pem ] && [ -f client-expired/key.pem ]; then
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert client-expired/cert.pem \
        --key client-expired/key.pem \
        --fail --silent --show-error \
        https://${servIP}:2020 2>&1)
    curl_exit=$?
    if [[ $curl_exit -ne 0 ]]; then
        echo "Test 7: expired cert rejected (exit=$curl_exit) [OK]"
    else
        echo "Test 7: expired cert ACCEPTED — server not checking cert validity [FAILED]"
        code=1
    fi
else
    echo "Test 7: [FAILED] client-expired/cert.pem missing — cert fixture not generated in config.sh"
    code=1
fi

echo "#########################################"
echo "Test 8: Client Cert Signed by Untrusted CA → Server Must Reject"
echo "#########################################"

# Test 8: Client presents a cert with a CN that matches the allowed pattern but is signed
# by a rogue CA (not the minica root).  If loxilb pins the CA, the connection is rejected.
# The curl CA bundle still uses minica.pem so the TLS handshake failure comes from the
# server side rejecting the client cert, not from curl unable to verify the server cert.
# Same as Test 7 — SKIP was silently hiding missing rogue-client fixture.
if [ -f rogue-client/cert.pem ] && [ -f rogue-client/key.pem ]; then
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert rogue-client/cert.pem \
        --key rogue-client/key.pem \
        --fail --silent --show-error \
        https://${servIP}:2020 2>&1)
    curl_exit=$?
    if [[ $curl_exit -ne 0 ]]; then
        echo "Test 8: untrusted CA cert rejected (exit=$curl_exit) [OK]"
    else
        echo "Test 8: untrusted CA cert ACCEPTED — CA pinning not enforced [FAILED]"
        code=1
    fi
else
    echo "Test 8: [FAILED] rogue-client/cert.pem missing — cert fixture not generated in config.sh"
    code=1
fi

echo "#########################################"
echo "Test 9: SAN-Only Cert (No CN) — Document Behavior (Informational)"
echo "#########################################"

# Test 9: Client presents a cert with a valid SAN extension but an empty CN field,
# signed by the trusted minica CA.  Whether loxilb accepts or rejects this depends on
# whether its CN-pattern matching falls back to SAN or requires a non-empty CN.
# This test is informational only — it never sets code=1 — to establish baseline behavior.
if [ -f san-only/cert.pem ] && [ -f san-only/key.pem ]; then
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert san-only/cert.pem \
        --key san-only/key.pem \
        --fail --silent --show-error \
        https://${servIP}:2020 2>&1)
    curl_exit=$?
    if [[ $curl_exit -eq 0 ]]; then
        echo "  Test 9: SAN-only cert ACCEPTED (loxilb uses SAN for matching) [INFO]"
    elif [[ $curl_exit -eq 35 || $curl_exit -eq 60 ]]; then
        echo "  Test 9: SAN-only cert REJECTED at TLS layer (exit=$curl_exit) [INFO]"
    else
        echo "  Test 9: SAN-only cert — curl exit=$curl_exit, output: $res [INFO]"
    fi
    echo "  Test 9: behavior documented above — not a pass/fail gate [OK]"
else
    echo "Test 9: SKIP — san-only/cert.pem not found (openssl or minica-key.pem unavailable during config)"
fi

echo "#########################################"
echo "Test 10: Backend mTLS — loxilb Presents Cert to Backend, Connection Succeeds"
echo "#########################################"

# Test 10: A valid mTLS client request traverses the full path:
#   client → loxilb (frontend TLS) → loxilb → backend (backend mTLS with loxilb client cert)
# Verifies the backend mTLS leg: loxilb presents backend_client.crt and backends verify it.
# Uses the valid CN cert so the frontend check passes and we reach the backend mTLS path.
res=$($hexec l3h1 curl --max-time 10 \
    --cacert minica.pem \
    --cert client1.internal.corp.com/cert.pem \
    --key client1.internal.corp.com/key.pem \
    -s https://${servIP}:2020 2>&1)
if [[ "$res" == "server1" || "$res" == "server2" || "$res" == "server3" ]]; then
    echo "  Test 10: backend mTLS connection succeeded (response=$res) [OK]"
else
    echo "  Test 10: backend mTLS connection failed: $res [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 11: Load Distribution Across mTLS Endpoints (≥2 backends receive traffic)"
echo "#########################################"

# Test 11: Send 6 valid mTLS requests and verify that at least 2 distinct backends
# receive traffic — confirms that mTLS enforcement does not break round-robin distribution.
declare -A mtls_hits
for i in $(seq 1 6); do
    srv=$($hexec l3h1 curl -s --max-time 5 \
        --cacert minica.pem \
        --cert client1.internal.corp.com/cert.pem \
        --key client1.internal.corp.com/key.pem \
        https://${servIP}:2020 2>/dev/null | grep -o 'server[0-9]*' | head -1)
    [[ -n "$srv" ]] && mtls_hits[$srv]=$((${mtls_hits[$srv]:-0} + 1))
done
backends_hit=${#mtls_hits[@]}
if [[ $backends_hit -ge 2 ]]; then
    echo "  Test 11: $backends_hit backends received mTLS traffic [OK]"
else
    echo "  Test 11: only $backends_hit backend(s) received traffic (expected ≥2) [FAILED]"
    code=1
fi

sudo killall -9 node 2>&1 > /dev/null

# REST API validation — verify mTLS rule fields are stored/retrievable via API
if [[ -f ./validate_api.sh ]]; then
  bash ./validate_api.sh || code=1
fi

if [[ $code == 0 ]]
then
    echo "#########################################"
    echo "SCENARIO-e2e-mtls-fullproxy [OK]"
    echo "#########################################"
else
    echo "#########################################"
    echo "SCENARIO-e2e-mtls-fullproxy [FAILED]"
    echo "#########################################"
fi

exit $code
