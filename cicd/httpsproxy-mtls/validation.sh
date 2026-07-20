#!/bin/bash
source ../common.sh
echo SCENARIO-mtls-fullproxy

# Start backend servers
$hexec l3ep1 node ../common/tcp_server.js server1 &
$hexec l3ep2 node ../common/tcp_server.js server2 &
$hexec l3ep3 node ../common/tcp_server.js server3 &

sleep 5
code=0
servIP="10.10.10.254"
servArr=( "server1" "server2" "server3" )

echo "#########################################"
echo "Test 1: mTLS Required - Valid Client Certificate"
echo "#########################################"

# Test with valid client certificate (CN matches pattern: client1.internal.corp.com)
lcode=0
for i in {1..1}
do
for j in {0..2}
do
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert client1.internal.corp.com/cert.pem \
        --key client1.internal.corp.com/key.pem \
        -s https://${servIP}:2020)
    echo "Valid client cert response: $res"
    # Check if response is one of the valid backend servers (order doesn't matter)
    if [[ $res != "server1" && $res != "server2" && $res != "server3" ]]
    then
        lcode=1
    fi
    sleep 1
done
done

if [[ $lcode == 0 ]]
then
    echo "Test 1: mTLS with valid client cert [OK]"
else
    echo "Test 1: mTLS with valid client cert [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 2: mTLS Required - Invalid Client Certificate (Wrong CN)"
echo "#########################################"

# Test with invalid client certificate (CN doesn't match pattern: client2.external.com)
# This should FAIL (connection rejected)
res=$($hexec l3h1 curl --max-time 10 \
    --cacert minica.pem \
    --cert client2.external.com/cert.pem \
    --key client2.external.com/key.pem \
    -v https://${servIP}:2020 2>&1)

# Check if connection was rejected (curl should fail)
if [[ $res =~ "SSL" || $res =~ "alert" || -z "$res" ]]
then
    echo "Test 2: mTLS rejected invalid CN pattern [OK]"
else
    echo "Test 2: mTLS should have rejected invalid CN: $res [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 3: mTLS Required - No Client Certificate"
echo "#########################################"

# Test without client certificate
# This should FAIL (connection rejected)
res=$($hexec l3h1 curl --max-time 10 \
    --cacert minica.pem \
    -s https://${servIP}:2020 2>&1)

# Check if connection was rejected
if [[ $res =~ "SSL" || $res =~ "alert" || -z "$res" ]]
then
    echo "Test 3: mTLS rejected missing client cert [OK]"
else
    echo "Test 3: mTLS should have rejected missing cert: $res [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 4: mTLS Optional - With Valid Client Certificate"
echo "#########################################"

# Test optional mode with valid client certificate
lcode=0
for i in {1..1}
do
for j in {0..2}
do
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        --cert client1.internal.corp.com/cert.pem \
        --key client1.internal.corp.com/key.pem \
        -s https://${servIP}:2021)
    echo "Optional mode with cert response: $res"
    # Check if response is one of the valid backend servers (order doesn't matter)
    if [[ $res != "server1" && $res != "server2" && $res != "server3" ]]
    then
        lcode=1
    fi
    sleep 1
done
done

if [[ $lcode == 0 ]]
then
    echo "Test 4: mTLS optional with client cert [OK]"
else
    echo "Test 4: mTLS optional with client cert [FAILED]"
    code=1
fi

echo "#########################################"
echo "Test 5: mTLS Optional - Without Client Certificate"
echo "#########################################"

# Test optional mode without client certificate (should work)
lcode=0
for i in {1..1}
do
for j in {0..2}
do
    res=$($hexec l3h1 curl --max-time 10 \
        --cacert minica.pem \
        -s https://${servIP}:2021)
    echo "Optional mode without cert response: $res"
    # Check if response is one of the valid backend servers (order doesn't matter)
    if [[ $res != "server1" && $res != "server2" && $res != "server3" ]]
    then
        lcode=1
    fi
    sleep 1
done
done

if [[ $lcode == 0 ]]
then
    echo "Test 5: mTLS optional without client cert [OK]"
else
    echo "Test 5: mTLS optional without client cert [FAILED]"
    code=1
fi

sudo killall -9 node 2>&1 > /dev/null

if [[ $code == 0 ]]
then
    echo "#########################################"
    echo "SCENARIO-mtls-fullproxy [OK]"
    echo "#########################################"
else
    echo "#########################################"
    echo "SCENARIO-mtls-fullproxy [FAILED]"
    echo "#########################################"
fi

exit $code
