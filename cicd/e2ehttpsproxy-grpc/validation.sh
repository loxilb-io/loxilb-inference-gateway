#!/bin/bash
source ../common.sh
echo SCENARIO-e2ehttpsproxy-grpc

servArr=( "server1" "server2" "server3" )
ep=( "31.31.31.1" "32.32.32.1" "33.33.33.1" )
code=0

# Start gRPC servers on endpoints
echo "Starting gRPC servers on endpoints..." >&2
docker exec -d l3ep1 /root/grpc-server -host server1 -cert /certs/server.crt -key /certs/server.key -port 8082
docker exec -d l3ep2 /root/grpc-server -host server2 -cert /certs/server.crt -key /certs/server.key -port 8082
docker exec -d l3ep3 /root/grpc-server -host server3 -cert /certs/server.crt -key /certs/server.key -port 8082

sleep 10

# Wait for servers to be ready by checking connectivity
# echo "Waiting for gRPC servers to be ready..." >&2
# waitCount=0
# while [ $waitCount -lt 30 ]
# do
#     # Try to connect to each server through loxilb
#     res=$(docker exec l3h1 /root/grpc-client -host 10.10.10.254:2022 -cacert /certs/ca.crt 2>&1)
#     if [[ $res == *"Hello World from"* ]]
#     then
#         echo "gRPC servers are ready" >&2
#         break
#     else
#         echo "Waiting for gRPC servers... ($waitCount/30)" >&2
#         waitCount=$(( $waitCount + 1 ))
#         sleep 1
#     fi
# done

# if [ $waitCount -ge 30 ]
# then
#     echo "gRPC servers failed to start" >&2
#     echo SCENARIO-e2ehttpsproxy-grpc [FAILED] >&2
#     $hexec l3ep1 killall -9 grpc-server > /dev/null 2>&1
#     $hexec l3ep2 killall -9 grpc-server > /dev/null 2>&1
#     $hexec l3ep3 killall -9 grpc-server > /dev/null 2>&1
#     exit 1
# fi

# Test round-robin load balancing
echo "Testing gRPC round-robin load balancing..." >&2
code=0
for i in {1..4}
do
    for j in {0..2}
    do
        res=$(docker exec l3h1 /root/grpc-client -host 10.10.10.254:2022 -cacert /certs/ca.crt 2>&1)
        echo "Response: $res" >&2
        exp="Hello World from ${servArr[j]}"
        if [[ $res != *"$exp"* ]]
        then
            echo "Expected: $exp, Received: $res" >&2
            code=1
        else
            echo "✓ Got response from ${servArr[j]}" >&2
        fi
        sleep 1
    done
done

# Cleanup
$hexec l3ep1 killall -9 grpc-server > /dev/null 2>&1
$hexec l3ep2 killall -9 grpc-server > /dev/null 2>&1
$hexec l3ep3 killall -9 grpc-server > /dev/null 2>&1

if [[ $code == 0 ]]
then
    echo SCENARIO-e2ehttpsproxy-grpc [OK]
else
    echo SCENARIO-e2ehttpsproxy-grpc [FAILED]
fi

exit $code

