#!/bin/bash
# B-2..B-5 management-plane baselines, run directly against llb1:11111.
# Values are read from the database rather than from the endpoint's own reply,
# because two of the endpoints under test are the ones suspected of lying.
source /root/authsep-baseline.env
API=http://localhost:11111/netlox/v1
mysqlq() { docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e "$1" 2>/dev/null; }

echo "############ B-3: GET /auth/users with a user present ############"
docker exec llb1 curl -s -m 15 -w "\nHTTP=%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" $API/auth/users

echo
echo "############ B-4: password material in the list body ############"
echo "--- the body above is the evidence; the response model carries the field regardless ---"

echo
echo "############ B-2: PUT /auth/users/{id} password change ############"
ADMIN_ID=$(mysqlq 'SELECT id FROM users WHERE username="admin";')
echo "admin id=$ADMIN_ID  hash before: $(mysqlq 'SELECT LEFT(password,20) FROM users WHERE username="admin";')"
T0=$(date +%s)
docker exec llb1 curl -s -m 30 -w "\nHTTP=%{http_code}\n" -X PUT $API/auth/users/"$ADMIN_ID" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"username":"admin","password":"NewPass456!"}'
T1=$(date +%s)
echo "elapsed=$((T1 - T0))s"
echo "hash after:  $(mysqlq 'SELECT LEFT(password,20) FROM users WHERE username="admin";')"
echo "--- login with the NEW password (expect no token if the change did not land) ---"
docker exec llb1 curl -s -m 10 -w "\nHTTP=%{http_code}\n" -X POST $API/auth/login \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"NewPass456!"}'
echo "--- login with the OLD password (expect a token if the change did not land) ---"
docker exec llb1 curl -s -m 10 -w "\nHTTP=%{http_code}\n" -X POST $API/auth/login \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"Admin123!"}'

echo
echo "############ B-5: data-plane key hash as a management Bearer ############"
BODY='{"model":"test-model","messages":[{"role":"user","content":"hi"}],"max_tokens":8}'
docker exec l3h1 curl -s -m 10 -o /dev/null -w "vip_keyed_status=%{http_code}\n" -X POST \
  http://10.10.10.254:2020/v1/chat/completions -H "Content-Type: application/json" \
  -H "X-Api-Key: $RAW_KEY" -d "$BODY"
HASH=$(printf "%s" "$RAW_KEY" | sha256sum | cut -d" " -f1)
echo "sha256hex(rawKey)=$HASH"
echo "--- GET /auth/users with Bearer=<keyhash> ---"
docker exec llb1 curl -s -m 15 -w "\nHTTP=%{http_code}\n" \
  -H "Authorization: Bearer $HASH" $API/auth/users
echo "--- is the gateway still serving? ---"
docker exec llb1 curl -s -m 10 -w "\nHTTP=%{http_code}\n" $API/version
