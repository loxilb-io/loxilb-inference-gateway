#!/bin/bash
# I-2 remainder: MGMT-2c, MGMT-4, MGMT-10, and the half of MGMT-15 that PR 1 owns.
#
# Run against a topology brought up with AUTHSEP_BOOTSTRAP=no, so the users table
# starts empty and MGMT-2c can drive the bootstrap race itself.
API=http://localhost:11111/netlox/v1
PASS=0
FAIL=0

chk() { # chk <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  [PASS] $1 (got $3)"
    PASS=$((PASS + 1))
  else
    echo "  [FAIL] $1 expected=$2 got=$3"
    FAIL=$((FAIL + 1))
  fi
}
code_llb() { docker exec llb1 curl -s -o /dev/null -m 30 -w "%{http_code}" "$@"; }
mysqlq() { docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e "$1" 2>/dev/null; }
jget() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

ROUNDS=${ROUNDS:-8}
RACERS=${RACERS:-12}

echo "===== MGMT-2c: $RACERS concurrent bootstrap requests, $ROUNDS rounds ====="
echo "  (the empty-table test and the insert must be one statement, or several"
echo "   racers each observe an empty table and each create an administrator)"
worst=0
for r in $(seq 1 "$ROUNDS"); do
  mysqlq "DELETE FROM users;" >/dev/null
  before=$(mysqlq "SELECT COUNT(*) FROM users;")
  if [ "$before" != "0" ]; then
    echo "  [FAIL] round $r: table not empty before the race (got $before)"
    FAIL=$((FAIL + 1))
    continue
  fi
  # Fire the racers simultaneously from inside llb1 so every peer is loopback.
  # Distinct usernames: a duplicate-key collision must not be what saves us.
  docker exec llb1 bash -c "
    for i in \$(seq 1 $RACERS); do
      curl -s -o /dev/null -m 30 -X POST $API/auth/users \
        -H 'Content-Type: application/json' \
        -d \"{\\\"username\\\":\\\"racer\$i\\\",\\\"password\\\":\\\"Racer123!\\\",\\\"role\\\":\\\"admin\\\"}\" &
    done
    wait" >/dev/null 2>&1
  after=$(mysqlq "SELECT COUNT(*) FROM users;")
  names=$(mysqlq "SELECT GROUP_CONCAT(username) FROM users;")
  if [ "$after" = "1" ]; then
    echo "  round $r: rows=1 ($names) OK"
  else
    echo "  round $r: rows=$after ($names)  <-- RACE LOST"
    [ "$after" -gt "$worst" ] && worst=$after
  fi
done
if [ "$worst" = "0" ]; then
  echo "  [PASS] MGMT-2c exactly one administrator after every round"
  PASS=$((PASS + 1))
else
  echo "  [FAIL] MGMT-2c a round produced $worst administrators"
  FAIL=$((FAIL + 1))
fi

echo
echo "===== set up a known state for the remaining legs ====="
mysqlq "DELETE FROM users;" >/dev/null
code_llb -X POST $API/auth/users -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!","role":"admin"}' >/dev/null
TOK=$(docker exec llb1 curl -s -m 30 -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}' | jget token)
code_llb -X POST $API/auth/users -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" \
  -d '{"username":"viewer1","password":"Viewer123!","role":"viewer"}' >/dev/null
VTOK=$(docker exec llb1 curl -s -m 30 -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"viewer1","password":"Viewer123!"}' | jget token)
KR=$(docker exec llb1 curl -s -m 30 -X POST $API/config/ai/apikey -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOK" \
  -d '{"tenant_id":"t1","name":"k1","allowed_models":["test-model"],"rate_limit_rps":100,"burst_size":200,"tokens_per_min":1000000,"enabled":true}')
KEY_ID=$(echo "$KR" | jget key_id)
echo "  admin token=${TOK:0:12}...  viewer token=${VTOK:0:12}...  key_id=$KEY_ID"

echo
echo "===== MGMT-4: unauthenticated PATCH /config/ai/apikey/{id} => 401, key UNCHANGED ====="
BEFORE=$(mysqlq "SELECT CONCAT(enabled,'|',rate_limit_rps,'|',tokens_per_min) FROM api_keys WHERE key_id='$KEY_ID';")
echo "  key row before: $BEFORE"
R=$(code_llb -X PATCH $API/config/ai/apikey/$KEY_ID -H "Content-Type: application/json" \
  -d '{"enabled":false,"rate_limit_rps":1,"tokens_per_min":1}')
chk "MGMT-4 unauthenticated PATCH rejected" "401" "$R"
AFTER=$(mysqlq "SELECT CONCAT(enabled,'|',rate_limit_rps,'|',tokens_per_min) FROM api_keys WHERE key_id='$KEY_ID';")
echo "  key row after:  $AFTER"
chk "MGMT-4 key row unchanged by the rejected PATCH" "$BEFORE" "$AFTER"

echo
echo "===== MGMT-10: generated DELETE and raw PATCH must agree per credential ====="
# Compare only the authentication verdict: 401/403 versus anything else. The two
# operations differ in what they do on success, so their success codes differ.
authclass() { case "$1" in 401) echo 401 ;; 403) echo 403 ;; *) echo allowed ;; esac; }
for cred in none garbage viewer admin; do
  case $cred in
    none)    H=() ;;
    garbage) H=(-H "Authorization: Bearer not-a-real-token") ;;
    viewer)  H=(-H "Authorization: Bearer $VTOK") ;;
    admin)   H=(-H "Authorization: Bearer $TOK") ;;
  esac
  # A key that does not exist, so neither call mutates anything: the auth
  # verdict is reached before the lookup either way.
  D=$(code_llb -X DELETE "$API/config/ai/apikey/doesnotexist" "${H[@]}")
  P=$(code_llb -X PATCH "$API/config/ai/apikey/doesnotexist" -H "Content-Type: application/json" \
    "${H[@]}" -d '{"enabled":false}')
  DC=$(authclass "$D")
  PC=$(authclass "$P")
  echo "  cred=$cred  generated DELETE=$D($DC)  raw PATCH=$P($PC)"
  chk "MGMT-10 identical auth verdict for cred=$cred" "$DC" "$PC"
done

echo
echo "===== MGMT-15 (PR 1 half): a row with an unknown role is denied by the authorizer ====="
# The authorizer is covered here; write-time role validation lands with the
# management-store port.
# Hand-insert the row so the authorizer is tested without depending on that.
SALT=$(mysqlq "SELECT password FROM users WHERE username='viewer1';")
for badrole in operator Viewer2 ""; do
  uname="odd$(echo "$badrole" | tr -cd '[:alnum:]')x"
  mysqlq "DELETE FROM users WHERE username='$uname';" >/dev/null
  mysqlq "INSERT INTO users (username, password, created_at, role) VALUES ('$uname', '$SALT', NOW(), '$badrole');" >/dev/null
  BTOK=$(docker exec llb1 curl -s -m 30 -X POST $API/auth/login -H "Content-Type: application/json" \
    -d "{\"username\":\"$uname\",\"password\":\"Viewer123!\"}" | jget token)
  if [ -z "$BTOK" ]; then
    echo "  [SKIP] role='$badrole': could not log in as the hand-inserted row"
    continue
  fi
  R=$(code_llb -H "Authorization: Bearer $BTOK" $API/config/loadbalancer/all)
  chk "MGMT-15 role='$badrole' denied a read" "403" "$R"
  R=$(code_llb -X POST $API/config/loadbalancer -H "Content-Type: application/json" -H "Authorization: Bearer $BTOK" \
    -d '{"serviceArguments":{"externalIP":"10.10.10.98","port":9998,"protocol":"tcp"},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]}')
  chk "MGMT-15 role='$badrole' denied a write" "403" "$R"
done

echo
echo "===== SUMMARY: pass=$PASS fail=$FAIL ====="
