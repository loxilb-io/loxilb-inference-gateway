#!/bin/bash
# Smoke run: verify management-plane auth on the wire against the authsep-i1 image.
# Shapes MGMT-1, MGMT-2, MGMT-2b, MGMT-5, MGMT-9, MGMT-15. Not the full I-2 matrix.
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
jtok() { python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))' 2>/dev/null; }

# The bootstrap legs below only mean anything against an empty user table. Say
# so plainly rather than letting a populated one look like a code failure.
PRE=$(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e 'SELECT COUNT(*) FROM users;' 2>/dev/null)
if [ "$PRE" != "0" ]; then
  echo "PRECONDITION NOT MET: the users table holds $PRE row(s)."
  echo "Bring the topology up with AUTHSEP_BOOTSTRAP=no and run this probe first."
  exit 2
fi

echo "===== MGMT-2: loopback bootstrap while the users table is EMPTY ====="
R=$(code_llb -X POST $API/auth/users -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!","role":"admin"}')
chk "bootstrap create from loopback, empty table" "200" "$R"
echo "  users rows now: $(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e 'SELECT COUNT(*) FROM users;' 2>/dev/null)"

echo "===== MGMT-2: SECOND unauthenticated create from loopback => 401 (bootstrap closed) ====="
R=$(code_llb -X POST $API/auth/users -H "Content-Type: application/json" \
  -d '{"username":"sneak","password":"Sneak123!","role":"admin"}')
chk "second loopback create rejected" "401" "$R"
echo "  users rows still: $(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e 'SELECT COUNT(*) FROM users;' 2>/dev/null)"

echo "===== MGMT-2 (variant): closed bootstrap reusing an EXISTING username ====="
# The password checks query the user table by name. If they ran before the
# bootstrap's own precondition, this returned the store's error as a 500 to an
# unauthenticated caller instead of a plain refusal.
R=$(code_llb -X POST $API/auth/users -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!","role":"admin"}')
chk "closed bootstrap with an existing username still 401" "401" "$R"
echo "  users rows still: $(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e 'SELECT COUNT(*) FROM users;' 2>/dev/null)"

echo "===== MGMT-1 / MGMT-2b: NON-loopback peer, with and without a forged loopback header ====="
# l3h1 is the off-box peer: it reaches the management listener over the data
# network, so its source address is 10.10.10.1 and never loopback. (mysql-ai is
# unusable here — the mariadb image ships no curl.)
MGMT=http://10.10.10.254:11111/netlox/v1
R=$(docker exec l3h1 curl -s -o /dev/null -m 20 -w '%{http_code}' \
  -X POST "$MGMT/auth/users" -H 'Content-Type: application/json' \
  -d '{"username":"remote","password":"Remote123!","role":"admin"}' 2>/dev/null)
chk "MGMT-1 non-loopback create rejected" "401" "$R"
R=$(docker exec l3h1 curl -s -o /dev/null -m 20 -w '%{http_code}' \
  -X POST "$MGMT/auth/users" -H 'Content-Type: application/json' \
  -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-Ip: 127.0.0.1' \
  -d '{"username":"forged","password":"Forged123!","role":"admin"}' 2>/dev/null)
chk "MGMT-2b forged X-Forwarded-For rejected" "401" "$R"
echo "  users rows after both attempts: $(docker exec mysql-ai mysql -uroot -ploxilb123 loxilb_db -N -e 'SELECT COUNT(*) FROM users;' 2>/dev/null)"

echo "===== the bootstrap row must be verifiable (login as the created admin) ====="
TOK=$(docker exec llb1 curl -s -m 30 -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!"}' | jtok)
if [ -n "$TOK" ]; then
  echo "  [PASS] bootstrap admin can log in"
  PASS=$((PASS + 1))
else
  echo "  [FAIL] bootstrap admin cannot log in"
  FAIL=$((FAIL + 1))
fi

echo "===== MGMT-5: raw (non-swagger) handlers unauthenticated => 401 ====="
for p in /config/opa/watcher /config/dpu/hwcounters /config/dpu/debug /config/ai/kv/inventory; do
  R=$(code_llb $API$p)
  chk "raw GET $p unauthenticated" "401" "$R"
done
R=$(code_llb -X PATCH $API/config/ai/apikey/deadbeef -H "Content-Type: application/json" -d '{"enabled":false}')
chk "raw PATCH /config/ai/apikey/{id} unauthenticated" "401" "$R"

echo "===== raw handlers WITH a valid admin token (the gate must not break them) ====="
for p in /config/dpu/hwcounters /config/ai/kv/inventory; do
  R=$(code_llb -H "Authorization: Bearer $TOK" $API$p)
  if [ "$R" = "401" ]; then
    echo "  [FAIL] authenticated GET $p returned 401"
    FAIL=$((FAIL + 1))
  else
    echo "  [PASS] authenticated GET $p -> $R (not 401)"
    PASS=$((PASS + 1))
  fi
done

echo "===== authenticated admin CAN still create a user ====="
R=$(code_llb -X POST $API/auth/users -H "Content-Type: application/json" -H "Authorization: Bearer $TOK" \
  -d '{"username":"viewer1","password":"Viewer123!","role":"viewer"}')
chk "authenticated admin create" "200" "$R"

echo "===== MGMT-9: viewer denied a mutating call, allowed a read ====="
VTOK=$(docker exec llb1 curl -s -m 30 -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"viewer1","password":"Viewer123!"}' | jtok)
if [ -n "$VTOK" ]; then
  R=$(code_llb -H "Authorization: Bearer $VTOK" $API/config/loadbalancer/all)
  if [ "$R" = "403" ]; then
    echo "  [FAIL] viewer GET /config/loadbalancer/all was denied"
    FAIL=$((FAIL + 1))
  else
    echo "  [PASS] viewer GET /config/loadbalancer/all -> $R (not 403)"
    PASS=$((PASS + 1))
  fi
  R=$(code_llb -X POST $API/config/loadbalancer -H "Content-Type: application/json" -H "Authorization: Bearer $VTOK" \
    -d '{"serviceArguments":{"externalIP":"10.10.10.99","port":9999,"protocol":"tcp"},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]}')
  chk "MGMT-9 viewer POST /config/loadbalancer denied" "403" "$R"
  R=$(code_llb -X PATCH $API/config/ai/apikey/deadbeef -H "Content-Type: application/json" -H "Authorization: Bearer $VTOK" -d '{"enabled":false}')
  chk "viewer PATCH raw handler denied" "403" "$R"
else
  echo "  [FAIL] viewer login failed"
  FAIL=$((FAIL + 1))
fi

echo "===== MGMT-3: a data-plane key hash presented as a management Bearer ====="
docker exec llb1 curl -s -X POST $API/config/loadbalancer -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOK" \
  -d '{"serviceArguments":{"externalIP":"10.10.10.254","port":2020,"protocol":"tcp","mode":4,"sse_mode":true,"inactiveTimeOut":60,"host":"10.10.10.254"},"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1}]}' >/dev/null
KR=$(docker exec llb1 curl -s -X POST $API/config/ai/apikey -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOK" \
  -d '{"tenant_id":"t1","name":"k1","allowed_models":["test-model"],"rate_limit_rps":100,"burst_size":200,"tokens_per_min":1000000,"enabled":true}')
RAW=$(echo "$KR" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("raw_key",""))' 2>/dev/null)
sleep 2
# use the key on the VIP so its hash lands in the shared credential cache
docker exec l3h1 curl -s -m 10 -o /dev/null -w '  vip_keyed=%{http_code}\n' -X POST \
  http://10.10.10.254:2020/v1/chat/completions -H 'Content-Type: application/json' \
  -H "X-Api-Key: $RAW" -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}],"max_tokens":8}'
HASH=$(printf '%s' "$RAW" | sha256sum | cut -d' ' -f1)
R=$(code_llb -H "Authorization: Bearer $HASH" $API/auth/users)
chk "MGMT-3 key hash as Bearer rejected as unauthenticated" "401" "$R"
R=$(code_llb $API/version)
chk "MGMT-3 gateway still serving after the attempt" "200" "$R"

echo
echo "===== SUMMARY: pass=$PASS fail=$FAIL ====="
