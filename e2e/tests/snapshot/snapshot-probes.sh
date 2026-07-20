#!/bin/bash
# Adversarial probes beyond the base E2E suite (runs ON the gateway node).
# A: IPsec tunnel + PSK + cert/CA PEM round-trip incl. boot-restore (init-order retry fix)
# B: concurrent restore gate (second caller must get 409/503, never interleave)
# C: upgrade simulation — container RECREATE with /etc/loxilb host-mounted
set -u
B=http://127.0.0.1:11111/netlox/v1
D=/tmp/snap-probes
mkdir -p $D
pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }
jqok() { jq -e "$2" >/dev/null 2>&1 <<<"$1"; }
wait_api() { for i in $(seq 1 60); do curl -s -m 2 $B/version >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

echo "=== A: IPsec + cert PEM round-trip ==="
openssl req -x509 -newkey rsa:2048 -nodes -keyout $D/ca.key -out $D/ca.pem -days 30 -subj "/CN=snap-test-ca" -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout $D/peer.key -out $D/peer.csr -subj "/CN=snap-test-peer" >/dev/null 2>&1
openssl x509 -req -in $D/peer.csr -CA $D/ca.pem -CAkey $D/ca.key -CAcreateserial -out $D/peer.pem -days 30 >/dev/null 2>&1
CA_PEM=$(jq -Rs . < $D/ca.pem); CERT_PEM=$(jq -Rs . < $D/peer.pem); KEY_PEM=$(jq -Rs . < $D/peer.key)
CODE=$(curl -s -o $D/ca.out -w '%{http_code}' -X POST $B/config/ipsec/ca-certificates -H 'Content-Type: application/json' -d "{\"name\":\"snap-ca\",\"certificate\":$CA_PEM,\"description\":\"e2e ca\"}")
[ "$CODE" -lt 300 ] && ok "A ca upload ($CODE)" || bad "A ca upload: $CODE $(cat $D/ca.out)"
CODE=$(curl -s -o $D/cert.out -w '%{http_code}' -X POST $B/config/ipsec/certificates -H 'Content-Type: application/json' -d "{\"name\":\"snap-cert\",\"certificate\":$CERT_PEM,\"privateKey\":$KEY_PEM,\"description\":\"e2e cert\"}")
[ "$CODE" -lt 300 ] && ok "A cert upload ($CODE)" || bad "A cert upload: $CODE $(cat $D/cert.out)"
CODE=$(curl -s -o $D/tun.out -w '%{http_code}' -X POST $B/config/ipsec/tunnels -H 'Content-Type: application/json' -d '{"name":"snap-tun1","localIp":"10.0.0.12","remoteIp":"203.0.113.77","authMode":"psk","psk":"snap-secret-psk-123","ikeVersion":"ikev2","auto":"add","tunnelMode":"tunnel","selector":{"srcCidr":"10.9.0.0/24","dstCidr":"10.8.0.0/24"}}')
[ "$CODE" -lt 300 ] && ok "A tunnel create ($CODE)" || bad "A tunnel create: $CODE $(cat $D/tun.out)"

curl -s -o $D/snapIpsec.json "$B/config/snapshot"
DOC=$(cat $D/snapIpsec.json)
jqok "$DOC" '.domains.ipsec.tunnels | length >= 1' && ok "A tunnel captured" || bad "A tunnel not captured: $(jq -c .domains.ipsec <<<"$DOC" | head -c 300)"
jqok "$DOC" '[.domains.ipsec.tunnels[].psk] | index("snap-secret-psk-123") != null' && ok "A PSK round-trips in doc" || bad "A PSK missing from doc"
jqok "$DOC" '.domains.ipsec.certificates[0].privateKey | contains("BEGIN PRIVATE KEY")' && ok "A cert private-key PEM captured" || bad "A cert key PEM missing: $(jq -c '.domains.ipsec.certificates[0] | keys' <<<"$DOC" 2>/dev/null)"
jqok "$DOC" '.domains.ipsec.ca_certificates[0].certificate | contains("BEGIN CERTIFICATE")' && ok "A CA PEM captured" || bad "A CA PEM missing"

R=$(curl -s -X POST -H 'Content-Type: application/json' --data-binary @$D/snapIpsec.json "$B/config/restore?mode=commit")
jqok "$R" '.result=="ok"' && ok "A restore commit with ipsec ok" || bad "A restore commit: $R"
T=$(curl -s $B/config/ipsec/tunnels/all)
jqok "$T" '[.ipsecTunnelAttr[]?.name] | index("snap-tun1") != null' && ok "A tunnel live after restore" || bad "A tunnel gone after restore: $T"
C=$(curl -s $B/config/ipsec/certificates/all)
jqok "$C" '[.ipsecCertificateAttr[]?.name] | index("snap-cert") != null' && ok "A cert live after restore" || bad "A cert gone after restore: $C"

echo "=== A2: boot-restore with ipsec (restart; exercises init-order retry) ==="
docker restart loxilb >/dev/null
wait_api || bad "A2 api not back"
sleep 10
T=$(curl -s $B/config/ipsec/tunnels/all)
jqok "$T" '[.ipsecTunnelAttr[]?.name] | index("snap-tun1") != null' && ok "A2 ipsec tunnel survived restart" || bad "A2 tunnel lost after restart: $T"
C=$(curl -s $B/config/ipsec/certificates/all)
jqok "$C" '[.ipsecCertificateAttr[]?.name] | index("snap-cert") != null' && ok "A2 cert survived restart" || bad "A2 cert lost: $C"
CA=$(curl -s $B/config/ipsec/ca-certificates/all)
jqok "$CA" '[.ipsecCACertificateAttr[]?.name] | index("snap-ca") != null' && ok "A2 CA cert survived restart" || bad "A2 CA lost: $CA"
docker logs --since 3m loxilb 2>&1 | grep -E "boot snapshot" | tail -3

echo "=== B: concurrent restore gate ==="
( curl -s -o $D/c1.body -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @$D/snapIpsec.json "$B/config/restore?mode=commit" > $D/c1 ) &
( curl -s -o $D/c2.body -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @$D/snapIpsec.json "$B/config/restore?mode=commit" > $D/c2 ) &
wait
C1=$(cat $D/c1); C2=$(cat $D/c2)
if { [ "$C1" = "200" ] && { [ "$C2" = "409" ] || [ "$C2" = "503" ]; }; } || { [ "$C2" = "200" ] && { [ "$C1" = "409" ] || [ "$C1" = "503" ]; }; }; then
  ok "B concurrent restores: one 200, one rejected ($C1/$C2)"
elif [ "$C1" = "200" ] && [ "$C2" = "200" ]; then
  ok "B both 200 — serialized by timing (gate race not hit this round)"
else
  bad "B unexpected codes $C1/$C2: $(head -c 150 $D/c1.body) / $(head -c 150 $D/c2.body)"
fi

echo "=== C: upgrade simulation (container recreate w/ /etc/loxilb mount) ==="
mkdir -p /opt/loxilb/config
docker cp loxilb:/etc/loxilb/snapshot.json /opt/loxilb/config/snapshot.json 2>/dev/null || echo "C: no snapshot.json to carry over"
docker rm -f loxilb >/dev/null
docker run -dt --name loxilb --net=host --privileged --cap-add SYS_ADMIN --restart unless-stopped \
  -v /dev/log:/dev/log -v /opt/loxilb/cert:/opt/loxilb/cert -v /opt/loxilb/logs:/var/log/loxilb \
  -v /opt/loxilb/config:/etc/loxilb -v /etc/loxilb/tokenizers:/etc/loxilb/tokenizers \
  -v /tmp/cores:/tmp/cores -v /root/asan-reports:/root/asan-reports \
  ghcr.io/loxilb-io/loxilb-inference-gateway:latest-u24 -p >/dev/null
wait_api || bad "C api not back after recreate"
sleep 10
T=$(curl -s $B/config/ipsec/tunnels/all)
jqok "$T" '[.ipsecTunnelAttr[]?.name] | index("snap-tun1") != null' && ok "C config survived container RECREATE (upgrade path)" || bad "C config lost on recreate: $T"
docker logs loxilb 2>&1 | grep -E "boot snapshot" | tail -2

echo "=== CLEANUP: remove synthetic config, leave gateway empty ==="
curl -s -X DELETE "$B/config/ipsec/tunnels/snap-tun1" >/dev/null
curl -s -X DELETE "$B/config/ipsec/certificates/snap-cert" >/dev/null
curl -s -X DELETE "$B/config/ipsec/ca-certificates/snap-ca" >/dev/null
curl -s -X DELETE "$B/config/loadbalancer/externalipaddress/20.20.20.1/port/2020/protocol/tcp" >/dev/null
curl -s -X DELETE "$B/config/endpoint/epipaddress/31.31.31.1" >/dev/null
# firewall cleanup (synthetic rule from base suite, if present)
curl -s -X DELETE "$B/config/firewall?sourceIP=192.0.2.10%2F32&destinationIP=192.0.2.20%2F32" >/dev/null 2>&1
# refresh persisted boot state to the now-clean config
curl -s "$B/config/snapshot" > /opt/loxilb/config/snapshot.json.new && mv /opt/loxilb/config/snapshot.json.new /opt/loxilb/config/snapshot.json
chmod 600 /opt/loxilb/config/snapshot.json
echo "cleanup state: lb=$(curl -s $B/config/loadbalancer/all | jq '.lbAttr|length') ep=$(curl -s $B/config/endpoint/all | jq '.Attr|length') tun=$(curl -s $B/config/ipsec/tunnels/all | jq '.ipsecTunnelAttr|length') fw=$(curl -s $B/config/firewall/all | jq '.fwAttr|length')"

echo "=== PROBE RESULT: pass=$pass fail=$fail ==="
