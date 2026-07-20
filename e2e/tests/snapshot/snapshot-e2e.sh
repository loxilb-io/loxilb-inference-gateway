#!/bin/bash
# Snapshot/restore E2E — SNAPSHOT-DESIGN.md §9 scenarios (runs ON the gateway node)
# Writes artifacts to /tmp/snap-e2e/; prints PASS/FAIL per step.
set -u
B=http://127.0.0.1:11111/netlox/v1
D=/tmp/snap-e2e
mkdir -p $D
pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

jqok() { jq -e "$2" >/dev/null 2>&1 <<<"$1"; }

echo "=== S0 baseline snapshot ==="
curl -s -D $D/base.hdr -o $D/baseline.json "$B/config/snapshot"
grep -qi "x-snapshot-checksum: sha256:" $D/base.hdr && ok "S0 checksum header" || bad "S0 checksum header missing: $(cat $D/base.hdr)"
jqok "$(cat $D/baseline.json)" '.kind=="loxilb-snapshot" and .schema_version=="1.0"' && ok "S0 doc shape" || bad "S0 doc shape: $(head -c 300 $D/baseline.json)"

echo "=== S1 populate ==="
curl -s -X POST $B/config/endpoint -H 'Content-Type: application/json' -d '{"hostName":"31.31.31.1","name":"snap-ep1","inactiveReTries":2,"probeType":"none","probeDuration":10,"probePort":0}' > $D/ep1.out
curl -s -X POST $B/config/loadbalancer -H 'Content-Type: application/json' -d '{"serviceArguments":{"externalIP":"20.20.20.1","port":2020,"protocol":"tcp","sel":0,"mode":0,"BGP":false,"monitor":false,"inactiveTimeOut":240},"endpoints":[{"endpointIP":"31.31.31.1","weight":1,"targetPort":5001,"state":"active"}]}' > $D/lb1.out
curl -s -X POST $B/config/firewall -H 'Content-Type: application/json' -d '{"ruleArguments":{"sourceIP":"192.0.2.10/32","destinationIP":"192.0.2.20/32","preference":333},"opts":{"allow":true}}' > $D/fw1.out
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '.lbAttr | length >= 1' && ok "S1 populate (lb present)" || bad "S1 populate: $LBS $(cat $D/ep1.out) $(cat $D/lb1.out) $(cat $D/fw1.out)"

echo "=== S2 snapshot + components ==="
curl -s -D $D/snapA.hdr -o $D/snapA.json "$B/config/snapshot"
CK_HDR=$(grep -i x-snapshot-checksum $D/snapA.hdr | tr -d '\r' | awk '{print $2}')
CK_DOC=$(jq -r .checksum $D/snapA.json)
[ -n "$CK_HDR" ] && [ "$CK_HDR" = "$CK_DOC" ] && ok "S2 header==doc checksum" || bad "S2 checksum hdr=$CK_HDR doc=$CK_DOC"
jqok "$(cat $D/snapA.json)" '.domains.loadbalancer | length >= 1' && ok "S2 lb captured" || bad "S2 lb not captured"
curl -s -o $D/snapLB.json "$B/config/snapshot?components=loadbalancer"
jqok "$(cat $D/snapLB.json)" '(.domains.loadbalancer|length>=1) and ((.domains.endpoint|length)==0)' && ok "S2 components honored" || bad "S2 components: $(jq -c '.domains|{lb:(.loadbalancer|length),ep:(.endpoint|length)}' $D/snapLB.json)"
CODE=$(curl -s -o $D/badcomp.out -w '%{http_code}' "$B/config/snapshot?components=bogus")
[ "$CODE" = "400" ] && ok "S2 bogus component 400" || bad "S2 bogus component got $CODE: $(cat $D/badcomp.out)"

echo "=== S3 dry-run default + no mutation ==="
BEFORE=$(curl -s $B/config/loadbalancer/all)
R=$(curl -s -X POST -H 'Content-Type: application/json' --data-binary @$D/snapA.json "$B/config/restore")
jqok "$R" '.mode=="dry-run" and .result=="ok" and (.plan|length>=1)' && ok "S3 dry-run ok+plan" || bad "S3 dry-run: $R"
AFTER=$(curl -s $B/config/loadbalancer/all)
[ "$BEFORE" = "$AFTER" ] && ok "S3 dry-run no mutation" || bad "S3 dry-run mutated config!"

echo "=== S4 drift + commit + write-through ==="
curl -s -X DELETE "$B/config/loadbalancer/externalipaddress/20.20.20.1/port/2020/protocol/tcp" > $D/lbdel.out
R=$(curl -s -X POST -H 'Content-Type: application/json' --data-binary @$D/snapA.json "$B/config/restore?mode=commit")
echo "$R" > $D/commit1.json
jqok "$R" '.mode=="commit" and .result=="ok" and (.pre_restore_snapshot_persisted|length>0)' && ok "S4 commit ok+preserve path" || bad "S4 commit: $R"
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '[.lbAttr[].serviceArguments.externalIP] | index("20.20.20.1") != null' && ok "S4 lb restored" || bad "S4 lb not restored: $LBS"
docker exec loxilb ls -l /etc/loxilb/snapshot.json > $D/wt.out 2>&1 && ok "S4 write-through file exists" || bad "S4 snapshot.json missing: $(cat $D/wt.out)"

echo "=== S5 restart survival ==="
docker restart loxilb > /dev/null
for i in $(seq 1 60); do curl -s -m 2 $B/version >/dev/null 2>&1 && break; sleep 2; done
sleep 5
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '[.lbAttr[].serviceArguments.externalIP] | index("20.20.20.1") != null' && ok "S5 lb survived restart" || bad "S5 lb lost after restart: $LBS"
EPS=$(curl -s $B/config/endpoint/all)
jqok "$EPS" '[.Attr[].hostName] | index("31.31.31.1") != null' && ok "S5 ep survived restart" || bad "S5 ep lost: $EPS"
docker logs loxilb 2>&1 | grep -q "boot snapshot" && ok "S5 boot-snapshot log present" || bad "S5 no boot snapshot log"

echo "=== S6 failure injection -> rollback ==="
# Doc with a duplicated LB entry: passes parse/validate, first apply ok,
# second hits already-exists -> APPLY aborts -> rollback. Re-encoded (valid
# checksum) with a Go helper that uses pkg/snapshot itself.
mkdir -p /tmp/mksnap && cat > /tmp/mksnap/main.go <<'EOF'
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	doc, err := snapshot.Decode(bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	if len(doc.Domains.LoadBalancer) == 0 {
		panic("no lb in doc")
	}
	doc.Domains.LoadBalancer = append(doc.Domains.LoadBalancer, doc.Domains.LoadBalancer[0])
	out, err := snapshot.Encode(doc)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[2], out, 0600); err != nil {
		panic(err)
	}
	fmt.Println("wrote", os.Args[2])
}
EOF
(cd /root/loxilb-inference-gateway && GOTOOLCHAIN=auto PATH=$PATH:/usr/local/go/bin go run /tmp/mksnap/main.go $D/snapA.json $D/snapDup.json) || bad "S6 helper build"
BEFORE=$(curl -s $B/config/loadbalancer/all)
CODE=$(curl -s -o $D/rollback.out -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @$D/snapDup.json "$B/config/restore?mode=commit")
R=$(cat $D/rollback.out)
[ "$CODE" = "500" ] && jqok "$R" '.result=="rolled-back"' && ok "S6 rollback on dup apply (500 rolled-back)" || bad "S6 rollback: code=$CODE body=$R"
AFTER=$(curl -s $B/config/loadbalancer/all)
[ "$BEFORE" = "$AFTER" ] && ok "S6 live config unchanged after rollback" || bad "S6 config drifted after rollback: before=$BEFORE after=$AFTER"

echo "=== S7 checksum tamper -> 400 ==="
jq '.hostname="tampered-host"' $D/snapA.json > $D/tamper.json
CODE=$(curl -s -o $D/tamper.out -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @$D/tamper.json "$B/config/restore")
grep -q "checksum" $D/tamper.out && [ "$CODE" = "400" ] && ok "S7 tamper rejected 400+checksum msg" || bad "S7 tamper: code=$CODE body=$(cat $D/tamper.out)"

echo "=== S8 bad mode rejected ==="
# go-swagger validates the mode enum at the spec layer -> 422; the handler's
# own 400 never runs. Either rejection is correct; nothing must mutate.
CODE=$(curl -s -o $D/badmode.out -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @$D/snapA.json "$B/config/restore?mode=yolo")
{ [ "$CODE" = "400" ] || [ "$CODE" = "422" ]; } && ok "S8 bad mode rejected ($CODE)" || bad "S8 bad mode got $CODE"

echo "=== S9 deprecated aliases ==="
curl -s -D $D/exp.hdr -o $D/exp.json "$B/config/export"
grep -qi "deprecation: true" $D/exp.hdr && ok "S9 export Deprecation header" || bad "S9 export no Deprecation header"
jqok "$(cat $D/exp.json)" '.kind=="loxilb-snapshot"' && ok "S9 export emits new doc" || bad "S9 export body: $(head -c 200 $D/exp.json)"
cat > $D/legacy.json <<EOF
{"loadbalancer":[{"serviceArguments":{"externalIP":"20.20.20.2","port":2021,"protocol":"tcp","sel":0,"mode":0,"BGP":false,"monitor":false,"inactiveTimeOut":240},"endpoints":[{"endpointIP":"31.31.31.1","weight":1,"targetPort":5002,"state":"active"}]}],"endpoint":[{"hostName":"31.31.31.1","name":"snap-ep1","inactiveReTries":2,"probeType":"none","probeDuration":10,"probePort":0}],"timestamp":"legacy","version":"0.9.7"}
EOF
R=$(curl -s -D $D/imp.hdr -X POST "$B/config/import" -F "configuration=@$D/legacy.json")
grep -qi "deprecation: true" $D/imp.hdr && ok "S9 import Deprecation header" || bad "S9 import no Deprecation header"
jqok "$R" '.result=="ok"' && ok "S9 legacy import ok" || bad "S9 legacy import: $R"
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '[.lbAttr[].serviceArguments.externalIP] | index("20.20.20.2") != null' && ok "S9 imported lb live" || bad "S9 imported lb missing: $LBS"

echo "=== S10 restore baseline (leave testbed as found) ==="
R=$(curl -s -X POST -H 'Content-Type: application/json' --data-binary @$D/baseline.json "$B/config/restore?mode=commit")
jqok "$R" '.result=="ok"' && ok "S10 baseline restore ok" || bad "S10 baseline restore: $R"
LBS=$(curl -s $B/config/loadbalancer/all)
jqok "$LBS" '[.lbAttr[]?.serviceArguments.externalIP] | index("20.20.20.1") == null and index("20.20.20.2") == null' && ok "S10 synthetic config gone" || bad "S10 synthetic config remains: $LBS"

echo "=== RESULT: pass=$pass fail=$fail ==="
