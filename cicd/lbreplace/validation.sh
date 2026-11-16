#!/bin/bash
# A replace (a POST on a rule that exists) and a merge-patch apply what they
# accept: every value sent reads back, a request that changes nothing is
# answered as one, and a value that is not sent stays as it was.
source ../common.sh
echo SCENARIO-lbreplace

BASE=http://localhost:11111/netlox/v1/config
L4=20.20.20.1; L4PORT=2020
FP=10.10.10.254; FPPORT=2030
code=0

fail() { echo "  FAIL: $*"; code=1; }
pass() { echo "  ok: $*"; }

post() { $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X POST $BASE/loadbalancer -H 'Content-Type: application/json' -d "$1"; }
patch() { $dexec llb1 curl -s -o /dev/null -w '%{http_code}' -X PATCH "$BASE/loadbalancer/externalipaddress/$L4/port/$L4PORT/protocol/tcp" -H 'Content-Type: application/json' -d "$1"; }
rule() { # port, jq filter
  $dexec llb1 curl -s $BASE/loadbalancer/all | jq -c --argjson p "$1" ".lbAttr[] | select(.serviceArguments.port==\$p) | $2"
}
probe_of() { # endpoint address, jq filter
  $dexec llb1 curl -s $BASE/endpoint/all | jq -c --arg h "$1" "[.Attr[] | select(.hostName==\$h) | $2] | first"
}
# expect <what> <got> <want>
expect() { [ "$2" == "$3" ] && pass "$1" || fail "$1: got $2, want $3"; }

l4() { # jq edit applied to the base rule
  jq -cn '{serviceArguments: {externalIP: "'$L4'", port: '$L4PORT', protocol: "tcp", sel: 0, mode: 0, name: "lbr-a",
             monitor: true, probetype: "ping", probeTimeout: 20, probeRetries: 2, inactiveTimeOut: 60},
           endpoints: [{endpointIP: "31.31.31.1", targetPort: 8080, weight: 1}, {endpointIP: "31.31.31.2", targetPort: 8080, weight: 1}],
           allowedSources: [{prefix: "10.1.0.0/24"}]} | '"${1:-.}"
}
# Its endpoint is not one of the L4 rule's: a probe two rules share keeps the
# timing of the rule that registered it first, and stays while either has it.
fp() {
  jq -cn '{serviceArguments: {externalIP: "'$FP'", port: '$FPPORT', protocol: "tcp", sel: 0, mode: 4, security: 1, name: "lbr-fp",
             backend_protocol: "http2", inactiveTimeOut: 60},
           endpoints: [{endpointIP: "31.31.31.3", targetPort: 8080, weight: 1}]} | '"${1:-.}"
}

echo "The rules"
expect "the L4 rule is created" "$(post "$(l4)")" 200
expect "the full-proxy rule is created" "$(post "$(fp)")" 200
expect "the same L4 rule again changes nothing and is answered so" "$(post "$(l4)")" 409
expect "the same full-proxy rule again changes nothing and is answered so" "$(post "$(fp)")" 409

echo "A name"
expect "a replace with another name is accepted" "$(post "$(l4 '.serviceArguments.name="lbr-b"')")" 200
expect "the name reads back" "$(rule $L4PORT .serviceArguments.name)" '"lbr-b"'
expect "a patch with another name is accepted" "$(patch '{"serviceArguments":{"name":"lbr-c"}}')" 200
expect "the patched name reads back" "$(rule $L4PORT .serviceArguments.name)" '"lbr-c"'
expect "a name that moves the rule to another cluster instance is refused" "$(post "$(l4 '.serviceArguments.name="lbr-c:other"')")" 409
expect "the refused name is not stored" "$(rule $L4PORT .serviceArguments.name)" '"lbr-c"'
NAME='.serviceArguments.name="lbr-c"'

echo "Probe timing"
expect "the probe runs with the rule's timing" "$(probe_of 31.31.31.1 '[.probeDuration, .inactiveReTries]')" "[20,2]"
expect "a patch of probeTimeout and probeRetries alone is accepted" "$(patch '{"serviceArguments":{"probeTimeout":30,"probeRetries":4}}')" 200
expect "both read back on the rule" "$(rule $L4PORT '[.serviceArguments.probeTimeout, .serviceArguments.probeRetries]')" "[30,4]"
expect "the running probe has them" "$(probe_of 31.31.31.1 '[.probeDuration, .inactiveReTries]')" "[30,4]"
expect "a replace that changes them alone is accepted" "$(post "$(l4 "$NAME"' | .serviceArguments.probeTimeout=40 | .serviceArguments.probeRetries=5')")" 200
expect "both read back after the replace" "$(rule $L4PORT '[.serviceArguments.probeTimeout, .serviceArguments.probeRetries]')" "[40,5]"
expect "the running probe has them after the replace" "$(probe_of 31.31.31.1 '[.probeDuration, .inactiveReTries]')" "[40,5]"
PROBE="$NAME"' | .serviceArguments.probeTimeout=40 | .serviceArguments.probeRetries=5'

echo "The members of an endpoint the rule already has"
EP="$PROBE"' | .endpoints[0] += {ep_role: 1, nixl_port: 5999, backup: true, subnetId: "sn-2"}'
expect "a replace that changes them is accepted" "$(post "$(l4 "$EP")")" 200
expect "they read back" "$(rule $L4PORT '.endpoints[] | select(.endpointIP=="31.31.31.1") | [.ep_role, .nixl_port, .backup, .subnetId]')" '[1,5999,true,"sn-2"]'
expect "the other endpoint is as it was" "$(rule $L4PORT '.endpoints[] | select(.endpointIP=="31.31.31.2") | [.ep_role // 0, .nixl_port // 0, .backup]')" "[0,0,false]"
expect "a replace that moves the probe to another address is accepted" "$(post "$(l4 "$EP"' | .endpoints[0].monitorAddress="31.31.31.9"')")" 200
expect "a probe runs on the new address" "$(probe_of 31.31.31.9 .hostName)" '"31.31.31.9"'
expect "no probe is left on the old address" "$(probe_of 31.31.31.1 .hostName)" "null"
EP="$EP"' | .endpoints[0].monitorAddress="31.31.31.9"'

echo "Allowed sources"
expect "the same sources again change nothing" "$(post "$(l4 "$EP")")" 409
expect "another source is accepted" "$(post "$(l4 "$EP"' | .allowedSources=[{prefix: "10.2.0.0/24"}]')")" 200
expect "it reads back" "$(rule $L4PORT '[.allowedSources[].prefix]')" '["10.2.0.0/24"]'
expect "a second source is accepted" "$(post "$(l4 "$EP"' | .allowedSources=[{prefix: "10.2.0.0/24"}, {prefix: "10.3.0.0/24"}]')")" 200
expect "one of two replaced is accepted" "$(post "$(l4 "$EP"' | .allowedSources=[{prefix: "10.2.0.0/24"}, {prefix: "10.4.0.0/24"}]')")" 200
expect "both read back" "$(rule $L4PORT '[.allowedSources[].prefix] | sort')" '["10.2.0.0/24","10.4.0.0/24"]'
expect "the same two in another order change nothing" "$(post "$(l4 "$EP"' | .allowedSources=[{prefix: "10.4.0.0/24"}, {prefix: "10.2.0.0/24"}]')")" 409

echo "The full-proxy rule: backend_protocol and frontend mTLS"
expect "a replace without backend_protocol and with nothing else new changes nothing" "$(post "$(fp 'del(.serviceArguments.backend_protocol)')")" 409
expect "a replace without backend_protocol and with another change is accepted" "$(post "$(fp 'del(.serviceArguments.backend_protocol) | .serviceArguments.inactiveTimeOut=90')")" 200
expect "backend_protocol is as it was" "$(rule $FPPORT .serviceArguments.backend_protocol)" '"http2"'
expect "a replace that names another backend_protocol is accepted" "$(post "$(fp '.serviceArguments.backend_protocol="both" | .serviceArguments.inactiveTimeOut=90')")" 200
expect "it reads back" "$(rule $FPPORT .serviceArguments.backend_protocol)" '"both"'
MT_NO_CA='.serviceArguments.backend_protocol="both" | .serviceArguments.inactiveTimeOut=90 | .serviceArguments.mtls_frontend={client_cert_mode: "optional"}'
expect "a replace enabling frontend mTLS without a CA is refused" "$(post "$(fp "$MT_NO_CA")")" 400
expect "the refused mTLS configuration is absent" "$(rule $FPPORT .serviceArguments.mtls_frontend)" null
MT="$MT_NO_CA"' | .serviceArguments.mtls_frontend.client_ca_path="/opt/loxilb/cert/server.crt"'
expect "a replace that changes frontend mTLS alone is accepted" "$(post "$(fp "$MT")")" 200
expect "frontend mTLS reads back" "$(rule $FPPORT .serviceArguments.mtls_frontend.client_cert_mode)" '"optional"'
expect "the frontend CA path reads back" "$(rule $FPPORT .serviceArguments.mtls_frontend.client_ca_path)" '"/opt/loxilb/cert/server.crt"'
expect "the same again changes nothing" "$(post "$(fp "$MT")")" 409

if [[ $code == 0 ]]; then
  echo SCENARIO-lbreplace [OK]
else
  echo SCENARIO-lbreplace [FAILED]
fi
exit $code
