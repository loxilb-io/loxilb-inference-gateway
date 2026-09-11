#!/bin/bash
#
# sockmap-fullproxy / validation_refcount.sh
#
# Validates the rule-level idempotent portset refcount in the loader
# (llb_sockmap_rule_ports_op, keyed by rule number). This repo re-issues
# DpCreate on an existing fullproxy rule without a DpRemove (CHWBL selector
# reconcile, QoS attach, fold/unfold) and proxy_add_entry refreshes a live pool
# in place, so a naive "+1 per add / -1 per delete" would leak portset entries.
#
# Self-contained: creates its own rules on dedicated VIP ports (2050-2053) and
# dedicated backend ports (9100-9105) so it never collides with config.sh's
# 2020/2021 -> 8080 rules, and deletes everything it created. No traffic is
# generated: only control-plane operations and bpftool map observation.
#
# Checks (plan §4 stage 2):
#   (a) repeated updates of one rule, then one delete -> portsets empty
#   (b) CHWBL selector (sel=8) rule updated several times in place, including
#       both->off->both, then deleted -> no residue; off releases the ports
#   (c) endpoint set shrunk in place -> the dropped endpoint port disappears
#   (d) two L7 rules (different host) on the same VIP:port -> deleting one keeps
#       the other's endpoint port and the shared VIP port; deleting both clears
#   (e) no sockmap failure messages in the loxilb log (fail-open never fired)

source ../common.sh
source ./sockmap_common.sh

sockmap_init_artifacts

SCENARIO="SCENARIO-sockmap-fullproxy-refcount"
VIP=10.10.10.254
EP1=31.31.31.1
EP2=32.32.32.1

_rc_post_lb() {
  # $1 json body; returns 0 on HTTP 20x
  local body=$1
  local resp
  resp=$(_sm_dexec llb1 curl -sS -w '\nHTTP %{http_code}\n' \
           -X POST -H 'Content-Type: application/json' -d "$body" \
           "http://localhost:11111/netlox/v1/config/loadbalancer")
  echo "$resp" >> "$SOCKMAP_ARTIFACTS_DIR/api_responses.log"
  echo "$resp" | grep -q "HTTP 20"
}

_rc_delete_lb_host() {
  # $1 host ("any" for none) $2 vip $3 port
  local host=$1 vip=$2 port=$3
  local resp
  resp=$(_sm_dexec llb1 curl -sS -w '\nHTTP %{http_code}\n' -X DELETE \
    "http://localhost:11111/netlox/v1/config/loadbalancer/hosturl/${host}/externalipaddress/${vip}/port/${port}/protocol/tcp")
  echo "$resp" >> "$SOCKMAP_ARTIFACTS_DIR/api_responses.log"
  echo "$resp" | grep -q "HTTP 20"
}

# _rc_lb_json <vport> <mode> <sel> <host> <ep_spec...>
#   ep_spec = ip:targetPort
_rc_lb_json() {
  local vport=$1 mode=$2 sel=$3 host=$4; shift 4
  local eps="" first=1 spec ip tp
  for spec in "$@"; do
    ip=${spec%%:*}; tp=${spec##*:}
    [[ $first -eq 0 ]] && eps+=","
    eps+="{\"endpointIP\":\"$ip\",\"targetPort\":$tp,\"weight\":1}"
    first=0
  done
  local hostjson=""
  if [[ -n "$host" ]]; then
    hostjson=", \"host\": \"$host\""
  fi
  cat <<EOF
{
  "serviceArguments": {
    "externalIP": "$VIP",
    "port": $vport,
    "protocol": "tcp",
    "mode": 4,
    "sel": $sel,
    "name": "refcount-$vport-${host:-nohost}",
    "sockMapMode": "$mode"$hostjson
  },
  "endpoints": [ $eps ]
}
EOF
}

_rc_expect() {
  # $1 label $2 map name $3 port $4 present|absent
  local label=$1 map=$2 port=$3 want=$4
  if sockmap_portset_wait llb1 "$map" "$port" "$want"; then
    sockmap_result "$label" "OK"
  else
    sockmap_result "$label" "FAILED" "port $port expected $want in $map"
  fi
}

cleanup() {
  _rc_delete_lb_host any "$VIP" 2050 >/dev/null 2>&1 || true
  _rc_delete_lb_host any "$VIP" 2051 >/dev/null 2>&1 || true
  _rc_delete_lb_host any "$VIP" 2052 >/dev/null 2>&1 || true
  _rc_delete_lb_host a.refcount.test "$VIP" 2053 >/dev/null 2>&1 || true
  _rc_delete_lb_host b.refcount.test "$VIP" 2053 >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "================ $SCENARIO ================"

fail_before=$(sockmap_log_failure_count llb1)

# ---------- (a) repeated updates, one delete ----------
sockmap_section 1 "(a) repeated updates of one rule (vip 2050 -> 9100)"
if _rc_post_lb "$(_rc_lb_json 2050 both 0 "" $EP1:9100 $EP2:9100)"; then
  _rc_expect "create: vip 2050 in vip_portset"      "$SOCKMAP_VIP_NAME" 2050 present
  _rc_expect "create: ep 9100 in ep_portset"        "$SOCKMAP_EP_NAME"  9100 present
  _rc_post_lb "$(_rc_lb_json 2050 both 0 "" $EP1:9100)" || sockmap_result "update#1 (shrink to 1 ep)" "FAILED" "API"
  _rc_post_lb "$(_rc_lb_json 2050 both 0 "" $EP1:9100 $EP2:9100)" || sockmap_result "update#2 (back to 2 eps)" "FAILED" "API"
  _rc_post_lb "$(_rc_lb_json 2050 both 0 "" $EP1:9100 $EP2:9100 33.33.33.1:9100)" || sockmap_result "update#3 (3 eps)" "FAILED" "API"
  _rc_expect "after 3 updates: vip 2050 still present" "$SOCKMAP_VIP_NAME" 2050 present
  _rc_expect "after 3 updates: ep 9100 still present"  "$SOCKMAP_EP_NAME"  9100 present
  if _rc_delete_lb_host any "$VIP" 2050; then
    _rc_expect "single delete: vip 2050 removed"     "$SOCKMAP_VIP_NAME" 2050 absent
    _rc_expect "single delete: ep 9100 removed"      "$SOCKMAP_EP_NAME"  9100 absent
  else
    sockmap_result "delete vip 2050" "FAILED" "API"
  fi
else
  sockmap_result "create vip 2050" "FAILED" "API"
fi

# ---------- (b) CHWBL selector, in-place DpCreate re-issue ----------
sockmap_section 2 "(b) CHWBL (sel=8) rule updated in place (vip 2051 -> 9101)"
if _rc_post_lb "$(_rc_lb_json 2051 both 8 "" $EP1:9101 $EP2:9101)"; then
  _rc_expect "create: vip 2051 present"             "$SOCKMAP_VIP_NAME" 2051 present
  _rc_expect "create: ep 9101 present"              "$SOCKMAP_EP_NAME"  9101 present
  _rc_post_lb "$(_rc_lb_json 2051 both 8 "" $EP1:9101)" || sockmap_result "chwbl update#1" "FAILED" "API"
  _rc_post_lb "$(_rc_lb_json 2051 both 8 "" $EP1:9101 $EP2:9101)" || sockmap_result "chwbl update#2" "FAILED" "API"
  _rc_expect "after in-place updates: vip 2051 present" "$SOCKMAP_VIP_NAME" 2051 present
  _rc_expect "after in-place updates: ep 9101 present"  "$SOCKMAP_EP_NAME"  9101 present
  # both -> off in place must release the ports (gate closed => old record released)
  _rc_post_lb "$(_rc_lb_json 2051 off 8 "" $EP1:9101 $EP2:9101)" || sockmap_result "chwbl both->off" "FAILED" "API"
  _rc_expect "both->off in place: vip 2051 released"  "$SOCKMAP_VIP_NAME" 2051 absent
  _rc_expect "both->off in place: ep 9101 released"   "$SOCKMAP_EP_NAME"  9101 absent
  _rc_post_lb "$(_rc_lb_json 2051 both 8 "" $EP1:9101 $EP2:9101)" || sockmap_result "chwbl off->both" "FAILED" "API"
  _rc_expect "off->both in place: vip 2051 back"      "$SOCKMAP_VIP_NAME" 2051 present
  _rc_expect "off->both in place: ep 9101 back"       "$SOCKMAP_EP_NAME"  9101 present
  if _rc_delete_lb_host any "$VIP" 2051; then
    _rc_expect "delete: vip 2051 removed"             "$SOCKMAP_VIP_NAME" 2051 absent
    _rc_expect "delete: ep 9101 removed (no residue)" "$SOCKMAP_EP_NAME"  9101 absent
  else
    sockmap_result "delete vip 2051" "FAILED" "API"
  fi
else
  sockmap_result "create CHWBL vip 2051" "FAILED" "API"
fi

# ---------- (c) endpoint shrink in place drops the vanished port ----------
sockmap_section 3 "(c) in-place endpoint shrink (vip 2052: 9102+9103 -> 9102)"
if _rc_post_lb "$(_rc_lb_json 2052 both 8 "" $EP1:9102 $EP2:9103)"; then
  _rc_expect "create: ep 9102 present"              "$SOCKMAP_EP_NAME" 9102 present
  _rc_expect "create: ep 9103 present"              "$SOCKMAP_EP_NAME" 9103 present
  _rc_post_lb "$(_rc_lb_json 2052 both 8 "" $EP1:9102)" || sockmap_result "shrink update" "FAILED" "API"
  _rc_expect "shrink: ep 9103 removed"              "$SOCKMAP_EP_NAME" 9103 absent
  _rc_expect "shrink: ep 9102 kept"                 "$SOCKMAP_EP_NAME" 9102 present
  _rc_expect "shrink: vip 2052 kept"                "$SOCKMAP_VIP_NAME" 2052 present
  if _rc_delete_lb_host any "$VIP" 2052; then
    _rc_expect "delete: vip 2052 removed"           "$SOCKMAP_VIP_NAME" 2052 absent
    _rc_expect "delete: ep 9102 removed"            "$SOCKMAP_EP_NAME"  9102 absent
  else
    sockmap_result "delete vip 2052" "FAILED" "API"
  fi
else
  sockmap_result "create vip 2052" "FAILED" "API"
fi

# ---------- (d) two L7 rules sharing VIP:port ----------
sockmap_section 4 "(d) two host-based rules on vip 2053 (a->9104, b->9105)"
if _rc_post_lb "$(_rc_lb_json 2053 both 0 a.refcount.test $EP1:9104)" &&
   _rc_post_lb "$(_rc_lb_json 2053 both 0 b.refcount.test $EP2:9105)"; then
  _rc_expect "both rules: vip 2053 present"        "$SOCKMAP_VIP_NAME" 2053 present
  _rc_expect "both rules: ep 9104 present"         "$SOCKMAP_EP_NAME"  9104 present
  _rc_expect "both rules: ep 9105 present"         "$SOCKMAP_EP_NAME"  9105 present
  if _rc_delete_lb_host a.refcount.test "$VIP" 2053; then
    _rc_expect "delete a: ep 9104 removed"         "$SOCKMAP_EP_NAME"  9104 absent
    _rc_expect "delete a: ep 9105 KEPT (rule b alive)" "$SOCKMAP_EP_NAME" 9105 present
    _rc_expect "delete a: vip 2053 KEPT (rule b alive)" "$SOCKMAP_VIP_NAME" 2053 present
  else
    sockmap_result "delete host a" "FAILED" "API"
  fi
  if _rc_delete_lb_host b.refcount.test "$VIP" 2053; then
    _rc_expect "delete b: ep 9105 removed"         "$SOCKMAP_EP_NAME"  9105 absent
    _rc_expect "delete b: vip 2053 removed"        "$SOCKMAP_VIP_NAME" 2053 absent
  else
    sockmap_result "delete host b" "FAILED" "API"
  fi
else
  sockmap_result "create host-based rules on vip 2053" "FAILED" "API"
fi

# ---------- (e) no fail-open / failure logs ----------
sockmap_section 5 "(e) loxilb log scan"
fail_after=$(sockmap_log_failure_count llb1)
if (( fail_after - fail_before == 0 )); then
  sockmap_result "no new sockmap failure messages" "OK"
else
  sockmap_result "no new sockmap failure messages" "FAILED" "$((fail_after - fail_before)) new"
  sudo docker logs llb1 2>&1 | grep -iE "sockmap" | tail -20 > "$SOCKMAP_ARTIFACTS_DIR/refcount_failures.log"
fi

# config.sh rules must be untouched by all of the above
sockmap_section 6 "config.sh rules unaffected"
_rc_expect "R1 vip 2020 still present"              "$SOCKMAP_VIP_NAME" 2020 present
_rc_expect "R1 ep 8080 still present"               "$SOCKMAP_EP_NAME"  8080 present

echo
if (( SOCKMAP_FAIL_COUNT == 0 )); then
  echo "RESULT: $SCENARIO [OK]"
  exit 0
else
  echo "RESULT: $SCENARIO [FAILED] ($SOCKMAP_FAIL_COUNT check(s) failed)"
  echo "Artifacts: $SOCKMAP_ARTIFACTS_DIR/"
  exit 1
fi
