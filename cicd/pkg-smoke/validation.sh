#!/bin/bash
# pkg-smoke validation: datapath through the VIP, REST sanity, and a
# systemd restart drill (service survives, persisted config reloads).

API=http://127.0.0.1:11111/netlox/v1
VIP_URL=http://20.20.20.1:2020/
code=0

vip_curl() {
    sudo ip netns exec pks-h1 curl -s --max-time 5 "$VIP_URL"
}

check_vip_traffic() {
    local label=$1 ok=0 ep1=0 ep2=0 out
    for i in $(seq 1 8); do
        out=$(vip_curl) || true
        case "$out" in
            pks-ep1) ok=$((ok+1)); ep1=1 ;;
            pks-ep2) ok=$((ok+1)); ep2=1 ;;
        esac
    done
    echo "$label: $ok/8 requests served (ep1=$ep1 ep2=$ep2)"
    if [ "$ok" -eq 8 ] && [ "$ep1" = 1 ] && [ "$ep2" = 1 ]; then
        return 0
    fi
    return 1
}

echo "#########################################"
echo "1. Datapath: curl through the VIP"
echo "#########################################"

if check_vip_traffic "vip traffic"; then
    echo "pkg-smoke datapath [OK]"
else
    echo "pkg-smoke datapath [FAIL]"
    code=1
fi

echo "#########################################"
echo "2. REST sanity"
echo "#########################################"

if curl -s "$API/config/loadbalancer/all" | grep -q '20.20.20.1'; then
    echo "pkg-smoke rest [OK]"
else
    echo "pkg-smoke rest [FAIL]"
    code=1
fi

echo "#########################################"
echo "3. Restart drill: service survives, config reloads"
echo "#########################################"

sudo systemctl restart loxilb

up=0
for i in $(seq 1 60); do
    if curl -s -o /dev/null "$API/config/loadbalancer/all"; then
        up=1
        break
    fi
    sleep 1
done

if [ "$up" = 1 ] && sudo systemctl is-active --quiet loxilb; then
    echo "pkg-smoke restart-alive [OK]"
else
    echo "pkg-smoke restart-alive [FAIL]"
    code=1
fi

# The REST port answers before the boot snapshot finishes replaying (the boot
# restore retries around subsystem-startup ordering), so poll for the rule
# rather than checking once.
reload_ok=0
for i in $(seq 1 30); do
    if curl -s "$API/config/loadbalancer/all" | grep -q '20.20.20.1'; then
        reload_ok=1
        break
    fi
    sleep 1
done
if [ "$reload_ok" = 1 ]; then
    echo "pkg-smoke restart-config-reload [OK]"
else
    echo "pkg-smoke restart-config-reload [FAIL]"
    code=1
fi

# Give the datapath a moment to re-attach after restart, then re-check traffic
traffic_ok=0
for i in $(seq 1 15); do
    out=$(vip_curl) || true
    case "$out" in
        pks-ep1|pks-ep2) traffic_ok=1; break ;;
    esac
    sleep 2
done
if [ "$traffic_ok" = 1 ] && check_vip_traffic "post-restart traffic"; then
    echo "pkg-smoke restart-datapath [OK]"
else
    echo "pkg-smoke restart-datapath [FAIL]"
    code=1
fi

if [ "$code" = 0 ]; then
    echo "pkg-smoke [OK]"
else
    echo "pkg-smoke [FAIL]"
fi
exit $code
