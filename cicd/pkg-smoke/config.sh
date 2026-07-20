#!/bin/bash
# pkg-smoke config: start the packaged loxilb service and build the netns
# test topology. Expects the loxilb-inference-gateway .deb/.rpm to be
# installed already; see README.md.
set -e

API=http://127.0.0.1:11111/netlox/v1
WORK=/tmp/pkg-smoke

if [ ! -f /lib/systemd/system/loxilb.service ] && [ ! -f /usr/lib/systemd/system/loxilb.service ]; then
    echo "pkg-smoke: loxilb.service not installed - install the package first" >&2
    exit 1
fi

echo "#########################################"
echo "Starting loxilb service"
echo "#########################################"

# Keep the datapath off the host's real interfaces (management NIC, docker
# bridges): attach only to this scenario's pks* veths. Drop-in, not a unit
# edit, so the packaged unit itself stays under test.
sudo mkdir -p /etc/systemd/system/loxilb.service.d
sudo tee /etc/systemd/system/loxilb.service.d/pkg-smoke.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/loxilb --blacklist=eth.*|ens.*|enp.*|eno.*|em.*|bond.*|docker.*|veth.*|br-.*|virbr.*|cni.*|flannel.*|cali.*|tun.*|wg.*|wlan.*
EOF
sudo systemctl daemon-reload
sudo systemctl start loxilb

up=0
for i in $(seq 1 60); do
    if curl -s -o /dev/null "$API/config/loadbalancer/all"; then
        up=1
        break
    fi
    sleep 1
done
if [ "$up" != 1 ]; then
    echo "pkg-smoke: REST API did not come up within 60s" >&2
    sudo systemctl status loxilb --no-pager || true
    exit 1
fi

echo "#########################################"
echo "Creating netns topology (1 client, 2 endpoints)"
echo "#########################################"

mkdir -p "$WORK"

# ns name | host-side veth | host addr        | ns addr
topo="pks-h1 pksh1 10.10.10.254/24 10.10.10.1/24
pks-ep1 pksep1 31.31.31.254/24 31.31.31.1/24
pks-ep2 pksep2 32.32.32.254/24 32.32.32.1/24"

sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

while read -r ns hveth haddr nsaddr; do
    sudo ip netns add "$ns"
    sudo ip link add "$hveth" type veth peer name "${hveth}ns"
    sudo ip link set "${hveth}ns" netns "$ns"
    sudo ip addr add "$haddr" dev "$hveth"
    sudo ip link set "$hveth" up
    sudo ip netns exec "$ns" ip link set lo up
    sudo ip netns exec "$ns" ip addr add "$nsaddr" dev "${hveth}ns"
    sudo ip netns exec "$ns" ip link set "${hveth}ns" up
    gw=${haddr%/*}
    sudo ip netns exec "$ns" ip route add default via "$gw"
done <<< "$topo"

echo "#########################################"
echo "Starting HTTP endpoints"
echo "#########################################"

for ep in ep1 ep2; do
    mkdir -p "$WORK/$ep"
    echo "pks-$ep" > "$WORK/$ep/index.html"
    sudo ip netns exec "pks-$ep" bash -c \
        "cd $WORK/$ep && nohup python3 -m http.server 8080 >/dev/null 2>&1 & echo \$! > $WORK/$ep.pid"
done
sleep 2

echo "#########################################"
echo "Creating LB rule via REST and persisting"
echo "#########################################"

curl -s -f -X POST "$API/config/loadbalancer" \
    -H "Content-Type: application/json" \
    -d '{
      "serviceArguments": {
        "externalIP": "20.20.20.1",
        "port": 2020,
        "protocol": "tcp",
        "sel": 0,
        "bgp": false,
        "inactiveTimeOut": 30
      },
      "endpoints": [
        {"endpointIP": "31.31.31.1", "targetPort": 8080, "weight": 1},
        {"endpointIP": "32.32.32.1", "targetPort": 8080, "weight": 1}
      ]
    }'

# Route the VIP from the client namespace through the host
sudo ip netns exec pks-h1 ip route add 20.20.20.1/32 via 10.10.10.254

# Persist the running configuration so a service restart reloads it
curl -s -f -X POST "$API/config/persist"

sleep 2
echo "pkg-smoke config done"
