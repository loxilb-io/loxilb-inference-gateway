#!/bin/bash
# lib.sh - shared helpers of the radix-h2 scenario (sourced).
#
# radix-h1's lib.sh with its isolation unchanged (containers with --network
# none, --cgroupns private, limits, nsenter links, only the gateway
# privileged, the host check), the gateway, the rules and the counters. What
# differs: the mocks are h2c backends (h2_mock.py, admin on HTTP/1.1 :8001)
# and the client speaks HTTP/2 (h2_client.py); both need python3-h2
# (mock.Dockerfile). Containers are named rx6-*.
export RX_PREFIX=${RX_PREFIX:-rx6-}
H2_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$H2_DIR/../radix-h1/lib.sh"
H1_DIR=$SCN_DIR

say() { echo "[radix-h2] $*"; }

# The client and the three h2c mocks: unprivileged, no capabilities.
start_hosts() {
  local n
  mkdir -p "$RUN/h1" "$EVID"
  docker run -d --name "${P}h1" $COMMON_RUN $LIMITS_SMALL --cap-drop ALL \
    --security-opt no-new-privileges -v "$H2_DIR:/opt/rxh2:ro" -v "$H1_DIR:/opt/rxh1:ro" \
    -v "$RUN/h1:/opt/out" "$IMG_MOCK" sleep infinity >/dev/null || return 1
  for n in $EPS; do
    mkdir -p "$RUN/$n"
    docker run -d --name "$P$n" $COMMON_RUN $LIMITS_SMALL --cap-drop ALL \
      --security-opt no-new-privileges -v "$H2_DIR:/opt/rxh2:ro" \
      "$IMG_MOCK" python3 /opt/rxh2/h2_mock.py "$n" 8000 8001 >/dev/null || return 1
    nsx "$n" ip link set lo up
  done
  nsx h1 ip link set lo up
}

mock_admin() { docker exec "$P$1" python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001$2').read()"; }
# client <port> <run|mux> <plan-file>: the HTTP/2 driver in the client container
client() { local port=$1; shift; docker exec "${P}h1" python3 /opt/rxh2/h2_client.py "$VIP" "$port" "$@"; }
