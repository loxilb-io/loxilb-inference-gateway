#!/bin/sh
# Launcher for the loxilb binary shipped by the loxilb-inference-gateway
# package. The binary links against a kTLS-enabled OpenSSL and a libbpf
# newer than the supported distributions provide; both are installed
# privately under /usr/lib/loxilb so they never shadow system libraries.
LOXILB_LIB_DIR=/usr/lib/loxilb
export LD_LIBRARY_PATH="${LOXILB_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
exec "${LOXILB_LIB_DIR}/loxilb" "$@"
