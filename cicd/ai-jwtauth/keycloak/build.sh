#!/bin/bash
# Build the pinned Keycloak image the ai-jwtauth scenario runs against.
#
# Regenerates the realm from mkrealm.py first, so the image can never drift
# from the users and roles the assertions assume.
#
# usage: ./build.sh [image-tag] [keycloak-version]
set -e

SDIR=$(cd "$(dirname "$0")" && pwd)
IMAGE=${1:-${AIGW_KEYCLOAK_IMAGE:-loxilb-aigw-keycloak:26.0-aigw}}
KC_VERSION=${2:-26.0}

echo "Generating the realm..."
python3 "$SDIR/../mkrealm.py" "$SDIR/aigw-realm.json"

echo "Building $IMAGE (Keycloak $KC_VERSION)..."
docker build \
  --build-arg "KEYCLOAK_VERSION=$KC_VERSION" \
  -t "$IMAGE" \
  "$SDIR"

echo "Built $IMAGE"
