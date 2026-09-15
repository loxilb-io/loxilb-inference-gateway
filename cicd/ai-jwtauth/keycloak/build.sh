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

# The realm's fingerprint travels with the image so a caller can tell whether
# the image it already has was baked from the realm the assertions now need.
# Without it the only question anyone can ask is "does the image exist?",
# which is answered "yes" by an image baked from a realm that no longer has
# the users the suite is about to authenticate.
REALM_HASH=$(sha256sum "$SDIR/aigw-realm.json" | cut -c1-16)

echo "Building $IMAGE (Keycloak $KC_VERSION, realm $REALM_HASH)..."
docker build \
  --build-arg "KEYCLOAK_VERSION=$KC_VERSION" \
  --label "aigw.realm.hash=$REALM_HASH" \
  -t "$IMAGE" \
  "$SDIR"

echo "Built $IMAGE"
