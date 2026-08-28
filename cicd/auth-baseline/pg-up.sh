#!/bin/bash
# Bring up the PostgreSQL 18.6 store the pkg/aikey gates run against, and
# provision it with the bootstrap script the product actually ships.
#
# Lives in the repository rather than on the testbed: rsync --delete wipes
# anything that only exists there, and an evidence run whose fixture cannot be
# reproduced is not evidence.
#
#   ./pg-up.sh            bring up and provision
#   ./pg-up.sh down       remove the container
#   ./pg-up.sh dsn        print the DSN for the gateway's role
#
# Then, from the repository root:
#   AIKEY_TEST_PG=required AIKEY_TEST_DSN="$(cicd/auth-baseline/pg-up.sh dsn)" \
#     go test ./pkg/aikey/ -count=1
#
# AIKEY_TEST_PG=required makes an absent store a failure rather than a skip.
# Without it the store legs skip, which is right on a laptop and wrong in an
# evidence run.
set -euo pipefail

NAME="${AIKEY_PG_NAME:-aikey-pg}"
IMAGE="${AIKEY_PG_IMAGE:-postgres:18.6}"
PORT="${AIKEY_PG_PORT:-55432}"
# The bootstrap superuser, mirroring the OAM compose: it owns POSTGRES_DB.
OWNER="${AIKEY_PG_OWNER:-oamuser}"
OWNER_PW="${AIKEY_PG_OWNER_PASSWORD:-oampass}"
DB="${AIKEY_PG_DB:-loxilb}"
DP_PW="${AIGW_DB_PASSWORD:-dp-secret-1}"
MGMT_PW="${AIGW_MGMT_DB_PASSWORD:-mgmt-secret-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP="$SCRIPT_DIR/../../scripts/aigw-db-bootstrap.sql"

dsn() { echo "postgres://aigwuser:${DP_PW}@127.0.0.1:${PORT}/${DB}?sslmode=disable"; }

case "${1:-up}" in
down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "removed $NAME"
    exit 0
    ;;
dsn)
    dsn
    exit 0
    ;;
esac

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
    -e POSTGRES_USER="$OWNER" -e POSTGRES_PASSWORD="$OWNER_PW" -e POSTGRES_DB="$DB" \
    -p "127.0.0.1:${PORT}:5432" "$IMAGE" >/dev/null

# pg_isready over the socket answers before the server is listening on TCP;
# ask over TCP, which is how the gateway reaches it.
for _ in $(seq 1 60); do
    if docker exec "$NAME" pg_isready -h 127.0.0.1 -U "$OWNER" -d "$DB" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec "$NAME" pg_isready -h 127.0.0.1 -U "$OWNER" -d "$DB" >/dev/null

docker cp "$BOOTSTRAP" "$NAME:/tmp/aigw-db-bootstrap.sql"
docker exec \
    -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
    "$NAME" psql -h 127.0.0.1 -U "$OWNER" -d "$DB" -q -f /tmp/aigw-db-bootstrap.sql

echo "$NAME up on 127.0.0.1:${PORT}, schemas provisioned"
echo "AIKEY_TEST_DSN=$(dsn)"
