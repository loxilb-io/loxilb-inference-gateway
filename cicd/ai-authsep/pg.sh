#!/bin/bash
# Bring up the PostgreSQL key store this scenario runs against, in either of
# the two postures the plan requires: plaintext, and TLS-required.
#
#   ./pg.sh up plain     plaintext store          (container: aisep-pg)
#   ./pg.sh up tls       TLS-required store       (container: aisep-pg-tls)
#   ./pg.sh ip plain|tls print the container's bridge address
#   ./pg.sh down         remove both
#
# Both are provisioned with scripts/aigw-db-bootstrap.sql — the file the
# product ships — so the fixture and the deployment path are the same thing
# and a bootstrap defect shows up here rather than in production.
#
# The TLS posture has no `host` line in pg_hba.conf at all, only `hostssl`.
# That is what makes "TLS required" real: a plaintext connection is refused by
# the server, and the refusal is written to the server log. Both servers run
# with log_connections=on, because several legs are decided by a connection
# being *absent* and an empty log is only evidence if the server would have
# written to it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP="$SCRIPT_DIR/../../scripts/aigw-db-bootstrap.sql"
CERTS="$SCRIPT_DIR/certs"

IMAGE="${AIKEY_PG_IMAGE:-postgres:18.6}"
OWNER="${AIKEY_PG_OWNER:-oamuser}"
OWNER_PW="${AIKEY_PG_OWNER_PASSWORD:-oampass}"
DB="${AIKEY_PG_DB:-loxilb}"
DP_PW="${AIGW_DB_PASSWORD:-dp-secret-1}"
MGMT_PW="${AIGW_MGMT_DB_PASSWORD:-mgmt-secret-1}"

PLAIN_NAME=aisep-pg
TLS_NAME=aisep-pg-tls

name_for() { [ "$1" = "tls" ] && echo "$TLS_NAME" || echo "$PLAIN_NAME"; }

wait_ready() {
    local name=$1
    for _ in $(seq 1 60); do
        # pg_isready over the unix socket answers before the server is
        # listening on TCP, and TCP is how the gateway reaches it.
        if docker exec "$name" pg_isready -h 127.0.0.1 -U "$OWNER" -d "$DB" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "$name never became ready" >&2
    docker logs --tail 40 "$name" >&2
    return 1
}

provision() {
    local name=$1
    docker cp "$BOOTSTRAP" "$name:/tmp/aigw-db-bootstrap.sql"
    docker exec \
        -e PGPASSWORD="$OWNER_PW" \
        -e AIGW_DB_PASSWORD="$DP_PW" -e AIGW_MGMT_DB_PASSWORD="$MGMT_PW" \
        "$name" psql -h 127.0.0.1 -U "$OWNER" -d "$DB" -q -v ON_ERROR_STOP=1 \
        -f /tmp/aigw-db-bootstrap.sql
}

case "${1:-up}" in
down)
    docker rm -f "$PLAIN_NAME" "$TLS_NAME" >/dev/null 2>&1 || true
    echo "removed $PLAIN_NAME and $TLS_NAME"
    exit 0
    ;;
ip)
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(name_for "${2:-plain}")"
    exit 0
    ;;
up) : ;;
*)  echo "usage: $0 {up plain|up tls|ip plain|ip tls|down}" >&2; exit 2 ;;
esac

MODE="${2:-plain}"
NAME="$(name_for "$MODE")"
docker rm -f "$NAME" >/dev/null 2>&1 || true

if [ "$MODE" = "tls" ]; then
    [ -f "$CERTS/server.crt" ] || { echo "no certs; run mkcerts.sh first" >&2; exit 1; }
    cat > "$CERTS/pg_hba.conf" <<'HBA'
# Deliberately no `host` line: only TLS connections have any entry here, so a
# plaintext connection is refused by the server rather than merely discouraged.
local   all all                     trust
hostssl all aigwuser  0.0.0.0/0     cert
hostssl all all       0.0.0.0/0     scram-sha-256
hostssl all all       ::0/0         scram-sha-256
HBA
    chmod 0644 "$CERTS/pg_hba.conf"
    # PostgreSQL refuses a key file it does not own unless root owns it, and
    # the server process is not root — a root-owned 0640 key is rejected with
    # "Permission denied" by the OS before PostgreSQL's own check is reached.
    # Hand the key to the image's postgres uid, read from the image rather than
    # assumed, and give it 0600.
    PGUID=$(docker run --rm --entrypoint id "$IMAGE" -u postgres 2>/dev/null || echo 999)
    sudo chown "$PGUID" "$CERTS/server.key"
    sudo chmod 0600 "$CERTS/server.key"
    docker run -d --name "$NAME" \
        -e POSTGRES_USER="$OWNER" -e POSTGRES_PASSWORD="$OWNER_PW" -e POSTGRES_DB="$DB" \
        -v "$CERTS:/certs:ro" \
        "$IMAGE" \
        -c ssl=on \
        -c ssl_cert_file=/certs/server.crt \
        -c ssl_key_file=/certs/server.key \
        -c ssl_ca_file=/certs/ca.crt \
        -c hba_file=/certs/pg_hba.conf \
        -c log_connections=on >/dev/null
else
    docker run -d --name "$NAME" \
        -e POSTGRES_USER="$OWNER" -e POSTGRES_PASSWORD="$OWNER_PW" -e POSTGRES_DB="$DB" \
        "$IMAGE" -c log_connections=on >/dev/null
fi

wait_ready "$NAME"
provision "$NAME"
echo "$NAME up ($MODE), schemas provisioned, ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")"
