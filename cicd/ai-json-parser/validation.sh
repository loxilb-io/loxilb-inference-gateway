#!/usr/bin/env bash
# Self-contained Linux Docker scenario. Always preserve evidence and clean up
# the containers/network created by this invocation.
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$script_dir/../.." && pwd)
image=${1:-${LOXILB_DOCKER_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:latest}}
image_id=$(docker image inspect --format '{{.Id}}' "$image")
run="ai-json-parser-$(date +%s)-$$-$RANDOM"
evidence=${2:-"$script_dir/artifacts/$run"}
mkdir -p "$(dirname "$evidence")"
umask 077
mkdir "$evidence"
evidence=$(cd "$evidence" && pwd)
echo "evidence=$evidence"
{
  uname -a
  python3 --version
  curl --version
  docker version --format '{{.Server.Version}}'
} > "$evidence/host.txt"

owned=()
network=''
gateway=''
backend=''
database=''
password_file=''
built_mock=''
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$gateway" ]]; then
    # Stop flushes the audit writer before the snapshot is read.
    docker stop --time 10 "$gateway" >/dev/null || status=1
    docker logs "$gateway" > "$evidence/gateway.log" 2>&1 || true
    docker cp "$gateway:/var/log/loxilbdp.log" "$evidence/dataplane.log" 2>/dev/null || true
    docker cp "$gateway:/tmp/ai-json-audit" "$evidence/audit" 2>/dev/null || status=1
  fi
  if [[ -n "$backend" ]]; then
    docker logs "$backend" > "$evidence/mock.log" 2>&1 || true
  fi
  if [[ -f "$evidence/expected.json" && -f "$evidence/receipts.json" &&
        -d "$evidence/audit" ]]; then
    python3 "$script_dir/check_results.py" "$evidence" | tee "$evidence/audit-check.log" || status=1
  else
    echo "Incomplete response, receipt or audit evidence" >&2
    status=1
  fi
  if ((${#owned[@]})); then
    docker rm -f -v "${owned[@]}" >/dev/null || status=1
  fi
  if [[ -n "$password_file" ]]; then
    rm -f "$password_file"
  fi
  if [[ -n "$network" ]]; then
    docker network rm "$network" >/dev/null || status=1
  fi
  if [[ -n "$built_mock" ]]; then
    docker image rm "$built_mock" >/dev/null || status=1
  fi
  remaining_containers=$(docker ps -aq --filter "label=io.loxilb.cicd.run=$run" | wc -l)
  remaining_networks=$(docker network ls -q --filter "label=io.loxilb.cicd.run=$run" | wc -l)
  if ((remaining_containers || remaining_networks)); then
    status=1
  fi
  printf 'remaining_containers=%s remaining_networks=%s\n' \
    "$remaining_containers" "$remaining_networks" | tee "$evidence/cleanup.txt"
  printf '%s\n' "$status" > "$evidence/exit-code.txt"
  python3 - "$evidence" <<'PY'
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
lines = [
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}"
    for path in sorted(root.rglob("*")) if path.is_file() and path.name != "SHA256SUMS"
]
(root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
PY
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker image inspect --format '{{.Id}} {{.Architecture}} {{json .Config.Labels}}' \
  "$image_id" > "$evidence/image.txt"
python3 - "$repo" "$evidence" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

repo, evidence = map(Path, sys.argv[1:])
def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()

identity = {
    "gateway": git(repo, "rev-parse", "HEAD"),
    "ebpf": git(repo / "loxilb-ebpf", "rev-parse", "HEAD"),
    "libbpf": git(repo / "loxilb-ebpf/libbpf", "rev-parse", "HEAD"),
    "dirty": bool(git(repo, "status", "--porcelain")),
}
(evidence / "source.json").write_text(json.dumps(identity, indent=2) + "\n")
scenario = repo / "cicd/ai-json-parser"
checksums = {
    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
    for path in scenario.iterdir() if path.is_file()
}
(evidence / "harness-sha256.json").write_text(json.dumps(checksums, indent=2) + "\n")
PY

mock_image=${JSON_PARSER_MOCK_IMAGE:-}
if [[ -z "$mock_image" ]]; then
  mock_image="$run-mock"
  docker build -f "$script_dir/Dockerfile.mock" --tag "$mock_image" "$repo" \
    2>&1 | tee "$evidence/mock-build.log"
  built_mock=$mock_image
fi
mock_id=$(docker image inspect --format '{{.Id}}' "$mock_image")
printf '%s\n' "$mock_id" > "$evidence/mock-image.txt"

network=$(docker network create --internal --label "io.loxilb.cicd.run=$run" "$run-net")
backend=$(docker create --network "$network" --label "io.loxilb.cicd.run=$run" \
  --name "$run-backend" "$mock_id")
owned+=("$backend")
docker start "$backend" >/dev/null
database=$(docker create --network "$network" --label "io.loxilb.cicd.run=$run" \
  --name "$run-database" --tmpfs /var/lib/postgresql \
  -e POSTGRES_USER=parserowner -e POSTGRES_DB=parser \
  -e POSTGRES_PASSWORD=parser-owner-test-only postgres:18.6)
owned+=("$database")
docker start "$database" >/dev/null
ready=0
for ((attempt=0; attempt<40; attempt++)); do
  if docker exec "$database" pg_isready -h 127.0.0.1 -U parserowner -d parser >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
((ready)) || { echo "test policy database did not become ready" >&2; exit 1; }
docker exec -i -e AIGW_DB_PASSWORD=parser-test-only \
  -e AIGW_MGMT_DB_PASSWORD=parser-mgmt-test-only "$database" \
  psql -q -U parserowner -d parser < "$repo/scripts/aigw-db-bootstrap.sql"
database_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$database")
password_file=$(mktemp)
printf '%s' parser-test-only > "$password_file"
gateway=$(docker create --network "$network" --cap-add NET_ADMIN \
  --label "io.loxilb.cicd.run=$run" --name "$run-gateway" \
  --entrypoint /root/loxilb-io/loxilb/loxilb "$image_id" \
  --proxyonlymode --loglevel debug --config-auto-persist off \
  --aikey-db-host "$database_ip" --aikey-db-user aigwuser --aikey-db-name parser \
  --aikey-db-password-file /tmp/json-parser-keydb-password \
  --audit-dir /tmp/ai-json-audit --audit-required)
owned+=("$gateway")
docker cp "$password_file" "$gateway:/tmp/json-parser-keydb-password"
docker start "$gateway" >/dev/null
docker exec "$gateway" sha256sum /root/loxilb-io/loxilb/loxilb \
  > "$evidence/runtime-binary-sha256.txt"
gateway_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$gateway")
backend_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$backend")
python3 "$script_dir/client.py" "$gateway_ip" "$backend_ip" "$evidence" \
  | tee "$evidence/assertions.log"
