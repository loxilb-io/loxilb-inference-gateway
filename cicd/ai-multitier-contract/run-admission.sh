#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo "usage: bash run-admission.sh IMAGE NEW_EVIDENCE_DIRECTORY" >&2; exit 2; }
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
image_id=$(docker image inspect --format '{{.Id}}' "$1")
evidence=$2
[[ $evidence = /* && $evidence != / ]] || exit 2
umask 077
mkdir "$evidence"
name="ai-multitier-admission-${RANDOM}-${RANDOM}"
container=''
cleanup() {
  local rc=$?
  if [[ -n $container ]]; then
    docker logs "$container" > "$evidence/gateway.log" 2>&1 || true
    docker stop --timeout 5 "$container" >/dev/null || true
    docker rm "$container" >/dev/null || true
  fi
  printf '%s\n' "$rc" > "$evidence/exit-code.txt"
  (cd "$evidence" && sha256sum ./*.json ./*.txt ./*.log > SHA256SUMS) || true
}
trap cleanup EXIT
printf '%s\n' "$image_id" > "$evidence/image-id.txt"
sha256sum "$script_dir/run-admission.sh" "$script_dir/admission.py" > "$evidence/harness-sha256.txt"
python3 --version > "$evidence/python-version.txt" 2>&1
container=$(docker run -d --name "$name" --network none --cap-add NET_ADMIN \
  --label io.loxilb.cicd=ai-multitier-contract \
  --entrypoint /root/loxilb-io/loxilb/loxilb "$image_id" \
  --proxyonlymode --config-auto-persist off)
docker inspect --format '{{json .HostConfig}}' "$container" > "$evidence/isolation.json"
docker exec "$container" sha256sum /root/loxilb-io/loxilb/loxilb > "$evidence/runtime-binary-sha256.txt"
ready=0
for ((i=0; i<30; i++)); do
  if docker exec "$container" curl --fail --silent --max-time 2 \
    http://127.0.0.1:11111/netlox/v1/config/loadbalancer/all > "$evidence/initial-rules.json"; then
    ready=1; break
  fi
  sleep 1
done
(( ready )) || { echo "REST prerequisite failed" >&2; exit 2; }
python3 "$script_dir/admission.py" "$container" "$evidence" | tee "$evidence/assertions.log"
