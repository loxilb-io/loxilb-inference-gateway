#!/bin/bash
# sockmap-restart / validation.sh
#
# A gateway started with --sockmapsupport must come back after a restart of
# the SAME container. The container keeps its writable layer across a restart
# but gets a fresh mount namespace, so the cgroup2 hierarchy the sockmap
# bootstrap joins has to be mounted again on every boot; a boot that trusts
# the directory left by the previous one aborts inside the data path init.
#
# The daemon must be the container's PID 1 (the image's own entrypoint), not
# a process started under --entrypoint /bin/bash: only then does docker
# restart recreate the mount namespace the way an operator's restart does.
#
#   LOXILB_IMAGE   image under test (default: the published latest)
#   RESTARTS       restarts to drive (default 2)
#   READY_TIMEOUT  seconds allowed for /status/ready to answer 200 (default 90)
#   OUT_DIR        where the evidence is written (default ./artifacts)
#
# Exit 0 when every boot is ready in time and the rule created before the
# first restart reads back after each one; 1 otherwise, with the container's
# exit code and last log lines in the evidence.

set -u
cd "$(dirname "$0")"

IMAGE=${LOXILB_IMAGE:-ghcr.io/loxilb-io/loxilb-inference-gateway:main}
RESTARTS=${RESTARTS:-2}
READY_TIMEOUT=${READY_TIMEOUT:-90}
OUT_DIR=${OUT_DIR:-./artifacts}
NAME=${NAME:-sockmap-restart-llb1}
RULE_VIP=20.20.20.1
RULE_EP=31.31.31.1

mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"
: > "$SUMMARY"
note() { echo "$*" | tee -a "$SUMMARY"; }

cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

fail() {
  local phase=$1
  note "FAIL [$phase]: $2"
  note "container running=$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null) exit=$(docker inspect -f '{{.State.ExitCode}}' "$NAME" 2>/dev/null)"
  docker logs "$NAME" > "$OUT_DIR/logs-$phase.txt" 2>&1
  note "--- cgroup / fatal lines ($phase)"
  grep -E "cgroup|fatal|abort" "$OUT_DIR/logs-$phase.txt" | tail -8 | tee -a "$SUMMARY"
  note "--- last log lines ($phase)"
  tail -5 "$OUT_DIR/logs-$phase.txt" | tee -a "$SUMMARY"
  exit 1
}

# Readiness: 200 from /netlox/v1/status/ready within READY_TIMEOUT. An exited container
# is a failure at once, not after the timeout.
wait_ready() {
  local phase=$1 ip code i
  for ((i = 0; i < READY_TIMEOUT; i++)); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
      fail "$phase" "container is not running after ${i}s"
    fi
    ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME" 2>/dev/null)
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$ip:11111/netlox/v1/status/ready" 2>/dev/null)
    if [ "$code" = "200" ]; then
      note "ready [$phase]: 200 after ${i}s"
      return 0
    fi
    sleep 1
  done
  fail "$phase" "/status/ready never answered 200 within ${READY_TIMEOUT}s (last code '${code:-none}')"
}

rule_readback() {
  local phase=$1 out
  out=$(docker exec "$NAME" loxicmd get lb -o json 2>/dev/null)
  if ! grep -q "$RULE_VIP" <<<"$out"; then
    echo "$out" > "$OUT_DIR/lb-$phase.json"
    fail "$phase" "rule $RULE_VIP not found in the load-balancer list"
  fi
  note "rule readback [$phase]: $RULE_VIP present"
}

note "image: $IMAGE ($(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null))"
note "host: $(uname -r), cgroup fs $(stat -f -c %T /sys/fs/cgroup 2>/dev/null), $(docker version --format 'docker {{.Server.Version}}' 2>/dev/null)"

docker run -d --privileged --name "$NAME" "$IMAGE" --sockmapsupport >/dev/null \
  || { note "FAIL [boot-1]: docker run refused"; exit 1; }
wait_ready boot-1

docker exec "$NAME" loxicmd create lb "$RULE_VIP" --tcp=2020:8080 --endpoints="$RULE_EP":1 >/dev/null \
  || fail boot-1 "loxicmd create lb refused"
rule_readback boot-1
# Mutating API calls are written through to the snapshot after a quiet
# period; give the debouncer that period before the restart.
sleep 5

for ((n = 1; n <= RESTARTS; n++)); do
  note "docker restart #$n at $(date -u +%H:%M:%S)"
  docker restart "$NAME" >/dev/null || fail "restart-$n" "docker restart refused"
  wait_ready "restart-$n"
  rule_readback "restart-$n"
done

note "PASS: $RESTARTS restart(s) of the same container, ready each time, rule retained"
exit 0
