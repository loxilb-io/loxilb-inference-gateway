#!/usr/bin/env bash
# Run on the controller against Dockerfile.u24's test-build image.
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "usage: bash run-unit.sh TEST_BUILD_IMAGE NEW_EVIDENCE_DIRECTORY" >&2
  exit 2
fi
image=$1
evidence=$2
[[ $evidence = /* && $evidence != / ]] || { echo "evidence path must be absolute" >&2; exit 2; }
# Refuse reuse: a failed run must not retain a previous run's PASS artifacts.
mkdir "$evidence"
umask 077
image_id=$(docker image inspect --format '{{.Id}}' "$image")
printf '%s\n' "$image_id" > "$evidence/image-id.txt"
docker image inspect --format '{{json .RepoDigests}}' "$image_id" > "$evidence/image-digests.json"
df -Pk "$evidence" > "$evidence/disk-before.txt"

work=/root/loxilb-io/loxilb
mounts=()
# A baseline can run newly written tests against OLD production code. Only
# these two test files can be overlaid, and their checksums are evidence.
if [[ -n ${TEST_SOURCE_DIR:-} ]]; then
  for file in api/models/ai_multitier_arguments_test.go pkg/loxinet/rules_ai_multitier_arguments_test.go; do
    [[ -f $TEST_SOURCE_DIR/$file ]] || { echo "missing test overlay: $file" >&2; exit 2; }
    sha256sum "$TEST_SOURCE_DIR/$file" >> "$evidence/test-overlay-sha256.txt"
    mounts+=(--mount "type=bind,src=$TEST_SOURCE_DIR/$file,dst=$work/$file,readonly")
  done
fi
docker_args=(--rm --network none --entrypoint /bin/bash --workdir "$work"
  -e 'CGO_CFLAGS=-DHAVE_MTLS=1 -DHAVE_L4_TRACE=1' "${mounts[@]}" "$image_id")

if ! docker run "${docker_args[@]}" -ec '
  test -f go.mod
  test -s loxilb-ebpf/kernel/libloxilbdp.a
  test -s /usr/local/lib/libtokenizers.a
  test -f api/models/ai_multitier_arguments_test.go
  test -f pkg/loxinet/rules_ai_multitier_arguments_test.go
  go version
  gcc --version | head -n 1
  sha256sum loxilb api/swagger.yml api/models/loadbalance_entry.go pkg/loxinet/rules.go loxilb-ebpf/kernel/libloxilbdp.a
' > "$evidence/prerequisites.log" 2>&1; then
  printf 'prerequisite\tHARNESS_OR_IMAGE_PREREQUISITE_FAIL\n' > "$evidence/results.tsv"
  exit 2
fi

failed=0
run_gate() {
  local name=$1 rc=0
  shift
  docker run "${docker_args[@]}" "$@" > "$evidence/$name.log" 2>&1 || rc=$?
  printf '%s\t%d\n' "$name" "$rc" >> "$evidence/results.tsv"
  if (( rc != 0 )); then failed=1; fi
  printf '%s: exit=%d\n' "$name" "$rc"
}
run_gate api-models -ec 'go test -json -count=1 ./api/models'
run_gate kv-admission -ec 'go test -json -tags=mtls,l4trace -count=1 ./pkg/loxinet -run "Test(AIMultitier|KvEngine|KvExactAdmission|KvTrtllmFeatureGuard|KvLlamacppFeatureGuard|KvSubscriberRankPortsBounds)"'
run_gate pd-cache -ec 'make -C loxilb-ebpf/common test_pd_cache'
run_gate kv-dataplane -ec 'make -C loxilb-ebpf/common test_kv'
df -Pk "$evidence" > "$evidence/disk-after.txt"
(cd "$evidence" && sha256sum ./*.log ./*.txt ./*.json ./*.tsv > SHA256SUMS)
exit "$failed"
