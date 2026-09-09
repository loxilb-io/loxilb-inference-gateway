#!/usr/bin/env bash
# Isolated source/generator qualification; does not build or deploy a Gateway.
set -euo pipefail
[[ $# == 4 ]] || { echo 'usage: run-swagger-contract.sh IMAGE FROZEN_SOURCE BEFORE_EMBEDDED NEW_EVIDENCE' >&2; exit 2; }
image=$1
source_dir=$2
before=$3
evidence=$4
for path in "$source_dir" "$before" "$evidence"; do
  [[ $path = /* && $path != / ]] || { echo 'paths must be absolute and scoped' >&2; exit 2; }
done
umask 077
mkdir "$evidence"
image_id=$(docker image inspect --format '{{.Id}}' "$image")
generator_id=$(docker image inspect --format '{{.Id}}' quay.io/goswagger/swagger:0.30.3)
printf '%s\n%s\n' "$image_id" "$generator_id" > "$evidence/image-ids.txt"
sha256sum "$0" "$source_dir/api/cmd/sync-swagger/"*.go \
  "$source_dir/cicd/ai-multitier-contract/verify_swagger_generation.py" \
  "$source_dir/cicd/ai-multitier-contract/test_swagger_generation.py" \
  "$source_dir/api/swagger.yml" "$source_dir/api/restapi/embedded_spec.go" "$before" > "$evidence/input-sha256.txt"
df -Pk "$evidence" > "$evidence/disk-before.txt"
docker ps --format '{{.ID}} {{.Names}} {{.Image}}' > "$evidence/services-before.txt"
common=(--rm --network none --cpus 2 --memory 2g --entrypoint /bin/bash
  -e GOPROXY=off -e GOTOOLCHAIN=local
  --mount "type=bind,src=$source_dir,dst=/work,readonly" --workdir /work)
gate() {
  local name=$1 rc=0
  shift
  "$@" > "$evidence/$name.log" 2>&1 || rc=$?
  printf '%s\t%d\n' "$name" "$rc" >> "$evidence/results.tsv"
  return "$rc"
}
expect_drift() {
  local name=$1 rc=0
  shift
  gate "$name" "$@" || rc=$?
  [[ $rc == 1 ]] && grep -q '^SwaggerJSON source drift:' "$evidence/$name.log"
}
gate unit docker run "${common[@]}" "$image_id" -ec 'go version; go test -json -count=1 -cover ./api/cmd/sync-swagger'
gate oracle docker run "${common[@]}" "$image_id" -ec 'python3 -B -m unittest discover -s cicd/ai-multitier-contract -p test_swagger_generation.py -v'
gate fixed-source docker run "${common[@]}" "$image_id" -ec 'go run ./api/cmd/sync-swagger -check'
expect_drift before-source docker run "${common[@]}" --mount "type=bind,src=$before,dst=/before.go,readonly" "$image_id" -ec 'go run ./api/cmd/sync-swagger -check -generated /before.go'

mkdir -p "$evidence/generated/src/github.com/loxilb-io/loxilb/api"
gate pinned-generation docker run --rm --network none --cpus 2 --memory 2g \
  -e GOPATH=/work --workdir /work \
  --mount "type=bind,src=$evidence/generated,dst=/work" \
  --mount "type=bind,src=$source_dir/api/swagger.yml,dst=/input/swagger.yml,readonly" \
  "$generator_id" generate server --spec /input/swagger.yml \
  --target /work/src/github.com/loxilb-io/loxilb/api --name LoxilbRestAPI \
  --principal 'interface{}' --exclude-main --skip-operations
generated="$evidence/generated/src/github.com/loxilb-io/loxilb/api/restapi/embedded_spec.go"
cp "$generated" "$evidence/generator-before.go"
mounted=("${common[@]}" --mount "type=bind,src=$evidence/generated,dst=/generated")
target=/generated/src/github.com/loxilb-io/loxilb/api/restapi/embedded_spec.go
expect_drift generator-drift docker run "${mounted[@]}" "$image_id" -ec "go run ./api/cmd/sync-swagger -check -generated $target"
gate synchronize docker run "${mounted[@]}" "$image_id" -ec "go run ./api/cmd/sync-swagger -generated $target"
gate regenerated-check docker run "${mounted[@]}" "$image_id" -ec "go run ./api/cmd/sync-swagger -check -generated $target"
gate semantic-repair docker run "${mounted[@]}" \
  --mount "type=bind,src=$evidence/generator-before.go,dst=/before-generated.go,readonly" \
  "$image_id" -ec "python3 --version; python3 -B cicd/ai-multitier-contract/verify_swagger_generation.py /before-generated.go $target"
docker ps --format '{{.ID}} {{.Names}} {{.Image}}' > "$evidence/services-after.txt"
gate services-unchanged cmp "$evidence/services-before.txt" "$evidence/services-after.txt"
df -Pk "$evidence" > "$evidence/disk-after.txt"
(cd "$evidence" && sha256sum ./*.log ./*.txt ./*.tsv generator-before.go generated/src/github.com/loxilb-io/loxilb/api/restapi/embedded_spec.go > SHA256SUMS)
echo 'PASS: scoped contract gates; expected RED controls retained in results.tsv'
