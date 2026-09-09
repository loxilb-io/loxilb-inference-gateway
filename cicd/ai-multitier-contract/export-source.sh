#!/usr/bin/env bash
# Freeze an isolated worktree before transfer; never build from a live rsync target.
set -euo pipefail
[[ $# == 1 && $1 = /* && $1 != / ]] || { echo "usage: bash export-source.sh NEW_ABSOLUTE_DIRECTORY" >&2; exit 2; }
evidence=$1
umask 077
mkdir "$evidence"
repo=$(git rev-parse --show-toplevel)
cd "$repo"
# --recurse-submodules includes tracked child working files. Refuse untracked
# child files until they have been explicitly reviewed and staged by the owner.
git submodule foreach --quiet --recursive 'test -z "$(git ls-files --others --exclude-standard)"'
git ls-files --cached --recurse-submodules -z > "$evidence/files.null"
git ls-files --others --exclude-standard -z >> "$evidence/files.null"
git rev-parse HEAD > "$evidence/base-revision.txt"
git status --porcelain=v1 > "$evidence/worktree-status.txt"
git submodule status --recursive > "$evidence/submodules.txt"
git diff --binary HEAD > "$evidence/source.patch"
# Exclude host-only macOS provenance/resource-fork metadata from Linux inputs.
COPYFILE_DISABLE=1 tar --no-xattrs --no-acls -czf "$evidence/source.tar.gz" --null -T "$evidence/files.null"
(cd "$evidence" && shasum -a 256 source.tar.gz files.null base-revision.txt worktree-status.txt submodules.txt source.patch > SHA256SUMS)
echo "Frozen source: $evidence/source.tar.gz"
echo "Transfer and verify SHA256SUMS, then extract into a NEW directory before make docker."
