#!/usr/bin/env bash
#
# The multi-tier argument contract gate, as CI runs it.
#
# WHY THIS EXISTS
#
#   auth-plane-sanity's "Multi-tier argument contract" step used to carry
#   these three commands inline. Nothing else could run them, so the product
#   harness registry pointed at run-unit.sh instead — a different, much
#   heavier script that drives twelve gates inside a Docker test-build image
#   and takes two mandatory arguments. The registry row could therefore never
#   pass (it exits 2 on the missing arguments, and 126 because run-unit.sh is
#   not executable), and even fixed it would have run something CI does not.
#
#   One script, called by both, is what keeps "what CI gates on" and "what QA
#   can re-run" the same thing. Change this file and both move together.
#
#   run-unit.sh is NOT superseded: it is the evidence-producing baseline rail,
#   invoked as `bash run-unit.sh IMAGE EVIDENCE_DIR`, and is a deliberately
#   wider net than the per-PR gate below.
#
# USAGE
#
#   ./run-ci-gates.sh        # from anywhere; it resolves the repo root itself
#
#   Needs python3 and a Go toolchain. It does not need a built datapath
#   library, a container, or network access.
#
# EXIT CODE
#
#   0 only if all three gates pass. Any failure is non-zero and names which
#   gate failed.

set -euo pipefail

# The go commands take repo-root-relative package paths, and the registry runs
# steps from inside the scenario directory, so resolve the root rather than
# assuming a working directory.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

echo "--- multi-tier contract: harness unit tests"
# Pins numeric/enum admission, engine-topology dependencies and the P/D
# threshold declaration contracts.
python3 -B -m unittest discover \
  -s cicd/ai-multitier-contract -p 'test_*.py'

echo "--- multi-tier contract: inventory generator tests"
go test -count=1 ./cicd/ai-multitier-contract/inventory

echo "--- multi-tier contract: inventory drift gate"
# The drift gate: it fails when the published argument inventory stops
# matching the Swagger sources it was generated from.
go run ./cicd/ai-multitier-contract/inventory \
  -check cicd/ai-multitier-contract/argument-inventory.json

echo "SCENARIO-ai-multitier-contract [OK]"
