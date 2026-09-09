# Multi-tier argument regression

This directory contains public regression tests for LoxiLB Inference Gateway
argument validation. The tests cover schema generation, numeric and enum
admission, engine/topology dependencies, fixed-size data-plane strings, and
HTTP rejection behavior.

## Local checks

Run the harness unit tests without deploying a Gateway:

```bash
python3 -B -m unittest discover \
  -s cicd/ai-multitier-contract -p 'test_*.py' -v
```

Check that the public argument inventory still matches the current Swagger
sources:

```bash
go test ./cicd/ai-multitier-contract/inventory
go run ./cicd/ai-multitier-contract/inventory \
  -check cicd/ai-multitier-contract/argument-inventory.json
```

Check that the source Swagger contract and the embedded original document are
synchronized:

```bash
go test ./api/cmd/sync-swagger
go run ./api/cmd/sync-swagger -check
ruby scripts/validate-swagger-contract.rb
```

## Container gates

`run-unit.sh` runs the selected Go, C, Swagger, inventory, and harness checks in
a retained build-stage image. `run-admission.sh` starts the packaged Gateway in
an isolated container and verifies that rejected requests do not mutate the
installed rule.

Both scripts require an explicit image and a new evidence directory:

```bash
bash cicd/ai-multitier-contract/run-unit.sh IMAGE EVIDENCE_DIR
bash cicd/ai-multitier-contract/run-admission.sh IMAGE EVIDENCE_DIR
```

These gates establish unit and REST-admission behavior only. They do not claim
eBPF forwarding, live engine interoperability, GPU/model qualification,
high-availability behavior, or production readiness.

## Contract notes

- `x-loxilb-max-utf8-bytes` is used where the data-plane limit is encoded byte
  length rather than Swagger 2.0 character count.
- `x-loxilb-contract-relations` describes selected cross-field dependencies;
  its public semantics are defined in `api/contract-relations.md`.
- The server remains the enforcement boundary. Client-side interpretation is
  advisory and must treat unknown relationship versions or kinds as unresolved.
- A passing inventory drift check means only that the checked-in public field
  inventory matches the current specifications. It is not a coverage or
  runtime-readiness claim.
