# Portal submission draft

## Category

Builder -> Intelligent Contract

## Contribution date

2026-10-26

## Description (English, under 1,000 characters)

Dependency Risk Gate is a reusable GenLayer primitive for public, reproducible
software release admission. A publisher registers an artifact identity, a
CycloneDX SBOM URL, and an advisory-count policy. Anyone can trigger a
screening. The contract fetches the SBOM and sends one JSON-encoded live batch
query to OSV,
then checks component coverage, artifact identity, advisory IDs, and affected
components. Validators independently repeat both reads and compare the
decision-bearing evidence. Known advisories above policy are blocked,
incomplete or unsupported coverage requires review, and complete coverage
within policy becomes clear. Other contracts can consume
`is_clear(release_id)`. The repository includes source, deterministic policy,
tests, deployment instructions, and clear failure semantics for package
registries, DAOs, procurement, and on-chain deployment gates.

## Live evidence

- Public source repository:
  https://github.com/Fan-Yu0/genlayer-dependency-risk-gate
- Contract:
  https://explorer-studio.genlayer.com/address/0x7493ED2C2DD1bBc81Fd05Dfdb47864cD67F91A2f
- Deployment transaction:
  https://explorer-studio.genlayer.com/tx/0x0bfd04cb366674d9334fed674d92763bd9c1a243729ee89eed3cdbca045bc42d
- Release registration transaction:
  https://explorer-studio.genlayer.com/tx/0xc9278fcf5585fd700249d50a1602ac097540740c292b13a078f3fa9ff1b8ed97
- Successful `screen` transaction:
  https://explorer-studio.genlayer.com/tx/0x9b9821bf3199912620bacfd3b5ba5ae3f2a23994777e77b45b30ec121626f778
- Live SBOM:
  https://raw.githubusercontent.com/Fan-Yu0/genlayer-dependency-risk-gate/main/examples/payments-api-1.4.0.cdx.json
- Recorded decision: `CLEAR`, 8 advisories within a limit of 10 across 2
  components, with complete OSV coverage.
- Portal submission ID: `e7a0a0d2-bd02-4c71-ad20-98592384d819`
- Portal status: awaiting Steward review

## Reviewer checklist

- Persistent state and a clear lifecycle.
- Publisher-only registration and withdrawal.
- Permissionless evidence refresh.
- Validator independently re-fetches the SBOM and repeats the JSON-encoded OSV
  query.
- The final decision is deterministic.
- Incomplete coverage fails closed.
- Source, tests, documentation, and deployment instructions are public.
