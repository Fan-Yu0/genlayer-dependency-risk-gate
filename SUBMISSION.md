# Portal submission draft

## Category

Builder -> Intelligent Contract

## Contribution date

Use the actual deployment date. Do not select a future date.

## Description (English, under 1,000 characters)

Dependency Risk Gate is a reusable GenLayer primitive for public, reproducible
software release admission. A publisher registers an artifact identity, a
CycloneDX SBOM URL, and an advisory-count policy. Anyone can trigger a
screening. The contract fetches the SBOM and sends one live batch query to OSV,
then checks component coverage, artifact identity, advisory IDs, and affected
components. Validators independently repeat both reads and compare the
decision-bearing evidence. Known advisories above policy are blocked,
incomplete or unsupported coverage requires review, and complete coverage
within policy becomes clear. Other contracts can consume
`is_clear(release_id)`. The repository includes source, deterministic policy,
tests, deployment instructions, and clear failure semantics for package
registries, DAOs, procurement, and on-chain deployment gates.

## Evidence to add after deployment

- Public source repository URL.
- Contract Explorer address URL in the form
  `https://explorer-studio.genlayer.com/address/<address>`.
- Deployment transaction URL.
- Successful `screen` transaction URL.
- The live SBOM URL and the recorded decision.

## Reviewer checklist

- Persistent state and a clear lifecycle.
- Publisher-only registration and withdrawal.
- Permissionless evidence refresh.
- Validator independently re-fetches the SBOM and repeats the OSV query.
- The final decision is deterministic.
- Incomplete coverage fails closed.
- Source, tests, documentation, and deployment instructions are public.
