# Dependency Risk Gate

A reusable GenLayer Intelligent Contract for evidence-backed release admission.
It reads a CycloneDX SBOM, queries OSV for known advisories, and records a
deterministic admission decision on-chain.

Repository:
<https://github.com/Fan-Yu0/genlayer-dependency-risk-gate>

## Live deployment

- Contract:
  <https://explorer-studio.genlayer.com/address/0x7493ED2C2DD1bBc81Fd05Dfdb47864cD67F91A2f>
- Deployment:
  <https://explorer-studio.genlayer.com/tx/0x0bfd04cb366674d9334fed674d92763bd9c1a243729ee89eed3cdbca045bc42d>
- Release registration:
  <https://explorer-studio.genlayer.com/tx/0xc9278fcf5585fd700249d50a1602ac097540740c292b13a078f3fa9ff1b8ed97>
- Live screening:
  <https://explorer-studio.genlayer.com/tx/0x9b9821bf3199912620bacfd3b5ba5ae3f2a23994777e77b45b30ec121626f778>

The final screening returned `CLEAR`, with 8 OSV advisories within the policy
limit of 10 across 2 components. OSV coverage was complete.

## Problem

Software consumers usually discover dependency risk in a CI dashboard. That
result is private, mutable, and not available to on-chain procurement,
marketplaces, DAOs, or other contracts.

This contract creates a public, reproducible screening record from two public
inputs:

1. a CycloneDX SBOM published for a specific release;
2. the live OSV vulnerability database.

The contract does not ask an LLM to invent a security score. It normalizes the
SBOM and OSV responses directly, then applies a fixed policy owned by the
publisher.

## How it works

1. A publisher registers a release ID, artifact name and version, SBOM URL, and
   the maximum number of OSV advisories it accepts.
2. Anyone calls `screen(release_id)`.
3. The leader fetches the SBOM and submits one JSON-encoded OSV
   `querybatch` request.
4. Validators independently fetch the same SBOM and repeat the OSV query.
5. The validator compares the artifact identity, component coverage, advisory
   IDs, and affected-component set.
6. Deterministic contract code stores the decision and the first 32 advisory
   IDs for inspection.

| Condition | Decision |
| --- | --- |
| Advisory count exceeds `max_findings` | `BLOCKED` |
| SBOM metadata does not match the registered artifact | `REVIEW_REQUIRED` |
| Any component lacks a versioned package URL | `REVIEW_REQUIRED` |
| More than 50 components would be queried | `REVIEW_REQUIRED` |
| OSV response is incomplete | `REVIEW_REQUIRED` |
| No component was queried | `REVIEW_REQUIRED` |
| Coverage is complete and the advisory count is within policy | `CLEAR` |

Other contracts can consume `is_clear(release_id)`.

## Why this is a GenLayer primitive

- SBOMs and vulnerability data are public web evidence, not on-chain facts.
- Advisory databases change after a release is published.
- Every caller can request a fresh screening without trusting a private CI
  dashboard.
- The contract uses structured data instead of an opaque model-generated risk
  score.
- A custom validator independently repeats both external reads, including the
  JSON POST body and request headers required by OSV.
- Unknown coverage fails closed instead of becoming a silent approval.

## Coverage model

The contract accepts CycloneDX JSON with a `metadata.component` identity and a
`components` array. Each dependency needs:

- a package URL beginning with `pkg:`;
- a version either in the component's `version` field or in the purl.

The purl version is removed before the OSV query and supplied through OSV's
separate `version` field. The contract caps one screening at 50 unique
components and 200 raw SBOM entries. A larger SBOM is recorded as truncated and
requires review.

`max_findings` counts OSV advisory records returned for all queried components.
One underlying issue can have more than one OSV advisory ID, so this is an
advisory-count policy rather than a claim of unique-CVE counting.

## State machine

```text
DRAFT --screen--> SCREENED --screen--> SCREENED
  |                   |
  +------withdraw-----+--> WITHDRAWN
```

`register_release` and `withdraw` are restricted to the publisher. `screen` is
permissionless because its evidence and policy are public.

## Consensus design

The non-deterministic block returns only decision-bearing fields:

```json
{
  "artifact_name": "payments-api",
  "artifact_version": "1.4.0",
  "identity_match": true,
  "component_count": 2,
  "queried_components": 2,
  "component_keys": [
    "pkg:pypi/flask@2.2.5",
    "pkg:pypi/requests@2.31.0"
  ],
  "unsupported_components": 0,
  "truncated": false,
  "osv_complete": true,
  "finding_count": 0,
  "affected_components": 0,
  "finding_ids": [],
  "per_component": []
}
```

The validator re-fetches the SBOM, repeats the OSV request, and compares those
fields. It does not trust only the leader's JSON shape. The final decision is
computed after consensus in deterministic code.

## Example

```text
release_id: payments-api-1.4.0
artifact_name: payments-api
artifact_version: 1.4.0
sbom_url: https://evidence.example.com/payments-api-1.4.0.cdx.json
max_findings: 0
```

Then call `screen("payments-api-1.4.0")`.

For a real deployment, use a public release SBOM rather than the example host.
The OSV endpoint is fixed in the contract:
`https://api.osv.dev/v1/querybatch`.

The repository includes
`examples/payments-api-1.4.0.cdx.json` as a reproducible fixture. After
publishing the repository, use its raw GitHub URL as `sbom_url`.

Public fixture URL:

```text
https://raw.githubusercontent.com/Fan-Yu0/genlayer-dependency-risk-gate/main/examples/payments-api-1.4.0.cdx.json
```

## Repository layout

```text
contracts/dependency_risk_gate.py
tests/direct/test_dependency_risk_gate.py
examples/payments-api-1.4.0.cdx.json
deploy/deployScript.ts
gltest.config.yaml
SUBMISSION.md
```

## Local verification

```shell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
genvm-lint check contracts/dependency_risk_gate.py
pytest tests/direct/ -v
```

On Windows, `tests/direct/conftest.py` contains a cleanup shim for a
`gltest-direct` temporary-file issue. It does not affect contract behavior.

## Deploy

### Studio

1. Open <https://studio.genlayer.com/>.
2. Select the current GenLayer testnet shown in Studio.
3. Paste `contracts/dependency_risk_gate.py` and deploy with no constructor
   arguments.
4. Register a public release SBOM.
5. Call `screen(release_id)`.
6. Save the contract address, deployment transaction, and successful screening
   transaction.

### CLI

```shell
npm install
genlayer network
genlayer deploy
```

## Security notes

- Only HTTPS SBOM URLs are accepted.
- Source documents are treated as untrusted data, never as instructions.
- Responses are capped at 2 MB before JSON parsing.
- Component coverage is capped and incomplete coverage requires review.
- The contract records a dependency-admission signal. It is not a complete
  software-composition analysis, exploitability assessment, or security
  certification.
