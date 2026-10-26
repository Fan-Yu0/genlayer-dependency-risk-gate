import json


RELEASE_ID = "payments-api-1.4.0"
ARTIFACT_NAME = "payments-api"
ARTIFACT_VERSION = "1.4.0"
SBOM_URL = "https://evidence.example.com/payments-api-1.4.0.cdx.json"


def _sbom(name=ARTIFACT_NAME, version=ARTIFACT_VERSION, components=None):
    if components is None:
        components = [
            {
                "type": "library",
                "name": "flask",
                "version": "2.2.5",
                "purl": "pkg:pypi/flask@2.2.5",
            },
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
        ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": name,
                "version": version,
            }
        },
        "components": components,
    }


def _mock_screening(vm, sbom, results):
    vm.mock_web(
        r".*evidence\.example\.com/payments-api-1\.4\.0\.cdx\.json.*",
        {"status": 200, "body": json.dumps(sbom)},
    )
    vm.mock_web(
        r".*api\.osv\.dev/v1/querybatch.*",
        {
            "method": "POST",
            "status": 200,
            "body": json.dumps({"results": results}),
        },
    )


def _register(contract, vm, publisher, max_findings=0):
    vm.sender = publisher
    contract.register_release(
        RELEASE_ID,
        ARTIFACT_NAME,
        ARTIFACT_VERSION,
        SBOM_URL,
        max_findings,
    )


def _vuln(vulnerability_id):
    return {"id": vulnerability_id, "modified": "2026-10-26T00:00:00Z"}


def test_marks_clean_release_clear(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(direct_vm, _sbom(), [{}, {}])

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["state"] == 1
    assert result["decision"] == 1
    assert result["identity_match"] is True
    assert result["component_count"] == 2
    assert result["queried_components"] == 2
    assert result["finding_count"] == 0
    assert result["round"] == 1
    assert contract.is_clear(RELEASE_ID) is True


def test_blocks_when_findings_exceed_policy(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice, max_findings=0)
    _mock_screening(
        direct_vm,
        _sbom(),
        [{"vulns": [_vuln("GHSA-test-0001")]}, {}],
    )

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["decision"] == 3
    assert result["finding_count"] == 1
    assert result["affected_components"] == 1
    assert result["finding_ids"] == ["GHSA-test-0001"]
    assert contract.is_clear(RELEASE_ID) is False


def test_allows_findings_within_policy_limit(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice, max_findings=2)
    _mock_screening(
        direct_vm,
        _sbom(),
        [
            {"vulns": [_vuln("GHSA-test-0001"), _vuln("GHSA-test-0002")]},
            {},
        ],
    )

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["decision"] == 1
    assert result["finding_count"] == 2
    assert result["finding_ids"] == ["GHSA-test-0001", "GHSA-test-0002"]
    assert contract.is_clear(RELEASE_ID) is True


def test_requires_review_when_sbom_identity_does_not_match(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(
        direct_vm,
        _sbom(name="different-service"),
        [{}, {}],
    )

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["decision"] == 2
    assert result["identity_match"] is False
    assert "identity mismatch" in result["summary"]


def test_requires_review_for_component_without_versioned_purl(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    components = [
        {
            "type": "library",
            "name": "private-library",
            "version": "9.1.0",
        }
    ]
    _mock_screening(
        direct_vm,
        _sbom(components=components),
        [{}],
    )

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["decision"] == 2
    assert result["unsupported_components"] == 1
    assert "lack a versioned purl" in result["summary"]


def test_requires_review_when_osv_response_is_incomplete(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(direct_vm, _sbom(), [{}])

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["decision"] == 2
    assert result["osv_complete"] is False
    assert "OSV coverage was incomplete" in result["summary"]


def test_truncates_component_coverage_and_requires_review(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    components = [
        {
            "type": "library",
            "name": f"package-{index}",
            "version": "1.0.0",
            "purl": f"pkg:npm/package-{index}@1.0.0",
        }
        for index in range(51)
    ]
    _mock_screening(direct_vm, _sbom(components=components), [{}] * 50)

    contract.screen(RELEASE_ID)

    result = contract.get_screening(RELEASE_ID)
    assert result["decision"] == 2
    assert result["truncated"] is True
    assert result["queried_components"] == 50
    assert "coverage was truncated" in result["summary"]


def test_only_publisher_can_withdraw(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)

    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("only the publisher can withdraw"):
        contract.withdraw(RELEASE_ID)

    direct_vm.sender = direct_alice
    contract.withdraw(RELEASE_ID)
    assert contract.get_screening(RELEASE_ID)["state"] == 2
    assert contract.is_clear(RELEASE_ID) is False


def test_rejects_duplicate_release_id(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)

    with direct_vm.expect_revert("release_id already registered"):
        contract.register_release(
            RELEASE_ID,
            ARTIFACT_NAME,
            ARTIFACT_VERSION,
            SBOM_URL,
            0,
        )


def test_rejects_non_https_sbom(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("sbom_url must be an https URL"):
        contract.register_release(
            RELEASE_ID,
            ARTIFACT_NAME,
            ARTIFACT_VERSION,
            "http://evidence.example.com/sbom.json",
            0,
        )


def test_unknown_release_is_not_clear(direct_deploy):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    assert contract.is_clear("unknown-release") is False
    assert contract.get_screening("unknown-release") == {}


def test_validator_accepts_matching_evidence(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(
        direct_vm,
        _sbom(),
        [{"vulns": [_vuln("GHSA-test-0001")]}, {}],
    )
    contract.screen(RELEASE_ID)

    assert direct_vm.run_validator() is True


def test_validator_rejects_changed_vulnerability_set(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(
        direct_vm,
        _sbom(),
        [{"vulns": [_vuln("GHSA-test-0001")]}, {}],
    )
    contract.screen(RELEASE_ID)

    direct_vm.clear_mocks()
    _mock_screening(
        direct_vm,
        _sbom(),
        [{"vulns": [_vuln("GHSA-test-0002")]}, {}],
    )

    assert direct_vm.run_validator() is False


def test_validator_rejects_changed_sbom_components(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(direct_vm, _sbom(), [{}, {}])
    contract.screen(RELEASE_ID)

    direct_vm.clear_mocks()
    changed = _sbom()
    changed["components"] = changed["components"][:1]
    _mock_screening(direct_vm, changed, [{}])

    assert direct_vm.run_validator() is False


def test_validator_rejects_substituted_clean_component(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(direct_vm, _sbom(), [{}, {}])
    contract.screen(RELEASE_ID)

    direct_vm.clear_mocks()
    changed = _sbom(
        components=[
            {
                "type": "library",
                "name": "flask",
                "version": "2.2.5",
                "purl": "pkg:pypi/flask@2.2.5",
            },
            {
                "type": "library",
                "name": "urllib3",
                "version": "2.0.7",
                "purl": "pkg:pypi/urllib3@2.0.7",
            },
        ]
    )
    _mock_screening(direct_vm, changed, [{}, {}])

    assert direct_vm.run_validator() is False


def test_validator_rejects_incomplete_osv_coverage(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/dependency_risk_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_screening(direct_vm, _sbom(), [{}, {}])
    contract.screen(RELEASE_ID)

    direct_vm.clear_mocks()
    _mock_screening(direct_vm, _sbom(), [{}])

    assert direct_vm.run_validator() is False


def test_policy_bits_exposes_the_osv_endpoint(direct_deploy):
    contract = direct_deploy("contracts/dependency_risk_gate.py")

    policy = contract.policy_bits()
    assert policy["clear"] == 1
    assert policy["review_required"] == 2
    assert policy["blocked"] == 3
    assert policy["max_components"] == 50
    assert policy["osv_query_url"] == "https://api.osv.dev/v1/querybatch"
