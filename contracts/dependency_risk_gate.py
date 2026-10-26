# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
from dataclasses import dataclass

from genlayer import *


DRAFT = 0
SCREENED = 1
WITHDRAWN = 2

UNSCREENED = 0
CLEAR = 1
REVIEW_REQUIRED = 2
BLOCKED = 3

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
MAX_COMPONENTS = 50
MAX_POLICY_FINDINGS = 100
MAX_STORED_FINDINGS = 32
MAX_SBOM_ENTRIES = 200
MAX_RESPONSE_BYTES = 2_000_000


@allow_storage
@dataclass
class ReleaseScreening:
    publisher: Address
    release_id: str
    artifact_name: str
    artifact_version: str
    sbom_url: str
    max_findings: u32
    state: u32
    decision: u32
    identity_match: u32
    component_count: u32
    queried_components: u32
    unsupported_components: u32
    truncated: u32
    osv_complete: u32
    finding_count: u32
    affected_components: u32
    finding_ids: str
    finding_ids_truncated: u32
    summary: str
    round: u64


class DependencyRiskGate(gl.Contract):
    screenings: TreeMap[str, ReleaseScreening]

    def __init__(self):
        pass

    def _require_https(self, url: str, label: str) -> None:
        if not url.startswith("https://"):
            raise gl.vm.UserError(f"{label} must be an https URL")

    def _request_json(self, url: str, method: str = "GET", body: object = None) -> object:
        if body is None:
            response = gl.nondet.web.request(
                url,
                method=method,
                headers={"Accept": "application/json"},
            )
        else:
            response = gl.nondet.web.request(
                url,
                method=method,
                body=json.dumps(body, separators=(",", ":"), sort_keys=True),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )

        status_value = getattr(response, "status_code", None)
        if status_value is None:
            status_value = response.status
        status = int(status_value)
        if status < 200 or status >= 300:
            raise gl.vm.UserError(f"web request returned HTTP {status}")

        raw_body = response.body
        if len(raw_body) > MAX_RESPONSE_BYTES:
            raise gl.vm.UserError("web response is too large")

        if isinstance(raw_body, bytes):
            text = raw_body.decode("utf-8")
        else:
            text = str(raw_body)
        return json.loads(text)

    def _split_purl(self, raw_purl: object) -> tuple[str, str]:
        purl = str(raw_purl or "").strip()
        if not purl.startswith("pkg:") or len(purl) > 300:
            return "", ""

        base, separator, suffix = purl.partition("@")
        version = ""
        if separator:
            version = suffix.split("?", 1)[0].split("#", 1)[0]
        if not base or " " in base:
            return "", ""
        return base, version

    def _parse_sbom(self, document: object) -> dict:
        if not isinstance(document, dict):
            raise gl.vm.UserError("SBOM must be a JSON object")
        if str(document.get("bomFormat", "")).strip().lower() != "cyclonedx":
            raise gl.vm.UserError("SBOM bomFormat must be CycloneDX")

        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        artifact = metadata.get("component", {})
        if not isinstance(artifact, dict):
            artifact = {}

        artifact_name = str(artifact.get("name", "")).strip()
        artifact_version = str(artifact.get("version", "")).strip()

        raw_components = document.get("components", [])
        if not isinstance(raw_components, list):
            raw_components = []

        supported = {}
        unsupported = {}
        truncated = False
        for index, component in enumerate(raw_components):
            if index >= MAX_SBOM_ENTRIES:
                truncated = True
                break
            if not isinstance(component, dict):
                unsupported[f"invalid:{index}"] = True
                continue

            purl, purl_version = self._split_purl(component.get("purl", ""))
            version = str(component.get("version", "")).strip() or purl_version
            if not purl or not version:
                fallback = "{}|{}|{}".format(
                    str(component.get("name", "")).strip(),
                    version,
                    str(component.get("purl", "")).strip(),
                )
                unsupported[fallback or f"missing:{index}"] = True
                continue

            key = f"{purl.lower()}@{version}"
            supported[key] = {
                "purl": purl,
                "version": version[:100],
            }

        ordered_components = []
        for key in sorted(supported.keys()):
            ordered_components.append(supported[key])
        if len(ordered_components) > MAX_COMPONENTS:
            ordered_components = ordered_components[:MAX_COMPONENTS]
            truncated = True

        return {
            "artifact_name": artifact_name[:200],
            "artifact_version": artifact_version[:100],
            "components": ordered_components,
            "component_count": len(supported) + len(unsupported),
            "unsupported_components": len(unsupported),
            "truncated": truncated,
        }

    def _query_osv(self, components: list) -> dict:
        queries = []
        for component in components:
            queries.append(
                {
                    "package": {"purl": component["purl"]},
                    "version": component["version"],
                }
            )

        if not queries:
            return {
                "osv_complete": True,
                "finding_count": 0,
                "affected_components": 0,
                "finding_ids": [],
                "per_component": [],
            }

        response = self._request_json(
            OSV_QUERY_URL,
            method="POST",
            body={"queries": queries},
        )
        if not isinstance(response, dict):
            raise gl.vm.UserError("OSV returned a non-object response")

        results = response.get("results", [])
        if not isinstance(results, list):
            raise gl.vm.UserError("OSV results must be a list")

        osv_complete = len(results) == len(queries)
        finding_ids = {}
        per_component = []
        affected_components = 0
        finding_count = 0

        for index, component in enumerate(components):
            if index >= len(results) or not isinstance(results[index], dict):
                osv_complete = False
                continue

            result = results[index]
            if result.get("next_page_token"):
                osv_complete = False
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                osv_complete = False
                continue

            component_ids = {}
            for vulnerability in vulns:
                if not isinstance(vulnerability, dict):
                    osv_complete = False
                    continue
                vulnerability_id = str(vulnerability.get("id", "")).strip()
                if not vulnerability_id:
                    osv_complete = False
                    continue
                component_ids[vulnerability_id] = True
                finding_ids[vulnerability_id] = True

            if component_ids:
                affected_components += 1
                ids = sorted(component_ids.keys())
                finding_count += len(ids)
                per_component.append(
                    "{}@{}={}".format(
                        component["purl"],
                        component["version"],
                        ",".join(ids),
                    )
                )

        return {
            "osv_complete": osv_complete,
            "finding_count": finding_count,
            "affected_components": affected_components,
            "finding_ids": sorted(finding_ids.keys()),
            "per_component": sorted(per_component),
        }

    def _inspect(
        self,
        artifact_name: str,
        artifact_version: str,
        sbom_url: str,
    ) -> dict:
        document = self._request_json(sbom_url)
        sbom = self._parse_sbom(document)
        osv = self._query_osv(sbom["components"])

        identity_match = (
            sbom["artifact_name"].strip().lower()
            == artifact_name.strip().lower()
            and sbom["artifact_version"] == artifact_version
        )
        component_keys = []
        for component in sbom["components"]:
            component_keys.append(
                "{}@{}".format(component["purl"], component["version"])
            )
        return {
            "artifact_name": sbom["artifact_name"],
            "artifact_version": sbom["artifact_version"],
            "identity_match": identity_match,
            "component_count": sbom["component_count"],
            "queried_components": len(sbom["components"]),
            "component_keys": sorted(component_keys),
            "unsupported_components": sbom["unsupported_components"],
            "truncated": sbom["truncated"],
            "osv_complete": osv["osv_complete"],
            "finding_count": osv["finding_count"],
            "affected_components": osv["affected_components"],
            "finding_ids": osv["finding_ids"],
            "per_component": osv["per_component"],
        }

    def _normalize_evidence(self, raw: object) -> dict:
        if isinstance(raw, str):
            raw = json.loads(raw)
        if not isinstance(raw, dict):
            raise gl.vm.UserError("Screening evidence returned a non-object")

        finding_ids = raw.get("finding_ids", [])
        if not isinstance(finding_ids, list):
            finding_ids = []
        normalized_ids = sorted(
            {
                str(item).strip()
                for item in finding_ids
                if str(item).strip()
            }
        )

        per_component = raw.get("per_component", [])
        if not isinstance(per_component, list):
            per_component = []
        normalized_components = sorted(
            {
                str(item).strip()
                for item in per_component
                if str(item).strip()
            }
        )

        component_keys = raw.get("component_keys", [])
        if not isinstance(component_keys, list):
            component_keys = []
        normalized_keys = sorted(
            {
                str(item).strip()
                for item in component_keys
                if str(item).strip()
            }
        )

        return {
            "artifact_name": str(raw.get("artifact_name", "")).strip()[:200],
            "artifact_version": str(raw.get("artifact_version", "")).strip()[:100],
            "identity_match": bool(raw.get("identity_match", False)),
            "component_count": int(raw.get("component_count", 0)),
            "queried_components": int(raw.get("queried_components", 0)),
            "component_keys": normalized_keys,
            "unsupported_components": int(raw.get("unsupported_components", 0)),
            "truncated": bool(raw.get("truncated", False)),
            "osv_complete": bool(raw.get("osv_complete", False)),
            "finding_count": int(raw.get("finding_count", 0)),
            "affected_components": int(raw.get("affected_components", 0)),
            "finding_ids": normalized_ids,
            "per_component": normalized_components,
        }

    def _screen_with_consensus(
        self,
        artifact_name: str,
        artifact_version: str,
        sbom_url: str,
    ) -> dict:
        def leader_fn() -> dict:
            return self._inspect(artifact_name, artifact_version, sbom_url)

        def validator_fn(leader_result) -> bool:
            try:
                if isinstance(leader_result, gl.vm.Return):
                    leader = self._normalize_evidence(leader_result.calldata)
                else:
                    leader = self._normalize_evidence(leader_result)

                own = self._normalize_evidence(
                    self._inspect(artifact_name, artifact_version, sbom_url)
                )
            except Exception:
                return False

            return (
                leader["artifact_name"].lower() == own["artifact_name"].lower()
                and leader["artifact_version"] == own["artifact_version"]
                and leader["identity_match"] == own["identity_match"]
                and leader["component_count"] == own["component_count"]
                and leader["queried_components"] == own["queried_components"]
                and leader["component_keys"] == own["component_keys"]
                and leader["unsupported_components"] == own["unsupported_components"]
                and leader["truncated"] == own["truncated"]
                and leader["osv_complete"] == own["osv_complete"]
                and leader["finding_count"] == own["finding_count"]
                and leader["affected_components"] == own["affected_components"]
                and leader["finding_ids"] == own["finding_ids"]
                and leader["per_component"] == own["per_component"]
            )

        result = gl.vm.run_nondet(leader_fn, validator_fn)
        if isinstance(result, gl.vm.Return):
            result = result.calldata
        return self._normalize_evidence(result)

    def _decide(self, evidence: dict, max_findings: u32) -> int:
        if evidence["finding_count"] > int(max_findings):
            return BLOCKED
        if not evidence["identity_match"]:
            return REVIEW_REQUIRED
        if evidence["unsupported_components"] > 0:
            return REVIEW_REQUIRED
        if evidence["truncated"]:
            return REVIEW_REQUIRED
        if not evidence["osv_complete"]:
            return REVIEW_REQUIRED
        if evidence["queried_components"] == 0:
            return REVIEW_REQUIRED
        return CLEAR

    def _summary(self, evidence: dict, max_findings: u32, decision: int) -> str:
        if decision == BLOCKED:
            return (
                f"{evidence['finding_count']} OSV advisories exceed the policy "
                f"limit of {int(max_findings)}"
            )
        if decision == REVIEW_REQUIRED:
            reasons = []
            if not evidence["identity_match"]:
                reasons.append("SBOM identity mismatch")
            if evidence["unsupported_components"] > 0:
                reasons.append(
                    f"{evidence['unsupported_components']} components lack a "
                    "versioned purl"
                )
            if evidence["truncated"]:
                reasons.append("component coverage was truncated")
            if not evidence["osv_complete"]:
                reasons.append("OSV coverage was incomplete")
            if evidence["queried_components"] == 0:
                reasons.append("no components were queried")
            return "; ".join(reasons)[:600]
        return (
            f"{evidence['finding_count']} OSV advisories within the policy limit "
            f"of {int(max_findings)} across {evidence['queried_components']} "
            "components"
        )

    @gl.public.write
    def register_release(
        self,
        release_id: str,
        artifact_name: str,
        artifact_version: str,
        sbom_url: str,
        max_findings: u32,
    ) -> None:
        release_id = release_id.strip().lower()
        artifact_name = " ".join(artifact_name.strip().split())
        artifact_version = artifact_version.strip()

        if not release_id:
            raise gl.vm.UserError("release_id is required")
        if len(release_id) > 200:
            raise gl.vm.UserError("release_id is too long")
        if release_id in self.screenings:
            raise gl.vm.UserError("release_id already registered")
        if not artifact_name or len(artifact_name) > 200:
            raise gl.vm.UserError("artifact_name is invalid")
        if not artifact_version or len(artifact_version) > 100:
            raise gl.vm.UserError("artifact_version is invalid")
        if max_findings > MAX_POLICY_FINDINGS:
            raise gl.vm.UserError("max_findings is too large")

        self._require_https(sbom_url, "sbom_url")
        if len(sbom_url) > 1000:
            raise gl.vm.UserError("sbom_url is too long")

        self.screenings[release_id] = ReleaseScreening(
            publisher=gl.message.sender_address,
            release_id=release_id,
            artifact_name=artifact_name,
            artifact_version=artifact_version,
            sbom_url=sbom_url,
            max_findings=max_findings,
            state=DRAFT,
            decision=UNSCREENED,
            identity_match=0,
            component_count=0,
            queried_components=0,
            unsupported_components=0,
            truncated=0,
            osv_complete=0,
            finding_count=0,
            affected_components=0,
            finding_ids="",
            finding_ids_truncated=0,
            summary="",
            round=0,
        )

    @gl.public.write
    def screen(self, release_id: str) -> None:
        release_id = release_id.strip().lower()
        if release_id not in self.screenings:
            raise gl.vm.UserError("unknown release_id")

        screening = gl.storage.copy_to_memory(self.screenings[release_id])
        if screening.state == WITHDRAWN:
            raise gl.vm.UserError("release is withdrawn")

        evidence = self._screen_with_consensus(
            screening.artifact_name,
            screening.artifact_version,
            screening.sbom_url,
        )
        decision = self._decide(evidence, screening.max_findings)
        stored_ids = evidence["finding_ids"][:MAX_STORED_FINDINGS]

        stored = self.screenings[release_id]
        stored.state = SCREENED
        stored.decision = decision
        stored.identity_match = 1 if evidence["identity_match"] else 0
        stored.component_count = evidence["component_count"]
        stored.queried_components = evidence["queried_components"]
        stored.unsupported_components = evidence["unsupported_components"]
        stored.truncated = 1 if evidence["truncated"] else 0
        stored.osv_complete = 1 if evidence["osv_complete"] else 0
        stored.finding_count = evidence["finding_count"]
        stored.affected_components = evidence["affected_components"]
        stored.finding_ids = ",".join(stored_ids)
        stored.finding_ids_truncated = (
            1 if len(evidence["finding_ids"]) > MAX_STORED_FINDINGS else 0
        )
        stored.summary = self._summary(
            evidence,
            screening.max_findings,
            decision,
        )
        stored.round = stored.round + 1

    @gl.public.write
    def withdraw(self, release_id: str) -> None:
        release_id = release_id.strip().lower()
        if release_id not in self.screenings:
            raise gl.vm.UserError("unknown release_id")

        screening = self.screenings[release_id]
        if screening.publisher != gl.message.sender_address:
            raise gl.vm.UserError("only the publisher can withdraw")

        screening.state = WITHDRAWN
        screening.decision = BLOCKED
        screening.summary = "withdrawn by publisher"

    @gl.public.view
    def is_clear(self, release_id: str) -> bool:
        release_id = release_id.strip().lower()
        if release_id not in self.screenings:
            return False
        screening = self.screenings[release_id]
        return screening.state == SCREENED and screening.decision == CLEAR

    @gl.public.view
    def get_screening(self, release_id: str) -> dict:
        release_id = release_id.strip().lower()
        if release_id not in self.screenings:
            return {}

        screening = self.screenings[release_id]
        finding_ids = []
        if screening.finding_ids:
            finding_ids = screening.finding_ids.split(",")

        return {
            "publisher": screening.publisher.as_hex,
            "release_id": screening.release_id,
            "artifact_name": screening.artifact_name,
            "artifact_version": screening.artifact_version,
            "sbom_url": screening.sbom_url,
            "max_findings": int(screening.max_findings),
            "state": int(screening.state),
            "decision": int(screening.decision),
            "identity_match": bool(screening.identity_match),
            "component_count": int(screening.component_count),
            "queried_components": int(screening.queried_components),
            "unsupported_components": int(screening.unsupported_components),
            "truncated": bool(screening.truncated),
            "osv_complete": bool(screening.osv_complete),
            "finding_count": int(screening.finding_count),
            "affected_components": int(screening.affected_components),
            "finding_ids": finding_ids,
            "finding_ids_truncated": bool(screening.finding_ids_truncated),
            "summary": screening.summary,
            "round": int(screening.round),
        }

    @gl.public.view
    def policy_bits(self) -> dict:
        return {
            "draft": DRAFT,
            "screened": SCREENED,
            "withdrawn": WITHDRAWN,
            "unscreened": UNSCREENED,
            "clear": CLEAR,
            "review_required": REVIEW_REQUIRED,
            "blocked": BLOCKED,
            "max_components": MAX_COMPONENTS,
            "max_policy_findings": MAX_POLICY_FINDINGS,
            "max_stored_findings": MAX_STORED_FINDINGS,
            "osv_query_url": OSV_QUERY_URL,
        }
