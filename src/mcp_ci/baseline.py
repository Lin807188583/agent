"""Sanitized, deterministic metadata baselines for reviewed CI drift checks."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .models import CheckReport, Finding, Severity
from .probe import ProbeEvidence


BASELINE_SCHEMA_VERSION = 1
MANIFEST_NAMES = ("tools", "resources", "resource_templates", "prompts")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class BaselineError(ValueError):
    """A baseline cannot be read, validated, or safely written."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _digest(value: Any) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


def _safe_identity(item: Any, identity_key: str, *, expose: bool) -> str:
    if isinstance(item, dict):
        value = item.get(identity_key)
        if isinstance(value, str) and value:
            return value if expose else f"sha256:{_digest(value)}"
    return f"sha256:{_digest(item)}"


def _manifest(
    items: list[Any],
    *,
    identity_key: str,
    expose_identity: bool,
) -> dict[str, Any]:
    entries = [
        {
            "identity": _safe_identity(
                item, identity_key, expose=expose_identity
            ),
            "sha256": _digest(item),
        }
        for item in items
    ]
    entries.sort(key=lambda item: (item["identity"], item["sha256"]))
    return {"count": len(items), "items": entries}


def create_baseline(evidence: ProbeEvidence) -> dict[str, Any]:
    """Build a snapshot without raw Resource identities or metadata bodies."""

    capabilities = sorted(str(name) for name in evidence.capabilities)
    resources = ProbeEvidence._items_from_pages(
        evidence.resources_list_pages, "resources"
    )
    resource_templates = ProbeEvidence._items_from_pages(
        evidence.resource_templates_list_pages, "resourceTemplates"
    )
    prompts = ProbeEvidence._items_from_pages(evidence.prompts_list_pages, "prompts")
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "protocol_version": evidence.negotiated_protocol_version,
        "capabilities": capabilities,
        "manifests": {
            "tools": _manifest(
                evidence.all_tools,
                identity_key="name",
                expose_identity=True,
            ),
            "resources": _manifest(
                resources,
                identity_key="uri",
                expose_identity=False,
            ),
            "resource_templates": _manifest(
                resource_templates,
                identity_key="uriTemplate",
                expose_identity=False,
            ),
            "prompts": _manifest(
                prompts,
                identity_key="name",
                expose_identity=True,
            ),
        },
    }


def _validate_manifest(name: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise BaselineError(f"baseline.manifests.{name} must be an object")
    unknown = sorted(set(value) - {"count", "items"})
    missing = sorted({"count", "items"} - set(value))
    if unknown or missing:
        raise BaselineError(
            f"baseline.manifests.{name} must contain only count and items"
        )
    count = value["count"]
    items = value["items"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise BaselineError(
            f"baseline.manifests.{name}.count must be a non-negative integer"
        )
    if not isinstance(items, list) or len(items) != count:
        raise BaselineError(
            f"baseline.manifests.{name}.items must be an array matching count"
        )
    for index, item in enumerate(items):
        if not isinstance(item, dict) or set(item) != {"identity", "sha256"}:
            raise BaselineError(
                f"baseline.manifests.{name}.items[{index}] must contain identity and sha256"
            )
        identity = item["identity"]
        digest = item["sha256"]
        if not isinstance(identity, str) or not identity:
            raise BaselineError(
                f"baseline.manifests.{name}.items[{index}].identity must be non-empty"
            )
        if not isinstance(digest, str) or SHA256_HEX.fullmatch(digest) is None:
            raise BaselineError(
                f"baseline.manifests.{name}.items[{index}].sha256 is invalid"
            )
    if items != sorted(items, key=lambda item: (item["identity"], item["sha256"])):
        raise BaselineError(
            f"baseline.manifests.{name}.items must use canonical sorted order"
        )


def validate_baseline(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BaselineError("baseline root must be an object")
    expected_keys = {
        "schema_version",
        "protocol_version",
        "capabilities",
        "manifests",
    }
    if set(value) != expected_keys:
        raise BaselineError(
            "baseline root must contain only schema_version, protocol_version, capabilities, and manifests"
        )
    if value["schema_version"] != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            f"unsupported baseline schema_version {value['schema_version']!r}"
        )
    protocol = value["protocol_version"]
    if protocol is not None and (not isinstance(protocol, str) or not protocol):
        raise BaselineError("baseline.protocol_version must be a string or null")
    capabilities = value["capabilities"]
    if not isinstance(capabilities, list) or any(
        not isinstance(item, str) or not item for item in capabilities
    ):
        raise BaselineError("baseline.capabilities must be an array of strings")
    if len(capabilities) != len(set(capabilities)):
        raise BaselineError("baseline.capabilities must not contain duplicates")
    if capabilities != sorted(capabilities):
        raise BaselineError("baseline.capabilities must use canonical sorted order")
    manifests = value["manifests"]
    if not isinstance(manifests, dict) or set(manifests) != set(MANIFEST_NAMES):
        raise BaselineError(
            "baseline.manifests must contain tools, resources, resource_templates, and prompts"
        )
    for name in MANIFEST_NAMES:
        _validate_manifest(name, manifests[name])
    return value


def load_baseline(path: str | Path) -> dict[str, Any]:
    baseline_path = Path(path)
    try:
        value = json.loads(baseline_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BaselineError(f"cannot read baseline {baseline_path}: {error}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"invalid JSON baseline {baseline_path}: {error}") from error
    return validate_baseline(value)


def write_baseline(path: str | Path, value: dict[str, Any]) -> None:
    """Atomically write a validated baseline in the destination directory."""

    validate_baseline(value)
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=baseline_path.parent,
            prefix=f".{baseline_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            json.dump(value, temporary, indent=2, sort_keys=True, ensure_ascii=False)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, baseline_path)
    except OSError as error:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise BaselineError(f"cannot write baseline {baseline_path}: {error}") from error


def _manifest_difference(
    expected: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    def grouped(value: dict[str, Any]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = defaultdict(list)
        for item in value["items"]:
            result[item["identity"]].append(item["sha256"])
        return {key: sorted(digests) for key, digests in result.items()}

    before = grouped(expected)
    after = grouped(current)
    return {
        "before_count": expected["count"],
        "after_count": current["count"],
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(
            identity
            for identity in set(before) & set(after)
            if before[identity] != after[identity]
        ),
    }


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    message: str,
    *,
    evidence: dict[str, Any],
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message,
        evidence=evidence,
        remediation=remediation,
    )


def apply_baseline(
    report: CheckReport,
    probe_evidence: ProbeEvidence,
    expected: dict[str, Any],
) -> CheckReport:
    """Append findings for differences from a validated reviewed baseline."""

    validate_baseline(expected)
    current = create_baseline(probe_evidence)
    findings: list[Finding] = []
    if expected["protocol_version"] != current["protocol_version"]:
        findings.append(
            _finding(
                "BASE001",
                "Baseline protocol version changed",
                Severity.HIGH,
                "The negotiated protocol version differs from the reviewed baseline.",
                evidence={
                    "before": expected["protocol_version"],
                    "after": current["protocol_version"],
                },
                remediation="Review protocol compatibility and regenerate the baseline only after approval.",
            )
        )
    if expected["capabilities"] != current["capabilities"]:
        findings.append(
            _finding(
                "BASE002",
                "Capability surface changed",
                Severity.HIGH,
                "The server capability set differs from the reviewed baseline.",
                evidence={
                    "before": expected["capabilities"],
                    "after": current["capabilities"],
                },
                remediation="Review the privilege and compatibility impact before updating the baseline.",
            )
        )

    expected_manifests = expected["manifests"]
    current_manifests = current["manifests"]
    if expected_manifests["tools"] != current_manifests["tools"]:
        findings.append(
            _finding(
                "BASE003",
                "Tool manifest changed",
                Severity.HIGH,
                "Tool identifiers or metadata fingerprints differ from the reviewed baseline.",
                evidence=_manifest_difference(
                    expected_manifests["tools"], current_manifests["tools"]
                ),
                remediation="Review Tool additions, removals, schemas, descriptions, and annotations before updating the baseline.",
            )
        )

    resource_changes: dict[str, Any] = {}
    for name in ("resources", "resource_templates"):
        if expected_manifests[name] != current_manifests[name]:
            resource_changes[name] = _manifest_difference(
                expected_manifests[name], current_manifests[name]
            )
    if resource_changes:
        findings.append(
            _finding(
                "BASE004",
                "Resource manifest changed",
                Severity.MEDIUM,
                "Resource identities or metadata fingerprints differ from the reviewed baseline.",
                evidence=resource_changes,
                remediation="Review Resource exposure without dereferencing content, then update the baseline if approved.",
            )
        )

    if expected_manifests["prompts"] != current_manifests["prompts"]:
        findings.append(
            _finding(
                "BASE005",
                "Prompt manifest changed",
                Severity.MEDIUM,
                "Prompt identifiers or metadata fingerprints differ from the reviewed baseline.",
                evidence=_manifest_difference(
                    expected_manifests["prompts"], current_manifests["prompts"]
                ),
                remediation="Review Prompt arguments and instruction metadata before updating the baseline.",
            )
        )

    report.findings.extend(findings)
    report.findings.sort(
        key=lambda item: (-item.severity.rank, item.rule_id, item.message)
    )
    report.observations["baseline"] = {
        "mode": "check",
        "schema_version": BASELINE_SCHEMA_VERSION,
        "finding_count": len(findings),
    }
    return report
