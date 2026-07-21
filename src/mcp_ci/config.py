"""Strict local policy, rule controls, and auditable finding suppressions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
from typing import Any

from .models import CheckReport, Finding, Severity, Suppression
from .probe import ProbeEvidence
from .rules import KNOWN_RULE_IDS


class ConfigError(ValueError):
    """Raised when policy configuration is missing, malformed, or ambiguous."""


@dataclass(frozen=True, slots=True)
class RuleControls:
    disabled: tuple[str, ...] = ()
    severity: tuple[tuple[str, Severity], ...] = ()


@dataclass(frozen=True, slots=True)
class Policy:
    allowed_protocol_versions: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    max_tools: int | None = None
    require_read_only: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Config:
    suppressions: tuple[Suppression, ...] = ()
    rules: RuleControls = RuleControls()
    policy: Policy = Policy()


def _non_empty_string(value: Any, *, field: str, index: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"suppression[{index}].{field} must be a non-empty string")
    return value.strip() if field != "tool" else value


def _parse_suppression(value: Any, index: int) -> Suppression:
    if not isinstance(value, dict):
        raise ConfigError(f"suppression[{index}] must be an object")
    supported = {"rule_id", "tool", "reason", "expires"}
    unknown = sorted(set(value) - supported)
    if unknown:
        raise ConfigError(
            f"suppression[{index}] has unknown fields: {', '.join(unknown)}"
        )

    rule_id = _non_empty_string(value.get("rule_id"), field="rule_id", index=index)
    if rule_id not in KNOWN_RULE_IDS:
        raise ConfigError(f"suppression[{index}] references unknown rule_id {rule_id!r}")
    reason = _non_empty_string(value.get("reason"), field="reason", index=index)

    tool_value = value.get("tool")
    tool = None
    if tool_value is not None:
        tool = _non_empty_string(tool_value, field="tool", index=index)

    expires_value = value.get("expires")
    expires = None
    if expires_value is not None:
        expires_text = _non_empty_string(
            expires_value, field="expires", index=index
        )
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires_text) is None:
            raise ConfigError(
                f"suppression[{index}].expires must be an ISO date (YYYY-MM-DD)"
            )
        try:
            expires = date.fromisoformat(expires_text)
        except ValueError as error:
            raise ConfigError(
                f"suppression[{index}].expires must be an ISO date (YYYY-MM-DD)"
            ) from error

    return Suppression(
        rule_id=rule_id,
        tool=tool,
        reason=reason,
        expires=expires,
    )


def _string_list(value: Any, *, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"config.{field} must be an array")
    parsed: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(
                f"config.{field}[{index}] must be a non-empty string"
            )
        parsed.append(item.strip())
    if len(set(parsed)) != len(parsed):
        raise ConfigError(f"config.{field} must not contain duplicates")
    return tuple(parsed)


def _parse_rule_controls(value: Any) -> RuleControls:
    if value is None:
        return RuleControls()
    if not isinstance(value, dict):
        raise ConfigError("config.rules must be an object")
    unknown = sorted(set(value) - {"disabled", "severity"})
    if unknown:
        raise ConfigError(f"config.rules has unknown fields: {', '.join(unknown)}")
    disabled = _string_list(value.get("disabled"), field="rules.disabled")
    for rule_id in disabled:
        if rule_id not in KNOWN_RULE_IDS:
            raise ConfigError(f"config.rules.disabled references unknown rule_id {rule_id!r}")

    raw_severity = value.get("severity", {})
    if not isinstance(raw_severity, dict):
        raise ConfigError("config.rules.severity must be an object")
    severity: list[tuple[str, Severity]] = []
    for rule_id, raw_value in raw_severity.items():
        if not isinstance(rule_id, str) or rule_id not in KNOWN_RULE_IDS:
            raise ConfigError(
                f"config.rules.severity references unknown rule_id {rule_id!r}"
            )
        if not isinstance(raw_value, str):
            raise ConfigError(
                f"config.rules.severity.{rule_id} must be a severity string"
            )
        try:
            parsed_severity = Severity.parse(raw_value)
        except ValueError as error:
            raise ConfigError(
                f"config.rules.severity.{rule_id}: {error}"
            ) from error
        severity.append((rule_id, parsed_severity))
    severity.sort(key=lambda item: item[0])
    overlap = sorted(set(disabled) & {rule_id for rule_id, _ in severity})
    if overlap:
        raise ConfigError(
            "config.rules cannot disable and override severity for the same rule: "
            + ", ".join(overlap)
        )
    return RuleControls(disabled=disabled, severity=tuple(severity))


def _parse_policy(value: Any) -> Policy:
    if value is None:
        return Policy()
    if not isinstance(value, dict):
        raise ConfigError("config.policy must be an object")
    supported = {
        "allowed_protocol_versions",
        "required_capabilities",
        "required_tools",
        "forbidden_tools",
        "max_tools",
        "require_read_only",
    }
    unknown = sorted(set(value) - supported)
    if unknown:
        raise ConfigError(f"config.policy has unknown fields: {', '.join(unknown)}")
    max_tools = value.get("max_tools")
    if max_tools is not None and (
        isinstance(max_tools, bool) or not isinstance(max_tools, int) or max_tools < 0
    ):
        raise ConfigError("config.policy.max_tools must be a non-negative integer")
    return Policy(
        allowed_protocol_versions=_string_list(
            value.get("allowed_protocol_versions"),
            field="policy.allowed_protocol_versions",
        ),
        required_capabilities=_string_list(
            value.get("required_capabilities"),
            field="policy.required_capabilities",
        ),
        required_tools=_string_list(
            value.get("required_tools"), field="policy.required_tools"
        ),
        forbidden_tools=_string_list(
            value.get("forbidden_tools"), field="policy.forbidden_tools"
        ),
        max_tools=max_tools,
        require_read_only=_string_list(
            value.get("require_read_only"), field="policy.require_read_only"
        ),
    )


def load_config(path: str | Path) -> Config:
    """Read and validate one local JSON configuration file."""

    config_path = Path(path)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfigError(f"cannot read config {config_path}: {error}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigError(f"invalid JSON config {config_path}: {error}") from error

    if not isinstance(payload, dict):
        raise ConfigError("config root must be a JSON object")
    unknown = sorted(set(payload) - {"suppressions", "rules", "policy"})
    if unknown:
        raise ConfigError(f"config has unknown fields: {', '.join(unknown)}")
    raw_suppressions = payload.get("suppressions", [])
    if not isinstance(raw_suppressions, list):
        raise ConfigError("config.suppressions must be an array")

    suppressions = tuple(
        _parse_suppression(value, index)
        for index, value in enumerate(raw_suppressions)
    )
    seen: set[tuple[str, str | None]] = set()
    for suppression in suppressions:
        scope = (suppression.rule_id, suppression.tool)
        if scope in seen:
            scope_text = suppression.tool if suppression.tool is not None else "all tools"
            raise ConfigError(
                f"duplicate suppression scope for {suppression.rule_id} ({scope_text})"
            )
        seen.add(scope)
    return Config(
        suppressions=suppressions,
        rules=_parse_rule_controls(payload.get("rules")),
        policy=_parse_policy(payload.get("policy")),
    )


def _policy_finding(
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


def apply_policy(
    report: CheckReport,
    evidence: ProbeEvidence,
    policy: Policy,
) -> CheckReport:
    """Append deterministic findings for repository-declared invariants."""

    findings: list[Finding] = []
    negotiated = evidence.negotiated_protocol_version
    if (
        policy.allowed_protocol_versions
        and negotiated not in policy.allowed_protocol_versions
    ):
        findings.append(
            _policy_finding(
                "POL001",
                "Negotiated protocol is outside repository policy",
                Severity.HIGH,
                "The server negotiated a protocol version not allowed by this repository.",
                evidence={
                    "negotiated": negotiated,
                    "allowed": list(policy.allowed_protocol_versions),
                },
                remediation="Update the server or explicitly review and add the version to allowed_protocol_versions.",
            )
        )

    declared_capabilities = set(evidence.capabilities)
    for capability in policy.required_capabilities:
        if capability not in declared_capabilities:
            findings.append(
                _policy_finding(
                    "POL002",
                    "Required capability is missing",
                    Severity.HIGH,
                    f"The repository requires the {capability!r} capability.",
                    evidence={"capability": capability},
                    remediation="Declare and implement the required capability, or update the reviewed repository policy.",
                )
            )

    raw_tools = evidence.all_tools
    tools = [tool for tool in raw_tools if isinstance(tool, dict)]
    names = [tool.get("name") for tool in tools if isinstance(tool.get("name"), str)]
    name_set = set(names)
    for name in policy.required_tools:
        if name not in name_set:
            findings.append(
                _policy_finding(
                    "POL003",
                    "Required Tool is missing",
                    Severity.HIGH,
                    f"The repository requires Tool {name!r}.",
                    evidence={"tool": name},
                    remediation="Expose the required Tool with a reviewed contract, or update required_tools.",
                )
            )

    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        forbidden_matches = [
            pattern for pattern in policy.forbidden_tools if fnmatchcase(name, pattern)
        ]
        if forbidden_matches:
            findings.append(
                _policy_finding(
                    "POL004",
                    "Forbidden Tool is exposed",
                    Severity.CRITICAL,
                    f"Tool {name!r} matches a repository deny pattern.",
                    evidence={"tool": name, "patterns": forbidden_matches},
                    remediation="Remove the Tool from this endpoint or narrow its exposure behind an independently authorized boundary.",
                )
            )

    if policy.max_tools is not None and len(raw_tools) > policy.max_tools:
        findings.append(
            _policy_finding(
                "POL005",
                "Tool count exceeds repository policy",
                Severity.HIGH,
                f"The server exposes {len(raw_tools)} Tools; the configured maximum is {policy.max_tools}.",
                evidence={"count": len(raw_tools), "maximum": policy.max_tools},
                remediation="Reduce the endpoint's Tool surface or explicitly review and raise max_tools.",
            )
        )

    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        matched = [
            pattern for pattern in policy.require_read_only if fnmatchcase(name, pattern)
        ]
        annotations = tool.get("annotations")
        read_only = (
            annotations.get("readOnlyHint")
            if isinstance(annotations, dict)
            else None
        )
        if matched and read_only is not True:
            findings.append(
                _policy_finding(
                    "POL006",
                    "Policy-selected Tool is not explicitly read-only",
                    Severity.HIGH,
                    f"Tool {name!r} must declare readOnlyHint=true under repository policy.",
                    evidence={"tool": name, "patterns": matched},
                    remediation="Set an accurate readOnlyHint=true only for genuinely read-only behavior and enforce authorization independently.",
                )
            )

    report.findings.extend(findings)
    report.findings.sort(
        key=lambda item: (-item.severity.rank, item.rule_id, item.message)
    )
    configured = any(
        (
            policy.allowed_protocol_versions,
            policy.required_capabilities,
            policy.required_tools,
            policy.forbidden_tools,
            policy.max_tools is not None,
            policy.require_read_only,
        )
    )
    report.observations["policy"] = {
        "configured": configured,
        "finding_count": len(findings),
    }
    return report


def apply_rule_controls(
    report: CheckReport,
    controls: RuleControls,
) -> CheckReport:
    """Apply explicit rule selection and severity overrides with an audit trail."""

    disabled = set(controls.disabled)
    severity = dict(controls.severity)
    disabled_count = sum(item.rule_id in disabled for item in report.findings)
    severity_count = 0
    updated: list[Finding] = []
    for finding in report.findings:
        if finding.rule_id in disabled:
            continue
        override = severity.get(finding.rule_id)
        if override is not None and override is not finding.severity:
            finding = replace(finding, severity=override)
            severity_count += 1
        updated.append(finding)
    updated.sort(key=lambda item: (-item.severity.rank, item.rule_id, item.message))
    report.findings = updated
    report.observations["rule_controls"] = {
        "disabled_rules": list(controls.disabled),
        "disabled_findings": disabled_count,
        "severity_rules": [rule_id for rule_id, _ in controls.severity],
        "severity_overrides": severity_count,
    }
    return report


def apply_suppressions(
    report: CheckReport,
    config: Config,
    *,
    today: date | None = None,
) -> CheckReport:
    """Attach matching risk acceptance while retaining every original finding."""

    current_date = today or date.today()
    valid = [
        suppression
        for suppression in config.suppressions
        if not suppression.is_expired(current_date)
    ]
    updated = []
    applied = 0
    for finding in report.findings:
        evidence_tool = finding.evidence.get("tool")
        scoped = next(
            (
                suppression
                for suppression in valid
                if suppression.rule_id == finding.rule_id
                and suppression.tool is not None
                and suppression.tool == evidence_tool
            ),
            None,
        )
        global_suppression = next(
            (
                suppression
                for suppression in valid
                if suppression.rule_id == finding.rule_id
                and suppression.tool is None
            ),
            None,
        )
        matched = scoped or global_suppression
        if matched is not None:
            applied += 1
        updated.append(replace(finding, suppression=matched))

    report.findings = updated
    report.observations["suppressions"] = {
        "declared": len(config.suppressions),
        "applied": applied,
        "expired": sum(
            suppression.is_expired(current_date)
            for suppression in config.suppressions
        ),
    }
    return report
