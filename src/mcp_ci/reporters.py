"""Human and machine-readable report rendering."""

from __future__ import annotations

import json
from xml.etree import ElementTree

from . import __version__
from .models import CheckReport, Severity


def _threshold_text(threshold: Severity | None) -> str:
    return threshold.value if threshold else "none"


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def render_json(
    report: CheckReport,
    *,
    threshold: Severity | None,
    failed: bool,
) -> str:
    payload = report.to_dict()
    payload["ci"] = {
        "status": "fail" if failed else "pass",
        "fail_on": _threshold_text(threshold),
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def render_text(
    report: CheckReport,
    *,
    threshold: Severity | None,
    failed: bool,
) -> str:
    counts = report.severity_counts()
    status = "FAIL" if failed else "PASS"
    threshold_text = _threshold_text(threshold)
    lines = [
        "MCP CI",
        f"target: {report.target}",
        (
            "protocol: "
            f"requested={report.requested_protocol_version or 'unknown'} "
            f"negotiated={report.negotiated_protocol_version or 'unknown'}"
        ),
        f"result: {status} (fail-on={threshold_text})",
        "tools executed: no",
        "resources read: no",
        "prompts resolved: no",
        (
            "summary: "
            f"critical={counts['critical']} high={counts['high']} "
            f"medium={counts['medium']} low={counts['low']} info={counts['info']} "
            f"suppressed={len(report.suppressed_findings)} total={len(report.findings)}"
        ),
    ]
    if not report.findings:
        lines.append("findings: none")
        return "\n".join(lines)

    lines.append("findings:")
    for finding in report.findings:
        status = " SUPPRESSED" if finding.is_suppressed else ""
        lines.append(
            f"  [{finding.severity.value.upper():8}] {finding.rule_id}{status} {finding.title}"
        )
        lines.append(f"    {finding.message}")
        if finding.evidence:
            evidence = json.dumps(finding.evidence, sort_keys=True, ensure_ascii=False)
            lines.append(f"    evidence: {evidence}")
        if finding.remediation:
            lines.append(f"    remediation: {finding.remediation}")
        if finding.suppression is not None:
            suppression = finding.suppression
            scope = suppression.tool or "all findings for this rule"
            expires = suppression.expires.isoformat() if suppression.expires else "never"
            lines.append(
                f"    suppression: {suppression.reason} (scope={scope}, expires={expires})"
            )
    return "\n".join(lines)


def render_junit(
    report: CheckReport,
    *,
    threshold: Severity | None,
    failed: bool,
) -> str:
    """Render finding-oriented JUnit XML for common CI test viewers."""

    suite = ElementTree.Element(
        "testsuite",
        {
            "name": "mcp-ci",
            "tests": str(len(report.findings)),
            "failures": str(len(report.active_findings)),
            "errors": "0",
            "skipped": str(len(report.suppressed_findings)),
            "time": "0",
        },
    )
    properties = ElementTree.SubElement(suite, "properties")
    property_values = {
        "target": report.target,
        "requested_protocol_version": report.requested_protocol_version or "unknown",
        "negotiated_protocol_version": report.negotiated_protocol_version or "unknown",
        "ci_status": "fail" if failed else "pass",
        "fail_on": _threshold_text(threshold),
        "tools_were_executed": str(
            report.observations.get("tools_were_executed", False)
        ).lower(),
        "resources_were_read": str(
            report.observations.get("resources_were_read", False)
        ).lower(),
        "prompts_were_resolved": str(
            report.observations.get("prompts_were_resolved", False)
        ).lower(),
    }
    for name, value in property_values.items():
        ElementTree.SubElement(
            properties,
            "property",
            {"name": name, "value": value},
        )

    for finding in report.findings:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": f"mcp-ci.{finding.rule_id}",
                "name": finding.rule_id,
                "time": "0",
            },
        )
        detail = [finding.message]
        if finding.evidence:
            detail.append(
                "evidence: "
                + json.dumps(finding.evidence, sort_keys=True, ensure_ascii=False)
            )
        if finding.remediation:
            detail.append(f"remediation: {finding.remediation}")
        if finding.suppression is not None:
            skipped = ElementTree.SubElement(
                case,
                "skipped",
                {"message": finding.suppression.reason},
            )
            skipped.text = "\n".join(detail)
        else:
            failure = ElementTree.SubElement(
                case,
                "failure",
                {
                    "message": finding.title,
                    "type": finding.severity.value,
                },
            )
            failure.text = "\n".join(detail)

    ElementTree.indent(suite, space="  ")
    return ElementTree.tostring(
        suite,
        encoding="unicode",
        xml_declaration=True,
    )


def render_sarif(
    report: CheckReport,
    *,
    threshold: Severity | None,
    failed: bool,
) -> str:
    """Render SARIF 2.1.0 without inventing source locations for black-box evidence."""

    first_by_rule = {}
    for finding in report.findings:
        first_by_rule.setdefault(finding.rule_id, finding)

    rules = []
    for rule_id in sorted(first_by_rule):
        finding = first_by_rule[rule_id]
        descriptor = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.title},
            "defaultConfiguration": {"level": _sarif_level(finding.severity)},
            "properties": {
                "severity": finding.severity.value,
                "tags": ["mcp", "protocol-conformance", "security-review"],
            },
        }
        if finding.remediation:
            descriptor["help"] = {"text": finding.remediation}
        rules.append(descriptor)

    results = []
    for finding in report.findings:
        result = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.title}: {finding.message}"},
            "properties": {
                "severity": finding.severity.value,
                "status": finding.status,
                "target": report.target,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            },
        }
        if finding.suppression is not None:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": finding.suppression.reason,
                }
            ]
            result["properties"]["suppression"] = finding.suppression.to_dict()
        results.append(result)

    payload = {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-ci",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "exitCode": 1 if failed else 0,
                        "properties": {
                            "target": report.target,
                            "failOn": _threshold_text(threshold),
                            "requestedProtocolVersion": report.requested_protocol_version,
                            "negotiatedProtocolVersion": report.negotiated_protocol_version,
                            "toolsWereExecuted": report.observations.get(
                                "tools_were_executed", False
                            ),
                            "resourcesWereRead": report.observations.get(
                                "resources_were_read", False
                            ),
                            "promptsWereResolved": report.observations.get(
                                "prompts_were_resolved", False
                            ),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
