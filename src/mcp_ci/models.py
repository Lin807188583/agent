"""Stable report types shared by the probe, rules, CLI, and CI output."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity with an explicit, reviewable ordering."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError as error:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"unknown severity {value!r}; choose one of: {choices}") from error


@dataclass(frozen=True, slots=True)
class Suppression:
    """One explicit, reviewable acceptance of a rule finding."""

    rule_id: str
    reason: str
    tool: str | None = None
    expires: date | None = None

    def is_expired(self, current_date: date) -> bool:
        """An expiration date is inclusive, like most risk-acceptance records."""

        return self.expires is not None and self.expires < current_date

    def to_dict(self) -> dict[str, str]:
        serialized = {
            "rule_id": self.rule_id,
            "reason": self.reason,
        }
        if self.tool is not None:
            serialized["tool"] = self.tool
        if self.expires is not None:
            serialized["expires"] = self.expires.isoformat()
        return serialized


@dataclass(frozen=True, slots=True)
class Finding:
    """One deterministic rule result."""

    rule_id: str
    title: str
    severity: Severity
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    suppression: Suppression | None = None

    @property
    def is_suppressed(self) -> bool:
        return self.suppression is not None

    @property
    def status(self) -> str:
        return "suppressed" if self.is_suppressed else "active"

    def to_dict(self) -> dict[str, Any]:
        serialized = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
        if self.suppression is not None:
            serialized["suppression"] = self.suppression.to_dict()
        return serialized


@dataclass(slots=True)
class CheckReport:
    """Serializable result returned by the checker."""

    target: str
    requested_protocol_version: str | None = None
    negotiated_protocol_version: str | None = None
    server_info: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)

    @property
    def active_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if not finding.is_suppressed]

    @property
    def suppressed_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.is_suppressed]

    def should_fail(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(
            finding.severity.rank >= threshold.rank
            for finding in self.active_findings
        )

    def severity_counts(self, *, include_suppressed: bool = False) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        findings = self.findings if include_suppressed else self.active_findings
        for finding in findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        counts = self.severity_counts()
        return {
            "target": self.target,
            "requested_protocol_version": self.requested_protocol_version,
            "negotiated_protocol_version": self.negotiated_protocol_version,
            "server_info": self.server_info,
            "summary": {
                "total": len(self.findings),
                "active": len(self.active_findings),
                "suppressed": len(self.suppressed_findings),
                **counts,
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "observations": self.observations,
        }
