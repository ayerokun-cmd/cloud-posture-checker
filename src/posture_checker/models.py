"""Core data types: severities, check metadata and findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Higher number = more severe."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # the check could not be evaluated (e.g. access denied)


@dataclass(frozen=True)
class CheckMeta:
    """Static description of a control check."""

    id: str
    title: str
    severity: Severity
    service: str
    remediation: str
    evidence: str  # the read-only API calls the check relies on
    cis: str | None = None  # CIS AWS Foundations v3.0.0 control number
    regional: bool = False


@dataclass(frozen=True)
class Result:
    """What a check function yields for one resource."""

    status: Status
    resource: str
    detail: str
    region: str = "global"

    @classmethod
    def ok(cls, resource: str, detail: str, region: str = "global") -> "Result":
        return cls(Status.PASS, resource, detail, region)

    @classmethod
    def fail(cls, resource: str, detail: str, region: str = "global") -> "Result":
        return cls(Status.FAIL, resource, detail, region)


@dataclass(frozen=True)
class Finding:
    """A result tied to the check that produced it."""

    check: CheckMeta
    status: Status
    resource: str
    detail: str
    region: str = "global"

    def to_dict(self) -> dict:
        return {
            "check_id": self.check.id,
            "cis": self.check.cis,
            "title": self.check.title,
            "service": self.check.service,
            "severity": self.check.severity.value,
            "status": self.status.value,
            "resource": self.resource,
            "region": self.region,
            "detail": self.detail,
            "remediation": self.check.remediation,
            "evidence": self.check.evidence,
        }
