"""Threat detection checks: Security Hub (CIS 4.16) and GuardDuty (AWS best practice)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Result, Severity
from ..registry import check
from ._util import error_code


@check(
    id="securityhub-enabled",
    cis="4.16",
    title="AWS Security Hub is enabled",
    severity=Severity.MEDIUM,
    service="securityhub",
    regional=True,
    evidence="securityhub:DescribeHub",
    remediation="Enable Security Hub in this region (ideally organization-wide from a delegated admin account).",
)
def securityhub_enabled(ctx, region):
    try:
        ctx.client("securityhub", region).describe_hub()
    except ClientError as exc:
        if error_code(exc) in ("InvalidAccessException", "ResourceNotFoundException"):
            yield Result.fail("securityhub", "Security Hub is not enabled.", region)
            return
        raise
    yield Result.ok("securityhub", "Security Hub is enabled.", region)


@check(
    id="guardduty-enabled",
    title="Amazon GuardDuty is enabled",
    severity=Severity.MEDIUM,
    service="guardduty",
    regional=True,
    evidence="guardduty:ListDetectors, guardduty:GetDetector",
    remediation="Enable GuardDuty in this region (ideally organization-wide from a delegated admin account).",
)
def guardduty_enabled(ctx, region):
    gd = ctx.client("guardduty", region)
    for detector_id in gd.list_detectors()["DetectorIds"]:
        if gd.get_detector(DetectorId=detector_id).get("Status") == "ENABLED":
            yield Result.ok(detector_id, "GuardDuty detector is enabled.", region)
            return
    yield Result.fail("guardduty", "No enabled GuardDuty detector.", region)
