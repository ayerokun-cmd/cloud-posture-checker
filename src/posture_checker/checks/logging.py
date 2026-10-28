"""Logging and monitoring checks: CloudTrail, AWS Config, KMS, VPC flow logs (CIS section 3)."""

from __future__ import annotations

from ..models import Result, Severity
from ..registry import check
from ._util import paginate


def _trails(ctx) -> list[dict]:
    # Shadow trails make multi-region trails created in other regions visible here.
    return ctx.cached(
        "cloudtrail_trails",
        lambda: ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"],
    )


def _unique_trails(ctx) -> list[dict]:
    seen: dict[str, dict] = {}
    for trail in _trails(ctx):
        seen.setdefault(trail["TrailARN"], trail)
    return list(seen.values())


@check(
    id="cloudtrail-multi-region",
    cis="3.1",
    title="A multi-region CloudTrail trail is enabled and logging",
    severity=Severity.HIGH,
    service="cloudtrail",
    evidence="cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
    remediation=(
        "Create a trail with 'Apply trail to all regions' on, recording management events "
        "(read and write), and make sure logging is started."
    ),
)
def cloudtrail_multi_region(ctx):
    for trail in _unique_trails(ctx):
        if not trail.get("IsMultiRegionTrail"):
            continue
        client = ctx.client("cloudtrail", trail.get("HomeRegion"))
        if client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            yield Result.ok(trail["Name"], "Multi-region trail is logging.")
            return
    yield Result.fail("account", "No multi-region trail is logging, so activity in some regions is not recorded.")


@check(
    id="cloudtrail-log-validation",
    cis="3.2",
    title="CloudTrail log file validation is enabled",
    severity=Severity.MEDIUM,
    service="cloudtrail",
    evidence="cloudtrail:DescribeTrails",
    remediation="Edit the trail and turn on 'Log file validation' so tampering with log files can be detected.",
)
def cloudtrail_log_validation(ctx):
    for trail in _unique_trails(ctx):
        if trail.get("LogFileValidationEnabled"):
            yield Result.ok(trail["Name"], "Log file validation is on.")
        else:
            yield Result.fail(trail["Name"], "Log file validation is off.")


@check(
    id="cloudtrail-kms",
    cis="3.5",
    title="CloudTrail logs are encrypted with a KMS key",
    severity=Severity.MEDIUM,
    service="cloudtrail",
    evidence="cloudtrail:DescribeTrails",
    remediation="Edit the trail and set SSE-KMS encryption with a customer-managed KMS key.",
)
def cloudtrail_kms(ctx):
    for trail in _unique_trails(ctx):
        if trail.get("KmsKeyId"):
            yield Result.ok(trail["Name"], "Logs are encrypted with a KMS key.")
        else:
            yield Result.fail(trail["Name"], "Logs use default S3 encryption, not a KMS key.")


@check(
    id="config-enabled",
    cis="3.3",
    title="AWS Config is recording",
    severity=Severity.MEDIUM,
    service="config",
    regional=True,
    evidence="config:DescribeConfigurationRecorderStatus",
    remediation="Set up AWS Config in this region, recording all supported resource types.",
)
def config_enabled(ctx, region):
    statuses = ctx.client("config", region).describe_configuration_recorder_status()[
        "ConfigurationRecordersStatus"
    ]
    if any(s.get("recording") for s in statuses):
        yield Result.ok("config-recorder", "A configuration recorder is recording.", region)
    else:
        yield Result.fail("config-recorder", "No configuration recorder is recording.", region)


@check(
    id="kms-rotation",
    cis="3.6",
    title="Rotation is enabled for customer-managed symmetric KMS keys",
    severity=Severity.MEDIUM,
    service="kms",
    regional=True,
    evidence="kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus",
    remediation="Turn on automatic key rotation for each customer-managed symmetric key.",
)
def kms_rotation(ctx, region):
    kms = ctx.client("kms", region)
    for key in paginate(kms, "list_keys", "Keys"):
        meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
        if (
            meta.get("KeyManager") != "CUSTOMER"
            or meta.get("KeyState") != "Enabled"
            or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
        ):
            continue
        if kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]:
            yield Result.ok(key["KeyId"], "Rotation is on.", region)
        else:
            yield Result.fail(key["KeyId"], "Rotation is off.", region)


@check(
    id="vpc-flow-logs",
    cis="3.7",
    title="VPC flow logging is enabled in every VPC",
    severity=Severity.MEDIUM,
    service="ec2",
    regional=True,
    evidence="ec2:DescribeVpcs, ec2:DescribeFlowLogs",
    remediation="Create a flow log for the VPC (at least REJECT traffic) sent to CloudWatch Logs or S3.",
)
def vpc_flow_logs(ctx, region):
    ec2 = ctx.client("ec2", region)
    logged = {f["ResourceId"] for f in paginate(ec2, "describe_flow_logs", "FlowLogs")}
    for vpc in paginate(ec2, "describe_vpcs", "Vpcs"):
        if vpc["VpcId"] in logged:
            yield Result.ok(vpc["VpcId"], "Flow logs are on.", region)
        else:
            yield Result.fail(vpc["VpcId"], "No flow logs.", region)
