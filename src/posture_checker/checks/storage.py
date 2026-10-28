"""Storage checks: S3 and EBS (CIS section 2)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Result, Severity
from ..registry import check
from ._util import as_list, error_code, parse_policy

_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _buckets(ctx) -> list[str]:
    return ctx.cached(
        "s3_buckets", lambda: [b["Name"] for b in ctx.client("s3").list_buckets()["Buckets"]]
    )


def _all_blocked(config: dict) -> bool:
    return all(config.get(k) for k in _PAB_KEYS)


@check(
    id="s3-block-public-access",
    cis="2.1.4",
    title="S3 Block Public Access is enabled (account-wide or on every bucket)",
    severity=Severity.HIGH,
    service="s3",
    evidence="s3control:GetPublicAccessBlock, s3:ListAllMyBuckets, s3:GetBucketPublicAccessBlock",
    remediation=(
        "Turn on all four Block Public Access settings at the account level "
        "(S3 > Block Public Access settings for this account), or on each bucket that must stay private."
    ),
)
def block_public_access(ctx):
    try:
        account = ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)
        if _all_blocked(account["PublicAccessBlockConfiguration"]):
            yield Result.ok("account", "All four settings are on at the account level.")
            return
    except ClientError as exc:
        if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise

    s3 = ctx.client("s3")
    for name in _buckets(ctx):
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                raise
            cfg = {}
        missing = [k for k in _PAB_KEYS if not cfg.get(k)]
        if missing:
            yield Result.fail(name, "Not blocked at account or bucket level: " + ", ".join(missing) + ".")
        else:
            yield Result.ok(name, "All four settings are on for the bucket.")


def _denies_insecure_transport(policy: dict) -> bool:
    for stmt in as_list(policy.get("Statement")):
        if stmt.get("Effect") != "Deny":
            continue
        cond = stmt.get("Condition", {}).get("Bool", {})
        if str(cond.get("aws:SecureTransport", "")).lower() == "false":
            return True
    return False


@check(
    id="s3-deny-http",
    cis="2.1.1",
    title="S3 bucket policies deny requests that do not use HTTPS",
    severity=Severity.MEDIUM,
    service="s3",
    evidence="s3:ListAllMyBuckets, s3:GetBucketPolicy",
    remediation=(
        'Add a bucket policy statement with Effect "Deny", Principal "*", Action "s3:*" '
        'and the condition {"Bool": {"aws:SecureTransport": "false"}}.'
    ),
)
def deny_http(ctx):
    s3 = ctx.client("s3")
    for name in _buckets(ctx):
        try:
            policy = parse_policy(s3.get_bucket_policy(Bucket=name)["Policy"])
        except ClientError as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
            yield Result.fail(name, "Bucket has no policy, so plain HTTP requests are allowed.")
            continue
        if _denies_insecure_transport(policy):
            yield Result.ok(name, "Bucket policy denies non-HTTPS requests.")
        else:
            yield Result.fail(name, "Bucket policy does not deny non-HTTPS requests.")


@check(
    id="ebs-default-encryption",
    cis="2.2.1",
    title="EBS encryption by default is enabled",
    severity=Severity.MEDIUM,
    service="ec2",
    regional=True,
    evidence="ec2:GetEbsEncryptionByDefault",
    remediation="EC2 > Settings > EBS encryption: turn on 'Always encrypt new EBS volumes' in each region.",
)
def ebs_default_encryption(ctx, region):
    enabled = ctx.client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    if enabled:
        yield Result.ok("ebs-default", "Encryption by default is on.", region)
    else:
        yield Result.fail("ebs-default", "Encryption by default is off.", region)
