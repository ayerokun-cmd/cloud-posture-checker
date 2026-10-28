"""Identity and Access Management checks (CIS section 1)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Result, Severity
from ..registry import check
from ._util import as_list, days_since, error_code, paginate, parse_policy

UNUSED_DAYS = 45
ROTATION_DAYS = 90


def _summary(ctx) -> dict:
    return ctx.cached(
        "iam_summary", lambda: ctx.client("iam").get_account_summary()["SummaryMap"]
    )


def _password_policy(ctx) -> dict | None:
    def load():
        try:
            return ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchEntity":
                return None
            raise

    return ctx.cached("iam_password_policy", load)


def _users(ctx) -> list[dict]:
    return ctx.cached("iam_users", lambda: paginate(ctx.client("iam"), "list_users", "Users"))


def _has_console_password(ctx, user: str) -> bool:
    try:
        ctx.client("iam").get_login_profile(UserName=user)
        return True
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            return False
        raise


def _active_keys(ctx, user: str) -> list[dict]:
    keys = ctx.client("iam").list_access_keys(UserName=user)["AccessKeyMetadata"]
    return [k for k in keys if k["Status"] == "Active"]


@check(
    id="iam-root-access-keys",
    cis="1.4",
    title="No access keys exist for the root user",
    severity=Severity.CRITICAL,
    service="iam",
    evidence="iam:GetAccountSummary",
    remediation=(
        "Sign in as the root user, open Security credentials and delete every root access key. "
        "Use IAM roles or IAM Identity Center for programmatic access."
    ),
)
def root_access_keys(ctx):
    if _summary(ctx).get("AccountAccessKeysPresent", 0):
        yield Result.fail("root", "The root user has at least one access key.")
    else:
        yield Result.ok("root", "The root user has no access keys.")


@check(
    id="iam-root-mfa",
    cis="1.5",
    title="MFA is enabled for the root user",
    severity=Severity.CRITICAL,
    service="iam",
    evidence="iam:GetAccountSummary",
    remediation=(
        "Sign in as the root user, open Security credentials and assign an MFA device "
        "(a hardware key is preferred, per CIS 1.6)."
    ),
)
def root_mfa(ctx):
    if _summary(ctx).get("AccountMFAEnabled", 0):
        yield Result.ok("root", "Root MFA is enabled.")
    else:
        yield Result.fail("root", "Root MFA is not enabled.")


@check(
    id="iam-password-length",
    cis="1.8",
    title="IAM password policy requires at least 14 characters",
    severity=Severity.MEDIUM,
    service="iam",
    evidence="iam:GetAccountPasswordPolicy",
    remediation="IAM > Account settings > Password policy: set minimum length to 14 or more.",
)
def password_length(ctx):
    policy = _password_policy(ctx)
    if policy is None:
        yield Result.fail("password-policy", "No account password policy is set.")
        return
    length = policy.get("MinimumPasswordLength", 0)
    if length >= 14:
        yield Result.ok("password-policy", f"Minimum length is {length}.")
    else:
        yield Result.fail("password-policy", f"Minimum length is {length} (required: 14).")


@check(
    id="iam-password-reuse",
    cis="1.9",
    title="IAM password policy prevents password reuse",
    severity=Severity.LOW,
    service="iam",
    evidence="iam:GetAccountPasswordPolicy",
    remediation="IAM > Account settings > Password policy: prevent reuse of the last 24 passwords.",
)
def password_reuse(ctx):
    policy = _password_policy(ctx)
    if policy is None:
        yield Result.fail("password-policy", "No account password policy is set.")
        return
    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse >= 24:
        yield Result.ok("password-policy", f"Reuse prevention covers {reuse} passwords.")
    else:
        yield Result.fail("password-policy", f"Reuse prevention covers {reuse} passwords (required: 24).")


@check(
    id="iam-user-mfa",
    cis="1.10",
    title="MFA is enabled for every IAM user with a console password",
    severity=Severity.HIGH,
    service="iam",
    evidence="iam:ListUsers, iam:GetLoginProfile, iam:ListMFADevices",
    remediation="Assign an MFA device to each console user, or move human access to IAM Identity Center.",
)
def user_mfa(ctx):
    iam = ctx.client("iam")
    for user in _users(ctx):
        name = user["UserName"]
        if not _has_console_password(ctx, name):
            continue
        if iam.list_mfa_devices(UserName=name)["MFADevices"]:
            yield Result.ok(name, "Console user has MFA.")
        else:
            yield Result.fail(name, "Console user has no MFA device.")


@check(
    id="iam-unused-credentials",
    cis="1.12",
    title=f"Credentials unused for {UNUSED_DAYS} days or more are disabled",
    severity=Severity.MEDIUM,
    service="iam",
    evidence="iam:ListUsers, iam:GetLoginProfile, iam:ListAccessKeys, iam:GetAccessKeyLastUsed",
    remediation="Remove console passwords and deactivate access keys that have not been used in 45 days.",
)
def unused_credentials(ctx):
    iam = ctx.client("iam")
    for user in _users(ctx):
        name = user["UserName"]
        stale: list[str] = []
        if _has_console_password(ctx, name):
            age = days_since(user.get("PasswordLastUsed") or user["CreateDate"])
            if age is not None and age >= UNUSED_DAYS:
                stale.append(f"console password unused for {age} days")
        for key in _active_keys(ctx, name):
            used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            last = used["AccessKeyLastUsed"].get("LastUsedDate") or key["CreateDate"]
            age = days_since(last)
            if age is not None and age >= UNUSED_DAYS:
                stale.append(f"access key {key['AccessKeyId']} unused for {age} days")
        if stale:
            yield Result.fail(name, "; ".join(stale).capitalize() + ".")
        else:
            yield Result.ok(name, "No stale credentials.")


@check(
    id="iam-one-active-key",
    cis="1.13",
    title="Each IAM user has at most one active access key",
    severity=Severity.LOW,
    service="iam",
    evidence="iam:ListUsers, iam:ListAccessKeys",
    remediation="Deactivate and delete extra access keys so each user has one at most.",
)
def one_active_key(ctx):
    for user in _users(ctx):
        count = len(_active_keys(ctx, user["UserName"]))
        if count > 1:
            yield Result.fail(user["UserName"], f"{count} active access keys.")
        else:
            yield Result.ok(user["UserName"], f"{count} active access key(s).")


@check(
    id="iam-key-rotation",
    cis="1.14",
    title=f"Active access keys are rotated every {ROTATION_DAYS} days or less",
    severity=Severity.MEDIUM,
    service="iam",
    evidence="iam:ListUsers, iam:ListAccessKeys",
    remediation="Create a new key, move workloads to it, then deactivate and delete the old key.",
)
def key_rotation(ctx):
    for user in _users(ctx):
        for key in _active_keys(ctx, user["UserName"]):
            age = days_since(key["CreateDate"]) or 0
            resource = f"{user['UserName']}/{key['AccessKeyId']}"
            if age > ROTATION_DAYS:
                yield Result.fail(resource, f"Key is {age} days old.")
            else:
                yield Result.ok(resource, f"Key is {age} days old.")


@check(
    id="iam-user-direct-policies",
    cis="1.15",
    title="IAM users get permissions only through groups",
    severity=Severity.LOW,
    service="iam",
    evidence="iam:ListUsers, iam:ListAttachedUserPolicies, iam:ListUserPolicies",
    remediation="Move policies attached directly to users onto groups (or roles), then detach them from the user.",
)
def user_direct_policies(ctx):
    iam = ctx.client("iam")
    for user in _users(ctx):
        name = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        inline = iam.list_user_policies(UserName=name)["PolicyNames"]
        if attached or inline:
            yield Result.fail(
                name, f"{len(attached)} attached and {len(inline)} inline policies on the user."
            )
        else:
            yield Result.ok(name, "No policies attached directly to the user.")


def _grants_full_admin(document: dict) -> bool:
    for stmt in as_list(document.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        if "*" in as_list(stmt.get("Action")) and "*" in as_list(stmt.get("Resource")):
            return True
    return False


@check(
    id="iam-full-admin-policies",
    cis="1.16",
    title='No attached customer-managed policy allows "*:*" administrative access',
    severity=Severity.HIGH,
    service="iam",
    evidence="iam:ListPolicies, iam:GetPolicyVersion",
    remediation="Replace the policy with least-privilege permissions scoped to the actions and resources needed.",
)
def full_admin_policies(ctx):
    iam = ctx.client("iam")
    policies = paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True)
    for policy in policies:
        version = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )
        doc = parse_policy(version["PolicyVersion"]["Document"])
        if _grants_full_admin(doc):
            yield Result.fail(policy["PolicyName"], 'Allows Action "*" on Resource "*".')
        else:
            yield Result.ok(policy["PolicyName"], "No full administrative statement.")
