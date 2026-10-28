import json

from conftest import statuses
from posture_checker.checks import iam

ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


def test_root_checks_on_fresh_account(run):
    assert statuses(run(iam.root_access_keys)) == {"root": "pass"}
    assert statuses(run(iam.root_mfa)) == {"root": "fail"}


def test_password_policy_missing_then_compliant(aws, run, ctx):
    assert statuses(run(iam.password_length)) == {"password-policy": "fail"}

    aws.client("iam").update_account_password_policy(
        MinimumPasswordLength=14, PasswordReusePrevention=24
    )
    ctx._cache.clear()
    assert statuses(run(iam.password_length)) == {"password-policy": "pass"}
    assert statuses(run(iam.password_reuse)) == {"password-policy": "pass"}


def test_console_user_without_mfa_fails(aws, run):
    client = aws.client("iam")
    client.create_user(UserName="alice")
    client.create_login_profile(UserName="alice", Password="Long-enough-pass-1!")
    client.create_user(UserName="ci-bot")  # no console password: out of scope

    assert statuses(run(iam.user_mfa)) == {"alice": "fail"}


def test_no_users_means_no_resources_in_scope(run):
    findings = run(iam.user_mfa)
    assert [(f.status.value, f.detail) for f in findings] == [("pass", "No resources in scope.")]


def test_two_active_keys_fail(aws, run):
    client = aws.client("iam")
    client.create_user(UserName="bob")
    client.create_access_key(UserName="bob")
    client.create_access_key(UserName="bob")

    assert statuses(run(iam.one_active_key)) == {"bob": "fail"}


def test_direct_user_policy_fails(aws, run):
    client = aws.client("iam")
    client.create_user(UserName="carol")
    client.put_user_policy(UserName="carol", PolicyName="inline", PolicyDocument=json.dumps(READ))

    assert statuses(run(iam.user_direct_policies)) == {"carol": "fail"}


def test_full_admin_policy_detected_only_when_attached(aws, run):
    client = aws.client("iam")
    client.create_group(GroupName="admins")
    admin = client.create_policy(PolicyName="god-mode", PolicyDocument=json.dumps(ADMIN))
    read = client.create_policy(PolicyName="read-only", PolicyDocument=json.dumps(READ))
    client.create_policy(PolicyName="unused-admin", PolicyDocument=json.dumps(ADMIN))
    client.attach_group_policy(GroupName="admins", PolicyArn=admin["Policy"]["Arn"])
    client.attach_group_policy(GroupName="admins", PolicyArn=read["Policy"]["Arn"])

    assert statuses(run(iam.full_admin_policies)) == {"god-mode": "fail", "read-only": "pass"}
