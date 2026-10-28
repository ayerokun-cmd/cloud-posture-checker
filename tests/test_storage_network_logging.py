import json

from conftest import REGION, statuses
from posture_checker.checks import logging, network, storage


def test_bucket_without_public_access_block_fails(aws, run):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="open-bucket")
    s3.create_bucket(Bucket="locked-bucket")
    s3.put_public_access_block(
        Bucket="locked-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert statuses(run(storage.block_public_access)) == {
        "open-bucket": "fail",
        "locked-bucket": "pass",
    }


def test_bucket_policy_must_deny_http(aws, run):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="no-policy")
    s3.create_bucket(Bucket="tls-only")
    s3.put_bucket_policy(
        Bucket="tls-only",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": ["arn:aws:s3:::tls-only", "arn:aws:s3:::tls-only/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ],
            }
        ),
    )
    assert statuses(run(storage.deny_http)) == {"no-policy": "fail", "tls-only": "pass"}


def test_ebs_default_encryption(aws, run):
    assert statuses(run(storage.ebs_default_encryption)) == {"ebs-default": "fail"}
    aws.client("ec2").enable_ebs_encryption_by_default()
    assert statuses(run(storage.ebs_default_encryption)) == {"ebs-default": "pass"}


def test_ssh_open_to_world_fails(aws, run):
    ec2 = aws.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="bastion", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )
    web = ec2.create_security_group(GroupName="web", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=web,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )
    results = statuses(run(network.sg_admin_ports_ipv4))
    assert results[f"{sg} (bastion)"] == "fail"
    assert results[f"{web} (web)"] == "pass"


def test_vpc_without_flow_logs_fails(aws, run):
    findings = run(logging.vpc_flow_logs)
    assert findings and all(f.status.value == "fail" for f in findings)


def test_cloudtrail_missing_then_logging(aws, run, ctx):
    assert statuses(run(logging.cloudtrail_multi_region)) == {"account": "fail"}

    aws.client("s3").create_bucket(Bucket="trail-logs")
    ct = aws.client("cloudtrail")
    ct.create_trail(
        Name="org-trail", S3BucketName="trail-logs", IsMultiRegionTrail=True, EnableLogFileValidation=True
    )
    ct.start_logging(Name="org-trail")
    ctx._cache.clear()

    assert statuses(run(logging.cloudtrail_multi_region)) == {"org-trail": "pass"}
    assert statuses(run(logging.cloudtrail_log_validation)) == {"org-trail": "pass"}
    assert statuses(run(logging.cloudtrail_kms)) == {"org-trail": "fail"}


def test_kms_rotation(aws, run):
    kms = aws.client("kms", region_name=REGION)
    key = kms.create_key()["KeyMetadata"]["KeyId"]
    assert statuses(run(logging.kms_rotation)) == {key: "fail"}
    kms.enable_key_rotation(KeyId=key)
    assert statuses(run(logging.kms_rotation)) == {key: "pass"}
