import os

import boto3
import pytest
from moto import mock_aws

from posture_checker.context import Context
from posture_checker.registry import _run_one

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    """Fake credentials so nothing can ever reach a real AWS account."""
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def ctx(aws):
    return Context(aws, regions=[REGION])


@pytest.fixture
def run(ctx):
    """Run one check function and return its findings."""

    def _run(fn):
        region = REGION if fn.meta.regional else None
        return _run_one(ctx, fn.meta, fn, region)

    return _run


def statuses(findings):
    return {f.resource: f.status.value for f in findings}
