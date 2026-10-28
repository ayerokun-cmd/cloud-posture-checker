import json

from botocore.exceptions import ClientError

from conftest import REGION
from posture_checker.cli import main
from posture_checker.models import Severity, Status
from posture_checker.registry import _run_one, check
from posture_checker.report import Report


def _denied(ctx):
    raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetThing")
    yield  # pragma: no cover


def test_access_denied_becomes_coverage_gap_not_pass(ctx):
    fn = check(
        id="test-denied",
        title="Denied check",
        severity=Severity.HIGH,
        service="test",
        remediation="-",
        evidence="test:GetThing",
    )(_denied)
    from posture_checker.registry import REGISTRY

    REGISTRY.remove((fn.meta, fn))  # keep the global registry clean

    [finding] = _run_one(ctx, fn.meta, fn, None)
    assert finding.status is Status.ERROR
    assert "access denied" in finding.detail.lower()


def test_full_scan_writes_reports(aws, tmp_path, capsys):
    aws.client("iam").create_user(UserName="dave")
    code = main(["--regions", REGION, "--output-dir", str(tmp_path), "--fail-on", "critical"])

    # A fresh account has no root MFA, which is critical.
    assert code == 2
    md = next(tmp_path.glob("*.md")).read_text(encoding="utf-8")
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))

    assert "# AWS Security Posture Report" in md
    assert "## Top risks" in md
    assert "CIS 1.5" in md
    assert data["account_id"] == "123456789012"
    assert data["summary"]["failed_by_severity"]["critical"] >= 1
    assert {c["check_id"] for c in data["controls"]} >= {"iam-root-mfa", "s3-block-public-access"}
    assert "Posture score" in capsys.readouterr().out


def test_score_ignores_errors(ctx):
    from posture_checker.checks import iam
    from posture_checker.models import Finding

    findings = [
        Finding(iam.root_mfa.meta, Status.FAIL, "root", "x"),
        Finding(iam.root_access_keys.meta, Status.PASS, "root", "x"),
        Finding(iam.password_length.meta, Status.ERROR, "-", "x"),
    ]
    report = Report.build(findings, "111111111111", [REGION])
    assert report.score == 50.0


def test_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    out = capsys.readouterr().out
    assert "iam-root-mfa" in out and "sg-admin-ports-ipv4" in out
