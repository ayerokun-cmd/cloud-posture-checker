"""Command-line entry point: posture-check."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .context import Context
from .models import Severity, Status
from .registry import all_checks, run_checks
from .report import Report

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 2, 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="posture-check",
        description="Read-only audit of an AWS account against the CIS AWS Foundations Benchmark.",
    )
    p.add_argument("--profile", help="AWS CLI profile to use (default: standard credential chain).")
    p.add_argument("--region", help="Home region for global API calls (default: profile region or us-east-1).")
    p.add_argument("--regions", help="Comma-separated regions to scan (default: all enabled regions).")
    p.add_argument("--checks", help="Comma-separated check IDs to run (default: all). See --list-checks.")
    p.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="low",
        help="Only run checks at or above this severity.",
    )
    p.add_argument(
        "--format", choices=["md", "json", "both"], default="both", help="Report format(s) to write."
    )
    p.add_argument("--output-dir", default="reports", help="Where to write reports (default: ./reports).")
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit with code 2 if any control at or above this severity fails (for CI pipelines).",
    )
    p.add_argument("--workers", type=int, default=8, help="Parallel API workers (default: 8).")
    p.add_argument("--list-checks", action="store_true", help="List available checks and exit.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _select_checks(args):
    checks = all_checks()
    floor = Severity(args.min_severity).rank
    checks = [(m, fn) for m, fn in checks if m.severity.rank >= floor]
    if args.checks:
        wanted = {c.strip() for c in args.checks.split(",") if c.strip()}
        unknown = wanted - {m.id for m, _ in all_checks()}
        if unknown:
            raise SystemExit(f"Unknown check id(s): {', '.join(sorted(unknown))}. Use --list-checks.")
        checks = [(m, fn) for m, fn in checks if m.id in wanted]
    return checks


def _list_checks() -> None:
    for meta, _ in sorted(all_checks(), key=lambda c: c[0].id):
        cis = f"CIS {meta.cis}" if meta.cis else "best practice"
        scope = "regional" if meta.regional else "global"
        print(f"{meta.id:28} {meta.severity.value:9} {cis:14} {scope:9} {meta.title}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        _list_checks()
        return EXIT_OK

    checks = _select_checks(args)
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
    ctx = Context(session, regions)

    try:
        account_id = ctx.account_id
        scan_regions = ctx.regions
    except (ClientError, BotoCoreError) as exc:
        print(f"error: could not reach AWS with these credentials: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Scanning account {account_id}: {len(checks)} checks across {len(scan_regions)} region(s)...")
    findings = run_checks(ctx, checks, workers=args.workers)
    report = Report.build(findings, account_id, scan_regions)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    written = []
    if args.format in ("md", "both"):
        path = out_dir / f"posture-{account_id}-{stamp}.md"
        path.write_text(report.to_markdown(), encoding="utf-8")
        written.append(path)
    if args.format in ("json", "both"):
        path = out_dir / f"posture-{account_id}-{stamp}.json"
        path.write_text(report.to_json(), encoding="utf-8")
        written.append(path)

    score = "n/a" if report.score is None else f"{report.score}%"
    print(
        f"Posture score {score}: {len(report.by_status(Status.PASS))} passed, "
        f"{len(report.by_status(Status.FAIL))} failed, "
        f"{len(report.by_status(Status.ERROR))} could not be evaluated."
    )
    for c in report.by_status(Status.FAIL):
        print(f"  [{c.check.severity.value.upper():8}] {c.check.id}: {len(c.failed)} resource(s)")
    for path in written:
        print(f"Report written: {path}")

    if args.fail_on and report.failed_at_or_above(Severity(args.fail_on)):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
