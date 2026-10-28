"""Turn findings into an assessor-style report (JSON and Markdown)."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .models import CheckMeta, Finding, Severity, Status

BENCHMARK = "CIS Amazon Web Services Foundations Benchmark v3.0.0 (automated subset)"
_SEVERITIES = sorted(Severity, key=lambda s: -s.rank)


@dataclass
class ControlResult:
    """All findings for one check, rolled up into a single control status."""

    check: CheckMeta
    findings: list[Finding] = field(default_factory=list)

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.FAIL]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.status is Status.ERROR]

    @property
    def status(self) -> Status:
        if self.failed:
            return Status.FAIL
        if self.errors:
            return Status.ERROR
        return Status.PASS


@dataclass
class Report:
    account_id: str
    regions: list[str]
    controls: list[ControlResult]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def build(cls, findings: list[Finding], account_id: str, regions: list[str]) -> "Report":
        grouped: dict[str, ControlResult] = {}
        for f in findings:
            grouped.setdefault(f.check.id, ControlResult(f.check)).findings.append(f)
        controls = sorted(
            grouped.values(), key=lambda c: (-c.check.severity.rank, _cis_key(c.check.cis), c.check.id)
        )
        return cls(account_id, regions, controls)

    def by_status(self, status: Status) -> list[ControlResult]:
        return [c for c in self.controls if c.status is status]

    @property
    def score(self) -> float | None:
        """Share of evaluated controls that passed (controls that errored are excluded)."""
        passed, failed = len(self.by_status(Status.PASS)), len(self.by_status(Status.FAIL))
        return None if passed + failed == 0 else round(100 * passed / (passed + failed), 1)

    def failed_at_or_above(self, severity: Severity) -> list[ControlResult]:
        return [c for c in self.by_status(Status.FAIL) if c.check.severity.rank >= severity.rank]

    # ---- JSON ---------------------------------------------------------------

    def to_dict(self) -> dict:
        failed = self.by_status(Status.FAIL)
        return {
            "tool": {"name": "cloud-posture-checker", "version": __version__},
            "benchmark": BENCHMARK,
            "account_id": self.account_id,
            "regions": self.regions,
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "summary": {
                "score_percent": self.score,
                "controls": {s.value: len(self.by_status(s)) for s in Status},
                "failed_by_severity": {
                    s.value: sum(1 for c in failed if c.check.severity is s) for s in _SEVERITIES
                },
            },
            "controls": [
                {
                    "check_id": c.check.id,
                    "cis": c.check.cis,
                    "title": c.check.title,
                    "severity": c.check.severity.value,
                    "status": c.status.value,
                    "remediation": c.check.remediation,
                    "evidence": c.check.evidence,
                    "findings": [
                        {k: v for k, v in f.to_dict().items() if k in ("status", "resource", "region", "detail")}
                        for f in c.findings
                    ],
                }
                for c in self.controls
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    # ---- Markdown -----------------------------------------------------------

    def to_markdown(self) -> str:
        failed = self.by_status(Status.FAIL)
        errored = self.by_status(Status.ERROR)
        passed = self.by_status(Status.PASS)
        score = "n/a" if self.score is None else f"{self.score}%"
        out: list[str] = [
            "# AWS Security Posture Report",
            "",
            "| | |",
            "|---|---|",
            f"| **Account** | `{self.account_id}` |",
            f"| **Regions** | {len(self.regions)} ({', '.join(self.regions)}) |",
            f"| **Benchmark** | {BENCHMARK} |",
            f"| **Generated** | {self.generated_at:%Y-%m-%d %H:%M UTC} |",
            f"| **Tool** | cloud-posture-checker {__version__} (read-only) |",
            "",
            "## Summary",
            "",
            f"**Posture score: {score}** of evaluated controls passed "
            f"({len(passed)} passed, {len(failed)} failed, {len(errored)} could not be evaluated).",
            "",
            "| Severity | Failed controls | Affected resources |",
            "|---|---:|---:|",
        ]
        for sev in _SEVERITIES:
            ctrls = [c for c in failed if c.check.severity is sev]
            out.append(f"| {sev.value.capitalize()} | {len(ctrls)} | {sum(len(c.failed) for c in ctrls)} |")

        top = [c for c in failed if c.check.severity.rank >= Severity.HIGH.rank]
        out += ["", "## Top risks", ""]
        if top:
            for i, c in enumerate(top, 1):
                out.append(
                    f"{i}. **{c.check.severity.value.upper()}**: {c.check.title} "
                    f"({_cis_label(c.check)}, {len(c.failed)} resource(s))"
                )
        else:
            out.append("No critical or high severity controls failed.")

        out += ["", "## Failed controls", ""]
        if not failed:
            out.append("None.")
        for c in failed:
            out += [
                f"### [{c.check.severity.value.upper()}] {_cis_label(c.check)}: {c.check.title}",
                "",
                f"**Affected resources ({len(c.failed)})**",
                "",
                "| Resource | Region | Detail |",
                "|---|---|---|",
                *[f"| `{_cell(f.resource)}` | {f.region} | {_cell(f.detail)} |" for f in c.failed],
                "",
                f"**Remediation:** {c.check.remediation}",
                "",
                f"**Evidence:** `{c.check.evidence}`",
                "",
            ]

        if errored:
            out += [
                "## Could not evaluate",
                "",
                "These are coverage gaps, not passes. Fix access and re-run.",
                "",
                "| Control | Region | Reason |",
                "|---|---|---|",
            ]
            for c in errored:
                for f in c.errors:
                    out.append(f"| {_cis_label(c.check)}: {_cell(c.check.title)} | {f.region} | {_cell(f.detail)} |")
            out.append("")

        out += ["## Passed controls", "", "| Control | Severity | Resources checked |", "|---|---|---:|"]
        for c in passed:
            checked = sum(1 for f in c.findings if f.resource != "-")
            shown = checked if checked else "none in scope"
            out.append(f"| {_cis_label(c.check)}: {_cell(c.check.title)} | {c.check.severity.value} | {shown} |")
        out.append("")
        return "\n".join(out)


def _cis_label(meta: CheckMeta) -> str:
    return f"CIS {meta.cis}" if meta.cis else "Best practice"


def _cis_key(cis: str | None) -> tuple:
    if not cis:
        return (999,)
    return tuple(int(p) for p in cis.split(".") if p.isdigit())


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
