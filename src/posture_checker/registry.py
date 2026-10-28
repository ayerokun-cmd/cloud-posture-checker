"""Check registration and the scan runner."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from .context import Context
from .models import CheckMeta, Finding, Result, Severity, Status

CheckFn = Callable[..., Iterable[Result]]
REGISTRY: list[tuple[CheckMeta, CheckFn]] = []

_DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "UnrecognizedClientException",
}


def check(
    *,
    id: str,
    title: str,
    severity: Severity,
    service: str,
    remediation: str,
    evidence: str,
    cis: str | None = None,
    regional: bool = False,
) -> Callable[[CheckFn], CheckFn]:
    """Register a check. Regional checks are called as fn(ctx, region), global ones as fn(ctx)."""
    meta = CheckMeta(id, title, severity, service, remediation, evidence, cis, regional)

    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY.append((meta, fn))
        fn.meta = meta  # type: ignore[attr-defined]
        return fn

    return deco


def all_checks() -> list[tuple[CheckMeta, CheckFn]]:
    from . import checks  # noqa: F401  (importing registers every check)

    return list(REGISTRY)


def _error_detail(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _DENIED:
            return f"Could not evaluate: access denied ({code}). Grant the SecurityAudit policy."
        return f"Could not evaluate: {code or 'ClientError'}: {exc}"
    return f"Could not evaluate: {type(exc).__name__}: {exc}"


def _run_one(ctx: Context, meta: CheckMeta, fn: CheckFn, region: str | None) -> list[Finding]:
    where = region or "global"
    try:
        results = list(fn(ctx, region) if meta.regional else fn(ctx))
    except (ClientError, BotoCoreError) as exc:
        return [Finding(meta, Status.ERROR, "-", _error_detail(exc), where)]
    if not results:
        return [Finding(meta, Status.PASS, "-", "No resources in scope.", where)]
    return [Finding(meta, r.status, r.resource, r.detail, r.region) for r in results]


def run_checks(
    ctx: Context,
    checks: list[tuple[CheckMeta, CheckFn]] | None = None,
    workers: int = 8,
) -> list[Finding]:
    """Run each check (once per region for regional checks) and collect findings."""
    checks = checks if checks is not None else all_checks()
    tasks: list[tuple[CheckMeta, CheckFn, str | None]] = []
    for meta, fn in checks:
        if meta.regional:
            tasks.extend((meta, fn, r) for r in ctx.regions)
        else:
            tasks.append((meta, fn, None))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        batches = pool.map(lambda t: _run_one(ctx, *t), tasks)
        return [f for batch in batches for f in batch]
