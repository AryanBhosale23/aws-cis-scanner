"""The @check decorator: this is how a function becomes a registered, evidence-producing check.

Rule 1: every check carries its control IDs in metadata (the decorator requires them).
Rule 2: every run produces a structured Evidence record, not just pass or fail.
Rule 3: every check ships with a test that includes a failing input (see tests/).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from scanner.models import Context, Controls, Evidence, Finding, Status

CheckFn = Callable[[Context], list[Finding]]


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    service: str
    controls: Controls
    remediation: str
    fn: CheckFn

    def run(self, ctx: Context) -> list[Evidence]:
        """Run the check and wrap every result in an Evidence record.

        A failing AWS call must never crash the whole run, so any exception becomes
        a single ERROR record that says why.
        """
        try:
            findings = self.fn(ctx)
        except Exception as exc:  # noqa: BLE001 - deliberate: report as ERROR, keep scanning
            findings = [
                Finding(
                    status=Status.ERROR,
                    resource=f"account:{ctx.account_id}",
                    evidence={"error": f"{type(exc).__name__}: {exc}"},
                )
            ]
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return [
            Evidence(
                check_id=self.check_id,
                title=self.title,
                status=f.status,
                resource=f.resource,
                region=ctx.region,
                account_id=ctx.account_id,
                timestamp=now,
                controls=self.controls,
                evidence=f.evidence,
                remediation=self.remediation,
            )
            for f in findings
        ]


REGISTRY: dict[str, Check] = {}


def check(
    *,
    check_id: str,
    title: str,
    service: str,
    controls: Controls,
    remediation: str,
) -> Callable[[CheckFn], Check]:
    """Register a function as a check. The decorated name becomes a Check object."""

    def decorator(fn: CheckFn) -> Check:
        if check_id in REGISTRY:
            raise ValueError(f"Duplicate check id: {check_id}")
        registered = Check(check_id, title, service, controls, remediation, fn)
        REGISTRY[check_id] = registered
        return registered

    return decorator
