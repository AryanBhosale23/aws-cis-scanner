"""Command line entry point: `scanner run --profile audit`."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import click

from scanner.evidence import mask_account, write_evidence
from scanner.models import Status, worst_status
from scanner.report import write_report
from scanner.runner import build_context, run_all


@click.group()
def main() -> None:
    """Read-only AWS scanner that writes audit evidence."""


@main.command()
@click.option("--profile", default=None, help="AWS CLI profile (use a read-only one).")
@click.option("--region", default="us-east-1", show_default=True)
@click.option("--output", "output_dir", type=click.Path(path_type=Path), default="evidence")
@click.option("--only", multiple=True, help="Run only these check ids, e.g. --only IAM-01")
def run(profile: str | None, region: str, output_dir: Path, only: tuple[str, ...]) -> None:
    """Run the checks and write one evidence file per check."""
    ctx = build_context(profile, region)
    click.echo(f"Scanning account {mask_account(ctx.account_id)} ({ctx.region})\n")
    results = run_all(ctx, set(only) or None)

    per_check: dict[str, list] = defaultdict(list)
    for r in results:
        per_check[r.check_id].append(r)
    for check_id, records in per_check.items():
        worst = worst_status(records)
        failed = sum(1 for r in records if r.status is not Status.PASS)
        detail = f"  ({failed} of {len(records)} resources)" if len(records) > 1 and failed else ""
        click.echo(f"[{worst.value}] {check_id:<7} {records[0].title}{detail}")

    counts = Counter(r.status for r in results)
    checks_passed = sum(
        1 for records in per_check.values() if all(r.status is Status.PASS for r in records)
    )
    run_dir = write_evidence(results, output_dir)
    report = write_report(ctx, results, run_dir)
    click.echo(f"\nSummary: {checks_passed} of {len(per_check)} checks passed")
    click.echo(
        f"Results: {counts[Status.PASS]} passed, {counts[Status.FAIL]} failed, "
        f"{counts[Status.ERROR]} error ({len(results)} records)"
    )
    click.echo(f"Evidence: {run_dir}/ ({len(per_check)} files)")
    click.echo(f"Report: {report}")
