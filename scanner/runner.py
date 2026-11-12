"""Runs every registered check and collects the evidence records."""

from __future__ import annotations

import boto3

import scanner.checks  # noqa: F401 - importing registers the checks
from scanner.checks.base import REGISTRY
from scanner.models import Context, Evidence


def build_context(profile: str | None, region: str) -> Context:
    session = boto3.Session(profile_name=profile, region_name=region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    return Context(session=session, account_id=account_id, region=region)

def check_order(check_id: str) -> int:
    """Sort key: the number in the id, so IAM-01 .. S3-07 .. CT-11 .. IAM-20 read in plan order."""
    return int(check_id.split("-")[1])

def run_all(ctx: Context, only: set[str] | None = None) -> list[Evidence]:
    results: list[Evidence] = []
    for check_id in sorted(REGISTRY, key=check_order):
        if only and check_id not in only:
            continue
        results.extend(REGISTRY[check_id].run(ctx))
    return results
