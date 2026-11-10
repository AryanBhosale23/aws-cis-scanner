"""IAM checks. IAM is global, so these run once per account, not once per region."""

from __future__ import annotations

import csv
import io
import time
from datetime import UTC, datetime

from botocore.exceptions import ClientError

from scanner.checks.base import check
from scanner.models import CIS_VERSION, Context, Controls, Finding, Status


def _credential_report(ctx: Context) -> list[dict[str, str]]:
    iam = ctx.session.client("iam")
    iam.generate_credential_report()
    for _ in range(10):
        try:
            content = iam.get_credential_report()["Content"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ReportInProgress", "ReportNotPresent"):
                raise
            time.sleep(1)
    else:
        raise RuntimeError("Credential report was not ready after 10 tries")
    text = content.decode("utf-8")
    return list(csv.DictReader(io.StringIO(text)))

@check(
    check_id="IAM-01",
    title="Root user has MFA enabled",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.5",  # verify the number against your pinned version
        nist_800_53_r5="IA-2(1)",
        iso_27001_2022="A.8.5",
        soc2="CC6.1",
    ),
    remediation="Sign in as the root user and register an MFA device (hardware key preferred).",
)
def root_mfa_enabled(ctx: Context) -> list[Finding]:
    iam = ctx.session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    enabled = summary.get("AccountMFAEnabled", 0) == 1
    return [
        Finding(
            status=Status.PASS if enabled else Status.FAIL,
            resource=f"arn:aws:iam::{ctx.account_id}:root",
            evidence={"AccountMFAEnabled": summary.get("AccountMFAEnabled")},
        )
    ]

@check(
    check_id="IAM-02",
    title="Root has no access keys",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.4",  # verify the number against your pinned version
        nist_800_53_r5="AC-6(5)",
        iso_27001_2022="A.8.2",
        soc2="CC6.1",
    ),
    remediation="Sign in as the root user and delete its access keys." 
    "Use an IAM role or user for programmatic access instead.",
)
def root_has_no_access_keys(ctx: Context) -> list[Finding]:
    iam = ctx.session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    keys_present = summary["AccountAccessKeysPresent"]
    return [
        Finding(
            status=Status.PASS if keys_present == 0 else Status.FAIL,
            resource=f"arn:aws:iam::{ctx.account_id}:root",
            evidence={"AccountAccessKeysPresent": keys_present},
        )
    ]

@check(
    check_id="IAM-03",
    title="Every console user has MFA",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.10",
        nist_800_53_r5="IA-2(1)",
        iso_27001_2022="A.8.5",
        soc2="CC6.1",
    ),
    remediation="Enable MFA for the user, or remove their console password.",
)
def console_users_have_mfa(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for row in _credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        has_password = row["password_enabled"] == "true"
        has_mfa = row["mfa_active"] == "true"
        findings.append(
            Finding(
                status=Status.FAIL if has_password and not has_mfa else Status.PASS,
                resource=row["arn"],
                evidence={"password_enabled": has_password, "mfa_active": has_mfa},
            )
        )
    return findings

STALE_AFTER_DAYS = 45


def _utcnow() -> datetime:
    """Today's date and time. Tests swap this for a fixed moment."""
    return datetime.now(UTC)


def _parse_time(text: str) -> datetime | None:
    """Turn a report timestamp into a datetime. 'N/A', 'no_information' etc. give None."""
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _active_credentials(row: dict[str, str]) -> list[tuple[str, str, str]]:
    """What this user can use right now, as (name, last used, created)."""
    found = []
    if row["password_enabled"] == "true":
        found.append(("password", row["password_last_used"], row["password_last_changed"]))
    for n in ("1", "2"):
        if row[f"access_key_{n}_active"] == "true":
            found.append(
                (
                    f"access_key_{n}",
                    row[f"access_key_{n}_last_used_date"],
                    row[f"access_key_{n}_last_rotated"],
                )
            )
    return found


@check(
    check_id="IAM-04",
    title="No active credential has gone unused for 45 days or more",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.11",
        nist_800_53_r5="AC-2(3)",
        iso_27001_2022="A.5.18",
        soc2="CC6.2",
    ),
    remediation="Disable or delete the password or access key that has not been used for 45 days.",
)
def unused_credentials(ctx: Context) -> list[Finding]:
    now = _utcnow()
    findings = []
    for row in _credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        days_unused = {}
        for name, last_used, created in _active_credentials(row):
            since = _parse_time(last_used) or _parse_time(created)
            if since is None:
                raise ValueError(f"{row['user']}: no usable date for {name}")
            days_unused[name] = (now - since).days
        stale = any(days >= STALE_AFTER_DAYS for days in days_unused.values())
        findings.append(
            Finding(
                status=Status.FAIL if stale else Status.PASS,
                resource=row["arn"],
                evidence={"days_unused": days_unused, "limit_days": STALE_AFTER_DAYS},
            )
        )
    return findings

# TODO (your turn, Nov 5): IAM-02 "Root user has no access keys"
#   Hint: the same get_account_summary() call has a key called AccountAccessKeysPresent.
#   Controls from the brief: NIST AC-6(5), ISO A.8.2, SOC 2 CC6.1.
# TODO (your turn, Nov 5): IAM-03 "Every user with a console password has MFA"
#   Hint: iam.generate_credential_report() then iam.get_credential_report(); read the CSV.
#   A user "has a console password" when password_enabled is "true"; MFA is mfa_active.
#   Skip the <root_account> row. One Finding per user, so each user is its own evidence.
