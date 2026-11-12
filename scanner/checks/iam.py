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

MAX_KEY_AGE_DAYS = 90


@check(
    check_id="IAM-05",
    title="Every active access key was rotated within the last 90 days",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.12",
        nist_800_53_r5="IA-5",
        iso_27001_2022="A.5.17",
        soc2="CC6.1",
    ),
    remediation="Create a new key, move your apps to it, then delete the old key.",
)
def old_access_keys(ctx: Context) -> list[Finding]:
    now = _utcnow()
    findings = []
    for row in _credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        key_age_days = {}
        for n in ("1", "2"):
            if row[f"access_key_{n}_active"] != "true":
                continue
            rotated = _parse_time(row[f"access_key_{n}_last_rotated"])
            if rotated is None:
                raise ValueError(f"{row['user']}: no usable date for access_key_{n}")
            key_age_days[f"access_key_{n}"] = (now - rotated).days
        too_old = any(days > MAX_KEY_AGE_DAYS for days in key_age_days.values())
        findings.append(
            Finding(
                status=Status.FAIL if too_old else Status.PASS,
                resource=row["arn"],
                evidence={"key_age_days": key_age_days, "limit_days": MAX_KEY_AGE_DAYS},
            )
        )
    return findings

def _as_list(value):
    """AWS lets a field be one item or a list of items. Always hand back a list."""
    return value if isinstance(value, list) else [value]


def _is_admin(document: dict) -> bool:
    """True if one statement says: Allow, every action, every resource."""
    for statement in _as_list(document["Statement"]):
        if (
            statement["Effect"] == "Allow"
            and "*" in _as_list(statement.get("Action", []))
            and "*" in _as_list(statement.get("Resource", []))
        ):
            return True
    return False


@check(
    check_id="IAM-06",
    title="No attached IAM policy grants full administrator access",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.14",
        nist_800_53_r5="AC-6",
        iso_27001_2022="A.8.2",
        soc2="CC6.3",
    ),
    remediation="Detach the policy from every user, group and role, then delete or narrow it.",
)
def admin_policies(ctx: Context) -> list[Finding]:
    iam = ctx.session.client("iam")
    pages = iam.get_paginator("list_policies").paginate(Scope="All", OnlyAttached=True)
    findings = []
    for page in pages:
        for policy in page["Policies"]:
            arn = policy["Arn"]
            version = iam.get_policy_version(
                PolicyArn=arn, VersionId=policy["DefaultVersionId"]
            )
            is_admin = _is_admin(version["PolicyVersion"]["Document"])
            evidence = {"allows_everything": is_admin}
            if is_admin:
                found = iam.list_entities_for_policy(PolicyArn=arn)
                evidence["attached_to"] = {
                    "users": [u["UserName"] for u in found["PolicyUsers"]],
                    "groups": [g["GroupName"] for g in found["PolicyGroups"]],
                    "roles": [r["RoleName"] for r in found["PolicyRoles"]],
                }
            findings.append(
                Finding(
                    status=Status.FAIL if is_admin else Status.PASS,
                    resource=arn,
                    evidence=evidence,
                )
            )
    if not findings:
        return [
            Finding(Status.PASS, f"account:{ctx.account_id}", {"attached_policies_found": 0})
        ]
    return findings

MIN_PASSWORD_LENGTH = 14
MIN_PASSWORD_REUSE_PREVENTION = 24


@check(
    check_id="IAM-20",
    title="The IAM password policy requires 14+ characters and remembers 24 passwords",
    service="iam",
    controls=Controls(
        cis=f"{CIS_VERSION}, 2.8 and 2.9",
        nist_800_53_r5="IA-5(1)",
        iso_27001_2022="A.5.17",
        soc2="CC6.1",
    ),
    remediation="Set the minimum password length to 14 and prevent reuse of the last 24 passwords.",
)
def password_policy(ctx: Context) -> list[Finding]:
    iam = ctx.session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        policy = {}  # no custom password policy has been set
    length = policy.get("MinimumPasswordLength")
    reuse = policy.get("PasswordReusePrevention")
    problems = []
    if length is None or length < MIN_PASSWORD_LENGTH:
        problems.append(f"minimum length is below {MIN_PASSWORD_LENGTH}")
    if reuse is None or reuse < MIN_PASSWORD_REUSE_PREVENTION:
        problems.append(f"password reuse prevention is below {MIN_PASSWORD_REUSE_PREVENTION}")
    return [
        Finding(
            status=Status.FAIL if problems else Status.PASS,
            resource=f"account:{ctx.account_id}",
            evidence={"minimum_length": length, "reuse_prevention": reuse, "problems": problems},
        )
    ]